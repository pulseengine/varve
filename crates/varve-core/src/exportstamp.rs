//! Export provenance stamp (REQ-EXPORT-SYNC-001).
//!
//! An export adapter materialises offline byte sources (a Cargo local registry,
//! a cargo-vendor tree, a Bazel distdir) from a verified layer. Left unmarked,
//! a committed export goes silently stale the moment the project's pin moves to
//! a new layer — it keeps serving the old crates. To make that loud, every
//! export writes a `.varve-export.json` stamp binding its bytes to the layer
//! that produced them: `{layer, manifest_digest, kind}`, where `manifest_digest`
//! is the sha256 of the DSSE-signed layer manifest — the same join key the rest
//! of varve uses. `varve verify --export <DIR>` re-derives the current pin's
//! manifest digest and fails when a stamped export diverges from it.
//!
//! That binds a directory to a LAYER; it says nothing about whether the
//! directory still holds what was written (varve#288). So the stamp also
//! carries the exported TREE: `files`, a sorted list of `(path, digest)` over
//! everything in the directory except the stamp, and `content_digest`, one
//! sha256 over that list. [`verify_content`] re-hashes the directory and names
//! the first path that differs.
//!
//! **Symlinks are never followed.** An SDK tree legitimately contains links,
//! and following one could hash (and so vouch for) bytes outside the export.
//! A link is recorded as its own entry whose digest is `link:<target>` — the
//! target text, verbatim — so retargeting a link is a `modified` path like any
//! other edit. Anything that is neither a regular file, a directory nor a
//! symlink (a fifo, a socket, a device) is REFUSED rather than skipped:
//! silently omitting a path from the digest is how a tree gets vouched for
//! while holding something unhashed. Directories themselves are not entries;
//! an empty directory is not content and is not tracked.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The stamp file written into an export directory's root.
pub const STAMP_FILE: &str = ".varve-export.json";

/// The recorded provenance of an export: which layer produced it, that layer's
/// signed-manifest digest (the join key), and which export shape it is.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ExportStamp {
    /// The layer identity, e.g. `2026.08.0`.
    pub layer: String,
    /// `sha256:<hex>` of the DSSE-signed layer manifest.
    pub manifest_digest: String,
    /// The export shape: `cargo` | `crates-vendor` | `bazel-distdir` | ...
    pub kind: String,
    /// `sha256:<hex>` over [`ExportStamp::files`] (see [`tree_digest`]). Absent
    /// on a stamp written before varve#288 — such a stamp is UNVERIFIABLE, not
    /// current: nothing recorded what the directory held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    /// Every file in the export except the stamp, sorted by path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileEntry>,
}

/// One exported file: its path relative to the export root (`/`-separated) and
/// its digest — `sha256:<hex>` of the bytes, or `link:<target>` for a symlink.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub digest: String,
}

/// Why an export stamp could not be read or trusted.
#[derive(Debug, thiserror::Error)]
pub enum ExportStampError {
    #[error(
        "no export stamp ({STAMP_FILE}) in {0} — not a varve export \
         (or produced before stamping); re-run the export"
    )]
    Missing(String),
    #[error("export stamp in {0} is malformed: {1}")]
    Malformed(String, String),
    #[error("i/o error on export stamp in {0}: {1}")]
    Io(String, String),
    #[error(
        "cannot digest the export in {0}: {1} — the export is not a plain tree of \
         files and symlinks, so varve will not vouch for it"
    )]
    Unhashable(String, String),
}

/// The drift verdict for a stamped export against the current pin.
#[derive(Debug, PartialEq, Eq)]
pub enum ExportStatus {
    /// The stamp's manifest digest matches the current pin — export is fresh.
    Current,
    /// The pin has moved: the export was produced from a different layer.
    Stale { stamped: String, current: String },
}

/// How the exported tree differs from what the stamp recorded.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContentDrift {
    /// The path exists in both but its bytes (or link target) changed.
    Modified(String),
    /// The stamp recorded the path; it is gone.
    Missing(String),
    /// The path is present and the stamp never recorded it.
    Extra(String),
}

impl ContentDrift {
    pub fn path(&self) -> &str {
        match self {
            ContentDrift::Modified(p) | ContentDrift::Missing(p) | ContentDrift::Extra(p) => p,
        }
    }
}

impl std::fmt::Display for ContentDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentDrift::Modified(p) => write!(f, "{p} was modified after export"),
            ContentDrift::Missing(p) => write!(f, "{p} is missing (it was exported, now deleted)"),
            ContentDrift::Extra(p) => {
                write!(f, "{p} is an unexpected extra file (never exported)")
            }
        }
    }
}

/// Whether an export directory still holds what its stamp recorded.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentStatus {
    /// Every recorded file is present and unchanged, and nothing else is.
    Intact,
    /// The stamp carries no content digest (written before varve#288), so
    /// nothing says what the directory held. Not a pass: re-export.
    Unverifiable,
    /// The tree differs; this is the first differing path in sorted order.
    Drifted(ContentDrift),
}

/// The one digest over a file list: sha256 of `path NUL digest LF` for each
/// entry, in the order given. Callers pass the list sorted by path.
pub fn tree_digest(files: &[FileEntry]) -> String {
    let mut h = Sha256::new();
    for f in files {
        h.update(f.path.as_bytes());
        h.update([0u8]);
        h.update(f.digest.as_bytes());
        h.update(b"\n");
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Walk `dir` and list every file (and symlink, unfollowed) except the stamp at
/// the root, sorted by path. See the module docs for the symlink policy.
pub fn scan_tree(dir: &Path) -> Result<Vec<FileEntry>, ExportStampError> {
    let shown = dir.display().to_string();
    let io = |e: std::io::Error| ExportStampError::Io(shown.clone(), e.to_string());
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name().into_string().map_err(|n| {
                ExportStampError::Unhashable(
                    shown.clone(),
                    format!("{:?} in {} is not valid UTF-8", n, d.display()),
                )
            })?;
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            // `file_type` of a DirEntry does not follow symlinks.
            let ft = entry.file_type().map_err(io)?;
            if ft.is_symlink() {
                let target = std::fs::read_link(entry.path()).map_err(io)?;
                out.push(FileEntry {
                    path: rel,
                    digest: format!("link:{}", target.to_string_lossy()),
                });
            } else if ft.is_dir() {
                stack.push((entry.path(), rel));
            } else if ft.is_file() {
                if rel == STAMP_FILE {
                    continue;
                }
                let bytes = std::fs::read(entry.path()).map_err(io)?;
                out.push(FileEntry {
                    path: rel,
                    digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
                });
            } else {
                return Err(ExportStampError::Unhashable(
                    shown.clone(),
                    format!("{rel} is not a regular file, directory or symlink"),
                ));
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Build the stamp for a freshly written export: scan `dir` and record the tree.
pub fn stamp_for(
    dir: &Path,
    layer: &str,
    manifest_digest: &str,
    kind: &str,
) -> Result<ExportStamp, ExportStampError> {
    let files = scan_tree(dir)?;
    Ok(ExportStamp {
        layer: layer.to_string(),
        manifest_digest: manifest_digest.to_string(),
        kind: kind.to_string(),
        content_digest: Some(tree_digest(&files)),
        files,
    })
}

/// Re-hash `dir` and compare it with the stamp's recorded tree.
///
/// A stamp whose own `files` list does not hash to its `content_digest` is
/// `Malformed` — someone edited the stamp, and a list that disagrees with its
/// digest cannot be trusted to name the path.
pub fn verify_content(dir: &Path, stamp: &ExportStamp) -> Result<ContentStatus, ExportStampError> {
    let Some(recorded) = &stamp.content_digest else {
        return Ok(ContentStatus::Unverifiable);
    };
    if tree_digest(&stamp.files) != *recorded {
        return Err(ExportStampError::Malformed(
            dir.display().to_string(),
            "the recorded file list does not match its content digest".into(),
        ));
    }
    let now = scan_tree(dir)?;
    let (mut a, mut b) = (stamp.files.iter().peekable(), now.iter().peekable());
    loop {
        match (a.peek(), b.peek()) {
            (None, None) => return Ok(ContentStatus::Intact),
            (Some(r), None) => {
                return Ok(ContentStatus::Drifted(ContentDrift::Missing(
                    r.path.clone(),
                )));
            }
            (None, Some(n)) => {
                return Ok(ContentStatus::Drifted(ContentDrift::Extra(n.path.clone())));
            }
            (Some(r), Some(n)) => match r.path.cmp(&n.path) {
                std::cmp::Ordering::Less => {
                    return Ok(ContentStatus::Drifted(ContentDrift::Missing(
                        r.path.clone(),
                    )));
                }
                std::cmp::Ordering::Greater => {
                    return Ok(ContentStatus::Drifted(ContentDrift::Extra(n.path.clone())));
                }
                std::cmp::Ordering::Equal => {
                    if r.digest != n.digest {
                        return Ok(ContentStatus::Drifted(ContentDrift::Modified(
                            r.path.clone(),
                        )));
                    }
                    a.next();
                    b.next();
                }
            },
        }
    }
}

/// Write the stamp into `dir`, creating `dir` if needed.
pub fn write_stamp(dir: &Path, stamp: &ExportStamp) -> Result<(), ExportStampError> {
    let path = dir.join(STAMP_FILE);
    std::fs::create_dir_all(dir)
        .map_err(|e| ExportStampError::Io(dir.display().to_string(), e.to_string()))?;
    let json = serde_json::to_string_pretty(stamp)
        .map_err(|e| ExportStampError::Malformed(dir.display().to_string(), e.to_string()))?;
    std::fs::write(&path, json)
        .map_err(|e| ExportStampError::Io(dir.display().to_string(), e.to_string()))
}

/// Read and parse the stamp from `dir`. A missing file is `Missing`; unparseable
/// JSON is `Malformed` — both are failures for a directory claimed to be an export.
pub fn read_stamp(dir: &Path) -> Result<ExportStamp, ExportStampError> {
    let path = dir.join(STAMP_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ExportStampError::Missing(dir.display().to_string()));
        }
        Err(e) => {
            return Err(ExportStampError::Io(
                dir.display().to_string(),
                e.to_string(),
            ));
        }
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| ExportStampError::Malformed(dir.display().to_string(), e.to_string()))
}

/// Compare a stamp against the current pin's manifest digest.
pub fn status(stamp: &ExportStamp, current_manifest_digest: &str) -> ExportStatus {
    if stamp.manifest_digest == current_manifest_digest {
        ExportStatus::Current
    } else {
        ExportStatus::Stale {
            stamped: stamp.manifest_digest.clone(),
            current: current_manifest_digest.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    /// True when mode 000 does not actually deny a read here (running as root,
    /// or a filesystem that ignores permission bits) — so the unreadable-file
    /// tests cannot hold their premise and must skip rather than fail.
    #[cfg(unix)]
    fn premise_unavailable() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let Ok(dir) = tempfile::tempdir() else {
            return true;
        };
        let probe = dir.path().join("probe");
        if std::fs::write(&probe, b"x").is_err() {
            return true;
        }
        if std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).is_err() {
            return true;
        }
        let readable = std::fs::read(&probe).is_ok();
        let _ = std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o644));
        readable
    }

    use super::*;

    fn sample() -> ExportStamp {
        ExportStamp {
            layer: "2026.08.0".into(),
            manifest_digest: "sha256:aaaa".into(),
            kind: "cargo".into(),
            content_digest: None,
            files: Vec::new(),
        }
    }

    fn put(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    /// A stamped three-file export: `a.txt`, `m/b.txt`, `z.txt`.
    fn stamped_export() -> (tempfile::TempDir, ExportStamp) {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "a.txt", b"alpha");
        put(dir.path(), "m/b.txt", b"bravo");
        put(dir.path(), "z.txt", b"zulu");
        let stamp = stamp_for(dir.path(), "2026.08.0", "sha256:aaaa", "cargo").unwrap();
        write_stamp(dir.path(), &stamp).unwrap();
        (dir, stamp)
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let s = sample();
        write_stamp(dir.path(), &s).unwrap();
        assert!(dir.path().join(STAMP_FILE).exists());
        assert_eq!(read_stamp(dir.path()).unwrap(), s);
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn read_missing_stamp_is_missing_error() {
        let dir = tempfile::tempdir().unwrap();
        match read_stamp(dir.path()) {
            Err(ExportStampError::Missing(_)) => {}
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[cfg(unix)]
    #[test]
    fn an_unreadable_stamp_is_an_io_error_not_a_missing_one() {
        // A stamp that EXISTS but cannot be read is not the same as no stamp.
        // Reporting it as Missing would tell the user "re-run the export" when
        // the real fault is permissions — advice that cannot work. (Found by
        // cargo-mutants: the NotFound guard survived being replaced with true.)
        // chmod(000) does not stop root, and some filesystems ignore modes, so
        // this case cannot always be exercised. Test the PREMISE directly
        // rather than guessing at uid: if an unreadable file is still readable
        // here, skip. A test that cannot hold its premise should say so, not go
        // red for the wrong reason.
        if premise_unavailable() {
            eprintln!("skipping: this environment does not deny reads on mode 000");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STAMP_FILE);
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = read_stamp(dir.path());
        // Restore before asserting, so a failure cannot leave an unremovable dir.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        match got {
            Err(ExportStampError::Io(..)) => {}
            other => panic!("expected Io for an unreadable stamp, got {other:?}"),
        }
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn read_malformed_stamp_is_malformed_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STAMP_FILE), b"{not json").unwrap();
        match read_stamp(dir.path()) {
            Err(ExportStampError::Malformed(..)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn status_is_current_when_digests_match() {
        assert_eq!(status(&sample(), "sha256:aaaa"), ExportStatus::Current);
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn status_is_stale_when_digests_differ() {
        assert_eq!(
            status(&sample(), "sha256:bbbb"),
            ExportStatus::Stale {
                stamped: "sha256:aaaa".into(),
                current: "sha256:bbbb".into(),
            }
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn the_stamp_records_a_sorted_per_file_list_and_one_digest_over_it() {
        let (dir, stamp) = stamped_export();
        let paths: Vec<&str> = stamp.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            ["a.txt", "m/b.txt", "z.txt"],
            "sorted, `/`-separated"
        );
        // sha256("alpha")
        assert_eq!(
            stamp.files[0].digest,
            "sha256:8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"
        );
        assert_eq!(
            stamp.content_digest.as_deref(),
            Some(tree_digest(&stamp.files).as_str())
        );
        assert!(
            stamp
                .content_digest
                .as_ref()
                .unwrap()
                .starts_with("sha256:")
        );
        // It survives the disk, and the stamp itself is not in its own list.
        assert_eq!(read_stamp(dir.path()).unwrap(), stamp);
        assert!(!paths.contains(&STAMP_FILE));
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Intact
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn the_tree_digest_depends_on_every_path_and_every_digest() {
        let e = |p: &str, d: &str| FileEntry {
            path: p.into(),
            digest: d.into(),
        };
        let base = tree_digest(&[e("a", "sha256:1"), e("b", "sha256:2")]);
        assert_ne!(base, tree_digest(&[e("a", "sha256:1"), e("b", "sha256:3")]));
        assert_ne!(base, tree_digest(&[e("a", "sha256:1"), e("c", "sha256:2")]));
        assert_ne!(base, tree_digest(&[e("a", "sha256:1")]));
        // The separators matter: moving a byte across the path/digest boundary
        // must not collide.
        assert_ne!(
            tree_digest(&[e("ab", "sha256:1")]),
            tree_digest(&[e("a", "bsha256:1")])
        );
        assert_ne!(
            tree_digest(&[e("a", "sha256:1"), e("b", "sha256:2")]),
            tree_digest(&[e("a", "sha256:1b"), e("", "sha256:2")])
        );
        assert_eq!(base, tree_digest(&[e("a", "sha256:1"), e("b", "sha256:2")]));
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn one_flipped_byte_is_a_modified_path() {
        let (dir, stamp) = stamped_export();
        put(dir.path(), "m/b.txt", b"bravp");
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Modified("m/b.txt".into()))
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_deleted_file_is_a_missing_path() {
        for gone in ["a.txt", "m/b.txt", "z.txt"] {
            let (dir, stamp) = stamped_export();
            std::fs::remove_file(dir.path().join(gone)).unwrap();
            assert_eq!(
                verify_content(dir.path(), &stamp).unwrap(),
                ContentStatus::Drifted(ContentDrift::Missing(gone.into())),
                "deleting {gone}"
            );
        }
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn an_added_file_is_an_extra_path_wherever_it_sorts() {
        // Before the first entry, between two, and after the last: the merge
        // walk has a distinct arm for each.
        for added in ["0-first.txt", "m/c.txt", "zz-last.txt"] {
            let (dir, stamp) = stamped_export();
            put(dir.path(), added, b"planted");
            assert_eq!(
                verify_content(dir.path(), &stamp).unwrap(),
                ContentStatus::Drifted(ContentDrift::Extra(added.into())),
                "adding {added}"
            );
        }
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn the_first_differing_path_in_sorted_order_is_the_one_named() {
        let (dir, stamp) = stamped_export();
        put(dir.path(), "z.txt", b"changed"); // modified, sorts last
        put(dir.path(), "m/b.txt", b"changed"); // modified, sorts second
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Modified("m/b.txt".into()))
        );
        std::fs::remove_file(dir.path().join("a.txt")).unwrap(); // missing, sorts first
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Missing("a.txt".into()))
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn only_the_stamp_at_the_root_is_exempt_from_the_digest() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "a.txt", b"x");
        // A file that merely shares the stamp's NAME deeper in the tree is
        // content like any other.
        put(dir.path(), &format!("sub/{STAMP_FILE}"), b"{}");
        let stamp = stamp_for(dir.path(), "l", "sha256:aaaa", "cargo").unwrap();
        let paths: Vec<&str> = stamp.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a.txt", "sub/.varve-export.json"]);
        // And rewriting the root stamp does not change what the tree digests to.
        write_stamp(dir.path(), &stamp).unwrap();
        assert_eq!(scan_tree(dir.path()).unwrap(), stamp.files);
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_stamp_without_a_content_digest_is_unverifiable_not_current() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "a.txt", b"x");
        assert_eq!(
            verify_content(dir.path(), &sample()).unwrap(),
            ContentStatus::Unverifiable
        );
        // An old stamp on disk parses: the new fields are optional on read.
        std::fs::write(
            dir.path().join(STAMP_FILE),
            br#"{"layer":"2026.08.0","manifest_digest":"sha256:aaaa","kind":"cargo"}"#,
        )
        .unwrap();
        let old = read_stamp(dir.path()).unwrap();
        assert_eq!(old.content_digest, None);
        assert!(old.files.is_empty());
        assert_eq!(
            verify_content(dir.path(), &old).unwrap(),
            ContentStatus::Unverifiable
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_file_list_that_disagrees_with_its_own_digest_is_malformed() {
        let (dir, mut stamp) = stamped_export();
        // Rewriting a recorded digest to match a tampered file, without
        // recomputing `content_digest`, must not launder the tamper.
        stamp.files[0].digest = "sha256:00".into();
        match verify_content(dir.path(), &stamp) {
            Err(ExportStampError::Malformed(..)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn an_empty_export_verifies_and_gaining_a_file_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let stamp = stamp_for(dir.path(), "l", "sha256:aaaa", "cargo").unwrap();
        assert!(stamp.files.is_empty());
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Intact
        );
        put(dir.path(), "x", b"1");
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Extra("x".into()))
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_drift_names_its_path_and_says_how() {
        let m = ContentDrift::Modified("a/b".into());
        let x = ContentDrift::Missing("a/b".into());
        let e = ContentDrift::Extra("a/b".into());
        for d in [&m, &x, &e] {
            assert_eq!(d.path(), "a/b");
        }
        assert!(m.to_string().contains("modified"));
        assert!(x.to_string().contains("missing"));
        assert!(e.to_string().contains("unexpected"));
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_recorded_by_target_and_never_followed() {
        let outside = tempfile::tempdir().unwrap();
        put(outside.path(), "secret", b"outside the export");
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "real.txt", b"x");
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        // A link to a directory outside the tree: following it would walk (and
        // vouch for) everything in there.
        std::os::unix::fs::symlink(outside.path(), dir.path().join("dirlink")).unwrap();
        let stamp = stamp_for(dir.path(), "l", "sha256:aaaa", "sdk").unwrap();
        let by_path = |p: &str| stamp.files.iter().find(|f| f.path == p).unwrap();
        assert_eq!(
            by_path("link").digest,
            format!("link:{}", outside.path().join("secret").display())
        );
        assert!(by_path("dirlink").digest.starts_with("link:"));
        assert!(
            !stamp.files.iter().any(|f| f.path.starts_with("dirlink/")),
            "walked through a symlink"
        );
        // The bytes behind a link are not the export's: changing them is not drift.
        put(outside.path(), "secret", b"changed out there");
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Intact
        );
        // Retargeting the link IS drift.
        std::fs::remove_file(dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("link")).unwrap();
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Modified("link".into()))
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[cfg(unix)]
    #[test]
    fn a_special_file_is_refused_rather_than_skipped() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), "a.txt", b"x");
        let made = std::process::Command::new("mkfifo")
            .arg(dir.path().join("pipe"))
            .status();
        if !matches!(made, Ok(s) if s.success()) {
            eprintln!("skipping: mkfifo is unavailable here");
            return;
        }
        match stamp_for(dir.path(), "l", "sha256:aaaa", "cargo") {
            Err(ExportStampError::Unhashable(_, why)) => assert!(why.contains("pipe"), "{why}"),
            other => panic!("expected Unhashable, got {other:?}"),
        }
    }
}
