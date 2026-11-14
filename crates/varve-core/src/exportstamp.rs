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
//!
//! **What this does not defend against.** The stamp is not signed. It catches
//! an export patched, pruned or overwritten in place — by a person, a build
//! step or a tool — not an adversary who can rewrite the stamp as well: anyone
//! with write access to the directory can also edit `varve.toml`. The layer
//! itself stays verifiable against its signature with `varve verify`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The stamp file written into an export directory's root.
pub const STAMP_FILE: &str = ".varve-export.json";

/// The recorded provenance of an export: which layer produced it, that layer's
/// signed-manifest digest (the join key), and which export shape it is.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
// A reader must not drop a field it does not know and call the stamp pure
// (REQ-PASSTHROUGH-001): a future reader meeting a newer stamp fails closed.
#[serde(deny_unknown_fields)]
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
    /// The tools the producing session allowed to run from PATH through a shim
    /// (`["*"]` or names; REQ-PASSTHROUGH-001 clause 4). Absent for a session
    /// that allowed none, so a pure export's stamp is byte-for-byte what it was.
    /// It says what the SESSION permitted, not that anything ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient_tools: Vec<String>,
    /// The tools the producing toolchain took from OTHER layers of the realm
    /// (REQ-OVERRIDE-001, DD-043 (6)). Absent for a pure toolchain, so a pure
    /// export's stamp is byte-for-byte what it was; present, `layer` reads
    /// `<layer>+mixed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<crate::overrides::RecordedOverride>,
}

impl ExportStamp {
    /// Record the overrides of a MIXED toolchain, and say so in `layer`
    /// (DD-043 (6)): `<layer>+mixed` matches no pin, so nothing that reads the
    /// identity alone can take the export for the pinned layer's.
    pub fn with_overrides(mut self, overrides: Vec<crate::overrides::RecordedOverride>) -> Self {
        self.layer = crate::overrides::identity(&self.layer, &overrides);
        self.overrides = crate::overrides::sorted(&overrides);
        self
    }

    /// Record the ambient tools the producing session allowed.
    pub fn with_ambient_tools(mut self, ambient_tools: Vec<String>) -> Self {
        self.ambient_tools = ambient_tools;
        self
    }
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
                // Streamed: one Zephyr HAL is a gigabyte unpacked, and reading
                // it whole to hash it would hold it all in memory.
                let mut h = Sha256::new();
                let mut file = std::fs::File::open(entry.path()).map_err(io)?;
                let mut buf = vec![0u8; 1 << 16];
                loop {
                    let n = std::io::Read::read(&mut file, &mut buf).map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                out.push(FileEntry {
                    path: rel,
                    digest: format!("sha256:{}", hex::encode(h.finalize())),
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
        ambient_tools: Vec::new(),
        overrides: Vec::new(),
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

/// Compare a stamp against the current pin's manifest digest AND the
/// overrides its toolchain has now (REQ-OVERRIDE-001).
///
/// Current only when both agree and the stamp's own identity agrees with what
/// it records: an export of the pure pin is stale for a mixed toolchain, an
/// export of one mix is stale for another, and a stamp labelled `+mixed` with
/// no overrides recorded (or the reverse) is evidence of neither.
pub fn status(
    stamp: &ExportStamp,
    current_manifest_digest: &str,
    current_overrides: &[crate::overrides::RecordedOverride],
) -> ExportStatus {
    let describe = |digest: &str, overrides: &[crate::overrides::RecordedOverride]| {
        if overrides.is_empty() {
            digest.to_string()
        } else {
            format!(
                "{digest} mixed with {}",
                crate::overrides::env_value(overrides)
            )
        }
    };
    let consistent = crate::overrides::identity_consistent(&stamp.layer, &stamp.overrides);
    if consistent
        && stamp.manifest_digest == current_manifest_digest
        && crate::overrides::mismatch(&stamp.overrides, current_overrides).is_none()
    {
        ExportStatus::Current
    } else {
        ExportStatus::Stale {
            stamped: if consistent {
                describe(&stamp.manifest_digest, &stamp.overrides)
            } else {
                format!(
                    "{} (labelled {}, which disagrees with the overrides it records)",
                    describe(&stamp.manifest_digest, &stamp.overrides),
                    stamp.layer
                )
            },
            current: describe(current_manifest_digest, current_overrides),
        }
    }
}

/// Why an `export-bazel` re-export refuses to clean its directory.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StaleRegistry {
    /// A top-level `*.json` this export does not write and no earlier
    /// `export-bazel` here recorded: not ours to delete, and sealing it under
    /// the new stamp would vouch for a registry varve never wrote.
    #[error(
        "{0} is in the export directory, this export does not write it, and no earlier \
         export-bazel here recorded it — refusing to delete it or to seal it under the stamp. \
         Remove it, or export into an empty directory."
    )]
    Foreign(String),
    /// One an earlier export recorded, changed since: someone edited it, and
    /// deleting their edit silently is not this command's call.
    #[error(
        "{0} was written by an earlier export-bazel and has been modified since — refusing to \
         delete an edited registry. Restore or remove it, then re-run the export."
    )]
    Edited(String),
}

/// The registries an `export-bazel` re-export must REMOVE from its directory
/// (REQ-OVERRIDE-001; the export-sync rule of REQ-EXPORT-SYNC-001): every
/// top-level `*.json` in `present` that this export will not write
/// (`written`), when the previous `bazel-registry` stamp (`prior`) recorded it
/// with the same digest. Whatever the reason a tool's registry is not written
/// this time — an override added, removed or swapped, a pin moved to a layer
/// without provenance for it — the last export's file must not survive for
/// the new stamp to seal: Bazel would fetch a tool this project does not run.
///
/// Pure, and decided in full BEFORE anything is deleted: a refusal leaves the
/// directory as it was. `present` is `scan_tree` of the directory (the stamp
/// itself excluded); nested files and other extensions are not registries.
pub fn stale_registries(
    prior: Option<&ExportStamp>,
    present: &[FileEntry],
    written: &std::collections::BTreeSet<String>,
) -> Result<Vec<String>, StaleRegistry> {
    let recorded = prior.filter(|s| s.kind == "bazel-registry");
    let mut remove = Vec::new();
    for f in present {
        if f.path.contains('/') || !f.path.ends_with(".json") || written.contains(&f.path) {
            continue;
        }
        match recorded.and_then(|s| s.files.iter().find(|r| r.path == f.path)) {
            None => return Err(StaleRegistry::Foreign(f.path.clone())),
            Some(r) if r.digest != f.digest => return Err(StaleRegistry::Edited(f.path.clone())),
            Some(_) => remove.push(f.path.clone()),
        }
    }
    Ok(remove)
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
            ambient_tools: Vec::new(),
            overrides: Vec::new(),
        }
    }

    fn synth_override(digest: &str) -> crate::overrides::RecordedOverride {
        crate::overrides::RecordedOverride {
            tool: "synth".into(),
            layer: "2026.07.0".into(),
            digest: digest.into(),
        }
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_mixed_export_is_stamped_layer_plus_mixed_and_records_its_overrides() {
        // DD-043 (6): the single identity field never names the pinned layer
        // alone for a mixed toolchain.
        let mixed = sample().with_overrides(vec![synth_override("sha256:cc")]);
        assert_eq!(mixed.layer, "2026.08.0+mixed");
        assert_eq!(
            mixed.manifest_digest, "sha256:aaaa",
            "the join key is the pin's"
        );
        assert_eq!(mixed.overrides, [synth_override("sha256:cc")]);
        let text = serde_json::to_string(&mixed).unwrap();
        assert!(
            text.contains("\"overrides\":[{\"tool\":\"synth\""),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<ExportStamp>(&text).unwrap(), mixed);
        // A pure export's stamp is byte-for-byte what it was.
        let pure = sample().with_overrides(Vec::new());
        assert_eq!(pure, sample());
        assert!(!serde_json::to_string(&pure).unwrap().contains("overrides"));
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_stamp_is_current_only_for_the_same_pin_and_the_same_overrides() {
        let o = synth_override("sha256:cc");
        let mixed = sample().with_overrides(vec![o.clone()]);
        assert_eq!(
            status(&mixed, "sha256:aaaa", std::slice::from_ref(&o)),
            ExportStatus::Current
        );
        // A pure export, now that the project is mixed.
        assert!(matches!(
            status(&sample(), "sha256:aaaa", std::slice::from_ref(&o)),
            ExportStatus::Stale { .. }
        ));
        // A mixed export, now that the project is pure.
        let ExportStatus::Stale { stamped, current } = status(&mixed, "sha256:aaaa", &[]) else {
            panic!("a mixed export is not current for the pure pin");
        };
        assert!(stamped.contains("synth=2026.07.0@sha256:cc"), "{stamped}");
        assert_eq!(current, "sha256:aaaa");
        // Another mix.
        assert!(matches!(
            status(&mixed, "sha256:aaaa", &[synth_override("sha256:dd")]),
            ExportStatus::Stale { .. }
        ));
        // A label that disagrees with the record is not evidence of either.
        let mut relabelled = mixed.clone();
        relabelled.layer = "2026.08.0".into();
        assert!(matches!(
            status(&relabelled, "sha256:aaaa", std::slice::from_ref(&o)),
            ExportStatus::Stale { .. }
        ));
        let mut unlabelled = sample();
        unlabelled.layer = "2026.08.0+mixed".into();
        assert!(matches!(
            status(&unlabelled, "sha256:aaaa", &[]),
            ExportStatus::Stale { .. }
        ));
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_v047_reader_refuses_a_mixed_stamp_instead_of_calling_it_current() {
        // DD-043 (6), the older-reader property. A copy of the v0.47.0
        // ExportStamp, which denies unknown fields: it meets `overrides` and
        // refuses the stamp (verify reports it unreadable, exit 1), so no
        // v0.47.0 varve takes a mixed export for the pinned layer's.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct ExportStampV047 {
            layer: String,
            manifest_digest: String,
            kind: String,
            #[serde(default)]
            content_digest: Option<String>,
            #[serde(default)]
            files: Vec<FileEntry>,
            #[serde(default)]
            ambient_tools: Vec<String>,
        }
        let mixed = sample().with_overrides(vec![synth_override("sha256:cc")]);
        let text = serde_json::to_string(&mixed).unwrap();
        assert!(serde_json::from_str::<ExportStampV047>(&text).is_err());
        let pure = serde_json::to_string(&sample()).unwrap();
        assert!(serde_json::from_str::<ExportStampV047>(&pure).is_ok());
    }

    fn entry(path: &str, digest: &str) -> FileEntry {
        FileEntry {
            path: path.into(),
            digest: digest.into(),
        }
    }

    fn bazel_stamp(files: &[(&str, &str)]) -> ExportStamp {
        ExportStamp {
            kind: "bazel-registry".into(),
            files: files.iter().map(|(p, d)| entry(p, d)).collect(),
            ..sample()
        }
    }

    fn written(names: &[&str]) -> std::collections::BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_reexport_removes_every_registry_the_last_export_wrote_and_this_one_does_not() {
        // Whatever the reason a tool's registry is not written this time — an
        // override removed or swapped, a pin moved — the last export's file
        // for it must not survive to be sealed by the new stamp.
        let prior = bazel_stamp(&[("synth.json", "sha256:s"), ("loom.json", "sha256:l")]);
        let present = [
            entry("loom.json", "sha256:l"),
            entry("synth.json", "sha256:s"),
        ];
        assert_eq!(
            stale_registries(Some(&prior), &present, &written(&["loom.json"])),
            Ok(vec!["synth.json".to_string()])
        );
        // Written again: overwritten, not removed.
        assert_eq!(
            stale_registries(
                Some(&prior),
                &present,
                &written(&["loom.json", "synth.json"])
            ),
            Ok(vec![])
        );
        // Nothing there, nothing to do — with or without a prior stamp.
        assert_eq!(
            stale_registries(None, &[], &written(&["synth.json"])),
            Ok(vec![])
        );
        // Not a registry: other files and nested ones are not this rule's.
        let other = [
            entry("README.md", "sha256:r"),
            entry("sub/x.json", "sha256:x"),
        ];
        assert_eq!(stale_registries(None, &other, &written(&[])), Ok(vec![]));
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_registry_no_export_recorded_or_one_edited_since_is_refused() {
        let prior = bazel_stamp(&[("synth.json", "sha256:s")]);
        // Never recorded: not ours to delete, and not ours to seal.
        assert_eq!(
            stale_registries(
                Some(&prior),
                &[entry("foo.json", "sha256:f")],
                &written(&[])
            ),
            Err(StaleRegistry::Foreign("foo.json".into()))
        );
        assert_eq!(
            stale_registries(None, &[entry("synth.json", "sha256:s")], &written(&[])),
            Err(StaleRegistry::Foreign("synth.json".into()))
        );
        // Recorded by an export of ANOTHER kind: not a registry we wrote.
        let cargo = ExportStamp {
            kind: "cargo".into(),
            ..bazel_stamp(&[("synth.json", "sha256:s")])
        };
        assert_eq!(
            stale_registries(
                Some(&cargo),
                &[entry("synth.json", "sha256:s")],
                &written(&[])
            ),
            Err(StaleRegistry::Foreign("synth.json".into()))
        );
        // Recorded, then hand-edited: refused rather than deleted.
        assert_eq!(
            stale_registries(
                Some(&prior),
                &[entry("synth.json", "sha256:EDITED")],
                &written(&[])
            ),
            Err(StaleRegistry::Edited("synth.json".into()))
        );
        // A foreign file that will be overwritten is no obstacle.
        assert_eq!(
            stale_registries(
                Some(&prior),
                &[entry("foo.json", "sha256:f")],
                &written(&["foo.json"])
            ),
            Ok(vec![])
        );
        assert!(
            StaleRegistry::Foreign("a.json".into())
                .to_string()
                .contains("a.json")
        );
        assert!(
            StaleRegistry::Edited("b.json".into())
                .to_string()
                .contains("b.json")
        );
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn ambient_tools_round_trip_and_a_pure_stamp_never_mentions_them() {
        let pure = serde_json::to_string(&sample()).unwrap();
        assert!(!pure.contains("ambient_tools"), "{pure}");
        let amb = sample().with_ambient_tools(vec!["ghost".into()]);
        assert_eq!(amb.ambient_tools, ["ghost"]);
        let text = serde_json::to_string(&amb).unwrap();
        assert!(text.contains("\"ambient_tools\":[\"ghost\"]"), "{text}");
        assert_eq!(serde_json::from_str::<ExportStamp>(&text).unwrap(), amb);
        // A stamp from before the field parses as pure.
        assert!(
            serde_json::from_str::<ExportStamp>(&pure)
                .unwrap()
                .ambient_tools
                .is_empty()
        );
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn a_stamp_with_a_field_this_reader_does_not_know_is_refused() {
        // A newer stamp's extra field must not be dropped and the stamp called
        // pure: this is what keeps FUTURE readers fail-closed.
        let mut v = serde_json::to_value(sample()).unwrap();
        v["something_newer"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ExportStamp>(v).is_err());
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
        assert_eq!(status(&sample(), "sha256:aaaa", &[]), ExportStatus::Current);
    }

    // rivet: verifies REQ-EXPORT-SYNC-001
    #[test]
    fn status_is_stale_when_digests_differ() {
        assert_eq!(
            status(&sample(), "sha256:bbbb", &[]),
            ExportStatus::Stale {
                stamped: "sha256:aaaa".into(),
                current: "sha256:bbbb".into(),
            }
        );
    }

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
    #[test]
    fn one_flipped_byte_is_a_modified_path() {
        let (dir, stamp) = stamped_export();
        put(dir.path(), "m/b.txt", b"bravp");
        assert_eq!(
            verify_content(dir.path(), &stamp).unwrap(),
            ContentStatus::Drifted(ContentDrift::Modified("m/b.txt".into()))
        );
    }

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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

    // rivet: verifies REQ-EXPORTCONTENT-001
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
