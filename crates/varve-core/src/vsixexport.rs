//! VS Code extension export (REQ-VSIX-001 clause 3).
//!
//! A `vsix`-kind entry carries one `.vsix` file — a zip, nothing more, which is
//! why extensions could ship in this release while the tree-shaped SDK store
//! (varve#67) could not. `export-vsix` lays the verified bytes out as files
//! `code --install-extension <file>` consumes directly:
//!
//! ```text
//! D/rust-lang.rust-analyzer-0.3.2260.vsix
//! D/vadimcn.vscode-lldb-1.11.4.vsix
//! D/.varve-export.json
//! ```
//!
//! The trust chain needs nothing new. A `.vsix` is signed like any blob (its
//! digest is in the DSSE-signed layer manifest) and the digest check is
//! kind-agnostic (DD-003). What this module owes the caller is the FILE NAME:
//! `code` dispatches on the `.vsix` suffix, refusing anything else outright,
//! and a human reading the directory has only the name to tell one extension
//! from another. So the marketplace convention — `publisher.name-version.vsix`
//! — is reproduced exactly, with the entry's payload name supplying the
//! `publisher.name` half.
//!
//! Names come out of a SIGNED manifest, which makes them attributable, not
//! benign: `../../evil` signed by a realm root must not place bytes outside
//! the export directory, and a name starting with `-` must not reach `code`'s
//! argument parser as a flag. Both are refused before anything is written.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One extension to lay out: its marketplace identity and the `.vsix` bytes.
#[derive(Debug, Clone)]
pub struct VsixEntry {
    /// The extension identity, conventionally `publisher.name`
    /// (e.g. `rust-lang.rust-analyzer`) — the payload's name annotation.
    pub name: String,
    /// The extension version, e.g. `0.3.2260`.
    pub version: String,
    /// The verified `.vsix` bytes.
    pub bytes: Vec<u8>,
}

/// The file extension `code --install-extension` dispatches on. It accepts a
/// path only when it ends in this; anything else is treated as a marketplace
/// ID and fetched from the network — the exact behaviour this export exists
/// to avoid.
pub const VSIX_SUFFIX: &str = ".vsix";

/// The file name for an extension: `publisher.name-version.vsix`, the
/// marketplace's own asset convention, so the file a user sees in the export
/// directory reads the same as the one they would have downloaded.
///
/// Total by construction — it never inspects the strings. `validate_entries`
/// is what refuses a name this could not express safely, and every writer here
/// runs it first.
pub fn vsix_file_name(name: &str, version: &str) -> String {
    format!("{name}-{version}{VSIX_SUFFIX}")
}

/// Why an extension could not be exported.
#[derive(Debug, thiserror::Error)]
pub enum VsixExportError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("extension id {name:?} cannot be exported: {why}")]
    UnrepresentableName { name: String, why: String },
    #[error("extension {name:?} has a version {version:?} that cannot be exported: {why}")]
    UnrepresentableVersion {
        name: String,
        version: String,
        why: String,
    },
    #[error(
        "extensions {first} and {second} both export to {file} — one would overwrite the \
         other, and the survivor would carry the wrong bytes under the right name"
    )]
    Collision {
        file: String,
        first: String,
        second: String,
    },
}

/// Is this string a single, safe, `code`-passable path component?
fn component_fault(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("empty".into());
    }
    if value == "." || value == ".." {
        return Some("a relative path element".into());
    }
    // A leading '-' reaches `code --install-extension` as a flag, not a file.
    if value.starts_with('-') {
        return Some("starts with '-', which `code` would read as a flag".into());
    }

    // A leading '.' hides the file and is the first character of `..`.
    if value.starts_with('.') {
        return Some("starts with '.', which hides the exported file".into());
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        return Some(format!(
            "contains {bad:?}; an extension id is ASCII alphanumeric, '.', '-' or '_'"
        ));
    }
    None
}

/// Refuse an extension id that cannot be a file name — before a byte is
/// written, so a bad entry leaves the export directory untouched rather than
/// half-populated.
pub fn validate_extension_id(name: &str) -> Result<(), VsixExportError> {
    match component_fault(name) {
        None => Ok(()),
        Some(why) => Err(VsixExportError::UnrepresentableName {
            name: name.to_string(),
            why,
        }),
    }
}

/// Refuse a version that cannot be a file name, for the same reasons.
pub fn validate_extension_version(name: &str, version: &str) -> Result<(), VsixExportError> {
    match component_fault(version) {
        None => Ok(()),
        Some(why) => Err(VsixExportError::UnrepresentableVersion {
            name: name.to_string(),
            version: version.to_string(),
            why,
        }),
    }
}

/// Resolve every destination before writing any of them: an unusable id or a
/// collision must leave the export directory untouched, not half-written. The
/// same discipline `Store::lay_down_payloads` follows, for the same reason —
/// the alternative is the wrong bytes under the right name.
fn plan(entries: &[VsixEntry]) -> Result<Vec<(PathBuf, &VsixEntry)>, VsixExportError> {
    let mut placed: BTreeMap<String, String> = BTreeMap::new();
    let mut planned = Vec::with_capacity(entries.len());
    for e in entries {
        validate_extension_id(&e.name)?;
        validate_extension_version(&e.name, &e.version)?;
        let file = vsix_file_name(&e.name, &e.version);
        let who = format!("{}@{}", e.name, e.version);
        if let Some(first) = placed.get(&file) {
            return Err(VsixExportError::Collision {
                file,
                first: first.clone(),
                second: who,
            });
        }
        placed.insert(file.clone(), who);
        planned.push((PathBuf::from(file), e));
    }
    Ok(planned)
}

/// Lay the verified extensions out in `out` as `publisher.name-version.vsix`
/// files. Returns the number written.
///
/// A `.vsix` is NOT made executable: it is a zip handed to `code`, and the
/// store already withholds the execute bit from every non-dispatchable payload
/// (REQ-VSIX-001 clause 2). Exporting it as 0o755 would undo that at the last
/// step, so the mode is set explicitly rather than inherited from the umask.
pub fn export_vsix(entries: &[VsixEntry], out: &Path) -> Result<usize, VsixExportError> {
    let planned = plan(entries)?;
    let io = |path: &Path, source: std::io::Error| VsixExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(out).map_err(|e| io(out, e))?;
    for (rel, entry) in planned {
        let path = out.join(rel);
        std::fs::write(&path, &entry.bytes).map_err(|e| io(&path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .map_err(|e| io(&path, e))?;
        }
    }
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, version: &str, bytes: &[u8]) -> VsixEntry {
        VsixEntry {
            name: name.into(),
            version: version.into(),
            bytes: bytes.to_vec(),
        }
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn the_file_name_is_the_one_code_and_a_human_both_read() {
        // `code --install-extension` dispatches on the `.vsix` suffix — without
        // it the argument is treated as a marketplace ID and FETCHED, which is
        // the network round-trip this whole requirement exists to remove. The
        // rest is the marketplace's own asset convention.
        assert_eq!(
            vsix_file_name("rust-lang.rust-analyzer", "0.3.2260"),
            "rust-lang.rust-analyzer-0.3.2260.vsix"
        );
        assert!(vsix_file_name("a.b", "1.0.0").ends_with(".vsix"));
        // The version is IN the name, which is what lets two versions of one
        // extension sit in one directory (clause 4).
        assert_ne!(
            vsix_file_name("a.b", "1.0.0"),
            vsix_file_name("a.b", "2.0.0")
        );
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn an_id_that_could_escape_or_look_like_a_flag_is_refused() {
        // These strings come out of a SIGNED manifest. Signed means
        // attributable, not benign.
        for bad in [
            "../../evil",
            "pub/name",
            "pub\\name",
            "",
            ".",
            "..",
            ".hidden",
            "--force",
            "name with spaces",
            "name;rm -rf /",
        ] {
            assert!(
                validate_extension_id(bad).is_err(),
                "id {bad:?} must be refused, not written"
            );
        }
        for good in ["rust-lang.rust-analyzer", "vadimcn.vscode-lldb", "my_ext"] {
            assert!(validate_extension_id(good).is_ok(), "{good} is a real id");
        }
        // The refusal must name the ACTUAL fault, or the depositor applies the
        // wrong fix. `.` and `..` are relative path elements — a distinct
        // problem from a hidden dotfile, with a distinct correction.
        for (bad, why) in [
            (".", "a relative path element"),
            ("..", "a relative path element"),
            (".hidden", "hides the exported file"),
            ("--force", "`code` would read as a flag"),
            ("pub/name", "contains '/'"),
        ] {
            let msg = validate_extension_id(bad).unwrap_err().to_string();
            assert!(
                msg.contains(why),
                "the refusal of {bad:?} must say {why:?}, got: {msg}"
            );
        }
        for bad in ["../1.0.0", "1.0/0", "", "-1.0.0"] {
            assert!(
                validate_extension_version("pub.name", bad).is_err(),
                "version {bad:?} must be refused"
            );
        }
        assert!(validate_extension_version("pub.name", "0.3.2260").is_ok());
        assert!(validate_extension_version("pub.name", "1.0.0-rc.1").is_ok());
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn nothing_is_written_when_one_entry_is_unexportable() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("ext");
        let outside = tmp.path().join("OUTSIDE");
        std::fs::create_dir_all(&outside).unwrap();
        let entries = [
            entry("good.ext", "1.0.0", b"good"),
            entry("../../OUTSIDE/evil", "1.0.0", b"evil"),
        ];
        assert!(export_vsix(&entries, &out).is_err());
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "a signed name must not place bytes outside the export directory"
        );
        // …and the good entry did not land either: a half-written export is a
        // directory a consumer would install from and believe complete.
        assert!(
            !out.join("good.ext-1.0.0.vsix").exists(),
            "the export must be refused whole, not written up to the bad entry"
        );
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn two_entries_that_would_share_a_file_are_refused_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("ext");
        let entries = [
            entry("pub.name", "1.0.0", b"first"),
            entry("pub.name", "1.0.0", b"second"),
        ];
        let err = export_vsix(&entries, &out).unwrap_err();
        assert!(
            matches!(err, VsixExportError::Collision { .. }),
            "expected a collision, got {err}"
        );
        assert!(!out.join("pub.name-1.0.0.vsix").exists());
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn every_extension_lands_with_its_own_bytes_and_no_execute_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("extensions");
        // Two extensions, and two VERSIONS of one of them (clause 4).
        let entries = [
            entry("rust-lang.rust-analyzer", "0.3.2260", b"ra-old-zip"),
            entry("rust-lang.rust-analyzer", "0.3.2300", b"ra-new-zip"),
            entry("vadimcn.vscode-lldb", "1.11.4", b"lldb-zip"),
        ];
        assert_eq!(export_vsix(&entries, &out).unwrap(), 3);
        for (file, want) in [
            ("rust-lang.rust-analyzer-0.3.2260.vsix", &b"ra-old-zip"[..]),
            ("rust-lang.rust-analyzer-0.3.2300.vsix", &b"ra-new-zip"[..]),
            ("vadimcn.vscode-lldb-1.11.4.vsix", &b"lldb-zip"[..]),
        ] {
            let path = out.join(file);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                want,
                "{file} must hold ITS OWN bytes"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(
                    mode & 0o111,
                    0,
                    "{file} is a zip handed to `code`, not a program: mode {mode:o}"
                );
            }
        }
    }
}
