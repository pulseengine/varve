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

use std::path::Path;

use serde::{Deserialize, Serialize};

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
    /// The export shape: `cargo` | `crates-vendor` | `bazel-distdir`.
    pub kind: String,
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
}

/// The drift verdict for a stamped export against the current pin.
#[derive(Debug, PartialEq, Eq)]
pub enum ExportStatus {
    /// The stamp's manifest digest matches the current pin — export is fresh.
    Current,
    /// The pin has moved: the export was produced from a different layer.
    Stale { stamped: String, current: String },
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
        }
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
}
