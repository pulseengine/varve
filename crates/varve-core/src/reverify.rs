//! Re-verification of an installed layer (REQ-VERIFY-001) — `varve verify`.
//!
//! The install-time verdict, repeatable forever after: the retained envelope
//! must verify against the trust root, its payload must be byte-identical to
//! the layer.json in the core, and every tool binary must match its digest in
//! the signed manifest. Corruption, tampering, and bit-rot all surface as the
//! same loud failure — and "I cannot check" (no envelope retained) is its own
//! distinct verdict, never silently treated as success.

use crate::install::{ManifestVerifier, VerifyError};
use crate::manifest::{LayerManifest, ManifestError};
use crate::store::{InstalledLayer, Store, StoreError, manifest_digest};

/// The file the install pipeline retains alongside `layer.json` so the
/// signature verdict stays reproducible offline.
pub const ENVELOPE_FILE: &str = "layer.dsse.json";

#[derive(Debug, thiserror::Error)]
pub enum ReverifyError {
    #[error(
        "layer {digest} has no retained signature envelope ({ENVELOPE_FILE}) — cannot re-verify \
         its signature; reinstall from a signed source"
    )]
    NoEnvelope { digest: String },
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(
        "retained envelope verifies, but its payload does not match layer.json — the core entry \
         was modified after install"
    )]
    PayloadMismatch,
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("payload '{tool}' is missing from the installed layer")]
    MissingTool { tool: String },
    #[error("payload '{tool}' does not match its signed digest {digest} — its bytes were altered")]
    ToolDigestMismatch { tool: String, digest: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// How to name a payload in a verdict. A layer may hold several versions of one
/// name, so the bare name no longer identifies WHICH payload failed — and a
/// verification tool that cannot say which artifact is wrong has not reported
/// the fault (REQ-STORE-002 clause 4).
fn named(entry: &crate::manifest::ManifestEntry, name: &str) -> String {
    match crate::store::entry_version(entry) {
        Some(version) => format!("{name}@{version}"),
        None => name.to_string(),
    }
}

/// Re-verify one installed layer against the trust root. Returns the number
/// of tool binaries checked.
pub fn verify_installed(
    store: &Store,
    layer: &InstalledLayer,
    verifier: &dyn ManifestVerifier,
    platform: &str,
) -> Result<usize, ReverifyError> {
    let io = |path: &std::path::Path, source: std::io::Error| ReverifyError::Io {
        path: path.display().to_string(),
        source,
    };

    // 1. The retained envelope must exist and verify against the trust root.
    let envelope_path = layer.root.join(ENVELOPE_FILE);
    let envelope = match std::fs::read(&envelope_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReverifyError::NoEnvelope {
                digest: layer.digest.clone(),
            });
        }
        Err(e) => return Err(io(&envelope_path, e)),
    };
    let payload = verifier.verify(&envelope)?;

    // 2. The verified payload must be byte-identical to the stored manifest.
    let manifest_path = layer.root.join("layer.json");
    let stored = std::fs::read(&manifest_path).map_err(|e| io(&manifest_path, e))?;
    if payload != stored {
        return Err(ReverifyError::PayloadMismatch);
    }

    // 3. Every tool the signed manifest names must be present and unaltered.
    let manifest = LayerManifest::parse(&payload)?;
    let mut checked = 0;
    for entry in &manifest.entries {
        if !crate::platform::entry_matches(
            entry
                .annotations
                .get(crate::platform::ANN_PLATFORM)
                .map(String::as_str),
            platform,
        ) {
            continue;
        }
        // A composed layer is a REFERENCE to another layer's manifest, not a
        // blob laid down here; install skips it and so must re-verification.
        if entry.kind() == Ok(crate::kind::PayloadKind::Layer) {
            continue;
        }
        let Some(tool) = entry.annotations.get("eu.pulseengine.tool") else {
            continue;
        };
        // Locate by ENTRY, not by name: several versions of one name coexist,
        // and each must be checked against its own signed digest
        // (REQ-STORE-002 clause 4).
        let Some(path) = store.entry_path(layer, entry) else {
            return Err(ReverifyError::MissingTool {
                tool: named(entry, tool),
            });
        };
        let bytes = std::fs::read(&path).map_err(|e| io(&path, e))?;
        if manifest_digest(&bytes) != entry.digest {
            return Err(ReverifyError::ToolDigestMismatch {
                tool: named(entry, tool),
                digest: entry.digest.clone(),
            });
        }
        checked += 1;
    }
    Ok(checked)
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
    use crate::install::{InstallPolicy, install};
    use crate::manifest::fixtures::manifest_with_tools;
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::MemorySource;
    use crate::verify::{PinnedKeyVerifier, generate_root_keypair, sign_layer_manifest};

    struct Installed {
        _tmp: tempfile::TempDir,
        store: Store,
        layer: InstalledLayer,
        verifier: PinnedKeyVerifier,
    }

    fn installed_layer() -> Installed {
        let (sk, pk) = generate_root_keypair();
        let synth = b"synth-bytes".to_vec();
        let blob_digest = manifest_digest(&synth);
        let payload = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blob_digest)],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&blob_digest, &synth);
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        Installed {
            _tmp: tmp,
            store,
            layer,
            verifier,
        }
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_freshly_installed_layer_reverifies() {
        let ctx = installed_layer();
        let checked =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap();
        assert_eq!(checked, 1);
    }

    /// A signed layer holding TWO versions of one crate, installed.
    fn installed_two_versions() -> (Installed, Vec<u8>, Vec<u8>) {
        use crate::manifest::fixtures::manifest_with_payloads;
        let (sk, pk) = generate_root_keypair();
        let a = b"serde-1.0.200-crate".to_vec();
        let b = b"serde-1.0.210-crate".to_vec();
        let (da, db) = (manifest_digest(&a), manifest_digest(&b));
        let payload = manifest_with_payloads(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("serde", "1.0.200", "crate", &da),
                ("serde", "1.0.210", "crate", &db),
            ],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&da, &a)
            .with_blob(&db, &b);
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        (
            Installed {
                _tmp: tmp,
                store,
                layer,
                verifier,
            },
            a,
            b,
        )
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn each_version_of_one_name_is_checked_against_its_own_signed_digest() {
        // Clause 4, verification half. `verify_installed` looked payloads up by
        // NAME, so with two versions present it would have hashed one file
        // twice — passing the entry whose bytes happened to land and failing
        // the other, with a verdict that named only "serde" and could not say
        // which. Both are checked here, and tampering with EITHER is caught and
        // named with its version.
        let (ctx, a, b) = installed_two_versions();
        assert_eq!(
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap(),
            2,
            "both versions must be checked, not one file twice"
        );
        // The bytes on disk really are each version's own.
        assert_eq!(
            std::fs::read(ctx.layer.root.join("payloads/serde/1.0.200")).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(ctx.layer.root.join("payloads/serde/1.0.210")).unwrap(),
            b
        );

        for (version, path) in [
            ("1.0.200", "payloads/serde/1.0.200"),
            ("1.0.210", "payloads/serde/1.0.210"),
        ] {
            let (ctx, ..) = installed_two_versions();
            std::fs::write(ctx.layer.root.join(path), b"EVIL").unwrap();
            let err = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform")
                .unwrap_err();
            assert!(
                matches!(&err, ReverifyError::ToolDigestMismatch { tool, .. }
                    if tool == &format!("serde@{version}")),
                "tampering with {version} must be caught AND named: {err}"
            );
        }

        // A payload that is simply gone is named with its version too — with
        // two versions present, "serde is missing" would not say which.
        let (ctx, ..) = installed_two_versions();
        std::fs::remove_file(ctx.layer.root.join("payloads/serde/1.0.210")).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(&err, ReverifyError::MissingTool { tool } if tool == "serde@1.0.210"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn install_retains_the_envelope_for_offline_reverification() {
        let ctx = installed_layer();
        assert!(
            ctx.layer.root.join(ENVELOPE_FILE).is_file(),
            "install must retain the signature envelope"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn an_altered_tool_binary_is_detected() {
        let ctx = installed_layer();
        std::fs::write(ctx.layer.root.join("bin/synth"), b"EVIL").unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(err, ReverifyError::ToolDigestMismatch { ref tool, .. } if tool == "synth"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn an_altered_manifest_payload_is_detected() {
        let ctx = installed_layer();
        let path = ctx.layer.root.join("layer.json");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(&path, bytes).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(matches!(err, ReverifyError::PayloadMismatch), "got: {err}");
    }

    // rivet: verifies REQ-PROOF-001
    #[cfg(unix)]
    #[test]
    fn an_unreadable_envelope_is_an_io_error_not_a_missing_one() {
        // An envelope that EXISTS but cannot be read is not a layer installed
        // without one. Collapsing the two would report "no retained envelope"
        // for what is really a permissions fault — a verification tool must
        // name the fault it actually hit. (Found by cargo-mutants: the
        // NotFound guard survived being replaced with `true`.)
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
        let ctx = installed_layer();
        let path = ctx.layer.root.join(ENVELOPE_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        assert!(
            matches!(err, ReverifyError::Io { .. }),
            "an unreadable envelope must be an Io error, got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_missing_envelope_is_its_own_loud_verdict() {
        let ctx = installed_layer();
        std::fs::remove_file(ctx.layer.root.join(ENVELOPE_FILE)).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(err, ReverifyError::NoEnvelope { .. }),
            "got: {err}"
        );
    }
}
