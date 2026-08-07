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
    #[error("tool '{tool}' is missing from the installed layer")]
    MissingTool { tool: String },
    #[error("tool '{tool}' does not match its signed digest {digest} — the binary was altered")]
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

/// Re-verify one installed layer against the trust root. Returns the number
/// of tool binaries checked.
pub fn verify_installed(
    store: &Store,
    layer: &InstalledLayer,
    verifier: &dyn ManifestVerifier,
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
        let Some(tool) = entry.annotations.get("eu.pulseengine.tool") else {
            continue;
        };
        let Some(path) = store.tool_path(layer, tool) else {
            return Err(ReverifyError::MissingTool { tool: tool.clone() });
        };
        let bytes = std::fs::read(&path).map_err(|e| io(&path, e))?;
        if manifest_digest(&bytes) != entry.digest {
            return Err(ReverifyError::ToolDigestMismatch {
                tool: tool.clone(),
                digest: entry.digest.clone(),
            });
        }
        checked += 1;
    }
    Ok(checked)
}

#[cfg(test)]
mod tests {
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
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
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
        let checked = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier).unwrap();
        assert_eq!(checked, 1);
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
        let err = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier).unwrap_err();
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
        let err = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier).unwrap_err();
        assert!(matches!(err, ReverifyError::PayloadMismatch), "got: {err}");
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_missing_envelope_is_its_own_loud_verdict() {
        let ctx = installed_layer();
        std::fs::remove_file(ctx.layer.root.join(ENVELOPE_FILE)).unwrap();
        let err = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier).unwrap_err();
        assert!(
            matches!(err, ReverifyError::NoEnvelope { .. }),
            "got: {err}"
        );
    }
}
