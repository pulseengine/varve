//! Manifest signature verification against the PulseEngine trust root
//! (REQ-VERIFY-001, DD-003).
//!
//! Layer manifests travel as DSSE envelopes (payload = the OCI image index
//! JSON), signed with the PulseEngine root ed25519 key via sigil's `wsc`
//! library. The envelope authenticates both the payload bytes and the
//! payload *type* (DSSE PAE), so a signed something-else cannot be replayed
//! as a layer manifest.
//!
//! The verifier holds the trust root; sources cannot see it, supply it, or
//! relax it. Keyless/Fulcio verification via sigil's airgapped module is the
//! intended future — blocked on sigil#219 — and slots in behind the same
//! [`crate::install::ManifestVerifier`] trait when it lands.

use wsc::dsse::{DsseEnvelope, Ed25519DsseSigner, Ed25519DsseVerifier};

use crate::install::{ManifestVerifier, VerifyError};

/// The authenticated payload type for a layer manifest envelope.
pub const LAYER_PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.layer.v1+json";

/// Verifies layer-manifest envelopes against a pinned ed25519 root public
/// key (32 raw bytes).
pub struct PinnedKeyVerifier {
    verifier: Ed25519DsseVerifier,
}

impl PinnedKeyVerifier {
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self, VerifyError> {
        let verifier = Ed25519DsseVerifier::from_bytes(public_key)
            .map_err(|e| VerifyError(format!("invalid trust-root public key: {e}")))?;
        Ok(PinnedKeyVerifier { verifier })
    }
}

impl ManifestVerifier for PinnedKeyVerifier {
    fn verify(&self, fetched: &[u8]) -> Result<Vec<u8>, VerifyError> {
        verify_with(&self.verifier, fetched, LAYER_PAYLOAD_TYPE)
    }
}

/// Verify a DSSE envelope of a specific payload type against a pinned root
/// public key, returning the authenticated payload. The one verification
/// path shared by layer manifests, line-status documents (DD-008) and
/// release sums (DD-009) — different payload types, one trust root, so the
/// type check is what keeps signed documents from posing as each other.
pub fn dsse_verify_typed(
    envelope: &[u8],
    expected_payload_type: &str,
    root_public_key: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    let verifier = Ed25519DsseVerifier::from_bytes(root_public_key)
        .map_err(|e| VerifyError(format!("invalid trust-root public key: {e}")))?;
    verify_with(&verifier, envelope, expected_payload_type)
}

fn verify_with(
    verifier: &Ed25519DsseVerifier,
    envelope: &[u8],
    expected_payload_type: &str,
) -> Result<Vec<u8>, VerifyError> {
    let text = std::str::from_utf8(envelope)
        .map_err(|_| VerifyError("fetched bytes are not UTF-8 DSSE JSON".into()))?;
    let envelope = DsseEnvelope::from_json(text)
        .map_err(|e| VerifyError(format!("not a DSSE envelope: {e}")))?;
    if envelope.payload_type != expected_payload_type {
        return Err(VerifyError(format!(
            "envelope payload type is '{}', expected '{expected_payload_type}' — refusing to \
             accept a signed document as something it is not",
            envelope.payload_type
        )));
    }
    envelope.verify_all(verifier).map_err(|e| {
        VerifyError(format!(
            "signature does not verify against the trust root: {e}"
        ))
    })
}

/// Sign a payload of a given type into a DSSE envelope (JSON) — the
/// producing half, shared by deposit, line-status and release-sums signing
/// so the two sides can never drift apart.
pub fn dsse_sign_typed(
    payload: &[u8],
    payload_type: &str,
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, VerifyError> {
    let signer = Ed25519DsseSigner::from_bytes(secret_key, Some(key_id.to_string()))
        .map_err(|e| VerifyError(format!("invalid signing key: {e}")))?;
    let envelope = DsseEnvelope::sign(payload, payload_type, &signer)
        .map_err(|e| VerifyError(format!("signing failed: {e}")))?;
    envelope
        .to_json_pretty()
        .map_err(|e| VerifyError(format!("envelope serialization failed: {e}")))
}

/// Sign layer-manifest payload bytes into a DSSE envelope (JSON).
pub fn sign_layer_manifest(
    payload: &[u8],
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, VerifyError> {
    dsse_sign_typed(payload, LAYER_PAYLOAD_TYPE, secret_key, key_id)
}

/// Generate an ed25519 root keypair: (secret 64 bytes, public 32 bytes).
/// Test and provisioning helper — real roots are generated in a key
/// ceremony, not on a build machine.
pub fn generate_root_keypair() -> (Vec<u8>, Vec<u8>) {
    let kp = wsc::KeyPair::generate();
    (kp.sk.sk.to_vec(), kp.pk.pk.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{InstallError, InstallPolicy, install};
    use crate::manifest::fixtures::manifest_with_tools;
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::MemorySource;
    use crate::store::{Store, manifest_digest};

    fn keys() -> (Vec<u8>, Vec<u8>) {
        generate_root_keypair()
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_signed_manifest_verifies_and_yields_its_payload() {
        let (sk, pk) = keys();
        let payload = manifest_with_tools("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z", &[]);
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        use crate::install::ManifestVerifier as _;
        assert_eq!(verifier.verify(envelope.as_bytes()).unwrap(), payload);
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_signature_from_an_untrusted_key_is_rejected() {
        let (sk, _) = keys();
        let (_, other_pk) = keys();
        let payload = manifest_with_tools("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z", &[]);
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&other_pk).unwrap();
        use crate::install::ManifestVerifier as _;
        assert!(verifier.verify(envelope.as_bytes()).is_err());
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_tampered_payload_is_rejected() {
        let (sk, pk) = keys();
        let payload = manifest_with_tools("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z", &[]);
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        // Flip the counter inside the base64 payload by re-signing... no —
        // tamper the envelope JSON's payload field directly.
        let mut parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        let b64 = parsed["payload"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = b64.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        parsed["payload"] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = serde_json::to_string(&parsed).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        use crate::install::ManifestVerifier as _;
        assert!(verifier.verify(tampered.as_bytes()).is_err());
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_signed_envelope_of_the_wrong_payload_type_is_rejected() {
        let (sk, pk) = keys();
        let payload = b"some signed but non-manifest content";
        let signer = wsc::dsse::Ed25519DsseSigner::from_bytes(&sk, None).unwrap();
        let envelope = wsc::dsse::DsseEnvelope::sign(payload, "application/other", &signer)
            .unwrap()
            .to_json()
            .unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        use crate::install::ManifestVerifier as _;
        let err = verifier.verify(envelope.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("payload type"), "got: {err}");
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn install_accepts_a_properly_signed_layer_and_rejects_the_same_bytes_resigned_by_an_impostor()
    {
        let (sk, pk) = keys();
        let (impostor_sk, _) = keys();
        let synth = b"tool-bytes".to_vec();
        let blob_digest = manifest_digest(&synth);
        let payload = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blob_digest)],
        );
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let policy = InstallPolicy {
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
        };
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();

        // Properly signed: accepted, and the *payload* is what lands.
        let good = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(good.as_bytes())
            .with_blob(&blob_digest, &synth);
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("root"));
        let mut marks = HighWaterMarks::load(&tmp.path().join("root")).unwrap();
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        assert_eq!(outcome.digest, manifest_digest(&payload));
        let entry = store.get(&outcome.digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(entry.root.join("layer.json")).unwrap(),
            payload,
            "the core stores the verified payload, not the envelope"
        );

        // Same payload, impostor signature: rejected before anything lands.
        let evil = sign_layer_manifest(&payload, &impostor_sk, "varve-root-1").unwrap();
        let evil_source = MemorySource::new()
            .with_manifest(evil.as_bytes())
            .with_blob(&blob_digest, &synth);
        let tmp2 = tempfile::tempdir().unwrap();
        let store2 = Store::at(tmp2.path().join("root"));
        let mut marks2 = HighWaterMarks::load(&tmp2.path().join("root")).unwrap();
        let err =
            install(&pin, &evil_source, &verifier, &store2, &mut marks2, &policy).unwrap_err();
        assert!(matches!(err, InstallError::Verify(_)), "got: {err}");
        assert!(store2.list().unwrap().is_empty());
    }
}
