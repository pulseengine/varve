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

use wsc::dsse::{DsseEnvelope, DsseError, DsseSigner, Ed25519DsseSigner, Ed25519DsseVerifier};

use crate::install::{ManifestVerifier, VerifyError};
use crate::keyroles::RealmTrust;

/// The authenticated payload type for a layer manifest envelope.
pub const LAYER_PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.layer.v1+json";

/// Verifies layer-manifest envelopes against a realm's pinned trust.
///
/// Built from a bare root key it is the flat verifier that predates roles;
/// built from a [`RealmTrust`] (`from_trust`) a layer manifest is judged under
/// the realm's LAYER keys when the realm declares roles (REQ-KEYROLES-001).
pub struct PinnedKeyVerifier {
    trust: RealmTrust,
}

impl PinnedKeyVerifier {
    pub fn from_public_key_bytes(public_key: &[u8]) -> Result<Self, VerifyError> {
        Ok(PinnedKeyVerifier {
            trust: RealmTrust::root_only(public_key)?,
        })
    }

    /// A verifier for a realm's trust: a roles realm accepts a layer manifest
    /// only from its LAYER keys, a realm declaring no roles only from its root.
    pub fn from_trust(trust: RealmTrust) -> Self {
        PinnedKeyVerifier { trust }
    }

    /// The realm ROOT — what a document that must name the signer (the SBOM's
    /// author) names it by, and what the store partitions on. In a roles realm
    /// this is NOT the key that signs layer manifests.
    pub fn public_key(&self) -> &[u8] {
        self.trust.root()
    }
}

impl ManifestVerifier for PinnedKeyVerifier {
    fn verify(&self, fetched: &[u8]) -> Result<Vec<u8>, VerifyError> {
        self.trust.verify_bytes(fetched, LAYER_PAYLOAD_TYPE)
    }

    fn trust(&self) -> Option<&RealmTrust> {
        Some(&self.trust)
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
    crate::keyroles::RealmTrust::root_only(root_public_key)?
        .verify_bytes(envelope, expected_payload_type)
}

pub(crate) fn verify_with(
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

/// A key that signs for a realm, wherever it lives (REQ-SIGNERSEAM-001).
///
/// It IS a [`DsseSigner`] (so it feeds `DsseEnvelope::sign` directly) plus the
/// public half, which a producer needs to read its own work back before
/// publishing it. The id is `realm_key_id` rather than `key_id`: the supertrait
/// already has a `key_id() -> Option<String>`, and two methods of one name on
/// one object make every call ambiguous.
pub trait RealmSigner: DsseSigner {
    /// The 32 raw bytes of the ed25519 public key this signer signs as.
    fn public_key(&self) -> Vec<u8>;
    /// The key id written into every envelope this signer produces.
    fn realm_key_id(&self) -> String;
}

/// A [`RealmSigner`] backed by raw key bytes — today's `--key <FILE>` path,
/// kept exactly, as one implementation of the seam.
pub struct FileSigner {
    inner: Ed25519DsseSigner,
    public: Vec<u8>,
    key_id: String,
}

impl FileSigner {
    /// A signer whose 64-byte secret is checked to carry its own public half
    /// (`keys::check_keypair`'s probe), so a mismatched pair is refused here
    /// and not after a signature nobody can verify exists.
    pub fn new(secret_key: &[u8], key_id: &str) -> Result<Self, VerifyError> {
        crate::keys::check_keypair_bytes(secret_key, "signing key")
            .map_err(|e| VerifyError(format!("invalid signing key: {e}")))?;
        Self::new_unchecked(secret_key, key_id)
    }

    /// As [`FileSigner::new`], without the consistency probe: the behaviour of
    /// the pre-seam entry points, which signed with whatever bytes they were
    /// handed. The wrappers keep that so the refactor changes nothing; new
    /// code should use [`FileSigner::new`].
    pub fn new_unchecked(secret_key: &[u8], key_id: &str) -> Result<Self, VerifyError> {
        let inner = Ed25519DsseSigner::from_bytes(secret_key, Some(key_id.to_string()))
            .map_err(|e| VerifyError(format!("invalid signing key: {e}")))?;
        Ok(Self {
            inner,
            public: secret_key[32..].to_vec(),
            key_id: key_id.to_string(),
        })
    }
}

impl DsseSigner for FileSigner {
    fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, DsseError> {
        self.inner.sign(pae)
    }
    fn key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }
}

impl RealmSigner for FileSigner {
    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
    fn realm_key_id(&self) -> String {
        self.key_id.clone()
    }
}

/// Sign a payload of a given type into a DSSE envelope (JSON) with any
/// [`RealmSigner`] — the one place an envelope is made.
pub fn dsse_sign_with(
    payload: &[u8],
    payload_type: &str,
    signer: &dyn RealmSigner,
) -> Result<String, VerifyError> {
    let envelope = DsseEnvelope::sign(payload, payload_type, signer)
        .map_err(|e| VerifyError(format!("signing failed: {e}")))?;
    envelope
        .to_json_pretty()
        .map_err(|e| VerifyError(format!("envelope serialization failed: {e}")))
}

/// Sign a payload of a given type into a DSSE envelope (JSON) — the
/// producing half, shared by deposit, line-status and release-sums signing
/// so the two sides can never drift apart. A thin wrapper over
/// [`dsse_sign_with`] with a file-backed key.
pub fn dsse_sign_typed(
    payload: &[u8],
    payload_type: &str,
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, VerifyError> {
    let signer = FileSigner::new_unchecked(secret_key, key_id)?;
    dsse_sign_with(payload, payload_type, &signer)
}

/// Sign layer-manifest payload bytes into a DSSE envelope (JSON).
pub fn sign_layer_manifest(
    payload: &[u8],
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, VerifyError> {
    dsse_sign_typed(payload, LAYER_PAYLOAD_TYPE, secret_key, key_id)
}

/// [`sign_layer_manifest`] with any [`RealmSigner`].
pub fn sign_layer_manifest_with(
    payload: &[u8],
    signer: &dyn RealmSigner,
) -> Result<String, VerifyError> {
    dsse_sign_with(payload, LAYER_PAYLOAD_TYPE, signer)
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

    /// The SBOM names its author by this key (REQ-SBOMFIELDS-001 clause 2), so
    /// it must be the key the verifier accepts, not any stand-in bytes.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn the_verifier_reports_exactly_the_root_it_was_pinned_to() {
        let (_, pk) = keys();
        let (_, other) = keys();
        let a = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let b = PinnedKeyVerifier::from_public_key_bytes(&other).unwrap();
        assert_eq!(a.public_key(), pk.as_slice());
        assert_eq!(b.public_key(), other.as_slice());
        assert_ne!(a.public_key(), b.public_key());
    }

    // rivet: verifies REQ-ROLLBACK-002
    #[test]
    fn the_verifier_names_its_root_through_the_trait_so_a_status_is_checked_against_it() {
        use crate::install::ManifestVerifier as _;
        let (sk, pk) = keys();
        let (_, other) = keys();
        let v = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        assert_eq!(v.trust().map(|t| t.root()), Some(pk.as_slice()));
        // The document digest consent rests on verifies under that root and
        // only that root.
        let status = crate::linestatus::LineStatus {
            line: "2026.07".into(),
            counter: 1,
            issued_at: "2026-08-01T00:00:00Z".into(),
            support_until: None,
            min_counter: None,
            yanked: Default::default(),
            known_problems: Vec::new(),
        }
        .sign(&sk, "root-1")
        .unwrap();
        assert!(
            crate::linestatus::LineStatus::verify_and_parse(status.as_bytes(), v.trust().unwrap())
                .is_ok()
        );
        assert!(
            crate::linestatus::LineStatus::verify_and_parse(
                status.as_bytes(),
                &crate::keyroles::test_support::rt(&other)
            )
            .is_err()
        );
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
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
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

/// A signer that is not a file: it keeps a key in memory and counts how often
/// it is asked to sign. Stands in for a hardware or KMS-backed implementation
/// (REQ-SIGNERSEAM-001 clause 3).
#[cfg(test)]
pub(crate) mod testsigner {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wsc::dsse::{DsseError, DsseSigner, Ed25519DsseSigner};

    pub(crate) struct CountingSigner {
        inner: Ed25519DsseSigner,
        public: Vec<u8>,
        pub(crate) calls: AtomicUsize,
    }

    impl CountingSigner {
        pub(crate) fn new(secret: &[u8]) -> Self {
            Self {
                inner: Ed25519DsseSigner::from_bytes(secret, None).unwrap(),
                public: secret[32..].to_vec(),
                calls: AtomicUsize::new(0),
            }
        }
        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DsseSigner for CountingSigner {
        fn sign(&self, pae: &[u8]) -> Result<Vec<u8>, DsseError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(pae)
        }
        fn key_id(&self) -> Option<String> {
            Some("mock-1".into())
        }
    }

    impl super::RealmSigner for CountingSigner {
        fn public_key(&self) -> Vec<u8> {
            self.public.clone()
        }
        fn realm_key_id(&self) -> String {
            "mock-1".into()
        }
    }
}

#[cfg(test)]
mod seam_tests {
    use super::testsigner::CountingSigner;
    use super::*;

    // GOLDEN VALUES. Captured by running the PRE-REFACTOR code (main at
    // 709056b: `dsse_sign_typed` building `Ed25519DsseSigner::from_bytes`
    // inline) on this fixed key and these payloads. Ed25519 is deterministic,
    // so any change to the envelope bytes the seam produces is a regression.
    const SK: &str = "0d9437caa6c957a81613b1ba3c9dccceadfceed45a2c1a33a1e8018faa3dc5f369fdee54295697e20ae454e441ca9df08ded1856047024c05b54696bbeff2f69";
    const LAYER_SIG: &str =
        "nWOkRNIIjavcK4TeRGv/anydt/nVbsuQqdYuPTIfcMdPkpePMwNEE70qmKQHEJbt0+RBgNwtalea33gr0FUQAg==";
    const SUMS_SIG: &str =
        "gGBevxrM3BJSOC7z/R3TNOOz+vjmRlCA8X7FWk8y2aWbtVs6i0R1B4/ar6hvqrDK7QJDZBfxV99LybulMRioAg==";
    const STATUS_SIG: &str =
        "jJGBhhz1hL7DkUBKfb0LOFHnPbMEhWummWVXyskmJOMPN3ZtS5NYxRKUTpTsruDhwYEd4k7EJxmwoSzNDIMkAA==";
    const INDEX_SIG: &str =
        "zsQzudE5hon3HEHJsKmcLtCQ+8UMeaG63Niedgzk3I7U5wlSFqGPcIwgawmcgQB97D8N70+7K4kdMicErSkEDQ==";
    const ATTEST_PAYLOAD: &str = "eyJsYXllciI6IjIwMjYuMDguMCIsImxheWVyX21hbmlmZXN0X2RpZ2VzdCI6InNoYTI1NjphYSIsImtpbmQiOiJzYm9tIiwiZGlnZXN0Ijoic2hhMjU2OmJiIiwicHJvZHVjZXIiOiJ2YXJ2ZSJ9";
    const ATTEST_SIG: &str =
        "azGa/8Hxb0GE8hOd+8AGdUWNNb6JuXZMy8X++/wGtfwEQwW+Y+uxcvCQAUgeX2y2+QJZyynF9I1IzhxyNGWUDg==";

    fn sk() -> Vec<u8> {
        (0..SK.len() / 2)
            .map(|i| u8::from_str_radix(&SK[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// The exact pretty-JSON shape the pre-refactor code emitted.
    fn golden(payload_b64: &str, ty: &str, sig: &str) -> String {
        format!(
            "{{\n  \"payload\": \"{payload_b64}\",\n  \"payloadType\": \"{ty}\",\n  \"signatures\": [\n    {{\n      \"keyid\": \"k1\",\n      \"sig\": \"{sig}\"\n    }}\n  ]\n}}"
        )
    }

    fn statement() -> crate::attest::AttestationStatement {
        crate::attest::AttestationStatement {
            layer: "2026.08.0".into(),
            layer_manifest_digest: "sha256:aa".into(),
            kind: crate::attest::AttestationKind::Sbom,
            digest: "sha256:bb".into(),
            producer: "varve".into(),
            ambient_tools: Vec::new(),
            overrides: Vec::new(),
        }
    }

    // rivet: verifies REQ-SIGNERSEAM-001
    #[test]
    fn every_signing_entry_point_still_emits_the_pre_seam_bytes() {
        let sk = sk();
        let want = [
            golden("eyJsYXllciI6MX0=", LAYER_PAYLOAD_TYPE, LAYER_SIG),
            golden(
                "YWJjICBmaWxlCg==",
                crate::selfverify::RELEASE_SUMS_PAYLOAD_TYPE,
                SUMS_SIG,
            ),
            golden(
                "eyJzIjoxfQ==",
                crate::linestatus::LINE_STATUS_PAYLOAD_TYPE,
                STATUS_SIG,
            ),
            golden(
                "eyJpIjoxfQ==",
                crate::lineindex::LINE_INDEX_PAYLOAD_TYPE,
                INDEX_SIG,
            ),
            golden(ATTEST_PAYLOAD, crate::attest::PAYLOAD_TYPE, ATTEST_SIG),
        ];
        let signer = FileSigner::new(&sk, "k1").unwrap();
        // The wrappers (the old call shape) and the `_with` variants must both
        // equal the golden — which also makes them equal each other.
        let old = [
            sign_layer_manifest(b"{\"layer\":1}", &sk, "k1").unwrap(),
            crate::selfverify::sign_release_sums(b"abc  file\n", &sk, "k1").unwrap(),
            dsse_sign_typed(
                b"{\"s\":1}",
                crate::linestatus::LINE_STATUS_PAYLOAD_TYPE,
                &sk,
                "k1",
            )
            .unwrap(),
            dsse_sign_typed(
                b"{\"i\":1}",
                crate::lineindex::LINE_INDEX_PAYLOAD_TYPE,
                &sk,
                "k1",
            )
            .unwrap(),
            crate::attest::sign(&statement(), &sk, "k1").unwrap(),
        ];
        let new = [
            sign_layer_manifest_with(b"{\"layer\":1}", &signer).unwrap(),
            crate::selfverify::sign_release_sums_with(b"abc  file\n", &signer).unwrap(),
            dsse_sign_with(
                b"{\"s\":1}",
                crate::linestatus::LINE_STATUS_PAYLOAD_TYPE,
                &signer,
            )
            .unwrap(),
            dsse_sign_with(
                b"{\"i\":1}",
                crate::lineindex::LINE_INDEX_PAYLOAD_TYPE,
                &signer,
            )
            .unwrap(),
            crate::attest::sign_with(&statement(), &signer).unwrap(),
        ];
        for i in 0..want.len() {
            assert_eq!(old[i], want[i], "wrapper {i} drifted from the golden");
            assert_eq!(new[i], want[i], "_with variant {i} drifted from the golden");
        }
    }

    // rivet: verifies REQ-SIGNERSEAM-001
    #[test]
    fn a_non_file_signer_is_accepted_by_every_with_call_site_and_its_envelopes_verify() {
        let (secret, public) = generate_root_keypair();
        let mock = CountingSigner::new(&secret);

        let layer = sign_layer_manifest_with(b"{}", &mock).unwrap();
        assert_eq!(mock.calls(), 1);
        assert_eq!(
            dsse_verify_typed(layer.as_bytes(), LAYER_PAYLOAD_TYPE, &public).unwrap(),
            b"{}"
        );

        let att = crate::attest::sign_with(&statement(), &mock).unwrap();
        assert_eq!(mock.calls(), 2);
        assert_eq!(
            crate::attest::verify_statement(
                att.as_bytes(),
                &crate::keyroles::test_support::rt(&public)
            )
            .unwrap(),
            statement()
        );

        let sums = crate::selfverify::sign_release_sums_with(b"x  y\n", &mock).unwrap();
        assert_eq!(mock.calls(), 3);
        assert_eq!(
            dsse_verify_typed(
                sums.as_bytes(),
                crate::selfverify::RELEASE_SUMS_PAYLOAD_TYPE,
                &public
            )
            .unwrap(),
            b"x  y\n"
        );

        let any = dsse_sign_with(b"{}", "application/x.test", &mock).unwrap();
        assert_eq!(mock.calls(), 4);
        dsse_verify_typed(any.as_bytes(), "application/x.test", &public).unwrap();
    }

    // rivet: verifies REQ-SIGNERSEAM-001
    #[test]
    fn a_file_signer_refuses_a_mismatched_keypair() {
        let (mut secret, _) = generate_root_keypair();
        let (_, other_public) = generate_root_keypair();
        secret[32..].copy_from_slice(&other_public);
        let err = FileSigner::new(&secret, "k").err().expect("must refuse");
        assert!(err.to_string().contains("invalid signing key"), "{err}");
        // and a consistent pair is accepted, reporting its own public half
        let (ok_secret, ok_public) = generate_root_keypair();
        let s = FileSigner::new(&ok_secret, "k").unwrap();
        assert_eq!(s.public_key(), ok_public);
        assert_eq!(s.realm_key_id(), "k");
        assert_eq!(DsseSigner::key_id(&s), Some("k".to_string()));
    }
}
