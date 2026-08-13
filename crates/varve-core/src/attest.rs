//! Attestations carried with a layer (REQ-ATTEST-001).
//!
//! A layer's bytes are authentic and current — varve's signature and counter
//! say so. They say nothing about whether the code was *reviewed*, how it was
//! *built*, or what it *contains*. Other people produce those claims:
//! cargo-vet and cargo-crev audits, SLSA in-toto build provenance, CycloneDX
//! SBOMs, VEX documents, and vendor attestations (AdaCore ships DSSE-signed
//! in-toto provenance of its own).
//!
//! varve does NOT re-attest any of that. Re-signing someone else's claim under
//! our root would launder their judgement into ours, and an assessor reading
//! the chain could no longer tell who asserted what. What varve does instead is
//! narrow and honest: it **transports the bytes verbatim** and **binds them to
//! a layer**, by signing a short statement that says *this digest, of this kind,
//! accompanies this layer*. The consumer then verifies two separate things —
//! that varve vouches for the association (offline, against the pinned root),
//! and, using the producer's own key, whatever the producer actually claimed.
//!
//! That split is the point. It is what lets a disconnected site check an
//! AdaCore or Sigstore attestation whose issuer it cannot reach.

use serde::{Deserialize, Serialize};

/// What an attached attestation is. Unknown kinds are refused rather than
/// guessed — the same fail-closed rule payload kinds follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationKind {
    /// A software bill of materials (CycloneDX or SPDX).
    Sbom,
    /// Build provenance — SLSA / in-toto.
    Provenance,
    /// A human review record — cargo-vet, cargo-crev.
    Audit,
    /// Vulnerability exploitability exchange.
    Vex,
    /// A qualification or certification artifact (kit, report, certificate).
    Qualification,
}

impl std::fmt::Display for AttestationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Sbom => "sbom",
            Self::Provenance => "provenance",
            Self::Audit => "audit",
            Self::Vex => "vex",
            Self::Qualification => "qualification",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for AttestationKind {
    type Err = AttestError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sbom" => Ok(Self::Sbom),
            "provenance" => Ok(Self::Provenance),
            "audit" => Ok(Self::Audit),
            "vex" => Ok(Self::Vex),
            "qualification" => Ok(Self::Qualification),
            other => Err(AttestError::UnknownKind(other.to_string())),
        }
    }
}

/// varve's statement ABOUT an attestation — never a restatement OF it.
///
/// Signed under the trust root, so a consumer can check offline that these
/// bytes belong with this layer. `producer` records who made the underlying
/// claim, as a string varve copies rather than interprets: varve is asserting
/// association and integrity, not endorsing the producer's conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationStatement {
    /// The layer these bytes accompany, e.g. `2026.08.0`.
    pub layer: String,
    /// `sha256:<hex>` of the DSSE-signed layer manifest — the join key.
    pub layer_manifest_digest: String,
    /// What the attached document is.
    pub kind: AttestationKind,
    /// `sha256:<hex>` of the attached bytes, exactly as carried.
    pub digest: String,
    /// Who produced the underlying claim, verbatim and uninterpreted
    /// (e.g. `adacore`, `cargo-vet`, `varve`).
    pub producer: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error(
        "unknown attestation kind '{0}' (expected: sbom, provenance, audit, vex, qualification)"
    )]
    UnknownKind(String),
    #[error("attestation statement is not valid JSON: {0}")]
    Payload(String),
    #[error(
        "attestation bytes do not match the signed statement: statement names {expected}, \
         the carried bytes hash to {got} — refusing"
    )]
    DigestMismatch { expected: String, got: String },
    #[error(
        "this attestation belongs to layer manifest {expected}, but it was presented for \
         {got} — refusing to associate it"
    )]
    LayerMismatch { expected: String, got: String },
    #[error("signature: {0}")]
    Signature(String),
}

/// Build the statement varve will sign for a set of attestation bytes.
pub fn statement(
    layer: &str,
    layer_manifest_digest: &str,
    kind: AttestationKind,
    bytes: &[u8],
    producer: &str,
) -> AttestationStatement {
    AttestationStatement {
        layer: layer.to_string(),
        layer_manifest_digest: layer_manifest_digest.to_string(),
        kind,
        digest: crate::store::manifest_digest(bytes),
        producer: producer.to_string(),
    }
}

/// Check a statement against the bytes it describes and the layer it is
/// presented for. Both must hold: bytes that do not hash to the signed digest
/// are not the attested bytes, and a statement for another layer must never be
/// silently accepted here (the confused-deputy case).
pub fn check(
    st: &AttestationStatement,
    bytes: &[u8],
    layer_manifest_digest: &str,
) -> Result<(), AttestError> {
    let got = crate::store::manifest_digest(bytes);
    if got != st.digest {
        return Err(AttestError::DigestMismatch {
            expected: st.digest.clone(),
            got,
        });
    }
    if st.layer_manifest_digest != layer_manifest_digest {
        return Err(AttestError::LayerMismatch {
            expected: st.layer_manifest_digest.clone(),
            got: layer_manifest_digest.to_string(),
        });
    }
    Ok(())
}

/// Sign a statement into a DSSE envelope under the root key.
pub fn sign(
    st: &AttestationStatement,
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, AttestError> {
    let payload = serde_json::to_vec(st).map_err(|e| AttestError::Payload(e.to_string()))?;
    crate::verify::dsse_sign_typed(&payload, PAYLOAD_TYPE, secret_key, key_id)
        .map_err(|e| AttestError::Signature(e.to_string()))
}

/// Verify an envelope against the trust root and return the statement inside.
/// The payload TYPE is checked, so a signed line-status or layer manifest can
/// never be accepted here as an attestation statement.
pub fn verify_statement(
    envelope: &[u8],
    root_pk: &[u8],
) -> Result<AttestationStatement, AttestError> {
    let payload = crate::verify::dsse_verify_typed(envelope, PAYLOAD_TYPE, root_pk)
        .map_err(|e| AttestError::Signature(e.to_string()))?;
    serde_json::from_slice(&payload).map_err(|e| AttestError::Payload(e.to_string()))
}

/// The DSSE payload type for an attestation statement — distinct from every
/// other document varve signs, so the types cannot be confused.
pub const PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.attestation-statement.v1+json";

#[cfg(test)]
mod tests {
    use super::*;

    const BYTES: &[u8] = b"{\"bomFormat\":\"CycloneDX\"}";
    const LAYER_DIGEST: &str = "sha256:1111";

    fn st() -> AttestationStatement {
        statement(
            "2026.08.0",
            LAYER_DIGEST,
            AttestationKind::Sbom,
            BYTES,
            "varve",
        )
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn a_statement_names_the_bytes_and_the_layer() {
        let s = st();
        assert_eq!(s.digest, crate::store::manifest_digest(BYTES));
        assert_eq!(s.layer_manifest_digest, LAYER_DIGEST);
        assert_eq!(s.kind, AttestationKind::Sbom);
        assert!(check(&s, BYTES, LAYER_DIGEST).is_ok());
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn swapped_bytes_are_refused() {
        // The whole value of the statement is that it pins the bytes.
        let s = st();
        match check(&s, b"different attestation entirely", LAYER_DIGEST) {
            Err(AttestError::DigestMismatch { .. }) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn an_attestation_for_another_layer_is_refused() {
        // A validly-signed statement for layer A must not be accepted as
        // evidence about layer B — the confused-deputy case.
        let s = st();
        match check(&s, BYTES, "sha256:2222") {
            Err(AttestError::LayerMismatch { .. }) => {}
            other => panic!("expected LayerMismatch, got {other:?}"),
        }
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn an_unknown_kind_is_refused_not_guessed() {
        assert!("sbom".parse::<AttestationKind>().is_ok());
        assert!("qualification".parse::<AttestationKind>().is_ok());
        assert!("vibes".parse::<AttestationKind>().is_err());
        assert!("".parse::<AttestationKind>().is_err());
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn a_statement_round_trips_through_a_signature() {
        let (sk, pk) = crate::generate_root_keypair();
        let s = st();
        let env = sign(&s, &sk, "test-root").unwrap();
        let back = verify_statement(env.as_bytes(), &pk).unwrap();
        assert_eq!(back, s);
    }

    // rivet: verifies REQ-ATTEST-001
    #[test]
    fn the_wrong_root_cannot_vouch_for_an_association() {
        let (sk, _) = crate::generate_root_keypair();
        let (_, other_pk) = crate::generate_root_keypair();
        let env = sign(&st(), &sk, "test-root").unwrap();
        assert!(verify_statement(env.as_bytes(), &other_pk).is_err());
    }
}
