//! Ingestion proof (REQ-INGEST-001) — WHAT vouched for the bytes varve took in.
//!
//! Until this module existed, the layer assembler accepted exactly one proof
//! that an upstream artifact was genuine: a cosign-signed `SHA256SUMS.txt`.
//! Every PulseEngine repo publishes one, so the constraint was invisible until
//! a second realm was attempted — `bytecodealliance/wasm-tools` v1.257.1
//! publishes no sums and no cosign bundle at all, and the assembler aborted the
//! whole run rather than ingest it.
//!
//! It is not that wasm-tools is unproven. It carries GitHub **build
//! provenance**, which is STRONGER than a sums file:
//!
//! * a signed sums file says *these bytes hash to this*, and binds that
//!   statement to whoever holds the release-workflow identity;
//! * an attestation binds the artifact to the workflow that built it, the
//!   repository it was built from, and the source commit — measured on
//!   2026-08-21, wasm-tools' attestation names
//!   `https://github.com/bytecodealliance/wasm-tools/.github/workflows/publish.yml@refs/heads/main`
//!   and source digest `3ef3cefc…`, and its in-toto statement carries the
//!   sha256 of every asset in the release.
//!
//! So the mechanism is not an implementation detail a consumer may be left to
//! guess at. It is part of what the layer *asserts*, and it lives inside the
//! DSSE-signed payload beside the kind and the source digests — uncorrectable
//! after signing, and readable without leaving the layer.
//!
//! # The three states, and the fourth
//!
//! `cosign-sums`, `build-provenance` and `unverified` are the mechanisms an
//! entry can DECLARE. The fourth state is the ABSENT annotation, and it is
//! deliberately not any of them: every layer published before this requirement
//! carries no proof annotation, and reading that as "verified" would silently
//! upgrade a hundred payloads to a claim nobody made. Absent reads as
//! `unrecorded` (`IngestProof::label(None)`), which is a statement about the
//! layer's age and nothing else.
//!
//! `unverified` is a real, sayable state — bytes ingested with nothing vouching
//! for them — but never a silent one: `deposit` refuses it unless the operator's
//! reason is recorded alongside (see `DepositError::UnverifiedWithoutReason`),
//! and it may not name a signer, because nothing signed it.

use std::fmt;
use std::str::FromStr;

/// The mechanism that vouched for this payload's upstream bytes.
pub const ANN_PROOF: &str = "eu.pulseengine.source.proof";
/// The identity that vouched: the certificate identity cosign matched, or the
/// attestation's `buildSignerURI`. Absent where nothing vouched.
pub const ANN_PROOF_SIGNER: &str = "eu.pulseengine.source.proof-signer";
/// One line stating what that mechanism ASSERTED — the sums blob it covered,
/// the source commit it bound the build to, or the operator's recorded reason
/// for shipping bytes nothing vouched for.
pub const ANN_PROOF_ASSERTS: &str = "eu.pulseengine.source.proof-asserts";

/// How the assembler established that an upstream artifact was genuine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IngestProof {
    /// A `SHA256SUMS.txt` verified by `cosign verify-blob` against the repo's
    /// release-workflow identity and the GitHub Actions OIDC issuer. Asserts
    /// that the holder of that identity published these digests.
    CosignSums,
    /// A GitHub build attestation (`gh attestation verify`), whose in-toto
    /// statement names the artifact's digest as a subject. Asserts the workflow,
    /// repository and source commit the artifact was built from — a strictly
    /// stronger claim than a sums file, since it covers WHERE the bytes came
    /// from and not merely WHAT they hash to.
    BuildProvenance,
    /// Nothing vouched for these bytes. Only reachable through an explicit,
    /// recorded operator opt-in; the reason travels in `ANN_PROOF_ASSERTS`.
    Unverified,
}

impl IngestProof {
    /// The canonical wire string, as written in the signed annotation.
    pub fn as_str(self) -> &'static str {
        match self {
            IngestProof::CosignSums => "cosign-sums",
            IngestProof::BuildProvenance => "build-provenance",
            IngestProof::Unverified => "unverified",
        }
    }

    /// Did anything at all vouch for these bytes?
    ///
    /// Note what this does NOT say: it does not rank `cosign-sums` against
    /// `build-provenance`. Both are accepted proofs; provenance carries the
    /// stronger claim, and a consumer that cares which one can read the
    /// annotation rather than have varve collapse the distinction for it.
    pub fn is_verified(self) -> bool {
        !matches!(self, IngestProof::Unverified)
    }

    /// How an entry's proof reads when it may be absent — the pre-requirement
    /// case. Absent is `unrecorded`, never `unverified` and never "verified":
    /// it says the layer predates REQ-INGEST-001, and nothing more.
    pub fn label(proof: Option<IngestProof>) -> &'static str {
        match proof {
            Some(p) => p.as_str(),
            None => "unrecorded",
        }
    }
}

impl fmt::Display for IngestProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A mechanism this varve does not know. Reported verbatim rather than guessed
/// into a known one — a newer varve may mint mechanisms this build has never
/// heard of, and silently reading one as `cosign-sums` would be a lie about
/// what vouched for the bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown ingestion proof '{0}': this varve does not know what that mechanism asserts \
     (expected one of cosign-sums, build-provenance, unverified). The payload's bytes still \
     verify against the signed digest — only the claim about how they were vouched for is \
     unreadable here. A newer varve may know it."
)]
pub struct UnknownProof(pub String);

impl FromStr for IngestProof {
    type Err = UnknownProof;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cosign-sums" => Ok(IngestProof::CosignSums),
            "build-provenance" => Ok(IngestProof::BuildProvenance),
            "unverified" => Ok(IngestProof::Unverified),
            other => Err(UnknownProof(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mechanism, in one place, so the tests below cannot silently skip a
    /// newly added one — the mistake `kind.rs` records having made twice.
    const ALL: &[IngestProof] = &[
        IngestProof::CosignSums,
        IngestProof::BuildProvenance,
        IngestProof::Unverified,
    ];

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_wire_spelling_round_trips_and_is_what_the_spec_and_the_annotation_share() {
        for p in ALL {
            assert_eq!(p.as_str().parse::<IngestProof>().unwrap(), *p);
            // The deposit spec (TOML) and the signed annotation must spell the
            // mechanism the SAME way, or a spec would deposit a proof the
            // consumer reads as unknown. Deserialisation is derived and
            // `as_str` is hand-written, so pin them against each other.
            let via_serde: IngestProof =
                serde_json::from_str(&format!("\"{}\"", p.as_str())).unwrap();
            assert_eq!(via_serde, *p);
        }
        // Spelled out rather than left to whatever the derive happens to emit:
        // these strings are a compatibility promise, inside a signature.
        assert_eq!(IngestProof::CosignSums.as_str(), "cosign-sums");
        assert_eq!(IngestProof::BuildProvenance.as_str(), "build-provenance");
        assert_eq!(IngestProof::Unverified.as_str(), "unverified");
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn absent_is_unrecorded_and_only_unverified_is_unverified() {
        assert_eq!(IngestProof::label(None), "unrecorded");
        for p in ALL {
            assert_eq!(IngestProof::label(Some(*p)), p.as_str());
            assert_ne!(
                IngestProof::label(Some(*p)),
                "unrecorded",
                "a declared mechanism must never read as the absent case"
            );
        }
        assert!(IngestProof::CosignSums.is_verified());
        assert!(IngestProof::BuildProvenance.is_verified());
        assert!(
            !IngestProof::Unverified.is_verified(),
            "the whole point of the state is that nothing vouched for it"
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unknown_mechanism_is_reported_verbatim() {
        let err = "notary-v2".parse::<IngestProof>().unwrap_err();
        assert_eq!(err, UnknownProof("notary-v2".into()));
        assert!(err.to_string().contains("notary-v2"));
        // Near-misses are not guessed at either.
        for bad in ["cosign", "CosignSums", "provenance", ""] {
            assert!(bad.parse::<IngestProof>().is_err(), "{bad} must be refused");
        }
    }
}
