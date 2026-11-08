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
//! `cosign-sums`, `build-provenance`, `pgp-sums`, `upstream-sums` and `unverified` are the mechanisms an
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
/// The key that actually produced the signature, when it is a different fact
/// from `ANN_PROOF_SIGNER` (REQ-SIGNEDSUMS-001 clause 1): for an OpenPGP list,
/// the signer is the certificate's primary fingerprint and this is the
/// (sub)key that signed. Recorded separately because collapsing them is how a
/// compromised subkey goes unnoticed. Absent for mechanisms with no such split.
pub const ANN_PROOF_SIGNING_KEY: &str = "eu.pulseengine.source.proof-signing-key";
/// One line stating what that mechanism ASSERTED — the sums blob it covered,
/// the source commit it bound the build to, or the operator's recorded reason
/// for shipping bytes nothing vouched for.
pub const ANN_PROOF_ASSERTS: &str = "eu.pulseengine.source.proof-asserts";

/// The upstream repository's DECLARED license, as an SPDX expression
/// (REQ-SBOMFIELDS-001 clause 5). The repository's statement, recorded at
/// deposit — not a concluded audit of what the binary bundles. Absent on every
/// layer deposited before it existed, and absent must not read as "none".
pub const ANN_LICENSE: &str = "eu.pulseengine.source.license";
/// The file name of a CycloneDX SBOM upstream published in the SAME release
/// the payload came from (REQ-SBOMFIELDS-001 clause 4); relative to that
/// release, like `eu.pulseengine.source.asset`.
pub const ANN_SBOM: &str = "eu.pulseengine.source.sbom";
/// The sha256 (bare hex) of that SBOM file as the deposit fetched it, so a
/// reader following the reference can tell it was not replaced afterwards.
pub const ANN_SBOM_SHA256: &str = "eu.pulseengine.source.sbom.sha256";

/// The ONE declaration of every mechanism: the enum, its wire spelling and
/// [`IngestProof::VARIANTS`] are all emitted from this list, so a variant
/// cannot exist without a spelling and without being listed. They drifted once
/// (`upstream-sums` was written but not readable) while three hand-kept lists
/// had to agree; there is now nothing to keep in step. Adding a mechanism is
/// one line in the invocation below.
///
/// The spelling is also the serde `rename`, so deserialising a deposit spec
/// and `as_str` come from the same literal.
macro_rules! ingest_proofs {
    ($( $(#[$meta:meta])* $variant:ident => $spelling:literal, )+) => {
        /// How the assembler established that an upstream artifact was genuine.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
        pub enum IngestProof {
            $( $(#[$meta])* #[serde(rename = $spelling)] $variant, )+
        }

        impl IngestProof {
            /// Every mechanism. The single production list that `FromStr`, the
            /// unknown-mechanism error text and the tests all derive from, and
            /// itself emitted from the same declaration as the enum and
            /// `as_str`: a variant cannot be added without being listed.
            pub const VARIANTS: &'static [IngestProof] = &[ $( IngestProof::$variant, )+ ];

            /// The canonical wire string, as written in the signed annotation.
            pub fn as_str(self) -> &'static str {
                match self {
                    $( IngestProof::$variant => $spelling, )+
                }
            }
        }
    };
}

ingest_proofs! {
    /// A `SHA256SUMS.txt` verified by `cosign verify-blob` against the repo's
    /// release-workflow identity and the GitHub Actions OIDC issuer. Asserts
    /// that the holder of that identity published these digests.
    CosignSums => "cosign-sums",
    /// A GitHub build attestation (`gh attestation verify`), whose in-toto
    /// statement names the artifact's digest as a subject. Asserts the workflow,
    /// repository and source commit the artifact was built from — a strictly
    /// stronger claim than a sums file, since it covers WHERE the bytes came
    /// from and not merely WHAT they hash to.
    BuildProvenance => "build-provenance",
    /// A digest list that somebody SIGNED with OpenPGP (a detached binary
    /// signature, SHA-256 or stronger), verified against a certificate the
    /// operator pinned in the producer's committed input
    /// (REQ-SIGNEDSUMS-001). Asserts that the holder of that key, named by
    /// FINGERPRINT and never by the self-asserted user ID, published the
    /// digests. Says nothing about whether that publisher is trustworthy.
    PgpSums => "pgp-sums",
    /// A digest list the upstream published beside its assets and NOBODY
    /// SIGNED (REQ-UPSTREAMSUMS-001).
    ///
    /// Between `build-provenance` and `unverified`, and the name has to keep
    /// saying which. It establishes that the bytes are the bytes that list
    /// names — catching a corrupted or truncated download, which for a 90 MB
    /// toolchain is the failure that actually happens — and nothing about who
    /// produced them, because the same host serves the list and the bytes.
    UpstreamSums => "upstream-sums",
    /// Nothing vouched for these bytes. Only reachable through an explicit,
    /// recorded operator opt-in; the reason travels in `ANN_PROOF_ASSERTS`.
    Unverified => "unverified",
}

impl IngestProof {
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
     (expected one of {known}). The payload's bytes still \
     verify against the signed digest — only the claim about how they were vouched for is \
     unreadable here. A newer varve may know it.",
    known = known_mechanisms()
)]
pub struct UnknownProof(pub String);

/// The known wire spellings, comma-separated, generated from
/// [`IngestProof::VARIANTS`].
fn known_mechanisms() -> String {
    IngestProof::VARIANTS
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl FromStr for IngestProof {
    type Err = UnknownProof;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IngestProof::VARIANTS
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| UnknownProof(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[IngestProof] = IngestProof::VARIANTS;

    /// Drift guard. The enum, `as_str` and `VARIANTS` are emitted by one
    /// macro invocation, so there is no second list to forget; this pins what
    /// the macro promises: every variant is listed once, with its own distinct
    /// spelling.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn every_variant_is_listed_once_with_its_own_spelling() {
        let mut seen = std::collections::BTreeSet::new();
        for p in IngestProof::VARIANTS {
            assert!(seen.insert(p.as_str()), "{p} repeats a spelling");
        }
        assert_eq!(seen.len(), IngestProof::VARIANTS.len());
        assert!(!IngestProof::VARIANTS.is_empty());
    }

    /// Every spelling `as_str` writes is the one serde and `FromStr` read.
    /// (`IngestProof` derives only `Deserialize`, so the serde side is the
    /// reading direction, which is the one #339 broke.)
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn every_spelling_is_read_back_by_serde_and_from_str() {
        for p in IngestProof::VARIANTS {
            let s = p.as_str();
            assert_eq!(s.parse::<IngestProof>().unwrap(), *p, "FromStr: {s}");
            let via_serde: IngestProof = serde_json::from_str(&format!("\"{s}\"")).unwrap();
            assert_eq!(via_serde, *p, "serde: {s}");
        }
        assert!(serde_json::from_str::<IngestProof>("\"not-a-proof\"").is_err());
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_error_names_every_known_mechanism() {
        let msg = "nope".parse::<IngestProof>().unwrap_err().to_string();
        for p in ALL {
            assert!(msg.contains(p.as_str()), "{msg} omits {p}");
        }
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_wire_spelling_round_trips_and_is_what_the_spec_and_the_annotation_share() {
        for p in ALL {
            assert_eq!(p.as_str().parse::<IngestProof>().unwrap(), *p);
            assert_eq!(p.to_string(), p.as_str(), "Display is the wire spelling");
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
        assert_eq!(IngestProof::PgpSums.as_str(), "pgp-sums");
        assert_eq!(IngestProof::UpstreamSums.as_str(), "upstream-sums");
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
        assert!(IngestProof::PgpSums.is_verified());
        assert!(IngestProof::UpstreamSums.is_verified());
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
