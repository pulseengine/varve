//! Which mechanism vouched for an upstream release (REQ-INGEST-001).
//!
//! Two mechanisms are accepted, tried in order, and the one that applied is
//! recorded per payload so it lands inside the signed layer:
//!
//! * `cosign-sums` — a `SHA256SUMS.txt` verified by `cosign verify-blob`
//!   against an identity under the repository. Every PulseEngine repo has one.
//! * `build-provenance` — a GitHub build attestation. STRONGER than a sums
//!   file: a sums file says "these bytes hash to this", an attestation binds
//!   the artifact to the workflow, repository and source commit that produced
//!   it. It is how a second realm becomes ingestible at all —
//!   `bytecodealliance/wasm-tools` publishes no sums and no cosign bundle.
//!
//! A release offering neither is REFUSED. It can be ingested only through an
//! explicit opt-in whose stated reason is signed into the layer.
//!
//! ## The property this module exists to make structural
//!
//! **The ladder must not downgrade.** "This release offers no cosign proof"
//! and "this release's cosign proof FAILED to verify" are different facts, and
//! treating the second as the first turns a detected attack into a quiet
//! fallback to a weaker mechanism — or to none.
//!
//! In shell that distinction was a comment (*"NOT guarded by `if`"*) and one
//! stray `|| true` away from silently inverting. Here a rung returns
//! [`Rung`], whose three states cannot be collapsed by accident: only
//! [`Rung::NotOffered`] continues the ladder, and [`Rung::Failed`] has no path
//! back into it.

use crate::forge::Forge;
use std::collections::BTreeMap;
use std::fmt;

/// How a release's bytes were vouched for. Recorded inside the signed layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    CosignSums,
    BuildProvenance,
    Unverified,
}

impl Mechanism {
    /// The value written into `[tool.source]`, and shown by `varve inspect`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::CosignSums => "cosign-sums",
            Mechanism::BuildProvenance => "build-provenance",
            Mechanism::Unverified => "unverified",
        }
    }
}

/// The outcome of trying ONE rung of the ladder.
///
/// The three states are the whole point. `NotOffered` is the only one that
/// continues to the next rung; `Failed` aborts. A two-state result (bool,
/// `Option`, or `Result` collapsed with `unwrap_or`) cannot express the
/// difference, which is exactly how a rejected signature gets read as an
/// absent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rung {
    /// This mechanism applies and its proof verified.
    Accepted { signer: String, asserts: String },
    /// This release does not offer this mechanism at all — try the next.
    NotOffered,
    /// This release OFFERS this mechanism and it did not verify. Abort. Never
    /// continue the ladder.
    Failed(String),
}

/// What a release was observed to offer. Gathering this is IO; deciding on it
/// is not, which is why they are separate types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseProbe {
    /// `SHA256SUMS.txt` is published.
    pub has_sums: bool,
    /// `SHA256SUMS.txt.cosign.bundle` is published.
    pub has_cosign_bundle: bool,
    /// `cosign verify-blob` was run and its outcome. `None` when it was not
    /// run because the assets were absent.
    pub cosign: Option<Result<(), String>>,
    /// What `gh attestation verify` established. THREE states, for the same
    /// reason [`Rung`] has three: `Option` cannot distinguish "this release
    /// has no attestation" from "this release HAS one and it did not verify",
    /// and collapsing those is how a rejected proof becomes a silent
    /// downgrade. A clean-room review found the first version of this field
    /// was an `Option<(String, String)>`, which made
    /// [`Rung::Failed`] unreachable from rung 2 — the module prevented the
    /// conflation on rung 1 and reproduced it one rung down.
    ///
    /// The shell has the same hole: `if gh attestation verify … 2>/dev/null`
    /// reads a verification FAILURE as "not attested" and carries on.
    pub attestation: AttestationProbe,
}

/// What was observed about a release's build attestation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AttestationProbe {
    /// No attestation exists for any asset of this release.
    #[default]
    NotAttested,
    /// An attestation verified: (signer, source commit).
    Verified { signer: String, commit: String },
    /// An attestation EXISTS and did not verify. Not the same as absent.
    Rejected(String),
    /// Nobody looked. A caller that satisfied rung 1 has no reason to spend a
    /// download probing rung 2, and saying `NotAttested` there would be a
    /// claim about something never observed — the precise habit the rest of
    /// this module exists to break.
    ///
    /// Reaching rung 2 in this state is a caller ordering error, and it fails
    /// closed rather than reading as an absent mechanism.
    NotProbed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub mechanism: Mechanism,
    pub signer: String,
    pub asserts: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// A proof was offered and did not verify. Never a fallback.
    ProofRejected { repo: String, detail: String },
    /// Neither mechanism, and no opt-in.
    NoMechanism { repo: String, version: String },
    /// An opt-in naming the repo but stating no reason.
    OptInWithoutReason { repo: String },
    /// The same repository requested at two versions in one layer.
    RepoAtTwoVersions {
        repo: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::ProofRejected { repo, detail } => write!(
                f,
                "{repo} offers an ingestion proof that DID NOT VERIFY: {detail}. \
                 This is not the same as offering no proof, and varve will not \
                 treat it as such — a rejected signature read as an absent one \
                 turns a detected attack into a silent downgrade. Nothing from \
                 this release is ingested."
            ),
            IngestError::NoMechanism { repo, version } => write!(
                f,
                "{repo} {version} offers no ingestion proof this assembler \
                 accepts: no cosign-signed SHA256SUMS.txt, and no GitHub build \
                 provenance for any of its assets. varve will not sign bytes \
                 that nothing vouched for into a layer other people install.\n\
                 The alternative to reach for first: fork {repo} into this \
                 organisation and cut its release through the signed pipeline, \
                 then name the fork here instead of upstream.\n\
                 To ingest it anyway you must say why, and the reason is signed \
                 into the layer:\n  UNVERIFIED_INGEST=\"{repo}=<why this is \
                 acceptable, and what removes the need>\""
            ),
            IngestError::OptInWithoutReason { repo } => write!(
                f,
                "UNVERIFIED_INGEST names {repo} but records no reason. \"We \
                 could not verify this\" must never be the silent path — the \
                 reason is what travels with the bytes into the signed layer, \
                 so it is not optional. Write \
                 UNVERIFIED_INGEST=\"{repo}=<why>\"."
            ),
            IngestError::RepoAtTwoVersions {
                repo,
                first,
                second,
            } => write!(
                f,
                "{repo} is requested at more than one version in this layer \
                 ({first} and {second}) — one release per repo per layer, or \
                 its sums cannot be trusted: one release's assets would be \
                 checked against the other's sums."
            ),
        }
    }
}

impl std::error::Error for IngestError {}

/// Rung 1 — a cosign-signed sums file.
pub fn rung_cosign_sums(forge: &Forge, repo: &str, probe: &ReleaseProbe) -> Rung {
    if !(probe.has_sums && probe.has_cosign_bundle) {
        return Rung::NotOffered;
    }
    match &probe.cosign {
        // Offered but never actually run is a programming error in the caller,
        // not an absent mechanism. Refuse rather than assume either way.
        None => Rung::Failed(
            "the release publishes a cosign bundle but verification was never run".into(),
        ),
        Some(Err(e)) => Rung::Failed(e.clone()),
        Some(Ok(())) => {
            let identity = forge.identity_prefix(repo);
            Rung::Accepted {
                signer: identity.clone(),
                asserts: format!(
                    "SHA256SUMS.txt signed by an identity under {identity} via \
                     {}; this payload's recorded asset digest is transcribed \
                     from it",
                    forge.oidc_issuer
                ),
            }
        }
    }
}

/// Rung 2 — a GitHub build attestation.
pub fn rung_build_provenance(probe: &ReleaseProbe) -> Rung {
    match &probe.attestation {
        AttestationProbe::NotAttested => Rung::NotOffered,
        // Never observed, so nothing may be concluded — including "absent".
        AttestationProbe::NotProbed => Rung::Failed(
            "this release's attestation was never probed, so rung 2 cannot be \
             decided; reaching it in this state is an ordering error in the \
             caller, not an absent attestation"
                .into(),
        ),
        AttestationProbe::Rejected(detail) => Rung::Failed(detail.clone()),
        AttestationProbe::Verified { signer, commit } => Rung::Accepted {
            signer: signer.clone(),
            asserts: format!(
                "built by {signer} from source commit {commit}; this payload's \
                 recorded asset digest is a subject of that attestation"
            ),
        },
    }
}

/// Parse `UNVERIFIED_INGEST` — one `owner/repo=reason` PER LINE.
///
/// Lines, not a punctuation-separated list: the reason is prose an operator
/// writes, and any separator that can occur inside it truncates the reason
/// silently at exactly the moment it matters most.
pub fn parse_optins(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((repo, reason)) = line.split_once('=') {
            out.insert(repo.trim().to_string(), reason.trim().to_string());
        }
    }
    out
}

/// Walk the ladder for one release.
pub fn choose(
    forge: &Forge,
    repo: &str,
    version: &str,
    probe: &ReleaseProbe,
    optins: &BTreeMap<String, String>,
) -> Result<Accepted, IngestError> {
    match rung_cosign_sums(forge, repo, probe) {
        Rung::Accepted { signer, asserts } => {
            return Ok(Accepted {
                mechanism: Mechanism::CosignSums,
                signer,
                asserts,
            });
        }
        // The one branch that must never become a fallback.
        Rung::Failed(detail) => {
            return Err(IngestError::ProofRejected {
                repo: repo.to_string(),
                detail,
            });
        }
        Rung::NotOffered => {}
    }

    match rung_build_provenance(probe) {
        Rung::Accepted { signer, asserts } => {
            return Ok(Accepted {
                mechanism: Mechanism::BuildProvenance,
                signer,
                asserts,
            });
        }
        Rung::Failed(detail) => {
            return Err(IngestError::ProofRejected {
                repo: repo.to_string(),
                detail,
            });
        }
        Rung::NotOffered => {}
    }

    // REQ-INGEST-001 clause 3: no mechanism, no ingestion.
    match optins.get(repo) {
        Some(reason) if !reason.trim().is_empty() => Ok(Accepted {
            mechanism: Mechanism::Unverified,
            signer: String::new(),
            asserts: format!(
                "NOTHING vouched for these bytes — ingested on an explicit \
                 operator opt-in. Recorded reason: {reason}"
            ),
        }),
        Some(_) => Err(IngestError::OptInWithoutReason {
            repo: repo.to_string(),
        }),
        None => Err(IngestError::NoMechanism {
            repo: repo.to_string(),
            version: version.to_string(),
        }),
    }
}

/// Tracks which repositories have been verified, at which version.
///
/// Two jobs, both of which cost a real deposit: a repo appearing in BOTH the
/// tool list and the extension list (rivet and spar each ship a CLI and a VS
/// Code extension) must be verified ONCE — re-fetching its sums is what killed
/// the 2026.08.3 run — and the same repo at TWO versions must abort, because
/// one release's assets would then be checked against the other's sums.
#[derive(Debug, Default)]
pub struct VerifiedRepos {
    seen: BTreeMap<String, (String, Accepted)>,
}

impl VerifiedRepos {
    pub fn new() -> Self {
        Self::default()
    }

    /// Has this repo already been accepted at this version?
    pub fn accepted(&self, repo: &str, version: &str) -> Option<&Accepted> {
        match self.seen.get(repo) {
            Some((v, a)) if v == version => Some(a),
            _ => None,
        }
    }

    /// Record an acceptance, refusing a second version of the same repo.
    pub fn record(
        &mut self,
        repo: &str,
        version: &str,
        accepted: Accepted,
    ) -> Result<(), IngestError> {
        if let Some((first, _)) = self.seen.get(repo)
            && first != version
        {
            return Err(IngestError::RepoAtTwoVersions {
                repo: repo.to_string(),
                first: first.clone(),
                second: version.to_string(),
            });
        }
        self.seen
            .insert(repo.to_string(), (version.to_string(), accepted));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sums_ok() -> ReleaseProbe {
        ReleaseProbe {
            has_sums: true,
            has_cosign_bundle: true,
            cosign: Some(Ok(())),
            attestation: AttestationProbe::NotAttested,
        }
    }

    fn no_optins() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_cosign_signed_sums_file_is_the_first_rung() {
        let f = Forge::github_com();
        let a =
            choose(&f, "pulseengine/rivet", "v0.34.0", &sums_ok(), &no_optins()).expect("accepts");
        assert_eq!(a.mechanism, Mechanism::CosignSums);
        assert_eq!(a.signer, "https://github.com/pulseengine/rivet/");
    }

    /// A supply-chain tool that only works against one vendor's public host is
    /// not one an enterprise can adopt. The recorded signer and the asserted
    /// claim must both follow the instance, or a GHES layer would carry
    /// provenance naming a host its bytes never came from.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_enterprise_instance_records_its_own_identity_and_issuer() {
        let f = Forge::enterprise("ghe.example.com");
        let a = choose(&f, "acme/tool", "v1.0.0", &sums_ok(), &no_optins()).expect("accepts");
        assert_eq!(a.mechanism, Mechanism::CosignSums);
        assert_eq!(a.signer, "https://ghe.example.com/acme/tool/");
        assert!(
            a.asserts.contains("https://ghe.example.com/acme/tool/"),
            "{}",
            a.asserts
        );
        assert!(
            a.asserts
                .contains("https://ghe.example.com/_services/token"),
            "{}",
            a.asserts
        );
        // Nothing from the public instance may leak into an enterprise record.
        assert!(!a.signer.contains("github.com"), "{}", a.signer);
        assert!(!a.asserts.contains("githubusercontent"), "{}", a.asserts);
    }

    /// THE property. A release that offers a cosign bundle whose signature does
    /// not verify must ABORT — not fall through to build provenance, and not
    /// fall through to "offers nothing".
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_rejected_cosign_proof_aborts_and_does_not_fall_through() {
        let probe = ReleaseProbe {
            cosign: Some(Err("certificate identity mismatch".into())),
            // An attestation IS available: if the ladder downgraded, this is
            // the weaker rung it would silently land on.
            attestation: AttestationProbe::Verified {
                signer: "https://github.com/evil/wf".into(),
                commit: "deadbeef".into(),
            },
            ..sums_ok()
        };
        let err = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.34.0",
            &probe,
            &no_optins(),
        )
        .expect_err("aborts");
        assert!(
            matches!(&err, IngestError::ProofRejected { detail, .. }
                     if detail.contains("certificate identity mismatch")),
            "{err:?}"
        );
        assert!(err.to_string().contains("silent downgrade"), "{err}");
    }

    /// And an opt-in must not rescue a REJECTED proof either — the opt-in is
    /// for releases that offer nothing, not for ones that failed.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_opt_in_does_not_rescue_a_rejected_proof() {
        let probe = ReleaseProbe {
            cosign: Some(Err("bad signature".into())),
            ..sums_ok()
        };
        let mut optins = BTreeMap::new();
        optins.insert(
            "pulseengine/rivet".to_string(),
            "we really need it".to_string(),
        );
        let err = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.34.0",
            &probe,
            &optins,
        )
        .expect_err("aborts");
        assert!(matches!(err, IngestError::ProofRejected { .. }), "{err:?}");
    }

    /// The hole a clean-room review found: rung 2 could not express failure at
    /// all, so an attestation that EXISTS and fails to verify was
    /// indistinguishable from a release having none — and would have fallen
    /// through to the no-mechanism path, where an opt-in could wave it in.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_rejected_attestation_aborts_rather_than_reading_as_unattested() {
        let probe = ReleaseProbe {
            attestation: AttestationProbe::Rejected("no attestation matches the subject".into()),
            ..Default::default()
        };
        // Even with an opt-in that WOULD have rescued a release offering
        // nothing, a failed proof must not be rescued.
        let mut optins = BTreeMap::new();
        optins.insert("acme/tool".to_string(), "we need it".to_string());
        let err = choose(&Forge::github_com(), "acme/tool", "v1.0.0", &probe, &optins)
            .expect_err("aborts");
        assert!(
            matches!(&err, IngestError::ProofRejected { detail, .. }
                     if detail.contains("no attestation matches")),
            "{err:?}"
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_absent_attestation_is_still_merely_not_offered() {
        let probe = ReleaseProbe::default();
        assert_eq!(rung_build_provenance(&probe), Rung::NotOffered);
    }

    /// bytecodealliance publishes no sums and no bundle, and IS attested.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn build_provenance_carries_a_release_that_publishes_no_sums() {
        let probe = ReleaseProbe {
            attestation: AttestationProbe::Verified {
                signer:
                    "https://github.com/bytecodealliance/wasm-tools/.github/workflows/release.yml"
                        .into(),
                commit: "abc123".into(),
            },
            ..Default::default()
        };
        let a = choose(
            &Forge::github_com(),
            "bytecodealliance/wasm-tools",
            "v1.257.1",
            &probe,
            &no_optins(),
        )
        .expect("accepts");
        assert_eq!(a.mechanism, Mechanism::BuildProvenance);
        assert!(a.asserts.contains("source commit abc123"), "{}", a.asserts);
    }

    /// A bundle present but verification never run is a caller bug. It must not
    /// silently read as "no cosign proof".
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unrun_verification_is_a_failure_not_an_absence() {
        let probe = ReleaseProbe {
            cosign: None,
            ..sums_ok()
        };
        assert!(matches!(
            rung_cosign_sums(&Forge::github_com(), "r", &probe),
            Rung::Failed(_)
        ));
    }

    /// Only BOTH assets constitute the offer: a sums file with no bundle is
    /// unsigned, and must not be accepted as though it were.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_sums_file_without_a_bundle_is_not_offered() {
        let probe = ReleaseProbe {
            has_sums: true,
            has_cosign_bundle: false,
            cosign: Some(Ok(())),
            attestation: AttestationProbe::NotAttested,
        };
        assert_eq!(
            rung_cosign_sums(&Forge::github_com(), "r", &probe),
            Rung::NotOffered
        );
        let err = choose(&Forge::github_com(), "r", "v1", &probe, &no_optins())
            .expect_err("no mechanism");
        assert!(matches!(err, IngestError::NoMechanism { .. }), "{err:?}");
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_release_offering_nothing_is_refused_and_names_the_fork_route() {
        let err = choose(
            &Forge::github_com(),
            "acme/tool",
            "v1.0.0",
            &ReleaseProbe::default(),
            &no_optins(),
        )
        .expect_err("refuses");
        let msg = err.to_string();
        assert!(msg.contains("fork acme/tool"), "{msg}");
        assert!(msg.contains("UNVERIFIED_INGEST"), "{msg}");
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_explicit_reasoned_opt_in_ingests_and_records_the_reason() {
        let optins = parse_optins("acme/tool=upstream ships tarballs only; fork tracked in #77");
        let a = choose(
            &Forge::github_com(),
            "acme/tool",
            "v1.0.0",
            &ReleaseProbe::default(),
            &optins,
        )
        .expect("accepts");
        assert_eq!(a.mechanism, Mechanism::Unverified);
        assert_eq!(a.signer, "");
        assert!(a.asserts.contains("fork tracked in #77"), "{}", a.asserts);
        assert!(a.asserts.contains("NOTHING vouched"), "{}", a.asserts);
    }

    /// "We could not verify this" must never be the silent path.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_opt_in_stating_no_reason_is_refused() {
        for raw in ["acme/tool=", "acme/tool=   "] {
            let optins = parse_optins(raw);
            let err = choose(
                &Forge::github_com(),
                "acme/tool",
                "v1.0.0",
                &ReleaseProbe::default(),
                &optins,
            )
            .expect_err("refuses");
            assert!(
                matches!(err, IngestError::OptInWithoutReason { .. }),
                "{raw:?} -> {err:?}"
            );
        }
    }

    /// The reason is prose. A separator that can occur inside it would truncate
    /// it silently, so opt-ins are line-separated.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_reason_containing_punctuation_survives_intact() {
        let optins = parse_optins("a/b=no sums yet: upstream said Q3, tracked in #12\nc/d=other");
        assert_eq!(
            optins.get("a/b").map(String::as_str),
            Some("no sums yet: upstream said Q3, tracked in #12")
        );
        assert_eq!(optins.get("c/d").map(String::as_str), Some("other"));
    }

    /// The 2026.08.3 killer: rivet is in BOTH the tool list and the extension
    /// list, so its release is reached twice and must be verified once.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_repo_reached_twice_at_one_version_is_verified_once() {
        let mut seen = VerifiedRepos::new();
        let a = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.34.0",
            &sums_ok(),
            &no_optins(),
        )
        .unwrap();
        seen.record("pulseengine/rivet", "v0.34.0", a).unwrap();
        assert!(seen.accepted("pulseengine/rivet", "v0.34.0").is_some());
    }

    /// Two versions of one repo would check one release's assets against the
    /// other's sums.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_repo_at_two_versions_in_one_layer_is_refused() {
        let mut seen = VerifiedRepos::new();
        let a = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.34.0",
            &sums_ok(),
            &no_optins(),
        )
        .unwrap();
        seen.record("pulseengine/rivet", "v0.34.0", a.clone())
            .unwrap();
        let err = seen
            .record("pulseengine/rivet", "v0.33.1", a)
            .expect_err("refuses");
        assert_eq!(
            err,
            IngestError::RepoAtTwoVersions {
                repo: "pulseengine/rivet".into(),
                first: "v0.34.0".into(),
                second: "v0.33.1".into()
            }
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_different_version_is_not_reported_as_already_accepted() {
        let mut seen = VerifiedRepos::new();
        let a = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.34.0",
            &sums_ok(),
            &no_optins(),
        )
        .unwrap();
        seen.record("pulseengine/rivet", "v0.34.0", a).unwrap();
        assert!(seen.accepted("pulseengine/rivet", "v0.33.1").is_none());
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_recorded_mechanism_names_match_what_lands_in_the_layer() {
        assert_eq!(Mechanism::CosignSums.as_str(), "cosign-sums");
        assert_eq!(Mechanism::BuildProvenance.as_str(), "build-provenance");
        assert_eq!(Mechanism::Unverified.as_str(), "unverified");
    }
}
