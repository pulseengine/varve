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
    /// A digest manifest the upstream publishes beside its assets, that NOBODY
    /// SIGNED (REQ-UPSTREAMSUMS-001).
    ///
    /// Weaker than either rung above it, and the name has to keep saying so.
    /// It catches a corrupted or truncated download — which for a 90 MB
    /// toolchain is the failure that actually happens — and it stops nobody
    /// who can replace the manifest and the bytes together, because the same
    /// host serves both. Real, and not a signature.
    UpstreamSums,
    CosignSums,
    BuildProvenance,
    /// A digest list somebody SIGNED with OpenPGP, verified against a
    /// certificate the operator pinned in the producer's committed input
    /// (REQ-SIGNEDSUMS-001, DD-034). Below cosign and build provenance, above
    /// the unsigned list.
    PgpSums,
    Unverified,
}

impl Mechanism {
    /// The value written into `[tool.source]`, and shown by `varve inspect`.
    /// Does this mechanism carry a SIGNATURE over the digests?
    ///
    /// Clause 4: where a realm demands signed provenance, `upstream-sums` is
    /// refused rather than counted. The question is asked here, once, so no
    /// caller has to remember which of four names are signatures.
    pub fn is_signed(self) -> bool {
        match self {
            Mechanism::CosignSums | Mechanism::BuildProvenance | Mechanism::PgpSums => true,
            Mechanism::UpstreamSums | Mechanism::Unverified => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::CosignSums => "cosign-sums",
            Mechanism::BuildProvenance => "build-provenance",
            Mechanism::PgpSums => "pgp-sums",
            // Named so it cannot be mistaken for a signature by someone
            // skimming a manifest. "upstream-sums" says who vouched (upstream)
            // and what with (a digest list) — and conspicuously does not say
            // "signed".
            Mechanism::UpstreamSums => "upstream-sums",
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
    /// Every asset name the release publishes.
    ///
    /// Kept separate from the digests a proof covers, because the two answer
    /// different questions and confusing them is how an UNSIGNED asset gets
    /// treated as an unbuilt one. "This platform has no build" is routine —
    /// loom ships no aarch64-apple-darwin. "This platform was built and
    /// published but nothing vouches for it" is a refusal.
    pub published: Vec<String>,
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
    /// What verifying the entry's DECLARED signed digest list established
    /// (REQ-SIGNEDSUMS-001). More than two states for the reason `attestation`
    /// has them: a list that was offered and did not verify is not a list that
    /// was never offered.
    pub pgp_sums: PgpSumsProbe,
}

/// What was observed about an entry's declared PGP-signed digest list.
///
/// `Verified` is the only variant that carries digests, and it is only ever
/// built from [`crate::pgpsums::VerifiedList`]: there is no way to hold the
/// entries of a list whose signature did not verify (clause 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PgpSumsProbe {
    /// The entry declares no `pgp-sums`.
    #[default]
    NotDeclared,
    /// The entry declares one and nobody looked, because an earlier rung
    /// decides first. Reaching the rung in this state is a caller ordering
    /// error and fails closed.
    NotProbed,
    /// The signature verified. The digests come from the verified list.
    ///
    /// The payload has private fields and one constructor,
    /// [`PgpSumsProbe::from_verified`], which takes a
    /// [`crate::pgpsums::VerifiedList`]: no code outside this module can hold
    /// digests that did not come out of a verification (clause 5).
    Verified(VerifiedPgpSums),
    /// The entry declares a list and it could not be fetched, read, or
    /// verified. Never a fall-through.
    Rejected(String),
}

/// What a verified signed digest list established. Fields are private; the
/// only way to make one is [`PgpSumsProbe::from_verified`].
///
/// ```compile_fail
/// use varve_producer::ingest::{PgpSumsProbe, VerifiedPgpSums};
/// let _ = PgpSumsProbe::Verified(VerifiedPgpSums {
///     signer: String::new(),
///     asserts: String::new(),
///     sums: Default::default(),
/// });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPgpSums {
    signer: String,
    asserts: String,
    signing_key: String,
    sums: crate::sums::Sums,
}

impl VerifiedPgpSums {
    /// The verified list's digests, keyed by asset name.
    pub fn sums(&self) -> &crate::sums::Sums {
        &self.sums
    }
}

impl PgpSumsProbe {
    /// The ONLY constructor of the verified state: a list that passed
    /// [`crate::pgpsums::verify_digest_list`], and the release it was bound to.
    pub fn from_verified(
        verified: crate::pgpsums::VerifiedList,
        bound: &crate::pgpsums::BoundRelease<'_>,
    ) -> PgpSumsProbe {
        let (vouched, sums) = verified.into_parts();
        let signing = if vouched.signing_fingerprint == vouched.primary_fingerprint {
            String::new()
        } else {
            format!(", signing subkey {}", vouched.signing_fingerprint)
        };
        PgpSumsProbe::Verified(VerifiedPgpSums {
            signer: vouched.signer_annotation(),
            asserts: format!(
                "the publisher holding OpenPGP key {} signed the digest list for release {} \
                 (version {}) naming these bytes (binary signature, SHA-256 or \
                 stronger{signing}); this says who published the digests, not that they \
                 are trustworthy",
                vouched.primary_fingerprint, bound.release, bound.version
            ),
            signing_key: vouched.signing_fingerprint.clone(),
            sums,
        })
    }
}

/// Can the `pgp-sums` rung be reached for this probe? Only when neither
/// cosign-sums nor build-provenance decides first: each of those returns
/// (accepted OR failed) before the ladder gets here, so verifying the signed
/// list when one of them applies would be a download that cannot matter.
///
/// Coupled to [`rung_cosign_sums`] and [`rung_build_provenance`]: it must say
/// "reachable" exactly when both return `NotOffered`.
pub fn pgp_rung_is_reachable(probe: &ReleaseProbe) -> bool {
    !(probe.has_sums && probe.has_cosign_bundle)
        && probe.attestation == AttestationProbe::NotAttested
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
    /// WHO established the proof — `None` when the answer is "nobody".
    ///
    /// An `Option`, not an empty string, because this field is signed into the
    /// layer and a deposit REFUSES an unverified payload that names a signer.
    /// While "nobody" was spelled `""`, staging wrapped it in `Some("")` and
    /// the realm's own deposit rejected the layer it had just built: nothing
    /// vouched for the bytes, and the manifest said somebody had and declined
    /// to give a name. The empty string was the whole defect; the type now
    /// cannot express it.
    pub signer: Option<String>,
    pub asserts: String,
    /// The key that actually produced the signature, where that is a different
    /// fact from `signer`: for `pgp-sums`, the (sub)key under the certificate
    /// the signer names. `None` for every mechanism with no such split.
    pub signing_key: Option<String>,
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
pub fn rung_cosign_sums(forge: &Forge, repo: &str, release: &str, probe: &ReleaseProbe) -> Rung {
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
            // The identity the probe enforced (`Forge::identity_regexp`), not
            // the repository it lives in.
            let identity = forge.identity_pattern(repo, release);
            Rung::Accepted {
                signer: identity.clone(),
                asserts: format!(
                    "SHA256SUMS.txt signed by the workflow identity {identity}, run in {repo}, \
                     via {}; this payload's recorded asset digest is transcribed \
                     from it",
                    forge.oidc_issuer
                ),
            }
        }
    }
}

/// What a build-provenance record says about the statements that vouched: for
/// each distinct (signer, ref, commit) the actual `buildSignerURI`, the ref the
/// build ran from, and the commit, then the binding that was enforced. Used for
/// the probe's first statement and, once the assets are covered, for the
/// statements that actually vouched for them.
pub fn provenance_asserts(builds: &[(&str, &str, &str)], version: &str) -> String {
    let built: Vec<String> = builds
        .iter()
        .map(|(signer, source_ref, commit)| {
            let mut t = format!("built by {signer}");
            if !source_ref.is_empty() {
                t.push_str(&format!(" from ref {source_ref}"));
            }
            t.push_str(&format!(" at source commit {commit}"));
            t
        })
        .collect();
    format!(
        "{}; this payload's recorded asset digest is a subject of that attestation; bound to \
         release {version} by asset name: each asset is vouched for only by the attestation \
         subject carrying its own name and digest, and the attestation's source ref is not \
         pinned (a pull-request build is refused)",
        built.join("; ")
    )
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

/// Rung 3 — a digest list somebody signed with OpenPGP, verified against the
/// certificate the operator pinned.
///
/// `Failed` for every way a DECLARED list can be unusable. The entry said this
/// release carries a signed list; a list that is missing, unreadable or signed
/// by the wrong key is evidence of a problem, and continuing to the unsigned
/// rung would turn a detected forgery into a quiet downgrade.
pub fn rung_pgp_sums(probe: &ReleaseProbe) -> Rung {
    match &probe.pgp_sums {
        PgpSumsProbe::NotDeclared => Rung::NotOffered,
        PgpSumsProbe::NotProbed => Rung::Failed(
            "this release's signed digest list was never probed, so the pgp-sums rung \
             cannot be decided; reaching it in this state is an ordering error in the \
             caller, not an absent list"
                .into(),
        ),
        PgpSumsProbe::Rejected(detail) => Rung::Failed(detail.clone()),
        PgpSumsProbe::Verified(v) => Rung::Accepted {
            signer: v.signer.clone(),
            asserts: v.asserts.clone(),
        },
    }
}

/// Rung 4 — a digest manifest the upstream publishes and nobody signed.
///
/// `manifest_asset` is the asset that carries the digests; upstreams do not
/// agree on a name (`sha256.sum` for zephyrproject-rtos/sdk-ng), so the realm
/// states it rather than varve guessing. Guessing would be the worse failure:
/// a file that is not the digest manifest, parsed as one, vouches for nothing
/// while looking like it vouches.
pub fn rung_upstream_sums(repo: &str, manifest_asset: Option<&str>, probe: &ReleaseProbe) -> Rung {
    let Some(asset) = manifest_asset else {
        return Rung::NotOffered;
    };
    if !probe.published.iter().any(|n| n == asset) {
        // The realm says this release carries a digest manifest and it does
        // not. That is a statement about the release that turned out false,
        // not an absent mechanism — continuing to the unverified rung would
        // silently downgrade a realm that asked for more.
        return Rung::Failed(format!(
            "the manifest names {asset:?} as this release's digest list, and \
             {repo} does not publish it"
        ));
    }
    Rung::Accepted {
        signer: format!("{repo} (unsigned)"),
        asserts: format!(
            "this payload's digest is transcribed from {asset}, a digest list \
             {repo} publishes beside the assets and DOES NOT SIGN. It \
             establishes that the bytes are the bytes that list names — which \
             catches a corrupted or truncated download — and nothing about who \
             produced them: the same host serves the list and the bytes, so \
             anyone able to replace both is unconstrained by it. Not a \
             signature, and not to be counted as one"
        ),
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

/// Every opt-in in force: the manifest's, plus the environment's.
///
/// THE one answer to "is this repository ingested without proof, and why".
/// `plan` read the reasons from the MANIFEST and printed "opt-in recorded";
/// `deposit` read only `UNVERIFIED_INGEST` from the environment and refused —
/// so a `unverified-reason` in layer.toml parsed, displayed, and was ignored
/// at the one moment it decides anything. A realm that wrote it watched its
/// deposit fail with a message telling it to set an environment variable
/// instead, which is the field being inert in the only place it matters.
///
/// The manifest wins a conflict: it is the realm's committed, reviewed record,
/// while the environment is ambient and unreviewable. The environment can still
/// add a repository the manifest does not mention, which is what the legacy
/// shell path and one-off recoveries use.
pub fn optins_in_force(
    manifest_reasons: impl IntoIterator<Item = (String, String)>,
    env_raw: &str,
) -> BTreeMap<String, String> {
    let mut out = parse_optins(env_raw);
    for (repo, reason) in manifest_reasons {
        out.insert(repo, reason);
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
    upstream_sums: Option<&str>,
) -> Result<Accepted, IngestError> {
    match rung_cosign_sums(forge, repo, version, probe) {
        Rung::Accepted { signer, asserts } => {
            return Ok(Accepted {
                mechanism: Mechanism::CosignSums,
                signer: Some(signer),
                // The probe pinned the certificate identity to this tag
                // (`Forge::identity_regexp`); the record says so.
                asserts: format!(
                    "{asserts}; bound to release {version}: the signing workflow's identity \
                     was required to be refs/tags/{version}"
                ),
                signing_key: None,
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
        Rung::Accepted { signer, .. } => {
            let commit = match &probe.attestation {
                AttestationProbe::Verified { commit, .. } => commit.as_str(),
                _ => "",
            };
            return Ok(Accepted {
                mechanism: Mechanism::BuildProvenance,
                signer: Some(signer.clone()),
                // No ref is pinned (see `gh::attestation_verify_argv`): the
                // binding is the subject's name, enforced when the proof is
                // spent. `verify_release` replaces this with the statements
                // that vouched for the assets.
                asserts: provenance_asserts(&[(signer.as_str(), "", commit)], version),
                signing_key: None,
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

    // Rung 3 — a digest list somebody signed, against a key the operator
    // pinned. A verification failure is fatal here and never reaches the
    // unsigned list below, which would accept the same bytes with no
    // signature at all.
    match rung_pgp_sums(probe) {
        Rung::Accepted { signer, asserts } => {
            // Recorded as its own fact whenever this rung vouched.
            let signing_key = match &probe.pgp_sums {
                PgpSumsProbe::Verified(v) => Some(v.signing_key.clone()),
                _ => None,
            };
            return Ok(Accepted {
                mechanism: Mechanism::PgpSums,
                signer: Some(signer),
                asserts,
                signing_key,
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

    // Rung 4 — an unsigned upstream digest list. Below every signature and
    // above nothing, which is exactly where it belongs: it catches the
    // corrupted 90 MB download and stops nobody who can replace the list and
    // the bytes together.
    match rung_upstream_sums(repo, upstream_sums, probe) {
        Rung::Accepted { signer, asserts } => {
            return Ok(Accepted {
                mechanism: Mechanism::UpstreamSums,
                signer: Some(signer),
                // Nothing signed this list, so nothing proves which release
                // it belongs to. The only binding is that every asset name
                // must carry the release (checked at plan time and again at
                // ingestion), which is a name heuristic.
                asserts: format!(
                    "{asserts}; release {version}: bound only by the asset name carrying it \
                     (a name heuristic, not a proof)"
                ),
                signing_key: None,
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
            signer: None,
            asserts: format!(
                "NOTHING vouched for these bytes — ingested on an explicit \
                 operator opt-in. Recorded reason: {reason}"
            ),
            signing_key: None,
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
            published: Vec::new(),
            has_sums: true,
            has_cosign_bundle: true,
            cosign: Some(Ok(())),
            attestation: AttestationProbe::NotAttested,
            pgp_sums: PgpSumsProbe::NotDeclared,
        }
    }

    fn no_optins() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_cosign_signed_sums_file_is_the_first_rung() {
        let f = Forge::github_com();
        let a = choose(
            &f,
            "pulseengine/rivet",
            "v0.34.0",
            &sums_ok(),
            &no_optins(),
            None,
        )
        .expect("accepts");
        assert_eq!(a.mechanism, Mechanism::CosignSums);
        assert_eq!(
            a.signer.as_deref(),
            Some("https://github.com/pulseengine/rivet/.github/workflows/[^@]+@refs/tags/v0.34.0"),
            "the record names the identity pattern that was enforced, not a prefix"
        );
    }

    /// The text each rung writes into the signed record about its release
    /// binding, and nothing more: this checks what `choose` WRITES, and passes
    /// whether or not the probe enforced anything. That the cosign identity is
    /// pinned to the tag is proved where the command is built and run
    /// (`source::tests::the_recorded_cosign_identity_is_the_regexp_cosign_enforced`
    /// and `cosign_sums_signed_for_one_release_are_refused_for_another`);
    /// the attestation binding in `build_provenance_for_one_release_is_refused_for_another`.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn every_rung_states_the_binding_it_relies_on_in_its_record() {
        let f = Forge::github_com();
        let cosign = choose(&f, "o/r", "v3.1.0", &sums_ok(), &no_optins(), None).expect("accepts");
        assert!(
            cosign.asserts.contains("refs/tags/v3.1.0"),
            "{}",
            cosign.asserts
        );
        let attested = ReleaseProbe {
            published: vec!["a.tar.gz".into()],
            attestation: AttestationProbe::Verified {
                signer: "s".into(),
                commit: "c".into(),
            },
            ..Default::default()
        };
        let prov = choose(&f, "o/r", "v3.1.0", &attested, &no_optins(), None).expect("accepts");
        assert!(prov.asserts.contains("by asset name"), "{}", prov.asserts);
        let unsigned = ReleaseProbe {
            published: vec!["sha256.sum".into()],
            attestation: AttestationProbe::NotAttested,
            ..Default::default()
        };
        let up = choose(
            &f,
            "o/r",
            "v3.1.0",
            &unsigned,
            &no_optins(),
            Some("sha256.sum"),
        )
        .expect("accepts");
        assert!(up.asserts.contains("v3.1.0"), "{}", up.asserts);
        assert!(
            up.asserts.contains("asset name"),
            "the weaker binding is said to be the name only: {}",
            up.asserts
        );
    }

    /// A supply-chain tool that only works against one vendor's public host is
    /// not one an enterprise can adopt. The recorded signer and the asserted
    /// claim must both follow the instance, or a GHES layer would carry
    /// provenance naming a host its bytes never came from.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_enterprise_instance_records_its_own_identity_and_issuer() {
        let f = Forge::enterprise("ghe.example.com");
        let a = choose(&f, "acme/tool", "v1.0.0", &sums_ok(), &no_optins(), None).expect("accepts");
        assert_eq!(a.mechanism, Mechanism::CosignSums);
        assert_eq!(
            a.signer.as_deref(),
            Some("https://ghe.example.com/acme/tool/.github/workflows/[^@]+@refs/tags/v1.0.0")
        );
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
        let signer = a.signer.clone().expect("a verified rung names who");
        assert!(!signer.contains("github.com"), "{signer}");
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
            None,
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
            None,
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
        let err = choose(
            &Forge::github_com(),
            "acme/tool",
            "v1.0.0",
            &probe,
            &optins,
            None,
        )
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
            None,
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
            rung_cosign_sums(&Forge::github_com(), "r", "v1", &probe),
            Rung::Failed(_)
        ));
    }

    /// Only BOTH assets constitute the offer: a sums file with no bundle is
    /// unsigned, and must not be accepted as though it were.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_sums_file_without_a_bundle_is_not_offered() {
        let probe = ReleaseProbe {
            published: Vec::new(),
            has_sums: true,
            has_cosign_bundle: false,
            cosign: Some(Ok(())),
            attestation: AttestationProbe::NotAttested,
            pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
        };
        assert_eq!(
            rung_cosign_sums(&Forge::github_com(), "r", "v1", &probe),
            Rung::NotOffered
        );
        let err = choose(&Forge::github_com(), "r", "v1", &probe, &no_optins(), None)
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
            None,
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
            None,
        )
        .expect("accepts");
        assert_eq!(a.mechanism, Mechanism::Unverified);
        assert_eq!(
            a.signer, None,
            "nobody vouched, so the payload must name nobody — an empty signer is \
             signed into the layer as an identity and the deposit refuses it"
        );
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
                None,
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
            None,
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
            None,
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
            None,
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

#[cfg(test)]
mod upstream_sums_tests {
    use super::*;

    fn probe_with(published: &[&str]) -> ReleaseProbe {
        ReleaseProbe {
            published: published.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// zephyrproject-rtos/sdk-ng publishes a `sha256.sum` covering 160 assets
    /// and signs nothing. Treating that as `unverified` throws away a real
    /// property — it catches the truncated 90 MB download, which is the
    /// failure a transfer that size actually has.
    // rivet: verifies REQ-UPSTREAMSUMS-001
    #[test]
    fn an_unsigned_upstream_digest_list_is_its_own_mechanism() {
        let p = probe_with(&[
            "sha256.sum",
            "toolchain_gnu_linux-x86_64_arm-zephyr-eabi.tar.xz",
        ]);
        match rung_upstream_sums("zephyrproject-rtos/sdk-ng", Some("sha256.sum"), &p) {
            Rung::Accepted { signer, asserts } => {
                assert!(signer.contains("unsigned"), "{signer}");
                assert!(asserts.contains("DOES NOT SIGN"), "{asserts}");
                assert!(asserts.contains("Not a signature"), "{asserts}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Clause 1 and 4. The name must not be mistakable for a signature by
    /// someone skimning a manifest, and it must not COUNT as one.
    // rivet: verifies REQ-UPSTREAMSUMS-001
    #[test]
    fn it_is_named_and_classified_as_not_a_signature() {
        assert_eq!(Mechanism::UpstreamSums.as_str(), "upstream-sums");
        assert!(!Mechanism::UpstreamSums.as_str().contains("sign"));
        assert!(!Mechanism::UpstreamSums.is_signed());
        assert!(!Mechanism::Unverified.is_signed());
        assert!(Mechanism::CosignSums.is_signed());
        assert!(Mechanism::BuildProvenance.is_signed());
    }

    /// A realm that says a release carries a digest list, when it does not,
    /// has made a statement that turned out false. Continuing to the
    /// unverified rung would silently downgrade a realm that asked for more.
    // rivet: verifies REQ-UPSTREAMSUMS-001
    #[test]
    fn a_named_digest_list_that_the_release_lacks_aborts_rather_than_downgrades() {
        let p = probe_with(&["toolchain.tar.xz"]);
        match rung_upstream_sums("zephyrproject-rtos/sdk-ng", Some("sha256.sum"), &p) {
            Rung::Failed(d) => assert!(d.contains("does not publish it"), "{d}"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Clause 5. An upstream that publishes NOTHING stays `unverified` with an
    /// operator's reason — inventing a stronger word for nothing would be the
    /// same lie in the other direction. wasi-sdk is this case today.
    // rivet: verifies REQ-UPSTREAMSUMS-001
    #[test]
    fn an_upstream_that_publishes_nothing_is_not_promoted_to_this_rung() {
        let p = probe_with(&["wasi-sdk-34.0-x86_64-linux.tar.gz"]);
        assert_eq!(
            rung_upstream_sums("WebAssembly/wasi-sdk", None, &p),
            Rung::NotOffered,
            "no digest list named means this rung is not offered"
        );
        // …and the ladder then lands on unverified, which needs a reason.
        let mut optins = BTreeMap::new();
        optins.insert(
            "WebAssembly/wasi-sdk".to_string(),
            "no upstream proof of any kind".to_string(),
        );
        let a = choose(
            &Forge::github_com(),
            "WebAssembly/wasi-sdk",
            "wasi-sdk-34",
            &p,
            &optins,
            None,
        )
        .expect("an opt-in with a reason is accepted");
        assert_eq!(a.mechanism, Mechanism::Unverified);
    }

    /// The ladder's order: a signature outranks an unsigned list, always.
    // rivet: verifies REQ-UPSTREAMSUMS-001
    #[test]
    fn a_signature_is_preferred_over_an_unsigned_list_when_both_exist() {
        let p = ReleaseProbe {
            published: vec![
                "SHA256SUMS.txt".into(),
                "SHA256SUMS.txt.cosign.bundle".into(),
                "sha256.sum".into(),
            ],
            has_sums: true,
            has_cosign_bundle: true,
            cosign: Some(Ok(())),
            ..Default::default()
        };
        let a = choose(
            &Forge::github_com(),
            "pulseengine/rivet",
            "v0.35.0",
            &p,
            &BTreeMap::new(),
            Some("sha256.sum"),
        )
        .expect("accepts");
        assert_eq!(a.mechanism, Mechanism::CosignSums, "a signature must win");
    }

    /// The manifest's reasons must reach the deposit, or the field is inert
    /// exactly where it decides something.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_manifest_reason_is_an_optin_at_deposit_time() {
        let from_manifest = [(
            "bytecodealliance/wac".to_string(),
            "no provenance upstream; removed when they add attest-build-provenance".to_string(),
        )];
        let in_force = optins_in_force(from_manifest, "");
        assert!(
            in_force.contains_key("bytecodealliance/wac"),
            "a layer.toml unverified-reason did not become an opt-in — the deposit would \
             refuse a realm that has already stated why"
        );
    }

    /// The environment still works, for the legacy path and one-off recoveries.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_environment_can_still_name_a_repository_the_manifest_does_not() {
        let in_force = optins_in_force([], "acme/tool=vendor ships no sums; fork planned");
        assert_eq!(
            in_force.get("acme/tool").map(String::as_str),
            Some("vendor ships no sums; fork planned")
        );
    }

    /// Both name it: the committed, reviewed record wins over ambient state.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_manifest_wins_a_conflict_with_the_environment() {
        let in_force = optins_in_force(
            [("acme/tool".to_string(), "the manifest's reason".to_string())],
            "acme/tool=an environment variable nobody reviewed",
        );
        assert_eq!(
            in_force.get("acme/tool").map(String::as_str),
            Some("the manifest's reason"),
            "an unreviewable environment variable overrode the realm's committed record"
        );
    }
}

#[cfg(test)]
mod pgp_sums_tests {
    use super::*;
    use crate::sums::Sums;

    fn verified() -> PgpSumsProbe {
        PgpSumsProbe::Verified(VerifiedPgpSums {
            signer: "openpgp:abcd (Up Stream <up@example.invalid>)".into(),
            asserts: "the publisher holding OpenPGP key abcd signed the digest list".into(),
            sums: Sums::default(),
            signing_key: "abcd".into(),
        })
    }

    fn probe(pgp: PgpSumsProbe) -> ReleaseProbe {
        ReleaseProbe {
            published: vec!["SHA256SUMS".into(), "SHA256SUMS.asc".into()],
            pgp_sums: pgp,
            ..Default::default()
        }
    }

    fn pick(p: &ReleaseProbe, upstream: Option<&str>) -> Result<Accepted, IngestError> {
        choose(
            &Forge::github_com(),
            "up/stream",
            "v1",
            p,
            &BTreeMap::new(),
            upstream,
        )
    }

    /// The mechanism is named, counts as a signature, and is recorded under the
    /// spelling core reads back.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn pgp_sums_is_a_signed_mechanism_with_its_own_name() {
        assert_eq!(Mechanism::PgpSums.as_str(), "pgp-sums");
        assert!(Mechanism::PgpSums.is_signed());
        assert_eq!(
            Mechanism::PgpSums
                .as_str()
                .parse::<varve_core::IngestProof>(),
            Ok(varve_core::IngestProof::PgpSums)
        );
    }

    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_verified_signed_list_is_accepted_under_its_own_mechanism() {
        let a = pick(&probe(verified()), None).expect("accepts");
        assert_eq!(a.mechanism, Mechanism::PgpSums);
        assert_eq!(
            a.signer.as_deref(),
            Some("openpgp:abcd (Up Stream <up@example.invalid>)")
        );
        assert!(a.asserts.contains("OpenPGP key abcd"), "{}", a.asserts);
    }

    /// A rejected signature is a refusal. It must NOT land on the unsigned
    /// list the entry may also name, which would accept the same bytes with no
    /// signature at all.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_rejected_signature_aborts_and_never_falls_to_upstream_sums() {
        let p = probe(PgpSumsProbe::Rejected("no signature verifies".into()));
        for upstream in [None, Some("SHA256SUMS")] {
            let err = pick(&p, upstream).expect_err("must refuse");
            assert!(
                matches!(&err, IngestError::ProofRejected { detail, .. } if detail == "no signature verifies"),
                "{err:?}"
            );
        }
    }

    /// Declared and never probed is an ordering error, which fails closed.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_declared_but_never_probed_list_fails_closed() {
        let err = pick(&probe(PgpSumsProbe::NotProbed), Some("SHA256SUMS")).expect_err("refuses");
        assert!(matches!(err, IngestError::ProofRejected { .. }), "{err:?}");
    }

    /// Not declared: the rung is not offered and the ladder continues.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_entry_that_declares_nothing_is_unaffected() {
        assert_eq!(
            rung_pgp_sums(&probe(PgpSumsProbe::NotDeclared)),
            Rung::NotOffered
        );
        let a = pick(&probe(PgpSumsProbe::NotDeclared), Some("SHA256SUMS")).expect("accepts");
        assert_eq!(a.mechanism, Mechanism::UpstreamSums);
    }

    /// Ladder order: cosign and build provenance both outrank the signed list,
    /// and the signed list outranks the unsigned one.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_signed_list_sits_below_cosign_and_provenance_and_above_the_unsigned_list() {
        let mut p = probe(verified());
        p.has_sums = true;
        p.has_cosign_bundle = true;
        p.cosign = Some(Ok(()));
        let a = pick(&p, Some("SHA256SUMS")).unwrap();
        assert_eq!(a.mechanism, Mechanism::CosignSums);

        let mut p = probe(verified());
        p.attestation = AttestationProbe::Verified {
            signer: "wf".into(),
            commit: "c0ffee".into(),
        };
        let a = pick(&p, Some("SHA256SUMS")).unwrap();
        assert_eq!(a.mechanism, Mechanism::BuildProvenance);

        let a = pick(&probe(verified()), Some("SHA256SUMS")).unwrap();
        assert_eq!(a.mechanism, Mechanism::PgpSums);
    }

    /// The reachability test must agree with the rungs it summarises.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_pgp_rung_is_reachable_exactly_when_both_earlier_rungs_are_not_offered() {
        let forge = Forge::github_com();
        let plain = probe(PgpSumsProbe::NotProbed);
        assert!(pgp_rung_is_reachable(&plain));
        assert_eq!(
            rung_cosign_sums(&forge, "up/stream", "v1", &plain),
            Rung::NotOffered
        );
        assert_eq!(rung_build_provenance(&plain), Rung::NotOffered);

        let mut sums_only = plain.clone();
        sums_only.has_sums = true;
        assert!(pgp_rung_is_reachable(&sums_only));
        assert_eq!(
            rung_cosign_sums(&forge, "up/stream", "v1", &sums_only),
            Rung::NotOffered
        );
        let mut bundle_only = plain.clone();
        bundle_only.has_cosign_bundle = true;
        assert!(pgp_rung_is_reachable(&bundle_only));

        let mut cosign = plain.clone();
        cosign.has_sums = true;
        cosign.has_cosign_bundle = true;
        assert!(!pgp_rung_is_reachable(&cosign));

        for attestation in [
            AttestationProbe::Verified {
                signer: "s".into(),
                commit: "c".into(),
            },
            AttestationProbe::Rejected("bad".into()),
            AttestationProbe::NotProbed,
        ] {
            let mut p = plain.clone();
            p.attestation = attestation;
            assert!(!pgp_rung_is_reachable(&p), "{:?}", p.attestation);
            assert_ne!(rung_build_provenance(&p), Rung::NotOffered);
        }
    }
}
