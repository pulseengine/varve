//! Walking a plan: verify each release once, admit each payload against what
//! that verification actually established, and carry forward what has not
//! changed (REQ-PRODUCER-002, REQ-CARRYFORWARD-001).
//!
//! ## The claim this module has to make true
//!
//! When the ladder accepts a release it prints an `asserts` string, and that
//! string is what ends up in the deposit spec as the reason a payload is
//! trusted:
//!
//! > SHA256SUMS.txt signed by an identity under … ; **this payload's recorded
//! > asset digest is transcribed from it**
//!
//! A signature over a sums file proves the file came from that identity. It
//! proves nothing at all about the bytes sitting in the staging directory
//! unless somebody compares them. Verifying the sums and then recording a
//! digest computed from the downloaded bytes — without checking one against
//! the other — produces a spec whose every field is individually true and
//! whose sentence is a lie, and it is the exact failure this whole crate
//! exists to make impossible.
//!
//! So [`admit`] is not a formality between the download and the staging. It is
//! the step where the proof is spent. A payload whose bytes are not named by
//! the verified sums cannot be admitted *because the file was signed*: the
//! signature covers a list, and being absent from that list is being outside
//! the proof.
//!
//! ## Why the release is verified once, before any payload
//!
//! The shell verified per asset, so a layer taking four payloads from one repo
//! ran cosign four times over the same file, and re-downloaded it each time —
//! which is what made `--clobber` look necessary and, once added, silently
//! overwrote a *different* repo's sums file. Grouping by release makes the
//! proof a property of the release, obtained once, spent many times.

use crate::carryforward::{self, Decision, PreviousEntry};
use crate::forge::Forge;
use crate::ingest::{self, Accepted, IngestError, Mechanism, PgpSumsProbe, ReleaseProbe};
use crate::plan::{PayloadPlan, PgpSumsPlan};
use crate::sums::Sums;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// What a verified release established, and what it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub accepted: Accepted,
    /// Every asset the release publishes, whether or not the proof covers it.
    pub published: Vec<String>,
    /// The digests the proof covers. `None` for an `unverified` opt-in, where
    /// nothing vouches for anything and saying otherwise would be the lie.
    pub sums: Option<Sums>,
}

/// Everything this module needs from the outside world. The real
/// implementation runs `gh` and `cosign`; tests supply fixtures, so every
/// ordering and refusal property below is decided without a network.
pub trait Source {
    fn probe(&self, forge: &Forge, repo: &str, version: &str) -> Result<ReleaseProbe, RunError>;
    /// The text of a release's `SHA256SUMS.txt`, called only after cosign
    /// accepted it.
    fn sums_text(&self, repo: &str, version: &str) -> Result<String, RunError>;
    /// The in-toto statement `gh attestation verify` accepted, discovered by
    /// probing ONE asset of the release.
    fn attestation_json(&self, repo: &str, version: &str) -> Result<String, RunError>;
    /// The in-toto statement for ONE named asset, verified against that
    /// asset's own bytes.
    ///
    /// Needed because the two upstream publishing styles are not
    /// distinguishable in advance. A publisher that batches its release into
    /// one attestation yields a statement naming every asset, and the probe's
    /// copy answers for all of them. A publisher that calls
    /// `attest-build-provenance` per file yields a statement naming exactly
    /// one, and every other asset has a proof of its own that the probe never
    /// fetched (varve#245).
    fn attestation_json_for(
        &self,
        repo: &str,
        version: &str,
        asset: &str,
    ) -> Result<String, RunError>;
    fn asset_bytes(&self, repo: &str, version: &str, asset: &str) -> Result<Vec<u8>, RunError>;
    /// The repository's DECLARED SPDX license (REQ-SBOMFIELDS-001 clause 5),
    /// `GET /repos/{repo}`. `None` when GitHub itself has nothing to say —
    /// never a default this assembler invents.
    fn repo_license(&self, repo: &str) -> Result<Option<String>, RunError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    Ingest(IngestError),
    Carry(carryforward::CarryError),
    /// The bytes we hold are not the bytes the proof covers.
    DigestMismatch {
        repo: String,
        asset: String,
        expected: String,
        actual: String,
    },
    /// The proof is a signature over a LIST. An asset absent from that list is
    /// outside the proof, however well-signed the list is.
    NotCoveredByProof {
        repo: String,
        asset: String,
        mechanism: &'static str,
    },
    /// A tool matched no asset on ANY platform. Per-platform absence is
    /// routine; absence everywhere means the asset template no longer
    /// describes the release, and the layer would silently ship without a tool
    /// it claims to carry.
    NothingMatched {
        name: String,
        repo: String,
        version: String,
        tried: Vec<String>,
    },
    /// Payloads of one (repo, release) are verified once, with ONE
    /// declaration. Plans that disagree would have one member's declared
    /// verification silently not performed.
    GroupDisagrees {
        repo: String,
        release: String,
        field: &'static str,
        tools: Vec<String>,
    },
    /// A planned asset name does not contain the release it claims to belong
    /// to, so a signed list for another release could cover it.
    AssetNotBoundToRelease {
        tool: String,
        asset: String,
        version: String,
        release: String,
    },
    /// Something in the outside world failed.
    Io {
        context: String,
        detail: String,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Ingest(e) => write!(f, "{e}"),
            RunError::Carry(e) => write!(f, "{e}"),
            RunError::DigestMismatch {
                repo,
                asset,
                expected,
                actual,
            } => write!(
                f,
                "{repo}: the bytes downloaded for {asset} are not the bytes the \
                 proof covers.\n  proof says: {expected}\n  we hold:    {actual}\n\
                 Refusing. This is either a corrupted download or a substituted \
                 artifact, and this assembler cannot tell which — which is why \
                 it does not continue with either."
            ),
            RunError::NotCoveredByProof {
                repo,
                asset,
                mechanism,
            } => write!(
                f,
                "{repo}: {asset} is not named by the {mechanism} proof.\n\
                 The proof is a signature over a list of digests; an asset that \
                 is not in the list is not covered by it, however valid the \
                 signature over the list is. Refusing to record it as proven."
            ),
            RunError::AssetNotBoundToRelease {
                tool,
                asset,
                version,
                release,
            } => write!(
                f,
                "{tool}: the asset {asset:?} contains neither the declared version {version:?} \
                 nor the release {release:?}, so a proof for a different release (a signed \
                 list, an attestation, a certificate) could cover it. Refusing: a proof is \
                 bound to a release through the names it covers. An entry that cannot name \
                 its release can state why with unbound-release-reason, which is signed into \
                 the layer."
            ),
            RunError::GroupDisagrees {
                repo,
                release,
                field,
                tools,
            } => write!(
                f,
                "the entries {} all ingest from {repo} {release} but disagree on `{field}`. \
                 A release is verified once, with one declaration, so one entry's \
                 verification would silently not be performed. Give them the same `{field}`, \
                 or split them across releases.",
                tools.join(", ")
            ),
            RunError::NothingMatched {
                name,
                repo,
                version,
                tried,
            } => write!(
                f,
                "{name}: no asset of {repo} {version} matched on any platform.\n\
                 tried: {}\n\
                 A platform with no build is routine and is skipped with a \
                 notice. Matching NOTHING means the asset naming has changed or \
                 the entry is wrong, and shipping the layer anyway would omit a \
                 tool it claims to carry.",
                tried.join(", ")
            ),
            RunError::Io { context, detail } => write!(f, "{context}: {detail}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<IngestError> for RunError {
    fn from(e: IngestError) -> Self {
        RunError::Ingest(e)
    }
}

/// Hex sha256 of some bytes, spelled the way a sums file spells it.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Spend the proof: the digest this payload will be recorded with, or a
/// refusal.
///
/// Returns the digest **from the proof**, not the one computed from the bytes,
/// even though they are equal on the success path. They are equal *because
/// this function checked*, and returning the proof's copy keeps that
/// provenance visible at the call site.
pub fn admit(v: &Verified, repo: &str, asset: &str, bytes: &[u8]) -> Result<String, RunError> {
    let actual = sha256_hex(bytes);
    let Some(sums) = &v.sums else {
        // An unverified opt-in. Nothing covers these bytes; the digest is
        // simply what we observed, and the spec says so in the same breath.
        return Ok(actual);
    };
    let expected = sums
        .digest_of(asset)
        .ok_or_else(|| RunError::NotCoveredByProof {
            repo: repo.to_string(),
            asset: asset.to_string(),
            mechanism: v.accepted.mechanism.as_str(),
        })?;
    if expected != actual {
        return Err(RunError::DigestMismatch {
            repo: repo.to_string(),
            asset: asset.to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(expected.to_string())
}

/// The release's CycloneDX SBOM, admitted through the release's proof, with
/// the license its `metadata.component` states (REQ-SBOMFIELDS-001).
///
/// The proof decides, exactly as for a payload: an SBOM the verified sums do
/// not name is not recorded (it is optional — a note, not a refusal); one
/// whose bytes disagree with the sums is a tampered file and REFUSES the run,
/// as `admit` does for a payload. Where nothing vouches for the release (an
/// unverified opt-in), nothing is recorded: there is no proof to spend.
pub fn release_sbom<S: Source>(
    src: &S,
    v: &Verified,
    repo: &str,
    version: &str,
) -> Result<Option<(SbomRef, Option<String>)>, RunError> {
    let Some(name) = select_release_sbom(&v.published, version) else {
        return Ok(None);
    };
    let Some(sums) = &v.sums else {
        eprintln!(
            "note: {repo} {version} publishes {name}, but nothing vouches for this release, \
             so no upstream SBOM is recorded"
        );
        return Ok(None);
    };
    if sums.digest_of(name).is_none() {
        eprintln!(
            "note: {repo} {version} publishes {name}, but the {} proof does not cover it, \
             so no upstream SBOM is recorded",
            v.accepted.mechanism.as_str()
        );
        return Ok(None);
    }
    let bytes = src.asset_bytes(repo, version, name)?;
    let sha256 = admit(v, repo, name, &bytes)?;
    Ok(Some((
        SbomRef {
            name: name.to_string(),
            sha256,
        },
        sbom_declared_license(&bytes),
    )))
}

/// The license an SBOM states for its own subject, if it states exactly one.
/// Several entries have no agreed reading (AND? OR? per file?), so they are
/// not collapsed into a guess.
pub fn sbom_declared_license(bytes: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let entries = doc.pointer("/metadata/component/licenses")?.as_array()?;
    let [only] = entries.as_slice() else {
        return None;
    };
    only.get("expression")
        .or_else(|| only.pointer("/license/id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "NOASSERTION")
        .map(str::to_string)
}

/// Fetch an entry's signed digest list and its detached signature, and verify
/// the one against the key the operator pinned (REQ-SIGNEDSUMS-001).
///
/// Every failure is `Rejected`, which the ladder turns into a refusal: the entry
/// declared a signed list, so a list that is not published, cannot be fetched,
/// or does not verify is a finding and never an absent mechanism.
fn probe_pgp_sums<S: Source>(
    src: &S,
    repo: &str,
    version: &str,
    spec: &PgpSumsPlan,
    key: &[u8],
    published: &[String],
) -> PgpSumsProbe {
    for asset in [&spec.list, &spec.signature] {
        if !published.contains(asset) {
            return PgpSumsProbe::Rejected(format!(
                "the manifest names {asset:?} as part of this release's signed digest list, \
                 and {repo} does not publish it"
            ));
        }
    }
    let fetch = |asset: &str| {
        src.asset_bytes(repo, version, asset)
            .map_err(|e| PgpSumsProbe::Rejected(format!("could not fetch {asset}: {e}")))
    };
    let (list, signature) = match (fetch(&spec.list), fetch(&spec.signature)) {
        (Ok(l), Ok(s)) => (l, s),
        (Err(rejected), _) | (_, Err(rejected)) => return rejected,
    };
    let bound = crate::pgpsums::BoundRelease {
        version: &spec.version,
        release: &spec.release,
    };
    match crate::pgpsums::verify_digest_list(spec.format, &list, &signature, key, &bound) {
        Err(e) => PgpSumsProbe::Rejected(format!(
            "{} does not verify against the pinned key {}: {e}",
            spec.list,
            spec.key_file.display()
        )),
        Ok(verified) => PgpSumsProbe::from_verified(verified, &bound),
    }
}

/// The digest lists an entry DECLARES for its release: what the producer's
/// input says the release carries, as opposed to what the release was observed
/// to offer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Declared<'a> {
    /// The asset carrying an UNSIGNED digest list (REQ-UPSTREAMSUMS-001).
    pub upstream_sums: Option<&'a str>,
    /// The signed digest list and the key pinned for it (REQ-SIGNEDSUMS-001).
    pub pgp_sums: Option<&'a PgpSumsPlan>,
}

/// Verify one release, once.
pub fn verify_release<S: Source>(
    src: &S,
    forge: &Forge,
    repo: &str,
    version: &str,
    optins: &BTreeMap<String, String>,
    declared: &Declared<'_>,
    // The assets this layer actually plans to ingest from the release.
    //
    // Needed because build provenance may arrive per asset, and the covered
    // set must be COMPLETE before any payload is touched: `run` reads it to
    // decide carry-forward and `admit` reads it again when the bytes land, so
    // topping it up lazily would fix one caller and leave the other refusing
    // (DD-037).
    wanted: &[String],
) -> Result<Verified, RunError> {
    // The pinned key is read BEFORE anything is fetched, and a file that is
    // missing or unreadable stops the run. Falling back to a weaker rung here
    // would make "the operator pinned a key" something a deleted file undoes.
    let pinned_key = match declared.pgp_sums {
        Some(spec) => Some(std::fs::read(&spec.key_file).map_err(|e| RunError::Io {
            context: format!(
                "{repo} {version}: reading pgp-key-file {}",
                spec.key_file.display()
            ),
            detail: e.to_string(),
        })?),
        None => None,
    };
    let mut probe = src.probe(forge, repo, version)?;
    // What the probe says about a signed list is not evidence: only THIS
    // function decides it, from the entry's own declaration.
    probe.pgp_sums = PgpSumsProbe::NotDeclared;
    if let (Some(spec), Some(key)) = (declared.pgp_sums, &pinned_key) {
        // Verified only when the ladder can reach it: when cosign or build
        // provenance decides first, the signed list is never consulted.
        probe.pgp_sums = if ingest::pgp_rung_is_reachable(&probe) {
            probe_pgp_sums(src, repo, version, spec, key, &probe.published)
        } else {
            PgpSumsProbe::NotProbed
        };
    }
    let accepted = ingest::choose(forge, repo, version, &probe, optins, declared.upstream_sums)?;
    let sums = match accepted.mechanism {
        Mechanism::CosignSums => {
            let text = src.sums_text(repo, version)?;
            Some(Sums::parse(&text).map_err(|e| RunError::Io {
                context: format!("{repo} {version}: reading the verified SHA256SUMS.txt"),
                detail: e.to_string(),
            })?)
        }
        // The digests come from the upstream's own list, fetched like any
        // other asset and NOT verified against anything — there is nothing to
        // verify it against, which is the whole point of the mechanism's name.
        // The bytes are still checked against it in `admit`, so a truncated
        // download still fails; what is absent is any claim about who made
        // them.
        Mechanism::UpstreamSums => {
            let asset = declared.upstream_sums.ok_or_else(|| RunError::Io {
                context: format!("{repo} {version}"),
                detail: "the upstream-sums mechanism was accepted without an                          asset naming the digest list — a caller ordering error"
                    .into(),
            })?;
            let bytes = src.asset_bytes(repo, version, asset)?;
            let text = String::from_utf8(bytes).map_err(|e| RunError::Io {
                context: format!("{repo} {version}: {asset}"),
                detail: format!("not valid UTF-8: {e}"),
            })?;
            Some(Sums::parse(&text).map_err(|e| RunError::Io {
                context: format!("{repo} {version}: reading {asset}"),
                detail: e.to_string(),
            })?)
        }
        // The digests of the list whose signature the probe verified. They are
        // read out of the probe's `Verified` state, the only place they exist.
        Mechanism::PgpSums => match &probe.pgp_sums {
            PgpSumsProbe::Verified(v) => Some(v.sums().clone()),
            _ => {
                return Err(RunError::Io {
                    context: format!("{repo} {version}"),
                    detail: "the pgp-sums mechanism was accepted without a verified digest \
                             list — a caller ordering error"
                        .into(),
                });
            }
        },
        Mechanism::BuildProvenance => {
            // The statement the probe already verified. An upstream that
            // batches its release names every asset here, and this is the
            // whole answer — one verification, as clause 3 requires.
            let json = src.attestation_json(repo, version)?;
            let mut covered = crate::attestation::parse(&json)
                .map_err(|e| RunError::Io {
                    context: format!("{repo} {version}: reading the verified attestation"),
                    detail: e.to_string(),
                })?
                .sums;

            // An upstream that calls `attest-build-provenance` per file names
            // only ONE asset there, and every other asset of the release has
            // a proof of its own that the probe never fetched. Refusing those
            // rejects bytes upstream fully attests (varve#245), so each
            // planned asset the probed statement does not name is verified
            // against its own bytes and its own statement.
            for asset in wanted {
                if covered.digest_of(asset).is_some() {
                    continue;
                }
                // Not published at all is "this platform has no build", which
                // is routine and is the caller's to report. Asking upstream
                // for an attestation over a file that does not exist would
                // turn it into an error.
                if !probe.published.is_empty() && !probe.published.contains(asset) {
                    continue;
                }
                let one = src.attestation_json_for(repo, version, asset)?;
                let parsed = crate::attestation::parse(&one).map_err(|e| RunError::Io {
                    context: format!("{repo} {version}: reading {asset}'s own attestation"),
                    detail: e.to_string(),
                })?;
                // Merged, not replaced: a statement that names a DIFFERENT
                // asset leaves this one uncovered, and it is then refused by
                // the same rule as any other unproven asset rather than
                // credited with its sibling's proof.
                covered.merge(&parsed.sums).map_err(|e| RunError::Io {
                    context: format!("{repo} {version}: {asset}"),
                    detail: e.to_string(),
                })?;
            }
            Some(covered)
        }
        // No proof was offered and an operator said to proceed anyway. There
        // is no list of covered digests because there is no list.
        Mechanism::Unverified => None,
    };
    Ok(Verified {
        accepted,
        published: probe.published,
        sums,
    })
}

/// What [`release_sbom`] established about a release's OWN upstream SBOM
/// (REQ-ADVISORYWATCH-001 clause 4b's fallback, when no layer annotation
/// records one).
///
/// Deliberately has NO error variant of its own: every way this can fail —
/// the release offers no proof at all, the release offers no SBOM, or the
/// SBOM exists but the proof does not cover it — is a FACT about that one
/// release, not a reason to stop checking every other payload the run is
/// looking at. The caller decides what "unchecked" means for its report;
/// this function only ever decides what is true of the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseSbomOutcome {
    /// The release publishes exactly one `.cdx.json` candidate (or exactly
    /// one naming the payload's own version among several), and the
    /// release's own verified proof covers it with a matching digest.
    Found(Vec<u8>),
    /// The release publishes no `.cdx.json` asset at all.
    NoSbom,
    /// More than one `.cdx.json` asset is published, and none of them
    /// uniquely names the payload's own version — picking one anyway would
    /// be a GUESS, and checking the wrong SBOM silently reports nothing for
    /// the payload whose embedded components actually needed checking.
    Ambiguous,
    /// A `.cdx.json` asset exists, but the release's verified proof does
    /// not cover it — absent from the list, or present with a digest that
    /// does not match the bytes actually downloaded. Either way, nothing
    /// proves these are the bytes upstream published, so they are not used.
    NotCovered,
    /// The release itself could not be verified at all (no proof offered,
    /// a rejected signature, an unreadable sums file, …) — carries what
    /// `verify_release` or the asset fetch said, verbatim.
    VerifyFailed(String),
}

/// What [`classify_release_sbom`] decided a release's published assets name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SbomSelection {
    One(String),
    None,
    Ambiguous,
}

/// Picks the ONE `.cdx.json` asset a release's SBOM fallback should use —
/// the same rule the deposit pipeline's own asset selection follows for an
/// otherwise-ambiguous match: a single unqualified candidate wins outright;
/// with more than one, only a candidate whose name contains the PAYLOAD's
/// own bare version is good enough to break the tie, and only if EXACTLY
/// one does. Anything else is `Ambiguous` — a release that happens to
/// publish several `.cdx.json` files is not grounds to guess which one
/// describes this payload.
fn classify_release_sbom(published: &[String], version: &str) -> SbomSelection {
    let mut candidates: Vec<&String> = published
        .iter()
        .filter(|a| a.ends_with(".cdx.json"))
        .collect();
    candidates.sort();
    match candidates.len() {
        0 => SbomSelection::None,
        1 => SbomSelection::One(candidates[0].clone()),
        _ => {
            let naming_version: Vec<&&String> =
                candidates.iter().filter(|a| a.contains(version)).collect();
            match naming_version.len() {
                1 => SbomSelection::One(naming_version[0].to_string()),
                _ => SbomSelection::Ambiguous,
            }
        }
    }
}

/// The SINGLE `.cdx.json` asset a release publishes, admitted through that
/// release's own proof — the fallback this run uses for a payload whose
/// layer manifest recorded no `ANN_SBOM` of its own (REQ-ADVISORYWATCH-001
/// clause 4b).
///
/// `release` is the release TAG `verify_release` and `Source::asset_bytes`
/// need; `version` is the PAYLOAD's own bare version, used only to break a
/// tie among several published `.cdx.json` assets — the two differ for a
/// hub repository, and a release tag ("v0.11.0") is not generally a
/// substring of an asset name upstream wrote without the "v" ("wsc-0.11.0").
///
/// Reuses [`verify_release`] and [`admit`] rather than a second ladder:
/// this is the SAME question `deposit` already answers for every payload —
/// "does the proof cover these exact bytes" — asked about one more asset of
/// a release this run is already looking at.
///
/// `optins` is always empty here, deliberately: an operator's recorded
/// reason for ingesting a TOOL unverified is a decision about that payload,
/// made in `layer.toml`, and this fallback has no business spending it on a
/// DIFFERENT asset (the release's SBOM) nobody opted in for. A release with
/// no stronger proof therefore yields `VerifyFailed`, never a silent
/// `Unverified` admission of unproven bytes.
pub fn release_sbom_outcome<S: Source>(
    src: &S,
    forge: &Forge,
    repo: &str,
    release: &str,
    version: &str,
) -> ReleaseSbomOutcome {
    let verified = match verify_release(
        src,
        forge,
        repo,
        release,
        &BTreeMap::new(),
        &Declared::default(),
        &[],
    ) {
        Ok(v) => v,
        Err(e) => return ReleaseSbomOutcome::VerifyFailed(e.to_string()),
    };
    let asset = match classify_release_sbom(&verified.published, version) {
        SbomSelection::None => return ReleaseSbomOutcome::NoSbom,
        SbomSelection::Ambiguous => return ReleaseSbomOutcome::Ambiguous,
        SbomSelection::One(asset) => asset,
    };

    // `Mechanism::Unverified` is unreachable with empty optins (`choose`
    // refuses rather than inventing a reason), but the check is explicit
    // rather than relying on that: a release nothing vouches for must never
    // read as "covered" because of a code path this function does not take.
    if verified.sums.is_none() {
        return ReleaseSbomOutcome::NotCovered;
    }

    let bytes = match src.asset_bytes(repo, release, &asset) {
        Ok(b) => b,
        Err(e) => return ReleaseSbomOutcome::VerifyFailed(e.to_string()),
    };
    match admit(&verified, repo, &asset, &bytes) {
        Ok(_) => ReleaseSbomOutcome::Found(bytes),
        Err(RunError::NotCoveredByProof { .. }) | Err(RunError::DigestMismatch { .. }) => {
            ReleaseSbomOutcome::NotCovered
        }
        Err(e) => ReleaseSbomOutcome::VerifyFailed(e.to_string()),
    }
}

/// One payload, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub plan: PayloadPlan,
    pub digest: String,
    pub accepted: Accepted,
    /// `None` when the payload was carried forward and never re-downloaded.
    pub bytes: Option<Vec<u8>>,
    pub decision: Decision,
    /// The upstream repository's declared SPDX license (REQ-SBOMFIELDS-001
    /// clause 5). Shared by every payload of the repo — fetched once.
    pub license: Option<String>,
    /// The CycloneDX SBOM this payload's release published, if any
    /// (REQ-SBOMFIELDS-001 clause 4). Shared by every payload resolved from
    /// the same release.
    pub sbom: Option<SbomRef>,
}

/// An upstream-published CycloneDX SBOM this deposit will reference: its
/// file name (relative to the release) and the sha256 of the bytes fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomRef {
    pub name: String,
    pub sha256: String,
}

/// Which of a release's published assets IS its CycloneDX SBOM
/// (REQ-SBOMFIELDS-001 clause 4) — a name ending `.cdx.json`.
///
/// Exactly one such asset is recorded. Zero is a release that simply ships
/// none. Several is ambiguous UNLESS exactly one of them contains the
/// release's own version string, in which case that one is preferred; if it
/// is still ambiguous after that, NOTHING is recorded — a guess here would be
/// signed into the layer as fact — and a one-line note says why.
pub fn select_release_sbom<'a>(published: &'a [String], version: &str) -> Option<&'a str> {
    // ONE rule for the deposit and the advisory watcher: classify_release_sbom.
    // This wrapper keeps the deposit's signature and its note on ambiguity.
    match classify_release_sbom(published, version) {
        SbomSelection::One(name) => published.iter().find(|p| **p == name).map(String::as_str),
        SbomSelection::None => None,
        SbomSelection::Ambiguous => {
            eprintln!(
                "note: several CycloneDX SBOM candidates published for release {version:?} and \
                 none of them uniquely names it — recording no upstream SBOM rather than \
                 guessing"
            );
            None
        }
    }
}

/// Group a plan by the release its payloads come from, preserving the order
/// each release was first mentioned in.
///
/// Order is not cosmetic: it decides which repo's failure an operator sees
/// first, and a run that reports a different repo on each attempt is one
/// nobody can act on.
pub fn by_release(plans: &[PayloadPlan]) -> Vec<((String, String), Vec<usize>)> {
    let mut order: Vec<(String, String)> = Vec::new();
    let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, p) in plans.iter().enumerate() {
        let key = (p.repo.clone(), p.release.clone());
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(i);
    }
    order
        .into_iter()
        .map(|k| {
            let idx = groups.remove(&k).expect("key came from the map");
            (k, idx)
        })
        .collect()
}

/// Every plan of one (repo, release) must declare the same digest lists.
///
/// A release is verified once, from the first plan's declaration. If a sibling
/// declared something else — a signed list the first did not, a different key —
/// its declared verification would never run and its bytes would be admitted
/// under the first plan's weaker (or different) proof. Refused before anything
/// is fetched, naming the tools and the field.
fn check_group_agrees(
    plans: &[PayloadPlan],
    idxs: &[usize],
    repo: &str,
    release: &str,
) -> Result<(), RunError> {
    let Some(first) = idxs.first().map(|i| &plans[*i]) else {
        return Ok(());
    };
    let disagree = |field: &'static str, differs: &dyn Fn(&PayloadPlan) -> bool| {
        if idxs.iter().all(|i| !differs(&plans[*i])) {
            return Ok(());
        }
        let mut tools: Vec<String> = Vec::new();
        for i in idxs {
            if !tools.contains(&plans[*i].name) {
                tools.push(plans[*i].name.clone());
            }
        }
        Err(RunError::GroupDisagrees {
            repo: repo.to_string(),
            release: release.to_string(),
            field,
            tools,
        })
    };
    disagree("pgp-sums", &|p| p.pgp_sums != first.pgp_sums)?;
    disagree("upstream-sums", &|p| p.upstream_sums != first.upstream_sums)
}

/// Ingestion's own check that an asset is bound to the release it is ingested
/// for, whichever rung vouches for it. Runs AFTER the release is verified,
/// because only then is it known which mechanism accepted it.
///
/// A proof (a cosign identity, an attestation, a signed or unsigned digest
/// list) says who published bytes, not which release they are for. The plan
/// refuses versionless and moving names, but the plan is not the only way to
/// reach `run`, and a binding that holds only if an earlier step ran is not
/// one. Every expanded asset name must contain, on a token boundary and with a
/// leading `v` set aside, the release tag the group is fetched under (when it
/// names ONE release), or the payload's version when the plan-time check has
/// shown that version and tag to name the same release.
///
/// Skipped only for (a) an entry that states `unbound-release-reason`, a
/// recorded waiver, (b) a release that was actually accepted as
/// [`Mechanism::Unverified`], which is its own recorded exception, and (c) a
/// Rust channel, which binds through the channel manifest's own version. An
/// `unverified-reason` on an entry whose release resolves to a signed or listed
/// rung exempts nothing.
///
/// This is a NAME HEURISTIC. For cosign and build provenance the proof itself
/// is also pinned to the tag (`Forge::identity_regexp`,
/// `gh attestation verify --source-ref`); for the lists it is all there is.
fn check_assets_are_bound(
    plans: &[PayloadPlan],
    idxs: &[usize],
    mechanism: Mechanism,
) -> Result<(), RunError> {
    if mechanism == Mechanism::Unverified {
        return Ok(());
    }
    for i in idxs {
        let p = &plans[*i];
        if p.unbound_release_reason.is_some() {
            continue;
        }
        if p.pgp_sums
            .as_ref()
            .is_some_and(|s| s.format == crate::pgpsums::ListFormat::RustChannel)
        {
            continue;
        }
        let mut tokens: Vec<&str> = Vec::new();
        if crate::plan::names_a_release(&p.release) {
            tokens.push(&p.release);
        }
        if crate::plan::names_a_release(&p.version)
            && crate::plan::version_matches_release(&p.version, &p.release)
        {
            tokens.push(&p.version);
        }
        let bound = tokens.into_iter().map(|v| v.strip_prefix('v').unwrap_or(v));
        if !bound
            .into_iter()
            .any(|b| crate::plan::carries_at_a_boundary(&p.asset, b))
        {
            return Err(RunError::AssetNotBoundToRelease {
                tool: p.name.clone(),
                asset: p.asset.clone(),
                version: p.version.clone(),
                release: p.release.clone(),
            });
        }
    }
    Ok(())
}

/// The proof annotation of an entry carried without a release binding: what
/// the proof says, then plainly that it does not say which release, then the
/// operator's reason. Signed into the layer beside the proof.
fn annotate_unbound(accepted: &Accepted, p: &PayloadPlan) -> Accepted {
    let Some(why) = &p.unbound_release_reason else {
        return accepted.clone();
    };
    let mut out = accepted.clone();
    out.asserts = format!(
        "{}; NOT BOUND TO ITS RELEASE: this entry's asset names do not carry release {} \
         (an operator exception), so an older release's proof and bytes served under this \
         tag would have been accepted: the name binding was WAIVED. Recorded reason: {why}",
        accepted.asserts, p.release
    );
    out
}

/// Walk the whole plan.
pub fn run<S: Source>(
    src: &S,
    forge: &Forge,
    plans: &[PayloadPlan],
    previous: &BTreeMap<String, PreviousEntry>,
    optins: &BTreeMap<String, String>,
    blob_present: &dyn Fn(&str) -> bool,
    // Fetch a blob the DESTINATION registry already holds, by digest
    // (REQ-REUSEBLOB-001 clause 1). `None` means it could not be retrieved,
    // which is a fallback and never a failure.
    reuse_blob: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<Vec<Resolved>, RunError> {
    let mut out: Vec<Option<Resolved>> = vec![None; plans.len()];
    let mut seen = ingest::VerifiedRepos::new();
    // REQ-SBOMFIELDS-001 clause 5: ONE lookup per distinct repository, no
    // matter how many releases or payloads of it this run touches.
    let mut license_cache: BTreeMap<String, Option<String>> = BTreeMap::new();
    for ((repo, version), idxs) in by_release(plans) {
        // Verified ONCE per release, before any of its payloads are touched.
        // A property of the release, so any payload of the group carries it;
        // taking the first is not a choice between disagreeing values.
        let sums_asset = idxs
            .first()
            .and_then(|i| plans[*i].upstream_sums.as_deref());
        let wanted: Vec<String> = idxs.iter().map(|i| plans[*i].asset.clone()).collect();
        // ONE declaration per release, or none: verifying with whichever plan
        // happens to come first would silently skip another member's.
        check_group_agrees(plans, &idxs, &repo, &version)?;
        let declared = Declared {
            upstream_sums: sums_asset,
            pgp_sums: idxs.first().and_then(|i| plans[*i].pgp_sums.as_ref()),
        };
        let v = verify_release(src, forge, &repo, &version, optins, &declared, &wanted)?;
        check_assets_are_bound(plans, &idxs, v.accepted.mechanism)?;
        seen.record(&repo, &version, v.accepted.clone())?;

        // Clause 4: a property of the RELEASE, ADMITTED through the same
        // proof as its payloads — an SBOM nothing vouched for would be signed
        // into the layer as if something had.
        let admitted = release_sbom(src, &v, &repo, &version)?;
        let (sbom, sbom_license) = match admitted {
            Some((r, l)) => (Some(r), l),
            None => (None, None),
        };
        // Clause 5: the license the proof-covered SBOM states wins over
        // GitHub's repository guess, which is unsigned and, for several
        // PulseEngine repos, `null` where their SBOM says Apache-2.0 or MIT.
        // GitHub is asked ONCE per repository, and only when needed.
        let license = match sbom_license {
            Some(l) => Some(l),
            None => match license_cache.get(&repo) {
                Some(cached) => cached.clone(),
                None => {
                    let l = src.repo_license(&repo)?;
                    license_cache.insert(repo.clone(), l.clone());
                    l
                }
            },
        };

        for i in idxs {
            let p = &plans[i];
            // "This platform has no build" and "this platform was built,
            // published, and nothing vouches for it" are opposite facts, and
            // the release listing is what separates them. The shell asked only
            // the sums file, so an UNSIGNED asset was skipped with the same
            // friendly notice as an absent one.
            if !v.published.is_empty() && !v.published.contains(&p.asset) {
                continue; // no build for this platform — recorded by the caller
            }
            let upstream = match &v.sums {
                Some(s) => s
                    .digest_of(&p.asset)
                    .ok_or_else(|| RunError::NotCoveredByProof {
                        repo: repo.clone(),
                        asset: p.asset.clone(),
                        mechanism: v.accepted.mechanism.as_str(),
                    })?
                    .to_string(),
                None => String::new(),
            };
            // Carry-forward is decided from the FRESHLY verified digest, so a
            // republished release under an unchanged version is caught rather
            // than reused.
            let decision = if upstream.is_empty() {
                Decision::Fetch {
                    why: carryforward::FetchReason::NoPrevious,
                }
            } else {
                carryforward::decide(
                    // Keyed per platform. One layer carries the same tool for
                    // four of them, and a lookup by name alone would let the
                    // linux record answer a darwin question — carrying forward
                    // a digest for bytes of the wrong architecture.
                    previous.get(&crate::deposit::payload_key(&p.name, p.platform.as_deref())),
                    &repo,
                    &version,
                    &p.asset,
                    &upstream,
                    blob_present(&upstream),
                )
                .map_err(RunError::Carry)?
            };
            let mut decision = decision;
            let (digest, bytes) = match &decision {
                // Carried forward: the bytes come from the DESTINATION
                // registry rather than upstream — one host instead of four
                // CDNs, no upstream rate limits, and no re-verification of an
                // unchanged release. Clause 4 of REQ-CARRYFORWARD-001 already
                // requires the blob to be there before reuse is permitted, so
                // the check that makes reuse safe and the source that makes it
                // possible are the same check.
                //
                // Fetched by `upstream` — the digest the CURRENT proof states,
                // never the one the previous layer recorded (clause 2).
                // Otherwise a republished upstream is carried forward
                // unnoticed, which is the substitution carry-forward exists to
                // catch.
                Decision::Reuse { .. } => match reuse_blob(&upstream) {
                    // The destination is a source like any other and gets no
                    // more trust for being ours (clause 3).
                    Some(b) if sha256_hex(&b) == upstream => (upstream.clone(), Some(b)),
                    // Absent, unreachable, or serving something else: fall
                    // back to upstream rather than abort (clause 4). A
                    // presence check can race a garbage collection, and a
                    // deposit that failed because a cache was pruned would be
                    // worse than a slower one.
                    _ => {
                        decision = Decision::Fetch {
                            why: crate::carryforward::FetchReason::ReuseUnusable,
                        };
                        let b = src.asset_bytes(&repo, &version, &p.asset)?;
                        let d = admit(&v, &repo, &p.asset, &b)?;
                        (d, Some(b))
                    }
                },
                Decision::Fetch { .. } => {
                    let b = src.asset_bytes(&repo, &version, &p.asset)?;
                    let d = admit(&v, &repo, &p.asset, &b)?;
                    (d, Some(b))
                }
            };
            out[i] = Some(Resolved {
                plan: p.clone(),
                digest,
                accepted: annotate_unbound(&v.accepted, p),
                bytes,
                decision,
                license: license.clone(),
                sbom: sbom.clone(),
            });
        }
    }
    // A payload name that matched on NO platform is an asset template that no
    // longer describes the release. Per-platform gaps are fine; a total miss
    // is not, and going green with four notices is exactly how a tool went
    // missing from a published layer once already.
    let mut matched: BTreeMap<&str, bool> = BTreeMap::new();
    for (i, p) in plans.iter().enumerate() {
        let e = matched.entry(p.name.as_str()).or_insert(false);
        *e |= out[i].is_some();
    }
    for (name, ok) in &matched {
        if !ok {
            let tried: Vec<String> = plans
                .iter()
                .filter(|p| p.name == *name)
                .map(|p| p.asset.clone())
                .collect();
            let first = plans.iter().find(|p| p.name == *name).expect("named above");
            return Err(RunError::NothingMatched {
                name: (*name).to_string(),
                repo: first.repo.clone(),
                version: first.release.clone(),
                tried,
            });
        }
    }
    Ok(out.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::PayloadKind;

    /// The bytes are downloaded into a directory keyed by the release, because
    /// the release is what was fetched. Staging must look in THAT directory.
    ///
    /// For almost every tool the release and the version are the same string,
    /// so the two agree by accident and no test noticed they were computed
    /// from different fields. On a hub they diverge, and the symptom is the
    /// one `release_dir`'s own doc comment predicts: a missing file, naming
    /// nothing about the real cause.
    ///
    ///   downloads/pulseengine__jess/0.2.2/with-device-0.2.2-…tar.gz
    ///                               ^ the version; the bytes are under v0.7.2
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn a_hub_is_staged_from_the_directory_its_bytes_were_downloaded_into() {
        let hub = PayloadPlan {
            name: "with-device".into(),
            repo: "pulseengine/jess".into(),
            version: "0.2.2".into(),
            release: "v0.7.2".into(),
            asset: "with-device-0.2.2-aarch64-apple-darwin.tar.gz".into(),
            platform: Some("aarch64-apple-darwin".into()),
            named_explicitly: false,
            kind: PayloadKind::Tarball,
            unverified_reason: None,
            unbound_release_reason: None,
            contains: None,
            upstream_sums: None,
            pgp_sums: None,
            title: None,
            documents: None,
            allow_pip: None,
        };
        let root = std::path::Path::new("/w");

        // Where the downloader put them: `by_release` decides the grouping,
        // and the group key is what reaches `Source::download`.
        let ((repo, fetched_as), _) = by_release(std::slice::from_ref(&hub))
            .into_iter()
            .next()
            .expect("one group");
        let downloaded = crate::source::release_dir(root, &repo, &fetched_as);

        // Where staging looks.
        let staged = crate::source::plan_download_dir(root, &hub);

        assert_eq!(
            staged, downloaded,
            "staging reads a different directory than the downloader wrote"
        );
        assert!(
            staged.to_string_lossy().contains("v0.7.2"),
            "keyed on the release tag: {}",
            staged.display()
        );
    }

    const A: &[u8] = b"the real bytes";
    const B: &[u8] = b"different bytes";

    /// No registry to reuse from — what every test that predates
    /// REQ-REUSEBLOB-001 was written against.
    fn no_reuse(_: &str) -> Option<Vec<u8>> {
        None
    }

    fn plan(name: &str, repo: &str, version: &str, asset: &str) -> PayloadPlan {
        PayloadPlan {
            release: version.to_string(),
            upstream_sums: None,
            pgp_sums: None,
            title: None,
            documents: None,
            allow_pip: None,
            contains: None,
            name: name.into(),
            repo: repo.into(),
            version: version.into(),
            asset: asset.into(),
            platform: Some("x86_64-unknown-linux-gnu".into()),
            named_explicitly: false,
            kind: PayloadKind::Tarball,
            unverified_reason: None,
            // Most tests here are about something other than naming and use
            // arbitrary asset names; they model an entry that opted out. The
            // binding tests build their plans with `bound_plan`.
            unbound_release_reason: Some("test fixture: names are arbitrary".into()),
        }
    }

    /// A plan that has NOT opted out of the release binding.
    fn bound_plan(name: &str, repo: &str, version: &str, asset: &str) -> PayloadPlan {
        let mut p = plan(name, repo, version, asset);
        p.unbound_release_reason = None;
        p
    }

    /// Records what was asked of it, so ordering and call-count are testable.
    #[derive(Default)]
    struct Fixture {
        sums: BTreeMap<String, String>,
        blobs: BTreeMap<String, Vec<u8>>,
        probes: BTreeMap<String, ReleaseProbe>,
        /// `repo@version` -> the statement the PROBE returns.
        attestations: BTreeMap<String, String>,
        /// `repo@version/asset` -> the statement that asset's own
        /// verification returns.
        per_asset: BTreeMap<String, String>,
        /// repo -> what `repo_license` answers. Absent from the map reads as
        /// `Ok(None)` — a repo nobody scripted a license for.
        licenses: BTreeMap<String, Option<String>>,
        calls: std::cell::RefCell<Vec<String>>,
    }

    /// One `gh attestation verify --format json` document.
    fn attestation_doc(subjects: &[(&str, &[u8])]) -> String {
        let subs: Vec<String> = subjects
            .iter()
            .map(|(n, b)| {
                format!(
                    r#"{{"name":"{n}","digest":{{"sha256":"{}"}}}}"#,
                    sha256_hex(b)
                )
            })
            .collect();
        format!(
            r#"[{{"verificationResult":{{
                "statement":{{"subject":[{}]}},
                "signature":{{"certificate":{{
                    "buildSignerURI":"https://github.com/up/stream/.github/workflows/release.yml@refs/tags/v1",
                    "sourceRepositoryDigest":"cafebabe"
                }}}}
            }}}}]"#,
            subs.join(",")
        )
    }

    impl Fixture {
        fn signed(repo: &str, version: &str, pairs: &[(&str, &[u8])]) -> Self {
            let mut f = Fixture::default();
            let key = format!("{repo}@{version}");
            let text: String = pairs
                .iter()
                .map(|(n, b)| format!("{}  ./{n}\n", sha256_hex(b)))
                .collect();
            f.sums.insert(key.clone(), text);
            for (n, b) in pairs {
                f.blobs.insert(format!("{key}/{n}"), b.to_vec());
            }
            f.probes.insert(
                key,
                ReleaseProbe {
                    published: pairs.iter().map(|(n, _)| n.to_string()).collect(),
                    has_sums: true,
                    has_cosign_bundle: true,
                    cosign: Some(Ok(())),
                    ..Default::default()
                },
            );
            f
        }
        /// A release proven by BUILD PROVENANCE, in the shape a publisher
        /// that calls `attest-build-provenance` per file produces: every
        /// asset has its own statement, and each names only itself.
        ///
        /// Measured shape — `bytecodealliance/wasmtime` v49.0.1 (varve#245).
        fn attested_per_asset(repo: &str, version: &str, pairs: &[(&str, &[u8])]) -> Self {
            let mut f = Fixture::default();
            let key = format!("{repo}@{version}");
            for (n, b) in pairs {
                f.blobs.insert(format!("{key}/{n}"), b.to_vec());
                f.per_asset
                    .insert(format!("{key}/{n}"), attestation_doc(&[(*n, *b)]));
            }
            // The probe takes the first asset, so that is the statement it
            // caches for the release.
            let (first, fb) = pairs[0];
            f.attestations
                .insert(key.clone(), attestation_doc(&[(first, fb)]));
            f.probes.insert(
                key,
                ReleaseProbe {
                    published: pairs.iter().map(|(n, _)| n.to_string()).collect(),
                    has_sums: false,
                    has_cosign_bundle: false,
                    cosign: None,
                    attestation: crate::ingest::AttestationProbe::Verified {
                        signer: "https://github.com/up/stream/.github/workflows/release.yml@refs/tags/v1".into(),
                        commit: "cafebabe".into(),
                    },
                    pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
                },
            );
            f
        }

        /// The same release in the shape a publisher that batches produces:
        /// ONE statement naming every asset.
        ///
        /// Measured shape — `bytecodealliance/wasm-tools` v1.260.0, 10
        /// subjects in one statement.
        fn attested_as_one_batch(repo: &str, version: &str, pairs: &[(&str, &[u8])]) -> Self {
            let mut f = Fixture::attested_per_asset(repo, version, pairs);
            let key = format!("{repo}@{version}");
            let batch = attestation_doc(pairs);
            f.attestations.insert(key.clone(), batch.clone());
            // A batch publisher's per-asset lookup would also return the
            // batch, but nothing should need to ask: the probe's copy already
            // names every asset.
            for (n, _) in pairs {
                f.per_asset.insert(format!("{key}/{n}"), batch.clone());
            }
            f
        }

        fn with(mut self, other: Fixture) -> Self {
            self.sums.extend(other.sums);
            self.blobs.extend(other.blobs);
            self.probes.extend(other.probes);
            self.attestations.extend(other.attestations);
            self.per_asset.extend(other.per_asset);
            self.licenses.extend(other.licenses);
            self
        }
        fn license(mut self, repo: &str, l: Option<&str>) -> Self {
            self.licenses.insert(repo.into(), l.map(str::to_string));
            self
        }
        /// Publish an extra asset into an already-built fixture's release,
        /// without it being part of any proof — just another name `probe`
        /// reports, the way a CycloneDX SBOM sits beside the signed assets.
        fn publish(mut self, repo: &str, version: &str, name: &str, bytes: &[u8]) -> Self {
            let key = format!("{repo}@{version}");
            if let Some(p) = self.probes.get_mut(&key) {
                p.published.push(name.to_string());
            }
            self.blobs.insert(format!("{key}/{name}"), bytes.to_vec());
            self
        }
        fn log(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Source for Fixture {
        fn probe(&self, _f: &Forge, repo: &str, version: &str) -> Result<ReleaseProbe, RunError> {
            let k = format!("{repo}@{version}");
            self.calls.borrow_mut().push(format!("probe {k}"));
            self.probes.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "no such release".into(),
            })
        }
        fn sums_text(&self, repo: &str, version: &str) -> Result<String, RunError> {
            let k = format!("{repo}@{version}");
            self.calls.borrow_mut().push(format!("sums {k}"));
            self.sums.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "no sums".into(),
            })
        }
        fn attestation_json(&self, repo: &str, version: &str) -> Result<String, RunError> {
            let k = format!("{repo}@{version}");
            self.calls.borrow_mut().push(format!("attest {k}"));
            self.attestations.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "no attestation".into(),
            })
        }
        fn attestation_json_for(
            &self,
            repo: &str,
            version: &str,
            asset: &str,
        ) -> Result<String, RunError> {
            let k = format!("{repo}@{version}/{asset}");
            self.calls.borrow_mut().push(format!("attest-one {k}"));
            self.per_asset.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "this asset has no attestation of its own".into(),
            })
        }
        fn asset_bytes(&self, repo: &str, version: &str, asset: &str) -> Result<Vec<u8>, RunError> {
            let k = format!("{repo}@{version}/{asset}");
            self.calls.borrow_mut().push(format!("fetch {k}"));
            self.blobs.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "no such asset".into(),
            })
        }
        fn repo_license(&self, repo: &str) -> Result<Option<String>, RunError> {
            self.calls.borrow_mut().push(format!("license {repo}"));
            Ok(self.licenses.get(repo).cloned().flatten())
        }
    }

    fn never(_: &str) -> bool {
        false
    }

    fn payload_key_for_test(name: &str, platform: Option<&str>) -> String {
        crate::deposit::payload_key(name, platform)
    }

    /// An upstream that attests EACH ASSET SEPARATELY is ingested whole.
    ///
    /// Two publishing styles exist and nothing announces which is in use.
    /// `wasm-tools` v1.260.0 puts ten subjects in one statement; `wasmtime`
    /// v49.0.1 publishes one statement per asset, each naming one file. varve
    /// probed a single asset and treated its subject list as the release's
    /// complete set of covered digests, so against the second style it
    /// refused every asset but the probed one — bytes upstream fully attests,
    /// rejected as unproven (varve#245).
    ///
    /// Fail-closed, so never a hole; it blocked `pulseengine-wasm` from
    /// depositing at all.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn an_upstream_that_attests_each_asset_separately_is_ingested_whole() {
        let f =
            Fixture::attested_per_asset("o/r", "v1", &[("first.tar.gz", A), ("second.tar.gz", B)]);
        let plans = vec![
            plan("first", "o/r", "v1", "first.tar.gz"),
            plan("second", "o/r", "v1", "second.tar.gz"),
        ];

        let got = run(
            &f,
            &Forge::github_com(),
            &plans,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("both assets are attested by their own statements");

        assert_eq!(got.len(), 2, "both payloads resolve");
        // The digest recorded is the one the proof carries, for each.
        assert_eq!(got[0].digest, sha256_hex(A));
        assert_eq!(got[1].digest, sha256_hex(B));
        for r in &got {
            assert_eq!(
                r.accepted.mechanism,
                Mechanism::BuildProvenance,
                "recorded as proven, not downgraded"
            );
        }
    }

    /// The batch style keeps working, and keeps costing ONE verification.
    ///
    /// The fix must not turn a ten-subject statement into ten calls: that is
    /// the regression a naive "verify everything per asset" would ship, and
    /// it would be invisible because the result is still correct.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn a_batched_attestation_still_answers_for_every_asset_it_names() {
        let f = Fixture::attested_as_one_batch(
            "o/r",
            "v1",
            &[("first.tar.gz", A), ("second.tar.gz", B)],
        );
        let plans = vec![
            plan("first", "o/r", "v1", "first.tar.gz"),
            plan("second", "o/r", "v1", "second.tar.gz"),
        ];

        let got = run(
            &f,
            &Forge::github_com(),
            &plans,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("one statement names both assets");
        assert_eq!(got.len(), 2);

        let per_asset: Vec<String> = f
            .log()
            .into_iter()
            .filter(|c| c.starts_with("attest-one "))
            .collect();
        assert!(
            per_asset.is_empty(),
            "a statement that already names the asset must not be re-verified: {per_asset:?}"
        );
    }

    /// An asset the release does not publish is SKIPPED, not asked about.
    ///
    /// "This platform has no build" is routine and belongs to the caller to
    /// report. Asking upstream for an attestation over a file that does not
    /// exist would turn a normal omission into a failed deposit — and deleting
    /// the `!` from that guard survived the mutation gate, because nothing
    /// exercised a wanted asset the release never published.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn an_asset_the_release_does_not_publish_is_skipped_not_asked_about() {
        let mut f =
            Fixture::attested_per_asset("o/r", "v1", &[("first.tar.gz", A), ("second.tar.gz", B)]);
        // The release does not publish `second.tar.gz` at all: no build for
        // that platform. Remove it from the listing AND from what upstream
        // would answer about, so asking would be an error.
        f.probes.get_mut("o/r@v1").expect("probed").published = vec!["first.tar.gz".into()];
        f.per_asset.remove("o/r@v1/second.tar.gz");
        f.blobs.remove("o/r@v1/second.tar.gz");

        // ONE tool across two platforms, so the tool itself still matches
        // something: a tool matching nothing ANYWHERE is a different refusal
        // (`NothingMatched`) and would mask the skip under test.
        let mut absent = plan("t", "o/r", "v1", "second.tar.gz");
        absent.platform = Some("aarch64-apple-darwin".into());
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "first.tar.gz"), absent],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("an unpublished asset is an omission, not a failure");

        assert_eq!(got.len(), 1, "only the published asset resolves: {got:?}");
        assert_eq!(got[0].plan.asset, "first.tar.gz");
        // And upstream was never asked about the absent one.
        let asked: Vec<String> = f
            .log()
            .into_iter()
            .filter(|c| c.contains("second.tar.gz"))
            .collect();
        assert!(
            asked.is_empty(),
            "asked upstream about a file it does not publish: {asked:?}"
        );
    }

    /// An asset with no proof of its own, in a release whose other assets
    /// have one, is still refused.
    ///
    /// This is the property the per-asset top-up must not spend. Falling back
    /// to "ask that asset" must not become "accept whatever comes back", and
    /// an asset nothing attests has to stay a refusal.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn an_asset_no_attestation_names_is_still_refused_when_its_siblings_have_one() {
        let mut f =
            Fixture::attested_per_asset("o/r", "v1", &[("first.tar.gz", A), ("second.tar.gz", B)]);
        // Published, downloadable, and vouched for by nothing.
        f.per_asset.remove("o/r@v1/second.tar.gz");
        let plans = vec![
            plan("first", "o/r", "v1", "first.tar.gz"),
            plan("second", "o/r", "v1", "second.tar.gz"),
        ];

        let err = run(
            &f,
            &Forge::github_com(),
            &plans,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("an unattested asset must not ride in on its siblings' proofs");
        let msg = err.to_string();
        assert!(
            msg.contains("second.tar.gz"),
            "the refusal must name the asset: {msg}"
        );
    }

    /// A statement that names a DIFFERENT asset cannot vouch for this one.
    ///
    /// The per-asset lookup asks upstream about asset X; if what comes back
    /// names only Y, accepting it would credit X with Y's proof. The digest
    /// would then be absent and the asset must be refused rather than
    /// recorded from the bytes we happen to hold.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn a_statement_naming_another_asset_does_not_vouch_for_this_one() {
        let mut f =
            Fixture::attested_per_asset("o/r", "v1", &[("first.tar.gz", A), ("second.tar.gz", B)]);
        // Upstream answers the question about `second` with a statement about
        // `first` — a valid signature over the wrong subject.
        f.per_asset.insert(
            "o/r@v1/second.tar.gz".into(),
            attestation_doc(&[("first.tar.gz", A)]),
        );
        let plans = vec![
            plan("first", "o/r", "v1", "first.tar.gz"),
            plan("second", "o/r", "v1", "second.tar.gz"),
        ];

        let err = run(
            &f,
            &Forge::github_com(),
            &plans,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("a proof over another file is not a proof over this one");

        // THE KIND, not just the name. Asserting only that the message
        // mentions the asset would pass under the wrong implementation too:
        // crediting `second` with `first`'s digest also fails, as a
        // DigestMismatch. Only `NotCoveredByProof` says the statement was
        // refused for naming the wrong file, which is the property.
        assert!(
            matches!(
                &err,
                RunError::NotCoveredByProof { asset, mechanism, .. }
                    if asset == "second.tar.gz" && *mechanism == "build-provenance"
            ),
            "expected the asset to be left uncovered, got: {err:?}"
        );
    }

    /// THE property. A signature over a sums file says nothing about the bytes
    /// on disk until somebody compares them, and the spec's own words claim
    /// the digest was "transcribed from it".
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn bytes_that_do_not_match_the_verified_sums_are_refused() {
        let mut f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        // The proof still covers A; what arrives is B.
        f.blobs.insert("o/r@v1/a.tar.gz".into(), B.to_vec());
        let e = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("must refuse");
        match &e {
            RunError::DigestMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, &sha256_hex(A));
                assert_eq!(actual, &sha256_hex(B));
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().contains("cannot tell which"), "{e}");
    }

    /// The pair of facts the shell could not tell apart, because it asked only
    /// the sums file. loom genuinely ships no aarch64-apple-darwin build; that
    /// platform is skipped. An asset the release DOES publish but does not
    /// sign is the opposite situation and must stop the run.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_platform_with_no_build_is_skipped_but_an_unsigned_published_asset_is_not() {
        // Case 1 — never built: absent from the release listing entirely.
        let f = Fixture::signed("o/r", "v1", &[("linux.tar.gz", A)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[
                plan("t", "o/r", "v1", "linux.tar.gz"),
                plan("t", "o/r", "v1", "darwin.tar.gz"),
            ],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("a missing platform is routine");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].plan.asset, "linux.tar.gz");

        // Case 2 — built, published, and NOT covered by the proof.
        let mut f = Fixture::signed("o/r", "v1", &[("linux.tar.gz", A)]);
        f.probes
            .get_mut("o/r@v1")
            .unwrap()
            .published
            .push("darwin.tar.gz".into());
        f.blobs.insert("o/r@v1/darwin.tar.gz".into(), B.to_vec());
        let e = run(
            &f,
            &Forge::github_com(),
            &[
                plan("t", "o/r", "v1", "linux.tar.gz"),
                plan("t", "o/r", "v1", "darwin.tar.gz"),
            ],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("a published-but-unproven asset must stop the run");
        assert!(
            matches!(&e, RunError::NotCoveredByProof { asset, .. } if asset == "darwin.tar.gz"),
            "{e:?}"
        );
    }

    /// A tool that matched on NO platform is a template that no longer
    /// describes the release. The last time this went unchecked the run went
    /// green with four notices and published a layer missing a tool.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_tool_that_matches_nothing_anywhere_stops_the_run() {
        // The tool that matched nothing lives in a DIFFERENT repo from the one
        // that matched. The error has to name its own repo: an operator sent to
        // the wrong release finds a perfectly healthy one and learns nothing.
        let f = Fixture::signed("o/kept", "v1", &[("linux.tar.gz", A)]).with(Fixture::signed(
            "o/gone",
            "v9",
            &[("something-else.tar.gz", B)],
        ));
        let e = run(
            &f,
            &Forge::github_com(),
            &[
                plan("kept", "o/kept", "v1", "linux.tar.gz"),
                plan("gone", "o/gone", "v9", "gone-v9-linux.tar.gz"),
                plan("gone", "o/gone", "v9", "gone-v9-darwin.tar.gz"),
            ],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("must refuse");
        match &e {
            RunError::NothingMatched {
                name,
                repo,
                version,
                tried,
            } => {
                assert_eq!(name, "gone");
                assert_eq!(repo, "o/gone", "named the wrong repo");
                assert_eq!(version, "v9", "named the wrong release");
                assert_eq!(tried.len(), 2, "{tried:?}");
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().contains("claims to carry"), "{e}");
    }

    /// Being absent from a signed list is being outside the proof. The
    /// tempting bug is to accept it "because the sums file verified".
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_asset_the_proof_does_not_name_is_not_covered_by_it() {
        let mut f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        // Published by the release, absent from the signed list.
        f.probes
            .get_mut("o/r@v1")
            .unwrap()
            .published
            .push("elsewhere.tar.gz".into());
        f.blobs.insert("o/r@v1/elsewhere.tar.gz".into(), B.to_vec());
        let e = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "elsewhere.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("must refuse");
        assert!(
            matches!(&e, RunError::NotCoveredByProof { asset, mechanism, .. }
                if asset == "elsewhere.tar.gz" && *mechanism == "cosign-sums"),
            "{e:?}"
        );
        assert!(e.to_string().contains("not in the list"), "{e}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn matching_bytes_are_recorded_with_the_digest_the_proof_carries() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("admits");
        assert_eq!(got[0].digest, sha256_hex(A));
        assert_eq!(got[0].accepted.mechanism, Mechanism::CosignSums);
    }

    /// Four payloads from one repo used to mean four cosign runs and four
    /// downloads of the same sums file — which is what made `--clobber` look
    /// necessary, and `--clobber` is what let one repo's sums overwrite
    /// another's.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_release_is_verified_once_however_many_payloads_it_supplies() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("b.tar.gz", B)]);
        run(
            &f,
            &Forge::github_com(),
            &[
                plan("t1", "o/r", "v1", "a.tar.gz"),
                plan("t2", "o/r", "v1", "b.tar.gz"),
            ],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        let log = f.log();
        assert_eq!(
            log.iter().filter(|c| c.starts_with("probe ")).count(),
            1,
            "{log:?}"
        );
        assert_eq!(
            log.iter().filter(|c| c.starts_with("sums ")).count(),
            1,
            "{log:?}"
        );
        assert_eq!(
            log.iter().filter(|c| c.starts_with("fetch ")).count(),
            2,
            "{log:?}"
        );
    }

    /// Verification is not a step that happens somewhere near the download; it
    /// happens BEFORE it, or the download is unguarded.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn nothing_is_downloaded_before_its_release_has_been_verified() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        let log = f.log();
        let first_fetch = log
            .iter()
            .position(|c| c.starts_with("fetch "))
            .expect("fetched");
        let sums_at = log
            .iter()
            .position(|c| c.starts_with("sums "))
            .expect("verified");
        assert!(sums_at < first_fetch, "{log:?}");
    }

    /// An unchanged payload is not re-downloaded — but the decision is made
    /// from the freshly verified digest, never from the old record.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn an_unchanged_payload_is_carried_forward_without_a_download() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let mut prev = BTreeMap::new();
        prev.insert(
            payload_key_for_test("t", Some("x86_64-unknown-linux-gnu")),
            PreviousEntry {
                repo: "o/r".into(),
                release: "v1".into(),
                asset: "a.tar.gz".into(),
                sha256: sha256_hex(A),
            },
        );
        let present = |d: &str| d == sha256_hex(A);
        // The destination registry holds it, so the bytes come from there and
        // NOT from upstream (REQ-REUSEBLOB-001 clause 1).
        let from_registry = |d: &str| (d == sha256_hex(A)).then(|| A.to_vec());
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &prev,
            &BTreeMap::new(),
            &present,
            &from_registry,
        )
        .expect("runs");
        assert!(
            matches!(got[0].decision, Decision::Reuse { .. }),
            "{:?}",
            got[0].decision
        );
        assert_eq!(got[0].digest, sha256_hex(A));
        assert_eq!(
            got[0].bytes.as_deref(),
            Some(A),
            "the layout must be COMPLETE — a carried-forward payload still has \
             its bytes, or the artifact of record is not one"
        );
        // Still verified: the proof is what told us it was unchanged.
        let log = f.log();
        assert!(log.iter().any(|c| c.starts_with("sums ")), "{log:?}");
        assert!(
            !log.iter().any(|c| c.starts_with("fetch ")),
            "no UPSTREAM fetch: that is the whole saving — one host instead of \
             four CDNs, and no re-verification of an unchanged release. {log:?}"
        );
    }

    /// Helper: a previous entry that agrees with the current release, so
    /// carry-forward resolves to Reuse.
    fn prev_matching(asset: &str, bytes: &[u8]) -> BTreeMap<String, PreviousEntry> {
        let mut prev = BTreeMap::new();
        prev.insert(
            payload_key_for_test("t", Some("x86_64-unknown-linux-gnu")),
            PreviousEntry {
                repo: "o/r".into(),
                release: "v1".into(),
                asset: asset.to_string(),
                sha256: sha256_hex(bytes),
            },
        );
        prev
    }

    /// The registry is asked for the freshly verified digest, and asked ONCE.
    ///
    /// Named honestly after a clean-room review pointed out that the earlier
    /// name — "…the digest the CURRENT proof states, never the previous
    /// record" — claimed more than this test can show. `decide` only returns
    /// Reuse after `digest_eq(prev.sha256, upstream)` succeeds, so at this
    /// call site the two are equal BY CONSTRUCTION and no fixture can tell
    /// them apart. Clause 2's real protection is `decide`'s
    /// `UpstreamRepublished` refusal, which belongs to REQ-CARRYFORWARD-001
    /// and is tested there.
    ///
    /// What this DOES establish is that the registry is consulted at all, with
    /// the digest the proof produced — which is what was inert before.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn the_registry_is_asked_once_for_the_freshly_verified_digest() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let asked = std::cell::RefCell::new(Vec::<String>::new());
        let from_registry = |d: &str| {
            asked.borrow_mut().push(d.to_string());
            (d == sha256_hex(A)).then(|| A.to_vec())
        };
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &prev_matching("a.tar.gz", A),
            &BTreeMap::new(),
            &|_| true,
            &from_registry,
        )
        .expect("runs");
        assert!(matches!(got[0].decision, Decision::Reuse { .. }));
        assert_eq!(
            asked.borrow().as_slice(),
            &[sha256_hex(A)],
            "the fetch must name the freshly verified digest"
        );
    }

    /// Clause 3. The destination is a source like any other and gets no more
    /// trust for being ours. Bytes that do not hash to the digest they were
    /// fetched by are DISCARDED — never staged — and the payload falls back to
    /// upstream, so the layer is still correct.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_registry_serving_the_wrong_bytes_is_refused_and_does_not_reach_the_layer() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        // Present, reachable, and wrong.
        let liar = |_: &str| Some(B.to_vec());
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &prev_matching("a.tar.gz", A),
            &BTreeMap::new(),
            &|_| true,
            &liar,
        )
        .expect("a lying registry must not abort the deposit");
        assert!(
            matches!(
                got[0].decision,
                Decision::Fetch {
                    why: crate::carryforward::FetchReason::ReuseUnusable
                }
            ),
            "{:?}",
            got[0].decision
        );
        assert_eq!(
            got[0].bytes.as_deref(),
            Some(A),
            "the layer must carry the UPSTREAM bytes, not what the registry served"
        );
        assert_eq!(got[0].digest, sha256_hex(A));
    }

    /// Clause 4. A presence check can race a garbage collection. A deposit
    /// that failed because a cache was pruned would be worse than a slower
    /// one, so absence falls back rather than aborting — and the resulting
    /// payload is indistinguishable from one that was never carried forward
    /// (clause 5).
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_blob_that_vanished_between_check_and_fetch_falls_back_instead_of_failing() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &prev_matching("a.tar.gz", A),
            &BTreeMap::new(),
            // Reported present, then gone by the time it is fetched.
            &|_| true,
            &no_reuse,
        )
        .expect("a pruned cache must not fail the deposit");
        assert!(
            matches!(
                got[0].decision,
                Decision::Fetch {
                    why: crate::carryforward::FetchReason::ReuseUnusable
                }
            ),
            "{:?}",
            got[0].decision
        );
        assert_eq!(got[0].bytes.as_deref(), Some(A));
        assert_eq!(
            got[0].digest,
            sha256_hex(A),
            "same digest for the same content, whichever host served it"
        );
    }

    /// The bug this prevents: four platforms of one tool, a previous-entry
    /// lookup by name alone, and the linux record answers the darwin question —
    /// carrying forward a digest for bytes of the wrong architecture.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn one_platforms_history_does_not_answer_for_another_platforms_payload() {
        let f = Fixture::signed("o/r", "v1", &[("linux.tar.gz", A), ("darwin.tar.gz", B)]);
        let mut prev = BTreeMap::new();
        // Only linux has a history, and it is up to date.
        prev.insert(
            "t@x86_64-unknown-linux-gnu".to_string(),
            PreviousEntry {
                repo: "o/r".into(),
                release: "v1".into(),
                asset: "linux.tar.gz".into(),
                sha256: sha256_hex(A),
            },
        );
        let present = |_: &str| true;
        // The registry holds the linux bytes. Keyed BY DIGEST, so if the
        // darwin payload were ever answered by the linux record it would ask
        // for A's digest and this fixture would hand back A — which is exactly
        // the substitution the assertions below must catch.
        let from_registry = |d: &str| (d == sha256_hex(A)).then(|| A.to_vec());
        let mut linux = plan("t", "o/r", "v1", "linux.tar.gz");
        linux.platform = Some("x86_64-unknown-linux-gnu".into());
        let mut darwin = plan("t", "o/r", "v1", "darwin.tar.gz");
        darwin.platform = Some("aarch64-apple-darwin".into());
        let got = run(
            &f,
            &Forge::github_com(),
            &[linux, darwin],
            &prev,
            &BTreeMap::new(),
            &present,
            &from_registry,
        )
        .expect("runs");
        // linux is carried forward; darwin has no history and must be fetched.
        assert!(
            matches!(got[0].decision, Decision::Reuse { .. }),
            "{:?}",
            got[0].decision
        );
        assert!(
            matches!(got[1].decision, Decision::Fetch { .. }),
            "darwin was answered by linux's record: {:?}",
            got[1].decision
        );
        assert_eq!(got[1].digest, sha256_hex(B));
    }

    /// A rejected proof aborts the run. It must not become a quieter mechanism.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_rejected_proof_stops_the_run_rather_than_falling_to_a_weaker_rung() {
        let mut f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        f.probes.insert(
            "o/r@v1".into(),
            ReleaseProbe {
                has_sums: true,
                has_cosign_bundle: true,
                cosign: Some(Err("certificate identity mismatch".into())),
                ..Default::default()
            },
        );
        // An opt-in exists for this very repo. It must NOT rescue a rejection.
        let mut optins = BTreeMap::new();
        optins.insert("o/r".to_string(), "we trust them".to_string());
        let e = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &optins,
            &never,
            &no_reuse,
        )
        .expect_err("must abort");
        assert!(
            matches!(&e, RunError::Ingest(IngestError::ProofRejected { .. })),
            "{e:?}"
        );
        assert!(
            !f.log().iter().any(|c| c.starts_with("fetch ")),
            "{:?}",
            f.log()
        );
    }

    /// Grouping must not reorder the payloads it returns; the caller indexes
    /// them against the plan it passed in.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn payloads_come_back_in_the_order_they_were_planned() {
        let f = Fixture::signed("a/one", "v1", &[("x", A)]).with(Fixture::signed(
            "b/two",
            "v2",
            &[("y", B)],
        ));
        let plans = [
            plan("first", "a/one", "v1", "x"),
            plan("second", "b/two", "v2", "y"),
            plan("third", "a/one", "v1", "x"),
        ];
        let got = run(
            &f,
            &Forge::github_com(),
            &plans,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        assert_eq!(
            got.iter().map(|r| r.plan.name.as_str()).collect::<Vec<_>>(),
            ["first", "second", "third"]
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn releases_are_grouped_in_the_order_they_were_first_mentioned() {
        let plans = [
            plan("a", "z/last", "v1", "x"),
            plan("b", "a/first", "v1", "y"),
            plan("c", "z/last", "v1", "w"),
        ];
        let g = by_release(&plans);
        assert_eq!(g[0].0, ("z/last".to_string(), "v1".to_string()));
        assert_eq!(g[0].1, vec![0, 2]);
        assert_eq!(g[1].0, ("a/first".to_string(), "v1".to_string()));
        assert_eq!(g[1].1, vec![1]);
    }

    /// An unverified opt-in has no list of covered digests, so `admit` records
    /// what it observed. The spec says so in the same breath; the danger would
    /// be pretending a proof exists.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn an_unverified_payload_records_the_digest_we_observed_and_claims_nothing() {
        let v = Verified {
            published: Vec::new(),
            accepted: Accepted {
                mechanism: Mechanism::Unverified,
                signer: Some("nobody".into()),
                asserts: "no proof was offered".into(),
                signing_key: None,
            },
            sums: None,
        };
        assert_eq!(admit(&v, "o/r", "a.tar.gz", A).unwrap(), sha256_hex(A));
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_same_repo_at_two_versions_in_one_layer_is_refused() {
        let f = Fixture::signed("o/r", "v1", &[("a", A)]).with(Fixture::signed(
            "o/r",
            "v2",
            &[("b", B)],
        ));
        let e = run(
            &f,
            &Forge::github_com(),
            &[plan("t1", "o/r", "v1", "a"), plan("t2", "o/r", "v2", "b")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect_err("must refuse");
        assert!(
            matches!(&e, RunError::Ingest(IngestError::RepoAtTwoVersions { .. })),
            "{e:?}"
        );
    }

    /// Clause 5: one `gh api repos/<repo>` per distinct repository, however
    /// many payloads this run resolves from it — not one per payload.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_repos_declared_license_is_fetched_once_for_every_payload_of_it() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("b.tar.gz", B)])
            .license("o/r", Some("Apache-2.0"));
        let got = run(
            &f,
            &Forge::github_com(),
            &[
                plan("t1", "o/r", "v1", "a.tar.gz"),
                plan("t2", "o/r", "v1", "b.tar.gz"),
            ],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        assert_eq!(got[0].license.as_deref(), Some("Apache-2.0"));
        assert_eq!(got[1].license.as_deref(), Some("Apache-2.0"));
        let log = f.log();
        assert_eq!(
            log.iter().filter(|c| c.starts_with("license ")).count(),
            1,
            "fetched more than once for one repo: {log:?}"
        );
    }

    /// A repo nobody scripted a license for is exactly a repo GitHub answers
    /// `license: null` or `NOASSERTION` for — both read as absent, and the
    /// gh.rs unit tests already pin that parse. This pins that the absence
    /// actually reaches `Resolved` rather than being defaulted somewhere
    /// along the way.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_repo_with_no_declared_license_records_none_not_a_default() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        assert_eq!(got[0].license, None);
    }

    /// Clause 4: exactly one `.cdx.json` in the release is recorded, named
    /// and digested from the bytes actually fetched.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_releases_sole_cyclonedx_sbom_is_recorded_with_its_digest() {
        const SBOM: &[u8] = b"{\"bomFormat\":\"CycloneDX\"}";
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("rivet-v1.cdx.json", SBOM)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        let sbom = got[0].sbom.as_ref().expect("the one candidate is recorded");
        assert_eq!(sbom.name, "rivet-v1.cdx.json");
        assert_eq!(sbom.sha256, sha256_hex(SBOM));
    }

    /// A release that ships no CycloneDX SBOM records none — absence stays
    /// absence, never a default.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_release_with_no_cyclonedx_sbom_records_none() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        assert!(got[0].sbom.is_none());
    }

    /// Two candidates and neither names the release: guessing would be
    /// signed into the layer as fact, so nothing is recorded instead.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn two_ambiguous_sbom_candidates_record_nothing_rather_than_guess() {
        let f = Fixture::signed(
            "o/r",
            "v1",
            &[
                ("a.tar.gz", A),
                ("one.cdx.json", b"one"),
                ("two.cdx.json", b"two"),
            ],
        );
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        assert!(got[0].sbom.is_none(), "{:?}", got[0].sbom);
    }

    /// Two candidates, but exactly one names the release's own version —
    /// that one is preferred rather than treated as still ambiguous.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn two_candidates_disambiguated_by_the_release_version_are_not_ambiguous() {
        let f = Fixture::signed(
            "o/r",
            "v1",
            &[
                ("a.tar.gz", A),
                ("rivet-v1.cdx.json", b"one"),
                ("rivet-v2.cdx.json", b"two"),
            ],
        );
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
        .expect("runs");
        let sbom = got[0]
            .sbom
            .as_ref()
            .expect("disambiguated by the release's own version string");
        assert_eq!(sbom.name, "rivet-v1.cdx.json");
    }

    fn run_one(f: &Fixture) -> Result<Vec<Resolved>, RunError> {
        run(
            f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
            &no_reuse,
        )
    }

    /// Security review of this work: an SBOM the signed sums do not name was
    /// recorded anyway, and its digest signed into the layer as if vouched
    /// for. It is now recorded only through the proof.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn an_sbom_the_proof_does_not_cover_is_not_recorded() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]).publish(
            "o/r",
            "v1",
            "r-v1.cdx.json",
            b"{}",
        );
        let got = run_one(&f).expect("an uncovered optional file is a note, not a refusal");
        assert!(got[0].sbom.is_none(), "{:?}", got[0].sbom);
    }

    /// Bytes that disagree with the signed sums are a replaced file: the run
    /// refuses, exactly as it would for a payload.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn an_sbom_whose_bytes_disagree_with_the_proof_refuses_the_run() {
        let mut f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("r-v1.cdx.json", b"{}")]);
        f.blobs
            .insert("o/r@v1/r-v1.cdx.json".into(), b"{\"evil\":1}".to_vec());
        let e = run_one(&f).expect_err("a tampered SBOM must not be signed");
        assert!(matches!(e, RunError::DigestMismatch { .. }), "{e:?}");
    }

    /// Where nothing vouches for the release there is no proof to spend.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn an_unverified_release_records_no_sbom() {
        let mut f = Fixture::default();
        f.blobs
            .insert("o/r@v1/r-v1.cdx.json".into(), b"{}".to_vec());
        let v = Verified {
            published: vec!["r-v1.cdx.json".into()],
            accepted: Accepted {
                mechanism: Mechanism::Unverified,
                signer: None,
                asserts: "no proof was offered".into(),
                signing_key: None,
            },
            sums: None,
        };
        assert_eq!(release_sbom(&f, &v, "o/r", "v1").unwrap(), None);
        assert!(
            f.log().iter().all(|c| !c.contains("cdx.json")),
            "{:?}",
            f.log()
        );
    }

    /// The license a proof-covered SBOM states wins over GitHub's unsigned
    /// repository guess — measured: GitHub says null for pulseengine/rivet
    /// and pulseengine/sigil, whose release SBOMs say Apache-2.0 and MIT.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn the_covered_sboms_license_wins_and_github_is_not_asked() {
        const SBOM: &[u8] =
            br#"{"metadata":{"component":{"name":"rivet-cli","licenses":[{"expression":"Apache-2.0"}]}}}"#;
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("r-v1.cdx.json", SBOM)])
            .license("o/r", Some("MIT"));
        let got = run_one(&f).unwrap();
        assert_eq!(got[0].license.as_deref(), Some("Apache-2.0"));
        assert!(
            f.log().iter().all(|c| !c.starts_with("license ")),
            "GitHub was asked although the SBOM answered: {:?}",
            f.log()
        );
    }

    /// No covered SBOM, or one that states no single license: GitHub's
    /// declared license is the fallback.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn without_a_covered_license_github_is_the_fallback() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A), ("r-v1.cdx.json", b"{}")])
            .license("o/r", Some("MIT"));
        assert_eq!(run_one(&f).unwrap()[0].license.as_deref(), Some("MIT"));
    }

    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_sole_sbom_is_recorded_whatever_it_is_named() {
        let names = vec!["a.tar.gz".to_string(), "bom.cdx.json".to_string()];
        assert_eq!(select_release_sbom(&names, "v1"), Some("bom.cdx.json"));
        assert_eq!(select_release_sbom(&names[..1], "v1"), None);
    }

    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn an_sbom_license_is_read_only_when_it_states_exactly_one() {
        let one = |v: &str| sbom_declared_license(v.as_bytes());
        assert_eq!(
            one(r#"{"metadata":{"component":{"licenses":[{"expression":"MIT OR Apache-2.0"}]}}}"#)
                .as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            one(r#"{"metadata":{"component":{"licenses":[{"license":{"id":"MIT"}}]}}}"#).as_deref(),
            Some("MIT")
        );
        assert_eq!(
            one(
                r#"{"metadata":{"component":{"licenses":[{"license":{"id":"MIT"}},{"license":{"id":"BSD-3-Clause"}}]}}}"#
            ),
            None
        );
        assert_eq!(
            one(r#"{"metadata":{"component":{"licenses":[{"expression":"NOASSERTION"}]}}}"#),
            None
        );
        assert_eq!(one(r#"{"metadata":{"component":{}}}"#), None);
        assert_eq!(one("not json"), None);
    }

    // -------------------------------------------------------------
    // release_sbom (REQ-ADVISORYWATCH-001 clause 4b's fallback)
    // -------------------------------------------------------------

    const SBOM: &[u8] =
        br#"{"bomFormat":"CycloneDX","components":[{"name":"rustls","version":"0.23.34"}]}"#;

    /// The real shape: pulseengine/sigil v0.11.0 publishes a `.cdx.json`
    /// asset and lists it in its own cosign-signed SHA256SUMS.txt with a
    /// matching digest.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_covered_release_sbom_is_found() {
        let f = Fixture::signed(
            "pulseengine/sigil",
            "v0.11.0",
            &[("wsc-0.11.0.cdx.json", SBOM), ("wsc-0.11.0.tar.gz", A)],
        );
        let outcome = release_sbom_outcome(
            &f,
            &Forge::github_com(),
            "pulseengine/sigil",
            "v0.11.0",
            "0.11.0",
        );
        assert_eq!(outcome, ReleaseSbomOutcome::Found(SBOM.to_vec()));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_release_with_no_cdx_asset_has_no_sbom() {
        let f = Fixture::signed("o/r", "v1", &[("tool.tar.gz", A)]);
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::NoSbom
        );
    }

    /// Published, but ABSENT from the verified sums list — the proof simply
    /// never spoke about this asset, and it must not be used anyway.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_absent_from_the_verified_sums_is_not_covered() {
        let mut f = Fixture::default();
        let key = "o/r@v1".to_string();
        // Signed, but the list covers only the OTHER asset.
        f.sums
            .insert(key.clone(), format!("{}  ./tool.tar.gz\n", sha256_hex(A)));
        f.blobs.insert(format!("{key}/tool.tar.gz"), A.to_vec());
        f.blobs
            .insert(format!("{key}/sbom.cdx.json"), SBOM.to_vec());
        f.probes.insert(
            key,
            ReleaseProbe {
                published: vec!["tool.tar.gz".into(), "sbom.cdx.json".into()],
                has_sums: true,
                has_cosign_bundle: true,
                cosign: Some(Ok(())),
                ..Default::default()
            },
        );
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::NotCovered
        );
    }

    /// Published AND listed, but the bytes actually downloaded do not hash
    /// to what the signed list says — a tampered or corrupted fetch, not a
    /// proof this fallback may use.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_whose_bytes_do_not_match_its_signed_digest_is_not_covered() {
        let mut f = Fixture::default();
        let key = "o/r@v1".to_string();
        // The signed list names a digest that is NOT sha256(SBOM) — as if
        // the list was signed over different bytes than what got fetched.
        f.sums.insert(
            key.clone(),
            "0000000000000000000000000000000000000000000000000000000000000000  ./sbom.cdx.json\n"
                .to_string(),
        );
        f.blobs
            .insert(format!("{key}/sbom.cdx.json"), SBOM.to_vec());
        f.probes.insert(
            key,
            ReleaseProbe {
                published: vec!["sbom.cdx.json".into()],
                has_sums: true,
                has_cosign_bundle: true,
                cosign: Some(Ok(())),
                ..Default::default()
            },
        );
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::NotCovered
        );
    }

    /// The release itself could not be verified at all — no probe was ever
    /// scripted for it, which is exactly what an upstream `gh` failure or an
    /// unknown release looks like to this function.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_release_that_cannot_be_verified_is_reported_not_aborted() {
        let f = Fixture::default();
        let outcome = release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0");
        assert!(
            matches!(&outcome, ReleaseSbomOutcome::VerifyFailed(detail) if !detail.is_empty()),
            "{outcome:?}"
        );
    }

    /// A release offering NEITHER cosign sums nor build provenance, with no
    /// opt-in recorded (this fallback never supplies one) — `choose` itself
    /// refuses, which must read as `VerifyFailed`, never as an admitted
    /// `Unverified` SBOM.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_release_with_no_proof_mechanism_at_all_is_verifyfailed_not_admitted() {
        let mut f = Fixture::default();
        let key = "o/r@v1".to_string();
        f.blobs
            .insert(format!("{key}/sbom.cdx.json"), SBOM.to_vec());
        f.probes.insert(
            key,
            ReleaseProbe {
                published: vec!["sbom.cdx.json".into()],
                has_sums: false,
                has_cosign_bundle: false,
                cosign: None,
                attestation: crate::ingest::AttestationProbe::NotAttested,
                pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
            },
        );
        assert!(matches!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::VerifyFailed(_)
        ));
    }

    /// A release whose SBOM asset is covered but could not actually be
    /// downloaded — the proof is fine, the fetch is not.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_covered_sbom_that_cannot_be_downloaded_is_verifyfailed() {
        let mut f = Fixture::default();
        let key = "o/r@v1".to_string();
        f.sums.insert(
            key.clone(),
            format!("{}  ./sbom.cdx.json\n", sha256_hex(SBOM)),
        );
        // Deliberately NOT inserted into `f.blobs` — the digest is covered,
        // but the bytes cannot be fetched.
        f.probes.insert(
            key,
            ReleaseProbe {
                published: vec!["sbom.cdx.json".into()],
                has_sums: true,
                has_cosign_bundle: true,
                cosign: Some(Ok(())),
                ..Default::default()
            },
        );
        assert!(matches!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::VerifyFailed(_)
        ));
    }

    /// Two `.cdx.json` assets, NEITHER naming the payload's own version —
    /// picking one anyway would be a guess, and checking the wrong SBOM
    /// silently reports nothing for the payload that actually needed
    /// checking. `Ambiguous`, not a deterministic pick.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn two_cdx_assets_naming_neither_payload_version_is_ambiguous() {
        const OTHER: &[u8] = b"a different sbom";
        let f = Fixture::signed("o/r", "v1", &[("b.cdx.json", OTHER), ("a.cdx.json", SBOM)]);
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "9.9.9"),
            ReleaseSbomOutcome::Ambiguous
        );
    }

    /// Two `.cdx.json` assets, but exactly ONE names the payload's own
    /// version — the tie-break the deposit's own asset selection already
    /// uses, not a guess.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn two_cdx_assets_one_naming_the_payload_version_is_used() {
        const OTHER: &[u8] = b"a different sbom";
        let f = Fixture::signed(
            "o/r",
            "v1",
            &[
                ("other-tool-2.0.0.cdx.json", OTHER),
                ("this-tool-1.0.0.cdx.json", SBOM),
            ],
        );
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::Found(SBOM.to_vec())
        );
    }

    /// Both named the SAME version (or some other reason both still match)
    /// — still ambiguous, never "pick the first one anyway".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn two_cdx_assets_both_naming_the_payload_version_is_still_ambiguous() {
        const OTHER: &[u8] = b"a different sbom";
        let f = Fixture::signed(
            "o/r",
            "v1",
            &[("b-1.0.0.cdx.json", OTHER), ("a-1.0.0.cdx.json", SBOM)],
        );
        assert_eq!(
            release_sbom_outcome(&f, &Forge::github_com(), "o/r", "v1", "1.0.0"),
            ReleaseSbomOutcome::Ambiguous
        );
    }

    // ------------------------------------------------ pgp-sums (REQ-SIGNEDSUMS-001)

    use crate::pgpsums::testkit;

    const LIST: &str = "SHA256SUMS";
    const LIST_SIG: &str = "SHA256SUMS.asc";

    /// A release whose assets are covered by a digest list signed with a
    /// generated key, plus the pinned-key file an operator would commit.
    struct Pgp {
        dir: tempfile::TempDir,
        fingerprint: String,
    }

    impl Pgp {
        fn key_path(&self) -> std::path::PathBuf {
            self.dir.path().join("upstream.asc")
        }
        fn write_key(&self, bytes: &[u8]) {
            std::fs::write(self.key_path(), bytes).unwrap();
        }
    }

    fn list_for(pairs: &[(&str, &[u8])]) -> String {
        pairs
            .iter()
            .map(|(n, b)| format!("{}  {n}\n", sha256_hex(b)))
            .collect()
    }

    /// Publish `pairs` plus a list and its signature, no cosign, no attestation.
    fn pgp_release(
        repo: &str,
        version: &str,
        pairs: &[(&str, &[u8])],
        list: &str,
        signature: Vec<u8>,
        key: &[u8],
        fingerprint: &str,
    ) -> (Fixture, Pgp) {
        let mut f = Fixture::default();
        let k = format!("{repo}@{version}");
        let mut published: Vec<String> = pairs.iter().map(|(n, _)| n.to_string()).collect();
        published.push(LIST.into());
        published.push(LIST_SIG.into());
        for (n, b) in pairs {
            f.blobs.insert(format!("{k}/{n}"), b.to_vec());
        }
        f.blobs
            .insert(format!("{k}/{LIST}"), list.as_bytes().to_vec());
        f.blobs.insert(format!("{k}/{LIST_SIG}"), signature);
        f.probes.insert(
            k,
            ReleaseProbe {
                published,
                ..Default::default()
            },
        );
        let pgp = Pgp {
            dir: tempfile::tempdir().unwrap(),
            fingerprint: fingerprint.to_string(),
        };
        pgp.write_key(key);
        (f, pgp)
    }

    /// The ordinary good case, with a key generated for `uid`.
    fn good_pgp_release(pairs: &[(&str, &[u8])]) -> (Fixture, Pgp, String) {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(pairs);
        let sig = testkit::sign_binary(&secret, list.as_bytes());
        let fpr = hex::encode(pgp::types::KeyDetails::fingerprint(&secret.primary_key).as_bytes());
        let (f, pgp) = pgp_release("o/r", "v1.0", pairs, &list, sig, &key, &fpr);
        (f, pgp, list)
    }

    fn pgp_spec(key_file: std::path::PathBuf) -> crate::plan::PgpSumsPlan {
        crate::plan::PgpSumsPlan {
            list: LIST.into(),
            signature: LIST_SIG.into(),
            format: crate::pgpsums::ListFormat::Sha256Sums,
            version: "1.0".into(),
            release: "v1.0".into(),
            key_file,
        }
    }

    fn pgp_plan(asset: &str, key_file: std::path::PathBuf) -> PayloadPlan {
        let mut p = bound_plan("t", "o/r", "v1.0", asset);
        // The version the signed list was bound to (see `pgp_spec`).
        p.version = "1.0".into();
        p.pgp_sums = Some(pgp_spec(key_file));
        p
    }

    fn run_pgp(
        f: &Fixture,
        plans: &[PayloadPlan],
        optins: &BTreeMap<String, String>,
    ) -> Result<Vec<Resolved>, RunError> {
        run(
            f,
            &Forge::github_com(),
            plans,
            &BTreeMap::new(),
            optins,
            &never,
            &no_reuse,
        )
    }

    fn proof_rejected(e: &RunError) -> &str {
        match e {
            RunError::Ingest(IngestError::ProofRejected { detail, .. }) => detail,
            other => panic!("expected ProofRejected, got {other:?}"),
        }
    }

    /// The whole rung through `run`: the digest comes from the VERIFIED list,
    /// the mechanism is `pgp-sums`, and the signer leads with the fingerprint.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_good_signature_is_recorded_as_pgp_sums_under_the_fingerprint() {
        let (f, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        let got = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].accepted.mechanism, Mechanism::PgpSums);
        assert_eq!(got[0].digest, sha256_hex(A));
        let signer = got[0].accepted.signer.as_deref().unwrap();
        assert!(
            signer.starts_with(&format!("openpgp:{}", pgp.fingerprint)),
            "{signer}"
        );
        // Recorded as its own field whenever pgp-sums vouched; for a primary-key
        // signature it is the primary.
        assert_eq!(
            got[0].accepted.signing_key.as_deref(),
            Some(pgp.fingerprint.as_str())
        );
        let asserts = &got[0].accepted.asserts;
        assert!(
            asserts.contains(&format!("OpenPGP key {}", pgp.fingerprint)),
            "{asserts}"
        );
        assert!(asserts.contains("binary signature"), "{asserts}");
        assert!(
            asserts.contains("not that they are trustworthy"),
            "{asserts}"
        );
        assert!(
            !asserts.contains("signing subkey"),
            "a primary-key signature names no subkey: {asserts}"
        );
    }

    /// A subkey signature names the subkey separately from the identity.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_subkey_signature_records_the_signing_subkey_beside_the_identity() {
        let (secret, key) = testkit::generated_key_with_signing_subkey("Sub <sub@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary_with_subkey(&secret, list.as_bytes());
        let primary =
            hex::encode(pgp::types::KeyDetails::fingerprint(&secret.primary_key).as_bytes());
        let sub = hex::encode(
            pgp::types::KeyDetails::fingerprint(&secret.secret_subkeys[0].key).as_bytes(),
        );
        let (f, pgp) = pgp_release(
            "o/r",
            "v1.0",
            &[("a-1.0.tar.gz", A)],
            &list,
            sig,
            &key,
            &primary,
        );
        let got = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .unwrap();
        let signer = got[0].accepted.signer.as_deref().unwrap();
        assert!(
            signer.starts_with(&format!("openpgp:{primary}")),
            "{signer}"
        );
        assert_eq!(
            got[0].accepted.signing_key.as_deref(),
            Some(sub.as_str()),
            "the subkey that signed is recorded apart from the identity"
        );
        assert!(
            got[0]
                .accepted
                .asserts
                .contains(&format!("signing subkey {sub}")),
            "{}",
            got[0].accepted.asserts
        );
    }

    /// A signature over DIFFERENT bytes is refused, and an operator's opt-in
    /// to ingest unverified does not turn the refusal into an acceptance.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_bad_signature_is_rejected_and_is_neither_upstream_sums_nor_unverified() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, b"a different list");
        let (f, pgp) = pgp_release("o/r", "v1.0", &[("a-1.0.tar.gz", A)], &list, sig, &key, "-");
        let mut optins = BTreeMap::new();
        optins.insert("o/r".to_string(), "carry it anyway".to_string());
        let mut p = pgp_plan("a-1.0.tar.gz", pgp.key_path());
        let e = run_pgp(&f, std::slice::from_ref(&p), &optins).expect_err("must refuse");
        assert!(proof_rejected(&e).contains("does not verify"), "{e}");
        // And the bytes were never fetched on the strength of anything.
        assert!(!f.log().iter().any(|c| c == "fetch o/r@v1.0/a-1.0.tar.gz"));
        // A declared unsigned list is no way around it either.
        p.upstream_sums = Some(LIST.into());
        let e = run_pgp(&f, &[p], &optins).expect_err("must refuse");
        proof_rejected(&e);
    }

    /// A valid signature by some OTHER key is not the pinned key's.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_signature_by_a_different_key_is_rejected() {
        let (_, pinned) = testkit::generated_key("Pinned <pinned@example.invalid>");
        let (other, _) = testkit::generated_key("Other <other@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&other, list.as_bytes());
        let (f, pgp) = pgp_release(
            "o/r",
            "v1.0",
            &[("a-1.0.tar.gz", A)],
            &list,
            sig,
            &pinned,
            "-",
        );
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(proof_rejected(&e).contains("does not verify"), "{e}");
    }

    /// An operator re-pinning an export the upstream has since revoked.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_revoked_pinned_certificate_is_rejected() {
        let (secret, _) = testkit::generated_key("Up Stream <up@example.invalid>");
        let revoked = testkit::revoked_export(&secret);
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, list.as_bytes());
        let (f, pgp) = pgp_release(
            "o/r",
            "v1.0",
            &[("a-1.0.tar.gz", A)],
            &list,
            sig,
            &revoked,
            "-",
        );
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(proof_rejected(&e).contains("revocation"), "{e}");
    }

    /// A TEXT signature binds the line-ending-normalised form, not the bytes.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_text_type_signature_is_rejected() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_text(&secret, list.as_bytes());
        let (f, pgp) = pgp_release("o/r", "v1.0", &[("a-1.0.tar.gz", A)], &list, sig, &key, "-");
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(proof_rejected(&e).contains("binary-document"), "{e}");
    }

    /// Being absent from the verified list is being outside the proof.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_asset_the_verified_list_does_not_name_is_a_failure() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, list.as_bytes());
        let (f, pgp) = pgp_release(
            "o/r",
            "v1.0",
            &[("a-1.0.tar.gz", A), ("b-1.0.tar.gz", B)],
            &list,
            sig,
            &key,
            "-",
        );
        let e = run_pgp(
            &f,
            &[pgp_plan("b-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(
            matches!(&e, RunError::NotCoveredByProof { asset, mechanism, .. }
                if asset == "b-1.0.tar.gz" && *mechanism == "pgp-sums"),
            "{e:?}"
        );
    }

    /// The list verified and the downloaded bytes are not the bytes it names.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_asset_whose_bytes_differ_from_the_verified_list_is_a_failure() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, list.as_bytes());
        let (mut f, pgp) =
            pgp_release("o/r", "v1.0", &[("a-1.0.tar.gz", A)], &list, sig, &key, "-");
        f.blobs.insert("o/r@v1.0/a-1.0.tar.gz".into(), B.to_vec());
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(matches!(e, RunError::DigestMismatch { .. }), "{e:?}");
    }

    /// The key file is read from disk, and its absence is an error — not a
    /// quiet descent to a weaker rung, even with an opt-in standing by.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_missing_key_file_is_an_error_and_not_a_fallback() {
        let (f, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        let mut optins = BTreeMap::new();
        optins.insert("o/r".to_string(), "carry it anyway".to_string());
        let missing = pgp.dir.path().join("not-there.asc");
        let e =
            run_pgp(&f, &[pgp_plan("a-1.0.tar.gz", missing)], &optins).expect_err("must refuse");
        match &e {
            RunError::Io { context, .. } => {
                assert!(context.contains("pgp-key-file"), "{context}");
                assert!(context.contains("not-there.asc"), "{context}");
            }
            other => panic!("expected an Io error, got {other:?}"),
        }
        assert!(
            f.log().iter().all(|c| !c.starts_with("fetch")),
            "nothing may be fetched before the pinned key is in hand: {:?}",
            f.log()
        );
    }

    /// The entry declared a signed list the release does not publish.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_declared_list_the_release_does_not_publish_is_rejected() {
        let (mut f, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        f.probes
            .get_mut("o/r@v1.0")
            .unwrap()
            .published
            .retain(|n| n != LIST_SIG);
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        let d = proof_rejected(&e);
        assert!(
            d.contains(LIST_SIG) && d.contains("does not publish"),
            "{d}"
        );
    }

    /// A list that is published and cannot be fetched is a refusal too.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_list_that_cannot_be_fetched_is_rejected() {
        let (mut f, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        f.blobs.remove(&format!("o/r@v1.0/{LIST}"));
        let e = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .expect_err("must refuse");
        assert!(proof_rejected(&e).contains("could not fetch"), "{e}");
    }

    /// Ladder order through the real orchestration: cosign wins, and the
    /// signed list is not even fetched.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_cosign_capable_release_still_picks_cosign_when_pgp_sums_is_declared() {
        let (_, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        let f = Fixture::signed("o/r", "v1.0", &[("a-1.0.tar.gz", A)]);
        let got = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(got[0].accepted.mechanism, Mechanism::CosignSums);
        assert_eq!(got[0].accepted.signing_key, None);
        assert!(
            !f.log().iter().any(|c| c.contains(LIST)),
            "cosign decided first; the signed list is never consulted: {:?}",
            f.log()
        );
    }

    /// Likewise build provenance.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_attested_release_still_picks_build_provenance_when_pgp_sums_is_declared() {
        let (_, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        let f = Fixture::attested_as_one_batch("o/r", "v1.0", &[("a-1.0.tar.gz", A)]);
        let got = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(got[0].accepted.mechanism, Mechanism::BuildProvenance);
        assert!(!f.log().iter().any(|c| c.contains(LIST)), "{:?}", f.log());
    }

    /// No regression: an entry with only `upstream-sums` is still upstream-sums.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_entry_with_only_upstream_sums_still_yields_upstream_sums() {
        let mut f = Fixture::default();
        let list = list_for(&[("a-1.0.tar.gz", A)]);
        f.blobs.insert("o/r@v1.0/a-1.0.tar.gz".into(), A.to_vec());
        f.blobs
            .insert("o/r@v1.0/sha256.sum".into(), list.as_bytes().to_vec());
        f.probes.insert(
            "o/r@v1.0".into(),
            ReleaseProbe {
                published: vec!["a-1.0.tar.gz".into(), "sha256.sum".into()],
                ..Default::default()
            },
        );
        let mut p = plan("t", "o/r", "v1.0", "a-1.0.tar.gz");
        p.upstream_sums = Some("sha256.sum".into());
        let got = run_pgp(&f, &[p], &BTreeMap::new()).unwrap();
        assert_eq!(got[0].accepted.mechanism, Mechanism::UpstreamSums);
        assert_eq!(got[0].digest, sha256_hex(A));
    }

    // --------------------- the Rust channel, end to end (REQ-SIGNEDSUMS-001, DD-034)

    const CHANNEL: &str = "channel-rust-stable.toml";
    const CHANNEL_SIG: &str = "channel-rust-stable.toml.asc";

    fn rust_spec(key_file: std::path::PathBuf) -> crate::plan::PgpSumsPlan {
        crate::plan::PgpSumsPlan {
            list: CHANNEL.into(),
            signature: CHANNEL_SIG.into(),
            format: crate::pgpsums::ListFormat::RustChannel,
            version: "1.98.1".into(),
            release: "v1.0".into(),
            key_file,
        }
    }

    /// One real `(asset name, digest)` pair out of the real manifest, picked
    /// by looking at the verified entries rather than by writing a digest down.
    fn a_real_rust_asset() -> (String, String) {
        let (_, channel) = crate::pgpsums::verify_and_parse_rust_channel(
            &testkit::rust_manifest(),
            testkit::RUST_SIG_ASC,
            testkit::RUST_KEY_ASC,
        )
        .unwrap();
        let e = channel
            .entries
            .iter()
            .find(|e| {
                e.url
                    .ends_with("/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz")
            })
            .expect("the 2026-09-03 stable channel carries rustc for x86_64 linux");
        (
            e.url.rsplit('/').next().unwrap().to_string(),
            e.sha256.clone(),
        )
    }

    /// A release of the real channel manifest, its real signature, and one
    /// asset whose bytes are NOT the real toolchain (the real one is 90 MB).
    fn rust_release(asset: &str, key: &[u8]) -> (Fixture, Pgp) {
        let mut f = Fixture::default();
        let k = "o/r@v1.0";
        f.blobs
            .insert(format!("{k}/{CHANNEL}"), testkit::rust_manifest());
        f.blobs
            .insert(format!("{k}/{CHANNEL_SIG}"), testkit::RUST_SIG_ASC.to_vec());
        f.blobs.insert(format!("{k}/{asset}"), A.to_vec());
        f.probes.insert(
            k.into(),
            ReleaseProbe {
                published: vec![asset.into(), CHANNEL.into(), CHANNEL_SIG.into()],
                ..Default::default()
            },
        );
        let pgp = Pgp {
            dir: tempfile::tempdir().unwrap(),
            fingerprint: testkit::RUST_PRIMARY_FPR.into(),
        };
        pgp.write_key(key);
        (f, pgp)
    }

    /// The real channel manifest verifies against Rust's real key through the
    /// ladder, an asset named by one of its urls takes its digest from the
    /// VERIFIED list, and the signer leads with Rust's key fingerprint.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_real_rust_channel_vouches_for_an_asset_it_names() {
        let (asset, digest) = a_real_rust_asset();
        let (f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        let spec = rust_spec(pgp.key_path());
        let v = verify_release(
            &f,
            &Forge::github_com(),
            "o/r",
            "v1.0",
            &BTreeMap::new(),
            &Declared {
                upstream_sums: None,
                pgp_sums: Some(&spec),
            },
            std::slice::from_ref(&asset),
        )
        .expect("the real signature verifies against the real key");
        assert_eq!(v.accepted.mechanism, Mechanism::PgpSums);
        let signer = v.accepted.signer.as_deref().unwrap();
        assert!(
            signer.starts_with(&format!("openpgp:{}", testkit::RUST_PRIMARY_FPR)),
            "{signer}"
        );
        assert!(signer.contains("rust-key@rust-lang.org"), "{signer}");
        assert_eq!(
            v.sums.as_ref().unwrap().digest_of(&asset),
            Some(digest.as_str()),
            "the digest must come from the verified list"
        );
    }

    /// Through `run`: the digest the proof states is the real one, so bytes
    /// that are not the real toolchain are refused AGAINST THAT DIGEST — the
    /// refusal quotes the digest from the verified manifest.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn bytes_that_are_not_the_ones_the_real_channel_names_are_refused() {
        let (asset, digest) = a_real_rust_asset();
        let (f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        let mut p = plan("rust", "o/r", "v1.0", &asset);
        p.pgp_sums = Some(rust_spec(pgp.key_path()));
        let e = run_pgp(&f, &[p], &BTreeMap::new()).expect_err("must refuse");
        match e {
            RunError::DigestMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, digest);
                assert_eq!(actual, sha256_hex(A));
            }
            other => panic!("expected a digest mismatch, got {other:?}"),
        }
    }

    /// An asset no url of the verified manifest names is outside the proof.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_asset_the_real_channel_does_not_name_is_not_covered() {
        let (asset, _) = a_real_rust_asset();
        let (mut f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        f.probes
            .get_mut("o/r@v1.0")
            .unwrap()
            .published
            .push("not-in-the-channel.tar.xz".into());
        f.blobs
            .insert("o/r@v1.0/not-in-the-channel.tar.xz".into(), A.to_vec());
        let mut p = plan("rust", "o/r", "v1.0", "not-in-the-channel.tar.xz");
        p.pgp_sums = Some(rust_spec(pgp.key_path()));
        let e = run_pgp(&f, &[p], &BTreeMap::new()).expect_err("must refuse");
        assert!(
            matches!(&e, RunError::NotCoveredByProof { mechanism, .. } if *mechanism == "pgp-sums"),
            "{e:?}"
        );
    }

    /// A manifest changed after signing is refused, not read.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_tampered_channel_manifest_is_rejected() {
        let (asset, _) = a_real_rust_asset();
        let (mut f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        let mut manifest = testkit::rust_manifest();
        manifest.extend_from_slice(b"\n# one more line\n");
        f.blobs.insert(format!("o/r@v1.0/{CHANNEL}"), manifest);
        let mut p = plan("rust", "o/r", "v1.0", &asset);
        p.pgp_sums = Some(rust_spec(pgp.key_path()));
        let e = run_pgp(&f, &[p], &BTreeMap::new()).expect_err("must refuse");
        assert!(proof_rejected(&e).contains("does not verify"), "{e}");
    }

    /// The format is the operator's declaration: a Rust manifest read as a
    /// `sha256sums` list is refused, never half-read.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_channel_read_as_the_wrong_format_is_rejected() {
        let (asset, _) = a_real_rust_asset();
        let (f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        let mut p = plan("rust", "o/r", "v1.0", &asset);
        let mut spec = rust_spec(pgp.key_path());
        spec.format = crate::pgpsums::ListFormat::Sha256Sums;
        p.pgp_sums = Some(spec);
        let e = run_pgp(&f, &[p], &BTreeMap::new()).expect_err("must refuse");
        assert!(proof_rejected(&e).contains("not readable"), "{e}");
    }

    // ------------- one declaration per release; a list is bound to its release

    /// Two plans of one release, from two tools, both asking for `a-1.0.tar.gz`
    /// and `b-1.0.tar.gz`, so a group of two is exercised.
    fn two_tool_group(pgp: &Pgp) -> (Fixture, Vec<PayloadPlan>) {
        let mut f = good_pgp_release(&[("a-1.0.tar.gz", A), ("b-1.0.tar.gz", B)]).0;
        let _ = pgp;
        f.blobs.insert("o/r@v1.0/b-1.0.tar.gz".into(), B.to_vec());
        let mut one = plan("one", "o/r", "v1.0", "a-1.0.tar.gz");
        let mut two = plan("two", "o/r", "v1.0", "b-1.0.tar.gz");
        one.pgp_sums = Some(pgp_spec(pgp.key_path()));
        two.pgp_sums = Some(pgp_spec(pgp.key_path()));
        (f, vec![one, two])
    }

    fn pgp_for_group() -> Pgp {
        // The key the group's release was signed with.
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let _ = secret;
        let pgp = Pgp {
            dir: tempfile::tempdir().unwrap(),
            fingerprint: String::new(),
        };
        pgp.write_key(&key);
        pgp
    }

    /// FAIL-OPEN, closed: one plan declares pgp-sums and its sibling in the
    /// same release declares nothing. Verifying with only the first plan's
    /// declaration would silently skip the other's.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn plans_of_one_release_that_disagree_on_pgp_sums_are_refused() {
        let pgp = pgp_for_group();
        let (f, mut plans) = two_tool_group(&pgp);
        plans[1].pgp_sums = None;
        for order in [false, true] {
            if order {
                plans.reverse();
            }
            let e = run_pgp(&f, &plans, &BTreeMap::new()).expect_err("must refuse");
            match &e {
                RunError::GroupDisagrees { field, tools, .. } => {
                    assert_eq!(*field, "pgp-sums");
                    assert!(tools.contains(&"one".to_string()), "{tools:?}");
                    assert!(tools.contains(&"two".to_string()), "{tools:?}");
                }
                other => panic!("expected GroupDisagrees, got {other:?}"),
            }
            assert!(e.to_string().contains("pgp-sums"), "{e}");
            assert!(
                f.log().iter().all(|c| !c.starts_with("fetch")),
                "refused before anything was fetched: {:?}",
                f.log()
            );
        }
    }

    /// Two declarations that differ in any one field are a disagreement.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn plans_of_one_release_with_different_lists_keys_or_formats_are_refused() {
        let pgp = pgp_for_group();
        type Tweak = fn(&mut crate::plan::PgpSumsPlan);
        let tweaks: [(&str, Tweak); 5] = [
            ("list", |s| s.list = "OTHER".into()),
            ("signature", |s| s.signature = "OTHER.asc".into()),
            ("key", |s| s.key_file = "elsewhere.asc".into()),
            ("format", |s| {
                s.format = crate::pgpsums::ListFormat::RustChannel
            }),
            ("version", |s| s.version = "v2".into()),
        ];
        for (what, tweak) in tweaks {
            let (f, mut plans) = two_tool_group(&pgp);
            tweak(plans[1].pgp_sums.as_mut().unwrap());
            let e = run_pgp(&f, &plans, &BTreeMap::new()).expect_err(what);
            assert!(
                matches!(
                    &e,
                    RunError::GroupDisagrees {
                        field: "pgp-sums",
                        ..
                    }
                ),
                "{what}: {e:?}"
            );
        }
    }

    /// The unsigned list has the same shape of hole.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn plans_of_one_release_that_disagree_on_upstream_sums_are_refused() {
        let pgp = pgp_for_group();
        let (f, mut plans) = two_tool_group(&pgp);
        for p in &mut plans {
            p.pgp_sums = None;
        }
        plans[0].upstream_sums = Some(LIST.into());
        let e = run_pgp(&f, &plans, &BTreeMap::new()).expect_err("must refuse");
        assert!(
            matches!(
                &e,
                RunError::GroupDisagrees {
                    field: "upstream-sums",
                    ..
                }
            ),
            "{e:?}"
        );
    }

    /// The accepting direction: identical declarations are one declaration.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn plans_of_one_release_with_identical_declarations_are_accepted() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let list = list_for(&[("a-1.0.tar.gz", A), ("b-1.0.tar.gz", B)]);
        let sig = testkit::sign_binary(&secret, list.as_bytes());
        let (f, pgp) = pgp_release(
            "o/r",
            "v1.0",
            &[("a-1.0.tar.gz", A), ("b-1.0.tar.gz", B)],
            &list,
            sig,
            &key,
            "-",
        );
        let mut one = plan("one", "o/r", "v1.0", "a-1.0.tar.gz");
        let mut two = plan("two", "o/r", "v1.0", "b-1.0.tar.gz");
        one.pgp_sums = Some(pgp_spec(pgp.key_path()));
        two.pgp_sums = Some(pgp_spec(pgp.key_path()));
        let got = run_pgp(&f, &[one, two], &BTreeMap::new()).unwrap();
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .all(|r| r.accepted.mechanism == Mechanism::PgpSums)
        );
    }

    /// REPLAY, rust-channel: the real 1.98.1 manifest, validly signed, served
    /// for an entry that declares 1.99.0. The asset names are the old ones.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_older_signed_channel_served_for_a_newer_version_is_refused() {
        let (asset, _) = a_real_rust_asset();
        let (f, pgp) = rust_release(&asset, testkit::RUST_KEY_ASC);
        let mut p = plan("rust", "o/r", "v1.0", &asset);
        let mut spec = rust_spec(pgp.key_path());
        spec.version = "1.99.0".into();
        spec.release = "1.99.0".into();
        p.pgp_sums = Some(spec);
        let e = run_pgp(&f, &[p], &BTreeMap::new()).expect_err("must refuse");
        let d = proof_rejected(&e);
        assert!(d.contains("different release"), "{d}");
        assert!(d.contains("1.98.1") && d.contains("1.99.0"), "{d}");
    }

    /// (c) The signed manifest states which release the signature was bound to.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_recorded_assertion_names_the_release_it_was_bound_to() {
        let (f, pgp, _) = good_pgp_release(&[("a-1.0.tar.gz", A)]);
        let got = run_pgp(
            &f,
            &[pgp_plan("a-1.0.tar.gz", pgp.key_path())],
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(
            got[0]
                .accepted
                .asserts
                .contains("digest list for release v1"),
            "{}",
            got[0].accepted.asserts
        );
    }

    /// The same plans an operator's input would produce, so the test goes
    /// through the PLAN path and not around it.
    fn planned(
        version: &str,
        asset: &str,
        key_file: &std::path::Path,
    ) -> Result<Vec<PayloadPlan>, crate::plan::PlanError> {
        let text = format!(
            "[varve]\nversion = \"v0.29.0\"\n\n[realm]\nname = \"r\"\nchannel = \"rolling\"\n\
             registry = \"oci://x\"\n\n[[tool]]\nname = \"t\"\nrepo = \"o/r\"\n\
             version = \"{version}\"\nasset = \"{asset}\"\npgp-sums = \"SUMS-%V\"\n\
             pgp-key-file = \"{}\"\n",
            key_file.display()
        );
        let m = varve_core::layerspec::parse_layer_manifest(&text).expect("parses");
        crate::plan::plan(&m, &["x86_64-unknown-linux-gnu"])
    }

    /// REPLAY, sha256sums, through the plan path: an OLD release's list and
    /// assets are validly signed, and the entry now declares the new release.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_older_signed_list_served_for_a_newer_release_is_refused() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let old = list_for(&[("t-1.0.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, old.as_bytes());
        let (mut f, pgp) = pgp_release("o/r", "2.0", &[("t-1.0.tar.gz", A)], &old, sig, &key, "-");
        // The host serves the list and signature under the NEW release's names
        // and the old bytes under the new asset name.
        for name in ["SUMS-2.0", "SUMS-2.0.asc"] {
            let from = if name.ends_with(".asc") {
                LIST_SIG
            } else {
                LIST
            };
            let bytes = f.blobs.get(&format!("o/r@2.0/{from}")).unwrap().clone();
            f.blobs.insert(format!("o/r@2.0/{name}"), bytes);
            f.probes
                .get_mut("o/r@2.0")
                .unwrap()
                .published
                .push(name.into());
        }
        f.probes
            .get_mut("o/r@2.0")
            .unwrap()
            .published
            .push("t-2.0.tar.gz".into());
        f.blobs.insert("o/r@2.0/t-2.0.tar.gz".into(), A.to_vec());
        let plans = planned("2.0", "t-%V.tar.gz", &pgp.key_path()).expect("a real version plans");
        let e = run_pgp(&f, &plans, &BTreeMap::new()).expect_err("must refuse");
        assert!(
            matches!(&e, RunError::NotCoveredByProof { asset, .. } if asset == "t-2.0.tar.gz"),
            "{e:?}"
        );
    }

    /// REPLAY by MOVING TAG: with a version of `latest` the expanded names are
    /// the same every time, so the old list names exactly what is asked for.
    /// Only the plan can refuse this.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_moving_tag_cannot_be_planned_so_an_old_list_never_covers_it() {
        let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
        let old = list_for(&[("t-latest.tar.gz", A)]);
        let sig = testkit::sign_binary(&secret, old.as_bytes());
        let (_, pgp) = pgp_release(
            "o/r",
            "latest",
            &[("t-latest.tar.gz", A)],
            &old,
            sig,
            &key,
            "-",
        );
        let err = planned("latest", "t-%V.tar.gz", &pgp.key_path()).expect_err("must refuse");
        assert!(
            matches!(err, crate::plan::PlanError::MovingRelease { .. }),
            "{err}"
        );
    }

    /// Ingestion does not trust that the plan ran: every expanded asset name
    /// must contain the concrete version or release it is bound to.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_asset_name_that_carries_no_release_is_refused_at_ingestion() {
        let mut p = pgp_plan("a-1.0.tar.gz", "k.asc".into());
        p.asset = "a.tar.gz".into();
        p.version = "2.0".into();
        p.release = "v2.0".into();
        let e = check_assets_are_bound(&[p], &[0], Mechanism::PgpSums).expect_err("must refuse");
        assert!(
            matches!(&e, RunError::AssetNotBoundToRelease { asset, .. } if asset == "a.tar.gz"),
            "{e:?}"
        );
    }

    /// Ingestion refuses a moving version on its own account too.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_moving_version_is_refused_at_ingestion_even_when_the_name_contains_it() {
        let mut p = pgp_plan("a-1.0.tar.gz", "k.asc".into());
        p.asset = "a-latest.tar.gz".into();
        p.version = "latest".into();
        p.release = "latest".into();
        let e = check_assets_are_bound(&[p], &[0], Mechanism::PgpSums).expect_err("must refuse");
        assert!(
            matches!(e, RunError::AssetNotBoundToRelease { .. }),
            "{e:?}"
        );
    }

    /// Either the version or the release in the name binds it, a leading `v`
    /// is not part of either.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_name_carrying_the_version_or_the_release_is_accepted_at_ingestion() {
        for (asset, version, release) in [
            ("t-1.2.3.tar.gz", "v1.2.3", "release-1.2.3"),
            ("t-1.2.3.tar.gz", "v1.2.3", "v1.2.3"),
            ("t-2026-10-01.tar.gz", "other", "2026-10-01"),
        ] {
            let (secret, key) = testkit::generated_key("Up Stream <up@example.invalid>");
            let list = list_for(&[(asset, A)]);
            let sig = testkit::sign_binary(&secret, list.as_bytes());
            let (f, pgp) = pgp_release("o/r", release, &[(asset, A)], &list, sig, &key, "-");
            let mut p = pgp_plan(asset, pgp.key_path());
            p.version = version.into();
            p.release = release.into();
            let spec = p.pgp_sums.as_mut().unwrap();
            spec.version = version.into();
            spec.release = release.into();
            run_pgp(&f, &[p], &BTreeMap::new())
                .unwrap_or_else(|e| panic!("{asset} {version} {release}: {e}"));
        }
    }

    /// `Source::probe` has no business reporting a pgp-sums state for an entry
    /// that declared none. Whatever it says is overwritten with NotDeclared,
    /// so a stale or hostile probe can neither fail a run nor vouch for one.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_probe_that_reports_a_pgp_state_for_an_undeclared_entry_is_ignored() {
        for state in [
            PgpSumsProbe::Rejected("a probe's own opinion".into()),
            PgpSumsProbe::NotProbed,
        ] {
            let mut f = Fixture::default();
            let list = list_for(&[("a-1.0.tar.gz", A)]);
            f.blobs.insert("o/r@v1.0/a-1.0.tar.gz".into(), A.to_vec());
            f.blobs
                .insert("o/r@v1.0/sha256.sum".into(), list.as_bytes().to_vec());
            f.probes.insert(
                "o/r@v1.0".into(),
                ReleaseProbe {
                    published: vec!["a-1.0.tar.gz".into(), "sha256.sum".into()],
                    pgp_sums: state,
                    ..Default::default()
                },
            );
            let mut p = plan("t", "o/r", "v1.0", "a-1.0.tar.gz");
            p.upstream_sums = Some("sha256.sum".into());
            let got = run_pgp(&f, &[p], &BTreeMap::new()).expect("the probe's value is ignored");
            assert_eq!(got[0].accepted.mechanism, Mechanism::UpstreamSums);
        }
    }

    /// The version must sit on a token boundary in the asset name: declared
    /// `1.2` is not `1.2.3`, `11.2` or `1.2.30`.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_version_must_sit_on_a_token_boundary_in_the_asset_name() {
        let bound = |asset: &str, version: &str| {
            let mut p = bound_plan("t", "o/r", "v1.0", asset);
            p.version = version.into();
            p.release = version.into();
            p.pgp_sums = Some(pgp_spec("k.asc".into()));
            check_assets_are_bound(&[p], &[0], Mechanism::PgpSums)
        };
        for refused in [
            "tool-v1.2.3.tar.gz",
            "tool-11.2.tar.gz",
            "tool-1.2.30-old.tar.gz",
            "tool-1.23.tar.gz",
            "tool-1.2.3",
            "tool-0.1.2.tar.gz",
        ] {
            let e = bound(refused, "1.2").expect_err(refused);
            assert!(
                matches!(&e, RunError::AssetNotBoundToRelease { asset, .. } if asset == refused),
                "{refused}: {e:?}"
            );
        }
        for accepted in [
            "tool-v1.2.tar.gz",
            "tool-1.2-x86_64.tar.gz",
            "tool-1.2.tar.gz",
            "1.2",
            "tool_1.2_linux",
        ] {
            bound(accepted, "1.2").unwrap_or_else(|e| panic!("{accepted}: {e:?}"));
        }
        // One occurrence on a boundary is enough, wherever it is.
        bound("tool-1.2.3-and-1.2.tar.gz", "1.2").expect("the second occurrence is bounded");
        // The release is judged the same way.
        let mut p = bound_plan("t", "o/r", "v1.0", "tool-v1.2.3.tar.gz");
        p.version = "other".into();
        p.release = "1.2".into();
        p.pgp_sums = Some(pgp_spec("k.asc".into()));
        check_assets_are_bound(&[p], &[0], Mechanism::PgpSums)
            .expect_err("release 1.2 is not 1.2.3");
    }

    // ------------- every rung: a proof is bound to the release it is ingested for

    /// The three rungs that were never bound, each with a release whose proof
    /// is for `tag` and whose one asset is `asset`.
    fn rung_fixtures(tag: &str, asset: &str) -> Vec<(&'static str, Fixture, Mechanism)> {
        let mut upstream = Fixture::default();
        let list = list_for(&[(asset, A)]);
        upstream
            .blobs
            .insert(format!("o/r@{tag}/{asset}"), A.to_vec());
        upstream
            .blobs
            .insert(format!("o/r@{tag}/sha256.sum"), list.as_bytes().to_vec());
        upstream.probes.insert(
            format!("o/r@{tag}"),
            ReleaseProbe {
                published: vec![asset.into(), "sha256.sum".into()],
                ..Default::default()
            },
        );
        vec![
            (
                "cosign-sums",
                Fixture::signed("o/r", tag, &[(asset, A)]),
                Mechanism::CosignSums,
            ),
            (
                "build-provenance",
                Fixture::attested_as_one_batch("o/r", tag, &[(asset, A)]),
                Mechanism::BuildProvenance,
            ),
            ("upstream-sums", upstream, Mechanism::UpstreamSums),
        ]
    }

    fn run_plan(f: &Fixture, p: PayloadPlan) -> Result<Vec<Resolved>, RunError> {
        run_pgp(f, &[p], &BTreeMap::new())
    }

    fn with_sums(mut p: PayloadPlan, rung: &str) -> PayloadPlan {
        if rung == "upstream-sums" {
            p.upstream_sums = Some("sha256.sum".into());
        }
        p
    }

    /// REPLAY: an older release's bytes, under an asset name that carries the
    /// OLDER version, presented for the newer tag are refused on every rung,
    /// before anything is fetched.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_older_releases_assets_served_for_a_newer_tag_are_refused_on_every_rung() {
        for (rung, f, _) in rung_fixtures("v2.0.0", "t-1.0.0.tar.gz") {
            let p = with_sums(bound_plan("t", "o/r", "v2.0.0", "t-1.0.0.tar.gz"), rung);
            let e = run_plan(&f, p).expect_err(rung);
            assert!(
                matches!(&e, RunError::AssetNotBoundToRelease { asset, .. } if asset == "t-1.0.0.tar.gz"),
                "{rung}: {e:?}"
            );
            assert!(
                f.log().iter().all(|c| !c.ends_with("t-1.0.0.tar.gz")),
                "{rung}: the payload is not fetched for a refused name: {:?}",
                f.log()
            );
        }
    }

    /// A name that carries no release at all is refused the same way, and one
    /// that carries THIS release is accepted on every rung.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_versionless_asset_is_refused_at_ingestion_on_every_rung_and_a_versioned_one_passes() {
        for (rung, f, _) in rung_fixtures("v2.0.0", "t.tar.gz") {
            let p = with_sums(bound_plan("t", "o/r", "v2.0.0", "t.tar.gz"), rung);
            let e = run_plan(&f, p).expect_err(rung);
            assert!(
                matches!(e, RunError::AssetNotBoundToRelease { .. }),
                "{rung}: {e:?}"
            );
        }
        for (rung, f, mechanism) in rung_fixtures("v2.0.0", "t-2.0.0.tar.gz") {
            let p = with_sums(bound_plan("t", "o/r", "v2.0.0", "t-2.0.0.tar.gz"), rung);
            let got = run_plan(&f, p).unwrap_or_else(|e| panic!("{rung}: {e}"));
            assert_eq!(got[0].accepted.mechanism, mechanism, "{rung}");
            assert!(
                !got[0].accepted.asserts.contains("NOT BOUND"),
                "a bound entry carries no annotation: {}",
                got[0].accepted.asserts
            );
        }
    }

    /// `unbound-release-reason` lets a versionless asset through on every rung,
    /// and the reason is recorded in the proof annotation the signed manifest
    /// carries, in the operator's words.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unbound_release_reason_lets_it_through_and_is_recorded_on_every_rung() {
        let why = "upstream names its binaries with no version";
        for (rung, f, mechanism) in rung_fixtures("v2.0.0", "t.tar.gz") {
            let mut p = with_sums(bound_plan("t", "o/r", "v2.0.0", "t.tar.gz"), rung);
            p.unbound_release_reason = Some(why.into());
            let got = run_plan(&f, p).unwrap_or_else(|e| panic!("{rung}: {e}"));
            assert_eq!(got[0].accepted.mechanism, mechanism, "{rung}");
            let asserts = &got[0].accepted.asserts;
            assert!(asserts.contains(why), "{rung}: {asserts}");
            assert!(asserts.contains("NOT BOUND"), "{rung}: {asserts}");
            assert!(
                asserts.contains("WAIVED"),
                "{rung}: the binding was waived, and the record says so: {asserts}"
            );
        }
    }

    /// An `unverified-reason` on an entry whose release then resolves to a
    /// proven rung does not waive the name check, through `run`.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_opt_in_reason_does_not_waive_the_name_check_on_a_proven_release() {
        for (rung, f, _) in rung_fixtures("v2.0.0", "t.tar.gz") {
            let mut p = with_sums(bound_plan("t", "o/r", "v2.0.0", "t.tar.gz"), rung);
            p.unverified_reason = Some("nothing published".into());
            let optins = BTreeMap::from([("o/r".to_string(), "nothing published".to_string())]);
            let e = run_pgp(&f, &[p], &optins).expect_err(rung);
            assert!(
                matches!(e, RunError::AssetNotBoundToRelease { .. }),
                "{rung}: {e:?}"
            );
        }
        // A release nothing vouches for, ingested on the opt-in, passes.
        let mut f = Fixture::default();
        f.blobs.insert("o/r@v2.0.0/t.tar.gz".into(), A.to_vec());
        f.probes.insert(
            "o/r@v2.0.0".into(),
            ReleaseProbe {
                published: vec!["t.tar.gz".into()],
                ..Default::default()
            },
        );
        let mut p = bound_plan("t", "o/r", "v2.0.0", "t.tar.gz");
        p.unverified_reason = Some("nothing published".into());
        let optins = BTreeMap::from([("o/r".to_string(), "nothing published".to_string())]);
        let got = run_pgp(&f, &[p], &optins).expect("the opt-in is accepted");
        assert_eq!(got[0].accepted.mechanism, Mechanism::Unverified);
    }

    /// An asset that carries only the plan's VERSION, when the version and the
    /// release tag name different releases, is refused at ingestion: the
    /// release the group is fetched under is what the name must carry.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_asset_carrying_only_a_mismatched_version_is_refused_at_ingestion() {
        for (rung, f, _) in rung_fixtures("v0.7.2", "t-0.2.2.tar.gz") {
            let mut p = with_sums(bound_plan("t", "o/r", "v0.7.2", "t-0.2.2.tar.gz"), rung);
            p.version = "0.2.2".into();
            let e = run_plan(&f, p).expect_err(rung);
            assert!(
                matches!(e, RunError::AssetNotBoundToRelease { .. }),
                "{rung}: {e:?}"
            );
        }
        // The release tag in the name passes, and so does a consistent pair
        // whose name carries the version.
        for (rung, f, _) in rung_fixtures("v1.2.3", "t-1.2.3.tar.gz") {
            let p = with_sums(bound_plan("t", "o/r", "v1.2.3", "t-1.2.3.tar.gz"), rung);
            run_plan(&f, p).unwrap_or_else(|e| panic!("{rung}: {e}"));
        }
        let mut p = bound_plan("t", "o/r", "v1.2.3", "t-v1.2.3.tar.gz");
        p.version = "1.2.3".into();
        check_assets_are_bound(&[p], &[0], Mechanism::CosignSums).expect("consistent pair");
    }

    /// An unverified opt-in carries its own recorded exception, and a Rust
    /// channel binds through its manifest's own version: neither is refused by
    /// the name rule.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_opt_in_and_a_rust_channel_are_not_subject_to_the_name_rule() {
        let mut p = bound_plan("t", "o/r", "v2.0.0", "t.tar.gz");
        check_assets_are_bound(std::slice::from_ref(&p), &[0], Mechanism::CosignSums)
            .expect_err("a bound plan is checked");
        // An opt-in reason is no exemption from a SIGNED rung: only the
        // unverified mechanism actually accepted is its own exception.
        p.unverified_reason = Some("nothing published".into());
        for signed in [
            Mechanism::CosignSums,
            Mechanism::BuildProvenance,
            Mechanism::PgpSums,
            Mechanism::UpstreamSums,
        ] {
            check_assets_are_bound(std::slice::from_ref(&p), &[0], signed)
                .expect_err("an opt-in reason does not exempt a proven release");
        }
        check_assets_are_bound(std::slice::from_ref(&p), &[0], Mechanism::Unverified)
            .expect("an accepted opt-in is its own exception");
        let mut p = bound_plan("t", "o/r", "v2.0.0", "rustc.tar.xz");
        p.pgp_sums = Some(rust_spec("k.asc".into()));
        check_assets_are_bound(&[p], &[0], Mechanism::PgpSums)
            .expect("a channel binds through its own version");
    }
}
