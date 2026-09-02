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
use crate::ingest::{self, Accepted, IngestError, Mechanism, ReleaseProbe};
use crate::plan::PayloadPlan;
use crate::sums::Sums;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// What a verified release established, and what it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub accepted: Accepted,
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
    /// The in-toto statement `gh attestation verify` accepted.
    fn attestation_json(&self, repo: &str, version: &str) -> Result<String, RunError>;
    fn asset_bytes(&self, repo: &str, version: &str, asset: &str) -> Result<Vec<u8>, RunError>;
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

/// Verify one release, once.
pub fn verify_release<S: Source>(
    src: &S,
    forge: &Forge,
    repo: &str,
    version: &str,
    optins: &BTreeMap<String, String>,
) -> Result<Verified, RunError> {
    let probe = src.probe(forge, repo, version)?;
    let accepted = ingest::choose(forge, repo, version, &probe, optins)?;
    let sums = match accepted.mechanism {
        Mechanism::CosignSums => {
            let text = src.sums_text(repo, version)?;
            Some(Sums::parse(&text).map_err(|e| RunError::Io {
                context: format!("{repo} {version}: reading the verified SHA256SUMS.txt"),
                detail: e.to_string(),
            })?)
        }
        Mechanism::BuildProvenance => {
            let json = src.attestation_json(repo, version)?;
            Some(
                crate::attestation::parse(&json)
                    .map_err(|e| RunError::Io {
                        context: format!("{repo} {version}: reading the verified attestation"),
                        detail: e.to_string(),
                    })?
                    .sums,
            )
        }
        // No proof was offered and an operator said to proceed anyway. There
        // is no list of covered digests because there is no list.
        Mechanism::Unverified => None,
    };
    Ok(Verified { accepted, sums })
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
        let key = (p.repo.clone(), p.version.clone());
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

/// Walk the whole plan.
pub fn run<S: Source>(
    src: &S,
    forge: &Forge,
    plans: &[PayloadPlan],
    previous: &BTreeMap<String, PreviousEntry>,
    optins: &BTreeMap<String, String>,
    blob_present: &dyn Fn(&str) -> bool,
) -> Result<Vec<Resolved>, RunError> {
    let mut out: Vec<Option<Resolved>> = vec![None; plans.len()];
    let mut seen = ingest::VerifiedRepos::new();
    for ((repo, version), idxs) in by_release(plans) {
        // Verified ONCE per release, before any of its payloads are touched.
        let v = verify_release(src, forge, &repo, &version, optins)?;
        seen.record(&repo, &version, v.accepted.clone())?;
        for i in idxs {
            let p = &plans[i];
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
                    previous.get(&p.name),
                    &repo,
                    &version,
                    &p.asset,
                    &upstream,
                    blob_present(&upstream),
                )
                .map_err(RunError::Carry)?
            };
            let (digest, bytes) = match &decision {
                // Nothing to download: the proof already matched what the
                // registry holds.
                Decision::Reuse { .. } => (upstream.clone(), None),
                Decision::Fetch { .. } => {
                    let b = src.asset_bytes(&repo, &version, &p.asset)?;
                    let d = admit(&v, &repo, &p.asset, &b)?;
                    (d, Some(b))
                }
            };
            out[i] = Some(Resolved {
                plan: p.clone(),
                digest,
                accepted: v.accepted.clone(),
                bytes,
                decision,
            });
        }
    }
    Ok(out
        .into_iter()
        .map(|r| r.expect("every index was assigned by its release group"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::PayloadKind;

    const A: &[u8] = b"the real bytes";
    const B: &[u8] = b"different bytes";

    fn plan(name: &str, repo: &str, version: &str, asset: &str) -> PayloadPlan {
        PayloadPlan {
            name: name.into(),
            repo: repo.into(),
            version: version.into(),
            asset: asset.into(),
            platform: Some("x86_64-unknown-linux-gnu".into()),
            kind: PayloadKind::Tarball,
            unverified_reason: None,
        }
    }

    /// Records what was asked of it, so ordering and call-count are testable.
    #[derive(Default)]
    struct Fixture {
        sums: BTreeMap<String, String>,
        blobs: BTreeMap<String, Vec<u8>>,
        probes: BTreeMap<String, ReleaseProbe>,
        calls: std::cell::RefCell<Vec<String>>,
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
                    has_sums: true,
                    has_cosign_bundle: true,
                    cosign: Some(Ok(())),
                    ..Default::default()
                },
            );
            f
        }
        fn with(mut self, other: Fixture) -> Self {
            self.sums.extend(other.sums);
            self.blobs.extend(other.blobs);
            self.probes.extend(other.probes);
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
        fn attestation_json(&self, _r: &str, _v: &str) -> Result<String, RunError> {
            unimplemented!("not reached by these fixtures")
        }
        fn asset_bytes(&self, repo: &str, version: &str, asset: &str) -> Result<Vec<u8>, RunError> {
            let k = format!("{repo}@{version}/{asset}");
            self.calls.borrow_mut().push(format!("fetch {k}"));
            self.blobs.get(&k).cloned().ok_or(RunError::Io {
                context: k,
                detail: "no such asset".into(),
            })
        }
    }

    fn never(_: &str) -> bool {
        false
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

    /// Being absent from a signed list is being outside the proof. The
    /// tempting bug is to accept it "because the sums file verified".
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_asset_the_proof_does_not_name_is_not_covered_by_it() {
        let f = Fixture::signed("o/r", "v1", &[("a.tar.gz", A)]);
        let e = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "elsewhere.tar.gz")],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &never,
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
            "t".to_string(),
            PreviousEntry {
                repo: "o/r".into(),
                release: "v1".into(),
                asset: "a.tar.gz".into(),
                sha256: sha256_hex(A),
            },
        );
        let present = |d: &str| d == sha256_hex(A);
        let got = run(
            &f,
            &Forge::github_com(),
            &[plan("t", "o/r", "v1", "a.tar.gz")],
            &prev,
            &BTreeMap::new(),
            &present,
        )
        .expect("runs");
        assert!(
            matches!(got[0].decision, Decision::Reuse { .. }),
            "{:?}",
            got[0].decision
        );
        assert!(got[0].bytes.is_none());
        assert_eq!(got[0].digest, sha256_hex(A));
        // Still verified: the proof is what told us it was unchanged.
        let log = f.log();
        assert!(log.iter().any(|c| c.starts_with("sums ")), "{log:?}");
        assert!(!log.iter().any(|c| c.starts_with("fetch ")), "{log:?}");
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
            accepted: Accepted {
                mechanism: Mechanism::Unverified,
                signer: "nobody".into(),
                asserts: "no proof was offered".into(),
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
        )
        .expect_err("must refuse");
        assert!(
            matches!(&e, RunError::Ingest(IngestError::RepoAtTwoVersions { .. })),
            "{e:?}"
        );
    }
}
