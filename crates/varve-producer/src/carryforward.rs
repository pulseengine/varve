//! Doing the work that changed, and re-proving the work that did not
//! (REQ-CARRYFORWARD-001).
//!
//! Every deposit currently downloads all four platforms of every tool — 421
//! MiB for layer 2026.08.4 — re-hashes and re-pushes them, even when one tool
//! moved. Consumers never pay this: `install` filters by platform before
//! fetching, so a machine pulls 99 MiB. The waste is the producer's, and daily
//! scanning multiplies it by the cadence.
//!
//! The previous layer's **signed** manifest already records each payload's
//! repo, release, asset and sha256. When the manifest still pins that release,
//! the bytes are already in the registry under that digest.
//!
//! ## The trap, which is the whole design
//!
//! A release asset can be deleted and re-uploaded under the same tag. "rivet
//! v0.34.0" today is not necessarily the bytes it was yesterday. Carrying a
//! digest forward because the *version string* matched would make varve blind
//! to precisely the substitution it exists to catch — and it would be blind
//! silently, because every later check would agree with the carried digest.
//!
//! So the saving comes from skipping the **download**, never from skipping the
//! **proof**. The ingestion proof is re-established every time; a sums file is
//! kilobytes and the binary it describes is tens of megabytes. Only once
//! upstream's CURRENT digest is in hand, and equal, do the bytes go unfetched.
//!
//! When they disagree, that is not a cache miss. It is an upstream that
//! re-published a release under the same version, and it stops the deposit.

use std::fmt;

/// What the previous layer's signed manifest recorded for one payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousEntry {
    pub repo: String,
    pub release: String,
    pub asset: String,
    /// The sha256 the previous deposit recorded, transcribed from a verified
    /// sums file or attestation at that time.
    pub sha256: String,
}

/// What to do about one payload this time round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Bytes already in the registry under a digest upstream still vouches
    /// for. Nothing to download, nothing to push.
    Reuse { sha256: String },
    /// Fetch and stage normally, for the stated reason — reasons are kept so
    /// a deposit can report WHY it did the expensive thing.
    Fetch { why: FetchReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchReason {
    /// No previous layer, or this payload is new to the layer.
    NoPrevious,
    /// The manifest pins a different release than last time.
    ReleaseChanged,
    /// The asset name changed even though the release did not — a template
    /// edit, or upstream renaming its archive.
    AssetChanged,
    /// Digests agree, but the blob is no longer in the destination registry.
    BlobAbsent,
}

impl FetchReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FetchReason::NoPrevious => "no previous entry",
            FetchReason::ReleaseChanged => "release changed",
            FetchReason::AssetChanged => "asset name changed",
            FetchReason::BlobAbsent => "blob absent from the registry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarryError {
    /// Upstream re-published the same release with different bytes.
    UpstreamRepublished {
        repo: String,
        release: String,
        asset: String,
        previously: String,
        now: String,
    },
}

impl fmt::Display for CarryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CarryError::UpstreamRepublished {
                repo,
                release,
                asset,
                previously,
                now,
            } => write!(
                f,
                "{repo} {release} now publishes {asset} with a DIFFERENT digest \
                 than the layer already signed:\n  previously  {previously}\n  \
                 now         {now}\nThe release tag did not change, so the \
                 bytes behind it were replaced. That is either an upstream \
                 re-release or a substitution, and varve cannot tell which — \
                 which is exactly why it will not choose. Establish what \
                 happened upstream, then either pin the new release explicitly \
                 or stop carrying this tool."
            ),
        }
    }
}

impl std::error::Error for CarryError {}

/// Decide what to do about one payload.
///
/// `upstream_sha256` is what a FRESHLY verified sums file or attestation says
/// the asset hashes to, right now. Obtaining it is the proof step, and it is
/// unconditional — this function is called with it in hand, never instead of
/// it.
pub fn decide(
    previous: Option<&PreviousEntry>,
    repo: &str,
    release: &str,
    asset: &str,
    upstream_sha256: &str,
    blob_present_in_registry: bool,
) -> Result<Decision, CarryError> {
    let Some(prev) = previous else {
        return Ok(Decision::Fetch {
            why: FetchReason::NoPrevious,
        });
    };
    if prev.repo != repo || prev.release != release {
        return Ok(Decision::Fetch {
            why: FetchReason::ReleaseChanged,
        });
    }
    if prev.asset != asset {
        return Ok(Decision::Fetch {
            why: FetchReason::AssetChanged,
        });
    }
    // Same repo, same release, same asset — and now the question that makes
    // this safe rather than merely fast.
    if !digest_eq(&prev.sha256, upstream_sha256) {
        return Err(CarryError::UpstreamRepublished {
            repo: repo.to_string(),
            release: release.to_string(),
            asset: asset.to_string(),
            previously: prev.sha256.clone(),
            now: upstream_sha256.to_string(),
        });
    }
    if !blob_present_in_registry {
        // A manifest entry is a record, not a guarantee of storage: a registry
        // can garbage-collect, and a realm can be re-hosted.
        return Ok(Decision::Fetch {
            why: FetchReason::BlobAbsent,
        });
    }
    Ok(Decision::Reuse {
        sha256: prev.sha256.clone(),
    })
}

/// Compare digests without letting spelling decide a trust question.
///
/// One side may be `sha256:`-prefixed (the OCI form) and the other bare (the
/// sums-file form), and case differs between tools. A comparison that treated
/// those as different would fetch needlessly; one that ignored more than case
/// and prefix would compare the wrong thing.
fn digest_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_start_matches("sha256:").to_ascii_lowercase();
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn prev() -> PreviousEntry {
        PreviousEntry {
            repo: "pulseengine/rivet".into(),
            release: "v0.34.0".into(),
            asset: "rivet-v0.34.0-aarch64-apple-darwin.tar.gz".into(),
            sha256: D1.into(),
        }
    }

    fn decide_same(upstream: &str, present: bool) -> Result<Decision, CarryError> {
        let p = prev();
        decide(
            Some(&p),
            "pulseengine/rivet",
            "v0.34.0",
            "rivet-v0.34.0-aarch64-apple-darwin.tar.gz",
            upstream,
            present,
        )
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn an_unchanged_payload_upstream_still_vouches_for_is_reused() {
        assert_eq!(
            decide_same(D1, true).expect("reuses"),
            Decision::Reuse { sha256: D1.into() }
        );
    }

    /// THE reason this is not a version-string cache. Upstream can delete and
    /// re-upload an asset under the same tag; reusing on the strength of the
    /// version alone would make varve blind to the substitution it exists to
    /// catch, and blind silently.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn an_upstream_that_republished_the_same_release_aborts() {
        let err = decide_same(D2, true).expect_err("must abort");
        assert_eq!(
            err,
            CarryError::UpstreamRepublished {
                repo: "pulseengine/rivet".into(),
                release: "v0.34.0".into(),
                asset: "rivet-v0.34.0-aarch64-apple-darwin.tar.gz".into(),
                previously: D1.into(),
                now: D2.into(),
            }
        );
        let msg = err.to_string();
        assert!(
            msg.contains(D1) && msg.contains(D2),
            "both digests must be named: {msg}"
        );
        assert!(msg.contains("varve cannot tell which"), "{msg}");
    }

    /// It must abort even when the blob is gone — the substitution is the
    /// finding, and a missing blob does not make it a routine fetch.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_republished_upstream_aborts_even_when_the_blob_is_absent() {
        assert!(matches!(
            decide_same(D2, false),
            Err(CarryError::UpstreamRepublished { .. })
        ));
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_missing_blob_is_fetched_even_though_the_digest_agrees() {
        assert_eq!(
            decide_same(D1, false).expect("fetches"),
            Decision::Fetch {
                why: FetchReason::BlobAbsent
            }
        );
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_new_payload_is_fetched() {
        assert_eq!(
            decide(None, "r", "v1", "a.tar.gz", D1, true).expect("fetches"),
            Decision::Fetch {
                why: FetchReason::NoPrevious
            }
        );
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_version_bump_is_fetched_and_says_so() {
        let p = prev();
        assert_eq!(
            decide(
                Some(&p),
                "pulseengine/rivet",
                "v0.35.0",
                "rivet-v0.35.0-aarch64-apple-darwin.tar.gz",
                D2,
                true
            )
            .expect("fetches"),
            Decision::Fetch {
                why: FetchReason::ReleaseChanged
            }
        );
    }

    /// A repo change at the same version is not the same payload, and must not
    /// inherit the previous digest.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_repo_change_at_the_same_version_is_fetched() {
        let p = prev();
        assert_eq!(
            decide(
                Some(&p),
                "acme/rivet",
                "v0.34.0",
                "rivet-v0.34.0-aarch64-apple-darwin.tar.gz",
                D1,
                true
            )
            .expect("fetches"),
            Decision::Fetch {
                why: FetchReason::ReleaseChanged
            }
        );
    }

    /// A template edit renames the asset without moving the release.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn an_asset_rename_at_the_same_release_is_fetched() {
        let p = prev();
        assert_eq!(
            decide(
                Some(&p),
                "pulseengine/rivet",
                "v0.34.0",
                "rivet-0.34.0-aarch64-apple-darwin.tar.gz",
                D1,
                true
            )
            .expect("fetches"),
            Decision::Fetch {
                why: FetchReason::AssetChanged
            }
        );
    }

    /// The OCI form and the sums-file form of the same digest are the same
    /// digest. Treating them as different would fetch needlessly; ignoring
    /// more than case and prefix would compare the wrong thing.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn the_two_spellings_of_one_digest_agree_and_nothing_looser_does() {
        assert!(digest_eq(D1, &format!("sha256:{D1}")));
        assert!(digest_eq(&D1.to_uppercase(), D1));
        assert!(digest_eq(&format!("  {D1}  "), D1));
        assert!(!digest_eq(D1, D2));
        // An empty digest is not equal to anything, including another empty
        // one — "we have no digest" must never satisfy a comparison.
        assert!(!digest_eq("", ""));
        assert!(!digest_eq("sha256:", ""));
        // A prefix is not a match.
        assert!(!digest_eq(&D1[..32], D1));
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn every_fetch_reason_can_say_why() {
        for r in [
            FetchReason::NoPrevious,
            FetchReason::ReleaseChanged,
            FetchReason::AssetChanged,
            FetchReason::BlobAbsent,
        ] {
            assert!(!r.as_str().is_empty());
        }
        assert_eq!(
            FetchReason::BlobAbsent.as_str(),
            "blob absent from the registry"
        );
        assert_eq!(FetchReason::NoPrevious.as_str(), "no previous entry");
    }
}
