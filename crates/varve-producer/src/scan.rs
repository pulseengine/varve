//! What moved upstream (REQ-SCAN-001).
//!
//! Layer 2026.09.2 was deposited on 2026-09-09 and was ALREADY four tools
//! behind when it landed — rivet, synth (four minor versions), meld and kiln.
//! Nothing was watching. The only scanner in the organisation lived in varve,
//! read its pins out of the legacy deposit workflow's env-var encoding, and had
//! been failing for three days because the realm moved out from under it. It
//! only ran on a schedule, where nobody looks.
//!
//! This is the comparison, kept PURE so it can be tested against fixtures
//! rather than only exercised by a cron job. Asking the network is the caller's
//! job; deciding what the answers mean is here.

use std::collections::BTreeMap;

use varve_core::layerspec::LayerManifest;

/// A pinned payload whose upstream has published something newer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub name: String,
    pub repo: String,
    pub pinned: String,
    pub latest: String,
}

/// Why a scan produced no usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// One or more upstreams could not be asked.
    ///
    /// NOT a variant that can be confused with "nothing moved", and that is the
    /// whole reason it exists. A scanner that reported no movement because it
    /// could not ask would freeze the realm while every check stayed green —
    /// releases would simply stop arriving and nobody would be told. Loud is
    /// the cheaper failure.
    Unreachable { repos: Vec<(String, String)> },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Unreachable { repos } => {
                writeln!(
                    f,
                    "{} upstream(s) could not be asked what they have published:",
                    repos.len()
                )?;
                for (repo, why) in repos {
                    writeln!(f, "  {repo}: {why}")?;
                }
                write!(
                    f,
                    "Refusing to report movement from an incomplete scan. \"I could not \
                     ask\" is not \"nothing moved\", and a realm that stops receiving \
                     releases while every check stays green is the failure nobody notices."
                )
            }
        }
    }
}

/// The repository a manifest entry names, defaulting the owner.
///
/// Same rule `layerspec` applies when it builds the ingest set: an absent
/// `repo` means `pulseengine/<name>`. Duplicated nowhere — a second spelling of
/// this default would let the scanner ask a different repository than the
/// deposit fetches from, and report movement for something that is never
/// carried.
pub fn repo_of(name: &str, repo: Option<&str>) -> String {
    match repo {
        Some(r) => r.to_string(),
        None => format!("pulseengine/{name}"),
    }
}

/// Compare the manifest's pins against what each upstream has published.
///
/// `latest` maps repository to either its newest release tag or the reason it
/// could not be asked. Every failure is collected rather than the first one
/// returned: an operator fixing access wants the whole list, not one repo at a
/// time across successive scans.
pub fn compare(
    manifest: &LayerManifest,
    latest: &BTreeMap<String, Result<String, String>>,
) -> Result<Vec<Moved>, ScanError> {
    let mut moved = Vec::new();
    let mut unreachable = Vec::new();
    for t in &manifest.tools {
        let repo = repo_of(&t.name, t.repo.as_deref());
        match latest.get(&repo) {
            Some(Ok(newest)) => {
                if newest != &t.version {
                    moved.push(Moved {
                        name: t.name.clone(),
                        repo,
                        pinned: t.version.clone(),
                        latest: newest.clone(),
                    });
                }
            }
            Some(Err(why)) => unreachable.push((repo, why.clone())),
            // Not asked at all is the same fact as asked-and-failed: the scan
            // is incomplete, and an incomplete scan may not report movement.
            None => unreachable.push((repo, "not queried".to_string())),
        }
    }
    if !unreachable.is_empty() {
        return Err(ScanError::Unreachable { repos: unreachable });
    }
    Ok(moved)
}

/// Autonomous deposit is permitted only for a channel that makes no
/// qualification promise (REQ-SCAN-001 clause 5).
///
/// `rolling` says outright that it promises nothing, so a layer arriving
/// without a person having judged it is consistent with what consumers were
/// already told. `qualified` promises the opposite. A scanner that treated the
/// two alike would hand qualified consumers the guarantee rolling explicitly
/// declines to make — silently, and at machine speed.
///
/// Read from the MANIFEST rather than taken from the caller: a flag is a claim,
/// and the realm's own file is the fact.
pub fn autonomous_deposit_permitted(manifest: &LayerManifest) -> Result<(), String> {
    match manifest.realm.channel.as_str() {
        "rolling" => Ok(()),
        other => Err(format!(
            "channel {other:?} does not permit an unattended deposit. Only a channel \
             that makes no qualification promise may be deposited without a person \
             judging the release — `rolling` says so in as many words, and {other:?} \
             does not. Dispatch the deposit by hand."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(tools: &str, channel: &str) -> LayerManifest {
        let src = format!(
            "[varve]\nversion = \"v0.33.0\"\n\n[realm]\nname = \"pulseengine\"\n\
             channel = \"{channel}\"\nregistry = \"oci://ghcr.io/pulseengine/layers\"\n\n{tools}"
        );
        varve_core::layerspec::parse_layer_manifest(&src).expect("fixture manifest parses")
    }

    fn seen(pairs: &[(&str, Result<&str, &str>)]) -> BTreeMap<String, Result<String, String>> {
        pairs
            .iter()
            .map(|(r, v)| {
                (
                    r.to_string(),
                    match v {
                        Ok(t) => Ok(t.to_string()),
                        Err(e) => Err(e.to_string()),
                    },
                )
            })
            .collect()
    }

    const TWO: &str = "[[tool]]\nname = \"meld\"\nversion = \"v0.53.0\"\n\n\
                       [[tool]]\nname = \"loom\"\nrepo = \"pulseengine/loom\"\nversion = \"v1.4.1\"\n";

    /// The case that motivated this: a layer deposited already behind.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_pin_behind_its_upstream_is_reported_with_both_versions() {
        let got = compare(
            &manifest(TWO, "rolling"),
            &seen(&[
                ("pulseengine/meld", Ok("v0.55.1")),
                ("pulseengine/loom", Ok("v1.4.1")),
            ]),
        )
        .expect("a complete scan");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].name, "meld");
        assert_eq!(got[0].pinned, "v0.53.0");
        assert_eq!(got[0].latest, "v0.55.1");
        assert_eq!(got[0].repo, "pulseengine/meld");
    }

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn nothing_moved_is_an_empty_list_not_an_error() {
        let got = compare(
            &manifest(TWO, "rolling"),
            &seen(&[
                ("pulseengine/meld", Ok("v0.53.0")),
                ("pulseengine/loom", Ok("v1.4.1")),
            ]),
        )
        .expect("a complete scan");
        assert!(got.is_empty(), "{got:?}");
    }

    /// CLAUSE 2, and the reason the type is shaped this way. An upstream that
    /// cannot be asked must never be reported as one that did not move: the
    /// realm would stop receiving releases while every check stayed green.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn an_upstream_that_cannot_be_asked_is_never_reported_as_unmoved() {
        let err = compare(
            &manifest(TWO, "rolling"),
            &seen(&[
                ("pulseengine/meld", Err("HTTP 403: rate limited")),
                ("pulseengine/loom", Ok("v1.4.1")),
            ]),
        )
        .expect_err("an incomplete scan must not report movement");
        let ScanError::Unreachable { repos } = &err;
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].0, "pulseengine/meld");
        let msg = err.to_string();
        assert!(msg.contains("rate limited"), "names the reason: {msg}");
        assert!(
            msg.contains("is not") && msg.contains("nothing moved"),
            "says why silence would be worse: {msg}"
        );
    }

    /// An upstream nobody asked about is the same fact as one that failed. It
    /// is the easier bug to write — a lookup loop that skips a repo leaves the
    /// map short, and a scanner that ignored the gap would under-report.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_repository_missing_from_the_answers_is_an_incomplete_scan() {
        let err = compare(
            &manifest(TWO, "rolling"),
            &seen(&[("pulseengine/meld", Ok("v0.53.0"))]),
        )
        .expect_err("a short answer map is an incomplete scan");
        let ScanError::Unreachable { repos } = &err;
        assert_eq!(repos[0].0, "pulseengine/loom");
    }

    /// Every failure at once. An operator fixing access wants the whole list,
    /// not one repository per scan across successive runs.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn every_unreachable_upstream_is_reported_together() {
        let err = compare(
            &manifest(TWO, "rolling"),
            &seen(&[
                ("pulseengine/meld", Err("no such repo")),
                ("pulseengine/loom", Err("timeout")),
            ]),
        )
        .expect_err("incomplete");
        let ScanError::Unreachable { repos } = &err;
        assert_eq!(repos.len(), 2, "{repos:?}");
    }

    /// The owner default must match the one the DEPOSIT uses. A second
    /// spelling would let the scanner ask a different repository than the
    /// deposit fetches from, and report movement for something never carried.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_repository_default_matches_the_one_the_deposit_resolves() {
        assert_eq!(repo_of("meld", None), "pulseengine/meld");
        assert_eq!(
            repo_of("wsc", Some("pulseengine/sigil")),
            "pulseengine/sigil"
        );
        // An explicit repo of another owner is honoured, not rewritten.
        assert_eq!(
            repo_of("x", Some("bytecodealliance/wasm-tools")),
            "bytecodealliance/wasm-tools"
        );
    }

    /// CLAUSE 5. Rolling promises nothing, so an unattended deposit is
    /// consistent with what its consumers were already told. Qualified promises
    /// the opposite.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn only_a_channel_that_promises_nothing_may_deposit_unattended() {
        autonomous_deposit_permitted(&manifest(TWO, "rolling")).expect("rolling promises nothing");

        let err = autonomous_deposit_permitted(&manifest(TWO, "qualified"))
            .expect_err("qualified must refuse");
        assert!(err.contains("qualified"), "{err}");
        assert!(
            err.contains("by hand"),
            "must say what to do instead: {err}"
        );

        // And an unknown channel is refused rather than allowed by omission —
        // a new channel must opt IN to being signed without a person.
        autonomous_deposit_permitted(&manifest(TWO, "experimental"))
            .expect_err("an unknown channel must not inherit rolling's permission");
    }
}
