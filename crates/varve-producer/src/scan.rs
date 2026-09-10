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
    /// What was compared: the RELEASE TAG this payload is fetched from.
    pub pinned: String,
    pub latest: String,
    /// The payload's own version, when it differs from the release tag.
    ///
    /// `None` for the ordinary case, where a repository's tag and its
    /// payload's version are the same number. `Some` marks a HUB payload —
    /// `pulseengine/jess` tags `v0.7.2` and ships `with-device` at `0.2.2` —
    /// and those cannot be bumped automatically. See [`Moved::auto_bumpable`].
    pub payload_version: Option<String>,
}

impl Moved {
    /// May an unattended depositor bump this pin by itself?
    ///
    /// No, for a hub payload. The new RELEASE TAG is known; the new PAYLOAD
    /// VERSION is not, and it cannot be derived — only the upstream's release
    /// notes say what version of `with-device` `v0.7.2` ships. A scanner that
    /// bumped `version` to the tag would write `v0.7.2` into a signed manifest
    /// for a binary that answers `0.2.2`: the layer stating something untrue
    /// about its own contents, which is the one thing it exists not to do, and
    /// exactly what REQ-PAYLOADID-001 added the `release` field to prevent.
    ///
    /// So it is REPORTED and not acted on. A human reads the release notes.
    pub fn auto_bumpable(&self) -> bool {
        self.payload_version.is_none()
    }
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

/// One payload's pin, whichever section of the manifest it came from.
///
/// `tools` and `vsix` are different tables carrying the same three facts, and
/// the scanner has no reason to care which one a payload was written in.
struct ToolRef<'a> {
    name: &'a str,
    repo: Option<&'a str>,
    version: &'a str,
    release: Option<&'a str>,
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

    // TOOLS AND VSIX BOTH. The first version walked `tools` only, so the two
    // vsix payloads were never scanned — `rivet-sdlc` sat at v0.35.0 while the
    // rivet TOOL moved to v0.37.0, and every scan said "nothing moved". A
    // scanner blind to a payload kind reports calm about a realm that is
    // drifting, which is the same silence this module refuses everywhere else.
    let entries: Vec<(&str, Option<&str>, &str)> = manifest
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t.repo.as_deref(), t.version.as_str()))
        .chain(
            manifest
                .vsix
                .iter()
                .map(|v| (v.name.as_str(), v.repo.as_deref(), v.version.as_str())),
        )
        .collect();
    let releases: std::collections::BTreeMap<&str, Option<&str>> = manifest
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t.release.as_deref()))
        .collect();

    for (name, repo_field, version) in entries {
        let t = ToolRef {
            name,
            repo: repo_field,
            version,
            release: releases.get(name).copied().flatten(),
        };
        let repo = repo_of(t.name, t.repo);
        match latest.get(&repo) {
            Some(Ok(newest)) => {
                // Compare against the RELEASE TAG, which is what upstream
                // publishes and what `latest` holds. For almost every payload
                // that is also its version; for a hub payload it is not, and
                // comparing a version against a tag answers a different
                // question — `0.2.1` is never equal to `v0.7.2`, so such a
                // payload would report as moved on every scan, forever.
                let pinned = t.release.unwrap_or(t.version).to_string();
                if newest != &pinned {
                    moved.push(Moved {
                        name: t.name.to_string(),
                        repo,
                        pinned,
                        latest: newest.clone(),
                        payload_version: t.release.map(|_| t.version.to_string()),
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

/// Ask every repository the manifest pins what it has most recently published.
///
/// Lives here rather than in `main` so the ENTERPRISE property is testable: the
/// forge's environment must reach every `gh` invocation, and the first version
/// of this loop passed an empty environment. That silently targeted github.com
/// no matter what `GH_HOST` said — on an enterprise instance every lookup would
/// have failed, or worse, answered about a different repository of the same
/// name on the public forge.
///
/// One query per REPOSITORY, not per payload: several payloads can come from
/// one repo (varve ships `varve` and `varve-producer`), and asking twice would
/// double the rate-limit cost of every scan for no new information.
pub fn latest_releases<R: crate::gh::CommandRunner>(
    runner: &R,
    forge: &crate::forge::Forge,
    manifest: &LayerManifest,
) -> BTreeMap<String, Result<String, String>> {
    let env = crate::gh::forge_env(forge);
    let mut out: BTreeMap<String, Result<String, String>> = BTreeMap::new();
    for t in &manifest.tools {
        let repo = repo_of(&t.name, t.repo.as_deref());
        if out.contains_key(&repo) {
            continue;
        }
        let d = runner.run("gh", &crate::gh::latest_release_argv(&repo), &env);
        let answer = if d.code == 127 {
            // Named separately: "gh is missing" and "gh said no" send an
            // operator to completely different places.
            Err("gh is not on PATH".to_string())
        } else if !d.ok() {
            Err(d.stderr.trim().chars().take(160).collect())
        } else {
            crate::gh::parse_latest_release(&d.stdout).map_err(|e| e.to_string())
        };
        out.insert(repo, answer);
    }
    out
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

    const HUB: &str = "[[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
                       version = \"0.2.1\"\nrelease = \"v0.7.1\"\n\
                       asset = \"with-device-%V-%T.tar.gz\"\n";

    /// A HUB payload is compared by its RELEASE TAG, not its version.
    ///
    /// `pulseengine/jess` tags `v0.7.1` and ships `with-device` at `0.2.1`.
    /// Comparing `0.2.1` against the latest tag answers a different question —
    /// they are never equal, so the payload reports as moved on every scan
    /// forever, and the first version of this function did exactly that.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_hub_payload_is_compared_by_its_release_tag_not_its_version() {
        // Upstream still at the pinned TAG: nothing moved, even though the tag
        // and the payload version differ.
        let same = compare(
            &manifest(HUB, "rolling"),
            &seen(&[("pulseengine/jess", Ok("v0.7.1"))]),
        )
        .expect("complete");
        assert!(
            same.is_empty(),
            "a hub payload at its pinned tag has not moved: {same:?}"
        );
    }

    /// …and when the TAG really moves, both numbers are reported, because one
    /// of them is what a human needs to look up.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_moved_hub_payload_reports_the_tag_and_the_payload_version() {
        let moved = compare(
            &manifest(HUB, "rolling"),
            &seen(&[("pulseengine/jess", Ok("v0.7.2"))]),
        )
        .expect("complete");
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].pinned, "v0.7.1", "the tag is what was compared");
        assert_eq!(moved[0].latest, "v0.7.2");
        assert_eq!(
            moved[0].payload_version.as_deref(),
            Some("0.2.1"),
            "the payload's own version must be carried, not discarded"
        );
    }

    /// VSIX payloads are scanned too. The first version walked `tools` only,
    /// so `rivet-sdlc` sat at v0.35.0 while the rivet TOOL moved to v0.37.0 and
    /// every scan reported "nothing moved". A scanner blind to a payload kind
    /// reports calm about a realm that is drifting.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_vsix_payload_is_scanned_like_any_other() {
        let m = manifest(
            "[[tool]]\nname = \"rivet\"\nversion = \"v0.37.0\"\n\n\
             [[vsix]]\nname = \"rivet-sdlc\"\nrepo = \"pulseengine/rivet\"\n\
             version = \"v0.35.0\"\nasset = \"rivet-sdlc-%V.vsix\"\n",
            "rolling",
        );
        let moved = compare(&m, &seen(&[("pulseengine/rivet", Ok("v0.37.0"))])).expect("complete");
        assert_eq!(
            moved.len(),
            1,
            "the vsix is behind and must be reported: {moved:?}"
        );
        assert_eq!(moved[0].name, "rivet-sdlc");
        assert_eq!(moved[0].pinned, "v0.35.0");
        assert_eq!(moved[0].latest, "v0.37.0");
    }

    /// And a vsix whose upstream cannot be asked is an incomplete scan, exactly
    /// as for a tool — the blindness must not come back as a silent skip.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn an_unreachable_vsix_upstream_is_also_an_incomplete_scan() {
        let m = manifest(
            "[[vsix]]\nname = \"spar-aadl\"\nrepo = \"pulseengine/spar\"\n\
             version = \"v0.40.0\"\nasset = \"spar-aadl-%P-%V.vsix\"\n",
            "rolling",
        );
        compare(&m, &seen(&[("pulseengine/spar", Err("timeout"))]))
            .expect_err("an unreachable vsix upstream is not 'nothing moved'");
    }

    /// THE ONE THAT MATTERS. An unattended depositor must not bump a hub
    /// payload: the new tag is known, the new payload VERSION is not, and it
    /// cannot be derived — only upstream's release notes say what version of
    /// `with-device` `v0.7.2` ships.
    ///
    /// Writing the tag into `version` would put `v0.7.2` in a signed manifest
    /// for a binary answering `0.2.2` — the layer stating something untrue
    /// about its own contents.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_hub_payload_is_reported_but_never_auto_bumped() {
        let hub = compare(
            &manifest(HUB, "rolling"),
            &seen(&[("pulseengine/jess", Ok("v0.7.2"))]),
        )
        .expect("complete");
        assert!(
            !hub[0].auto_bumpable(),
            "a hub payload's version is not derivable from its tag"
        );

        // An ordinary payload, where the tag IS the version, is bumpable.
        let plain = compare(
            &manifest(TWO, "rolling"),
            &seen(&[
                ("pulseengine/meld", Ok("v0.55.1")),
                ("pulseengine/loom", Ok("v1.4.1")),
            ]),
        )
        .expect("complete");
        assert!(plain[0].auto_bumpable());
        assert_eq!(plain[0].payload_version, None);
    }

    /// A recording runner, so what the producer ASKS can be asserted rather
    /// than inferred from what it answers.
    /// One recorded invocation: the argv, and the environment it carried.
    type Call = (Vec<String>, Vec<(String, String)>);

    struct Recorder {
        calls: std::cell::RefCell<Vec<Call>>,
        stdout: String,
        code: i32,
    }

    impl crate::gh::CommandRunner for Recorder {
        fn run(
            &self,
            program: &str,
            args: &[String],
            env: &[(String, String)],
        ) -> crate::gh::RunOutput {
            assert_eq!(program, "gh");
            self.calls.borrow_mut().push((args.to_vec(), env.to_vec()));
            crate::gh::RunOutput {
                code: self.code,
                stdout: self.stdout.clone(),
                stderr: String::new(),
            }
        }
    }

    fn recorder(stdout: &str, code: i32) -> Recorder {
        Recorder {
            calls: std::cell::RefCell::new(Vec::new()),
            stdout: stdout.to_string(),
            code,
        }
    }

    /// ENTERPRISE. `GH_HOST` must reach every lookup. The first version of this
    /// loop passed an empty environment, which silently targeted github.com
    /// whatever the forge said — on an enterprise instance every lookup fails,
    /// or answers about a same-named repository on the PUBLIC forge, which is
    /// worse because it succeeds.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn every_lookup_carries_the_enterprise_host() {
        let r = recorder(r#"{"tagName":"v9.9.9"}"#, 0);
        let forge = crate::forge::Forge::enterprise("github.acme.example");
        latest_releases(&r, &forge, &manifest(TWO, "rolling"));

        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 2, "one query per repository");
        for (args, env) in calls.iter() {
            assert!(args.contains(&"view".to_string()), "{args:?}");
            assert!(
                env.iter()
                    .any(|(k, v)| k == "GH_HOST" && v == "github.acme.example"),
                "every gh call must carry GH_HOST on an enterprise forge, got {env:?}"
            );
        }
    }

    /// …and public GitHub must NOT get a GH_HOST, because setting it there is
    /// how a working setup starts failing for a reason nobody can see.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn public_github_is_asked_without_an_overridden_host() {
        let r = recorder(r#"{"tagName":"v9.9.9"}"#, 0);
        latest_releases(
            &r,
            &crate::forge::Forge::github_com(),
            &manifest(TWO, "rolling"),
        );
        for (_, env) in r.calls.borrow().iter() {
            assert!(
                env.is_empty(),
                "public github needs no host override: {env:?}"
            );
        }
    }

    /// One query per REPOSITORY. varve ships two payloads from one repo, and
    /// asking twice doubles the rate-limit cost of every scan — at four scans
    /// an hour that is the difference between comfortable and throttled.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn two_payloads_from_one_repository_are_asked_about_once() {
        let two_from_one = "[[tool]]\nname = \"varve\"\nrepo = \"pulseengine/varve\"\nversion = \"v0.33.0\"\n\n\
                            [[tool]]\nname = \"varve-producer\"\nrepo = \"pulseengine/varve\"\nversion = \"v0.33.0\"\n";
        let r = recorder(r#"{"tagName":"v0.33.0"}"#, 0);
        let seen = latest_releases(
            &r,
            &crate::forge::Forge::github_com(),
            &manifest(two_from_one, "rolling"),
        );
        assert_eq!(r.calls.borrow().len(), 1, "asked more than once");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen["pulseengine/varve"], Ok("v0.33.0".to_string()));
    }

    /// A missing `gh` is its own answer, not a registry problem.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_missing_gh_is_named_rather_than_reported_as_upstream_silence() {
        let r = recorder("", 127);
        let seen = latest_releases(
            &r,
            &crate::forge::Forge::github_com(),
            &manifest(TWO, "rolling"),
        );
        for (_, v) in seen {
            assert_eq!(v, Err("gh is not on PATH".to_string()));
        }
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
