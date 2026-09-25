//! Which third-party actions does a release depend on that no pull request
//! ever runs?
//!
//! Dependabot opened three major bumps. Two are decidable from CI —
//! `actions/checkout` is exercised by roughly twenty jobs — and one,
//! `oras-project/setup-oras`, showed **26 checks green while nothing ran the
//! action at all**. It appears only in `deposit-layer.yml`, which is
//! `workflow_dispatch`, and the OCI systest downloads its own pinned `oras`
//! binary rather than using the action. The green was vacuous for that bump,
//! and "we cannot upgrade because we do not know" was the honest position.
//!
//! That is the shape this repository has paid for before: a check that first
//! speaks after the tag is documentation. An action first exercised by the
//! release is first exercised at the point of no return.
//!
//! So the gap is made mechanical. Every action a tag-time workflow depends on
//! must either be exercised by a workflow that runs on pull requests, or be
//! named here with the reason it cannot be — and a reason is required so the
//! list cannot grow by accident.

use std::collections::BTreeSet;

/// Actions that CANNOT be rehearsed on a pull request, and why.
///
/// Both remaining entries have side effects on systems outside this
/// repository. Rehearsing them would not be a test; it would be the thing
/// itself, performed for no reason.
const UNREHEARSABLE: &[(&str, &str)] = &[
    (
        "actions/attest-build-provenance",
        "mints a real SLSA attestation against the repository's attestation \
         store and a public transparency log. Running it on every PR would \
         publish provenance for artifacts that were never released, which is \
         exactly the confusion the attestation exists to prevent.",
    ),
    (
        "rust-lang/crates-io-auth-action",
        "exchanges the workflow's OIDC identity for a real crates.io publish \
         token. There is no dry run: obtaining the credential IS the \
         privileged operation.",
    ),
];

fn workflows() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "yml") {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, std::fs::read_to_string(&p).unwrap()));
        }
    }
    out
}

/// `owner/action` for every `uses:` in a workflow, ignoring local actions.
fn actions_in(text: &str) -> BTreeSet<String> {
    text.lines()
        // Both spellings: `uses:` on its own line, and `- uses:` as the first
        // key of a step. Missing the second form is not a smaller answer, it
        // is a WRONG one — the first draft of this test reported
        // `cosign-installer` as unrehearsed while ci.yml had been running it
        // on every pull request all along.
        .map(|l| l.trim().trim_start_matches("- ").trim())
        .filter_map(|l| l.strip_prefix("uses:"))
        .map(str::trim)
        .filter_map(|u| u.split('@').next())
        .filter(|u| u.matches('/').count() == 1 && !u.starts_with('.'))
        .map(str::to_string)
        .collect()
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn every_release_action_is_rehearsed_on_pull_requests_or_named_unrehearsable() {
    let mut on_pr: BTreeSet<String> = BTreeSet::new();
    let mut at_tag: BTreeSet<String> = BTreeSet::new();
    for (name, text) in workflows() {
        let acts = actions_in(&text);
        // A workflow that runs on pull_request is a rehearsal for everything
        // it uses; anything else first speaks when a tag is already pushed.
        if text.contains("pull_request:") {
            on_pr.extend(acts);
        } else {
            at_tag.extend(acts);
            let _ = name;
        }
    }
    let excused: BTreeSet<&str> = UNREHEARSABLE.iter().map(|(a, _)| *a).collect();
    let unproven: Vec<&String> = at_tag
        .iter()
        .filter(|a| !on_pr.contains(*a) && !excused.contains(a.as_str()))
        .collect();
    assert!(
        unproven.is_empty(),
        "these actions are used only where a tag has already been pushed, so a version bump to \
         any of them is decided on faith and a break is discovered at the point of no return: \
         {unproven:?}. Exercise each in a workflow that runs on pull requests, or add it to \
         UNREHEARSABLE with the reason it cannot be."
    );
}

/// The excuse list must not outlive its reasons: an action named here that no
/// workflow uses any more is stale, and stale exemptions are how a list stops
/// being read.
// rivet: verifies REQ-CIGATE-001
#[test]
fn nothing_is_excused_that_is_no_longer_used() {
    let all: BTreeSet<String> = workflows()
        .iter()
        .flat_map(|(_, t)| actions_in(t))
        .collect();
    for (action, reason) in UNREHEARSABLE {
        assert!(
            all.contains(*action),
            "{action} is excused from rehearsal but no workflow uses it — drop the entry"
        );
        assert!(
            reason.len() > 60,
            "{action}'s exemption needs a reason, not a word"
        );
    }
}

/// A workflow that does not PARSE produces no checks at all.
///
/// Found the hard way: removing `RIVET_VERSION` left `env:` with nothing but a
/// comment under it, which Actions rejects. `ci.yml` stopped parsing, all ten
/// of its jobs silently failed to register, and the pull request showed
/// "11 checks, 0 failed" — every one of them from OTHER workflows. Branch
/// protection caught it only because a required check never reported; had the
/// broken workflow held no required check, it would have looked green.
///
/// No YAML parser is available here, and one is not needed: the failure shape
/// is a mapping key with no mapping under it. A key ending in `:` at some
/// indentation must be followed by a more-indented line, or it declares
/// nothing.
// rivet: verifies REQ-CIGATE-001
#[test]
fn no_workflow_declares_a_mapping_with_nothing_under_it() {
    // Keys whose value is legitimately empty or inline are not this shape.
    const INLINE_OK: &[&str] = &["pull_request:", "workflow_dispatch:", "schedule:", "push:"];
    for (name, text) in workflows() {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_end();
            if !trimmed.ends_with(':') || trimmed.trim_start().starts_with('#') {
                continue;
            }
            let indent = trimmed.len() - trimmed.trim_start().len();
            if INLINE_OK.contains(&trimmed.trim_start()) {
                continue;
            }
            // The next line that actually declares something.
            let next = lines[i + 1..]
                .iter()
                .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'));
            let Some(next) = next else { continue };
            let next_indent = next.len() - next.trim_start().len();
            assert!(
                next_indent > indent,
                "{name}: `{}` has nothing under it — Actions refuses the whole file, every job                  in it fails to register, and the pull request shows only the checks from OTHER                  workflows",
                trimmed.trim()
            );
        }
    }
}
