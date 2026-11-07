//! A required PR gate cannot be switched off by a repository setting.
//!
//! On GitHub a SKIPPED required check satisfies the branch ruleset. So a job
//! whose `if:` reads a repository variable is a gate anyone with settings
//! access can turn into a pass by deleting the variable. Nothing in the diff
//! shows it and nothing in CI goes red. `selfhost-cargo` (REQ-SYSTEST-001
//! clause 1) was exactly that: `vars.VARVE_SYSTEST_EXPORT_CARGO == '1'`, found
//! by the pre-v0.45.0 gate-potency audit (#319, item 3).
//!
//! Parking a gate stays possible, but as a reviewable edit to the workflow,
//! never as a settings toggle. This also covers step-level `if:`: a step
//! skipped inside a passing job is the same hollow green.
//!
//! The workflows that run on pull requests are named here explicitly. A
//! release or deposit workflow may legitimately be switched by a variable
//! (`CRATES_PUBLISH_ENABLED`), because it is not a merge gate.

const PR_WORKFLOWS: &[&str] = &["ci.yml", "systest.yml", "fuzz.yml"];

fn workflow(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The exact `if:` conditions a job or step in a PR workflow may carry. An
/// ALLOWLIST, not a denylist of `vars.`: a denylist misses every switch it did
/// not think of (`github.repository == 'x/y' &&` passed it, #333 item 2). Each
/// form here is one currently used, and none reads anything a repository
/// setting can change. Adding a form is a reviewable edit to this file.
const ALLOWED_CONDITIONS: &[&str] = &[
    // a required job: runs unless cancelled or the change touched no code
    "!cancelled() && needs.changes.outputs.code != 'false'",
    // the same, for jobs that do not run in the merge queue
    "!cancelled() && github.event_name != 'merge_group' && needs.changes.outputs.code != 'false'",
    // the aggregate gates, which must run to turn a skipped shard red
    "always()",
    // upload-a-crash-corpus step: runs only to preserve evidence of a failure
    "failure()",
];

/// The condition of an `if:` line with its `${{ }}` wrapper stripped, or None
/// when the line is not an `if:`.
fn condition(line: &str) -> Option<String> {
    let t = line.trim_start().trim_start_matches("- ");
    let c = t.strip_prefix("if:")?.trim();
    let c = c
        .strip_prefix("${{")
        .and_then(|c| c.strip_suffix("}}"))
        .unwrap_or(c);
    Some(c.trim().to_string())
}

/// Every `if:` line in `text` whose condition is not on the allowlist, as
/// (line number, line).
fn variable_switches(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| condition(l).is_some_and(|c| !ALLOWED_CONDITIONS.contains(&c.as_str())))
        .map(|(i, l)| (i + 1, l.trim().to_string()))
        .collect()
}

// rivet: verifies REQ-SYSTEST-001
#[test]
fn no_pr_gate_is_switched_by_a_repository_variable() {
    for name in PR_WORKFLOWS {
        let w = workflow(name);
        assert!(
            w.contains("pull_request"),
            "{name} is listed as a PR workflow but has no pull_request trigger; \
             update PR_WORKFLOWS rather than letting this test check nothing"
        );
        let found = variable_switches(&w);
        assert!(
            found.is_empty(),
            "{name} gates a job or step on a condition outside ALLOWED_CONDITIONS: {found:?}. A \
             skipped required check counts as passed, so deleting the variable \
             would turn this gate green without running it (a variable, a \
             repository name, anything a setting or fork can change). Park a gate by \
             editing the workflow, where review sees it."
        );
    }
}

/// The scanner itself must be able to find what it looks for, at both the
/// job and the step level, or the test above would pass on nothing. The
/// negative controls are permanent: a `vars.` switch AND a non-variable one
/// (#333 item 2) must both be flagged, and today's forms must not.
#[test]
fn the_scanner_flags_any_switch_outside_the_allowlist_at_job_and_step_level() {
    let job = "  x:\n    if: ${{ !cancelled() && vars.FLAG == '1' }}\n";
    let step = "    steps:\n      - if: vars.FLAG == '1'\n        run: true\n";
    let repo = "  x:\n    if: ${{ github.repository == 'x/y' && !cancelled() && needs.changes.outputs.code != 'false' }}\n";
    let actor = "    steps:\n      - if: github.actor != 'bot'\n        run: true\n";
    for (name, text) in [
        ("job", job),
        ("step", step),
        ("repository", repo),
        ("actor", actor),
    ] {
        assert_eq!(
            variable_switches(text).len(),
            1,
            "{name} switch not flagged"
        );
    }
    for ok in ALLOWED_CONDITIONS {
        for text in [
            format!("    if: ${{{{ {ok} }}}}\n"),
            format!("    if: {ok}\n"),
            format!("      - if: {ok}\n"),
        ] {
            assert!(
                variable_switches(&text).is_empty(),
                "allowed form flagged: {text}"
            );
        }
    }
}
