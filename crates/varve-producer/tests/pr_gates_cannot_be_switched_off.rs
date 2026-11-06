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

/// Every `if:` line in `text` that reads a repository variable, as
/// (line number, line).
fn variable_switches(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start().trim_start_matches("- ");
            t.starts_with("if:") && t.contains("vars.")
        })
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
            "{name} gates a job or step on a repository variable: {found:?}. A \
             skipped required check counts as passed, so deleting the variable \
             would turn this gate green without running it. Park a gate by \
             editing the workflow, where review sees it."
        );
    }
}

/// The scanner itself must be able to find what it looks for, at both the
/// job and the step level, or the test above would pass on nothing.
#[test]
fn the_scanner_finds_a_variable_switch_at_job_and_step_level() {
    let job = "  x:\n    if: ${{ !cancelled() && vars.FLAG == '1' }}\n";
    let step = "    steps:\n      - if: vars.FLAG == '1'\n        run: true\n";
    let clean = "    if: ${{ !cancelled() && needs.changes.outputs.code != 'false' }}\n";
    assert_eq!(variable_switches(job).len(), 1);
    assert_eq!(variable_switches(step).len(), 1);
    assert!(variable_switches(clean).is_empty());
}
