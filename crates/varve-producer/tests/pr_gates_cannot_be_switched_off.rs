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

/// `continue-on-error` values that are exempt, as (workflow, job, step name or
/// None for the job level). EMPTY on purpose: no PR workflow uses it today (only
/// `mutants.yml`, which is not a PR gate, does). A red step that cannot fail
/// the job is the same hollow green as a skipped one; allow one here, with the
/// reason, rather than weakening the rule.
const CONTINUE_ON_ERROR_ALLOWED: &[(&str, &str, Option<&str>)] = &[];

use yaml_rust2::{Yaml, YamlLoader};

fn parse(workflow: &str, text: &str) -> Yaml {
    let mut docs = YamlLoader::load_from_str(text)
        .unwrap_or_else(|e| panic!("{workflow} is not parseable YAML: {e}"));
    assert_eq!(
        docs.len(),
        1,
        "{workflow}: expected exactly one YAML document"
    );
    docs.remove(0)
}

fn get<'a>(m: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    match m {
        Yaml::Hash(h) => h.get(&Yaml::String(key.to_string())),
        _ => None,
    }
}

/// The scalar as text, `${{ }}` wrapper stripped.
fn condition(v: &Yaml) -> String {
    let raw = match v {
        Yaml::String(s) | Yaml::Real(s) => s.clone(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Integer(i) => i.to_string(),
        other => format!("{other:?}"),
    };
    let c = raw.trim();
    let c = c
        .strip_prefix("${{")
        .and_then(|c| c.strip_suffix("}}"))
        .unwrap_or(c);
    c.trim().to_string()
}

fn is_literal_false(v: &Yaml) -> bool {
    match v {
        Yaml::Boolean(b) => !*b,
        Yaml::String(s) => s.trim() == "false",
        _ => false,
    }
}

/// Whether the parsed workflow runs on pull requests, from its `on:` key. A
/// YAML 1.1 parser reads that key as the boolean `true`; yaml-rust2 is 1.2 and
/// keeps the string, but both spellings are handled.
fn runs_on_pull_request(doc: &Yaml) -> bool {
    let Yaml::Hash(map) = doc else {
        return false;
    };
    let Some((_, on)) = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("on") || matches!(k, Yaml::Boolean(true)))
    else {
        return false;
    };
    let is_pr = |s: &str| s == "pull_request" || s == "pull_request_target";
    match on {
        Yaml::String(s) => is_pr(s),
        Yaml::Array(q) => q.iter().any(|e| e.as_str().is_some_and(is_pr)),
        Yaml::Hash(m) => m.keys().any(|k| k.as_str().is_some_and(is_pr)),
        _ => false,
    }
}

/// Every job and step in the parsed workflow `text` (named `workflow`) whose
/// `if:` is outside the allowlist, or whose `continue-on-error` is anything but
/// absent or `false`, as (location, what).
fn variable_switches(workflow: &str, text: &str) -> Vec<(String, String)> {
    let doc = parse(workflow, text);
    let mut found = Vec::new();
    let Some(Yaml::Hash(jobs)) = get(&doc, "jobs") else {
        return found;
    };
    for (job_id, job) in jobs {
        let job_id = job_id.as_str().unwrap_or("?");
        let mut check = |loc: String, node: &Yaml, step: Option<&str>| {
            if let Some(c) = get(node, "if") {
                let c = condition(c);
                if !ALLOWED_CONDITIONS.contains(&c.as_str()) {
                    found.push((loc.clone(), format!("if: {c}")));
                }
            }
            if let Some(v) = get(node, "continue-on-error") {
                let allowed = CONTINUE_ON_ERROR_ALLOWED.contains(&(workflow, job_id, step));
                if !is_literal_false(v) && !allowed {
                    found.push((loc, format!("continue-on-error: {v:?}")));
                }
            }
        };
        check(format!("jobs.{job_id}"), job, None);
        if let Some(Yaml::Array(steps)) = get(job, "steps") {
            for (i, step) in steps.iter().enumerate() {
                let name = get(step, "name").and_then(Yaml::as_str);
                check(
                    format!("jobs.{job_id}.steps[{i}]"),
                    step,
                    Some(name.unwrap_or("")),
                );
            }
        }
    }
    found
}

// rivet: verifies REQ-SYSTEST-001
#[test]
fn no_pr_gate_is_switched_by_a_repository_variable() {
    for name in PR_WORKFLOWS {
        let w = workflow(name);
        let doc = parse(name, &w);
        assert!(
            runs_on_pull_request(&doc),
            "{name} is listed as a PR workflow but has no pull_request trigger; \
             update PR_WORKFLOWS rather than letting this test check nothing"
        );
        let found = variable_switches(name, &w);
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
    let job = "jobs:\n  x:\n    if: ${{ !cancelled() && vars.FLAG == '1' }}\n";
    let step = "jobs:\n  x:\n    steps:\n      - if: vars.FLAG == '1'\n        run: true\n";
    let repo = "jobs:\n  x:\n    if: ${{ github.repository == 'x/y' && !cancelled() && needs.changes.outputs.code != 'false' }}\n";
    let actor = "jobs:\n  x:\n    steps:\n      - if: github.actor != 'bot'\n        run: true\n";
    for (name, text) in [
        ("job", job),
        ("step", step),
        ("repository", repo),
        ("actor", actor),
    ] {
        assert_eq!(
            variable_switches("t.yml", text).len(),
            1,
            "{name} switch not flagged"
        );
    }
    for ok in ALLOWED_CONDITIONS {
        for text in [
            format!("jobs:\n  x:\n    if: ${{{{ {ok} }}}}\n"),
            format!("jobs:\n  x:\n    if: \"{ok}\"\n"),
            format!("jobs:\n  x:\n    steps:\n      - if: \"{ok}\"\n        run: true\n"),
        ] {
            assert!(
                variable_switches("t.yml", &text).is_empty(),
                "allowed form flagged: {text}"
            );
        }
    }
}

#[test]
fn the_scanner_flags_valid_yaml_spellings_a_line_scanner_misses() {
    let forms = [
        (
            "extra spaces",
            "jobs:\n  x:\n    steps:\n      -   if: vars.SKIP_TEST != '1'\n          run: x\n",
        ),
        (
            "flow mapping",
            "jobs:\n  x:\n    steps:\n      - { name: t, if: \"vars.SKIP_TEST != '1'\", run: x }\n",
        ),
        (
            "quoted key",
            "jobs:\n  x:\n    steps:\n      - \"if\": vars.SKIP_TEST != '1'\n        run: x\n",
        ),
        (
            "job continue-on-error",
            "jobs:\n  x:\n    continue-on-error: true\n    steps:\n      - run: x\n",
        ),
        (
            "step continue-on-error",
            "jobs:\n  x:\n    steps:\n      - run: x\n        continue-on-error: ${{ vars.F }}\n",
        ),
    ];
    let missed: Vec<&str> = forms
        .iter()
        .filter(|(_, text)| variable_switches("t.yml", text).len() != 1)
        .map(|(name, _)| *name)
        .collect();
    assert!(missed.is_empty(), "not flagged exactly once: {missed:?}");
    let ok = "jobs:\n  x:\n    steps:\n      - { name: t, if: \"${{ failure() }}\", run: x, continue-on-error: false }\n";
    assert!(
        variable_switches("t.yml", ok).is_empty(),
        "allowed flow form flagged"
    );
}

/// Every parsed value in the workflow that reads the `vars` or `secrets`
/// context, wherever it sits (`env:`, `with:`, `run:`), as (path, value).
/// Comments are not values, so a comment naming `vars.X` is not a reader.
///
/// The `if:` allowlist above cannot see a step that switches itself off from
/// inside: `env: { SKIP: ${{ vars.SKIP_MUTANTS }} }` with
/// `[ "${SKIP:-}" = 1 ] && exit 0` stays green (#352, item 1). A deleted
/// secret is the same switch, read as an empty string. No PR workflow reads
/// either context today, so the rule is absolute.
fn setting_readers(workflow: &str, text: &str) -> Vec<(String, String)> {
    fn walk(node: &Yaml, path: String, out: &mut Vec<(String, String)>) {
        match node {
            Yaml::String(s) => {
                let reads = |ctx: &str| {
                    s.match_indices(ctx).any(|(i, _)| {
                        !s[..i]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
                    })
                };
                if reads("vars.") || reads("secrets.") {
                    out.push((path, s.clone()));
                }
            }
            Yaml::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    walk(v, format!("{path}[{i}]"), out);
                }
            }
            Yaml::Hash(h) => {
                for (k, v) in h {
                    walk(k, format!("{path}.<key>"), out);
                    walk(v, format!("{path}.{}", k.as_str().unwrap_or("?")), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(&parse(workflow, text), String::new(), &mut out);
    out
}

// rivet: verifies REQ-SYSTEST-001
#[test]
fn no_pr_workflow_reads_a_repository_variable_or_secret() {
    for name in PR_WORKFLOWS {
        let found = setting_readers(name, &workflow(name));
        assert!(
            found.is_empty(),
            "{name} reads a repository setting: {found:?}. A step can switch \
             itself off from inside on a variable, or on a secret deleted to an \
             empty string, and stay green (#352). Park a gate by editing the \
             workflow."
        );
    }
}

/// Negative and positive controls for `setting_readers`.
#[test]
fn the_reader_scan_flags_env_run_and_with_but_not_comments() {
    let env = "jobs:\n  x:\n    steps:\n      - env:\n          SKIP: ${{ vars.SKIP_MUTANTS }}\n        run: '[ \"${SKIP:-}\" = 1 ] && exit 0'\n";
    let run =
        "jobs:\n  x:\n    steps:\n      - run: echo \"${{ secrets.VARVE_ROOT_KEY }}\" > k.pem\n";
    let with = "jobs:\n  x:\n    steps:\n      - uses: a/b@c\n        with:\n          skip: ${{ vars.X }}\n";
    let job_env = "env:\n  S: ${{ vars.S }}\njobs: {}\n";
    for (name, text) in [
        ("env", env),
        ("run", run),
        ("with", with),
        ("workflow env", job_env),
    ] {
        assert_eq!(
            setting_readers("t.yml", text).len(),
            1,
            "{name} reader not flagged"
        );
    }
    let comment = "# vars.X is not read here\njobs:\n  x:\n    steps:\n      - run: echo myvars.x  # secrets.Y\n";
    assert!(setting_readers("t.yml", comment).is_empty());
}
