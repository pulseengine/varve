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

const PR_WORKFLOWS: &[&str] = &["ci.yml", "systest.yml", "fuzz.yml", "gate-probe.yml"];

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

/// `PR_WORKFLOWS` is a hand-kept list, so a workflow added with a
/// `pull_request` trigger would be checked by nothing above. Every workflow
/// that a pull request runs must be on it.
// rivet: verifies REQ-SYSTEST-001
#[test]
fn every_workflow_a_pull_request_runs_is_checked() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut unlisted = Vec::new();
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
    {
        let path = entry.expect("a workflow directory entry").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let text = workflow(name);
        // Parse only what can be a PR workflow: the trigger's name is in it.
        if text.contains("pull_request")
            && runs_on_pull_request(&parse(name, &text))
            && !PR_WORKFLOWS.contains(&name)
        {
            unlisted.push(name.to_string());
        }
    }
    assert!(
        unlisted.is_empty(),
        "pull requests run {unlisted:?}, which PR_WORKFLOWS does not list, so no gate rule \
         here checks them"
    );
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
                // Both spellings GitHub accepts: `vars.X` and `vars['X']`.
                let reads_ctx = |ctx: &str| {
                    reads(format!("{ctx}.").as_str()) || reads(format!("{ctx}[").as_str())
                };
                if reads_ctx("vars") || reads_ctx("secrets") {
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
    // Index syntax reads the same context: `secrets['X']` is `secrets.X`.
    let secret_index = "jobs:\n  x:\n    steps:\n      - env:\n          K: ${{ secrets['VARVE_ROOT_KEY'] }}\n        run: true\n";
    let var_index =
        "jobs:\n  x:\n    steps:\n      - run: '[ \"${{ vars[\"SKIP\"] }}\" = 1 ] && exit 0'\n";
    for (name, text) in [
        ("env", env),
        ("run", run),
        ("with", with),
        ("workflow env", job_env),
        ("secrets index", secret_index),
        ("vars index", var_index),
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

/// Every `run:` of a job's steps, as (job, text).
fn step_runs(workflow: &str, text: &str) -> Vec<(String, String)> {
    let doc = parse(workflow, text);
    let mut out = Vec::new();
    if let Some(Yaml::Hash(jobs)) = get(&doc, "jobs") {
        for (name, job) in jobs {
            let job_name = name.as_str().unwrap_or("?").to_string();
            if let Some(Yaml::Array(steps)) = get(job, "steps") {
                for step in steps {
                    if let Some(Yaml::String(run)) = get(step, "run") {
                        out.push((job_name.clone(), run.clone()));
                    }
                }
            }
        }
    }
    out
}

/// The workspace-wide test runs that must report every failing target.
fn fail_fast_runs(workflow: &str, text: &str) -> (usize, Vec<String>) {
    let mut seen = 0;
    let mut bad = Vec::new();
    for (job, run) in step_runs(workflow, text) {
        for line in run.lines() {
            let workspace_test = (line.contains("cargo test") || line.contains("cargo llvm-cov"))
                && line.contains("--workspace");
            if workspace_test {
                seen += 1;
                if !line.contains("--no-fail-fast") {
                    bad.push(format!("{workflow} job `{job}`: {}", line.trim()));
                }
            }
        }
    }
    (seen, bad)
}

/// A workspace `cargo test` without `--no-fail-fast` stops at the first failing
/// test target. The other targets never run, so one red test hides every
/// other regression on the same head: on #383 two new tests in a later target
/// were never executed while an earlier one failed. A gate must report every
/// failure it can see.
// rivet: verifies REQ-SYSTEST-001
#[test]
fn every_workspace_test_run_reports_every_failing_target() {
    let mut seen = 0;
    let mut bad = Vec::new();
    for wf in PR_WORKFLOWS {
        let (n, b) = fail_fast_runs(wf, &workflow(wf));
        seen += n;
        bad.extend(b);
    }
    assert!(
        seen > 0,
        "no workspace-wide cargo test found in {PR_WORKFLOWS:?}: the scan reads nothing"
    );
    assert!(
        bad.is_empty(),
        "workspace test runs that stop at the first failing target:\n  {}",
        bad.join("\n  ")
    );
}

/// Negative and positive controls for `fail_fast_runs`.
#[test]
fn the_fail_fast_scan_flags_a_workspace_test_without_no_fail_fast() {
    let bare = "jobs:\n  t:\n    steps:\n      - run: cargo test --workspace\n";
    let cov = "jobs:\n  c:\n    steps:\n      - run: |\n          cargo llvm-cov --workspace --lcov --output-path x\n";
    for (name, text) in [("test", bare), ("llvm-cov", cov)] {
        let (n, bad) = fail_fast_runs("t.yml", text);
        assert_eq!((n, bad.len()), (1, 1), "{name} not flagged");
    }
    let good = "jobs:\n  t:\n    steps:\n      - run: cargo test --workspace --no-fail-fast\n      - run: cargo test -p varve --test cli\n";
    assert_eq!(fail_fast_runs("t.yml", good), (1, vec![]));
}

// ---------------------------------------------------------------------------
// REQ-LOCKED-001: every lockfile committed, every CI build locked, every lock
// audited.
//
// fuzz/Cargo.lock was gitignored, so the five required `cargo fuzz` checks
// resolved their dependencies fresh on every run: a new upstream release could
// turn a required check red with no change in this repository (spar's highs-sys
// did exactly that). Builds without --locked silently re-resolve a stale lock,
// and `cargo deny check` without --locked audits the re-resolved graph rather
// than the committed one. The three checks below derive the set of locks from
// the tree, never from a hand list.
// ---------------------------------------------------------------------------

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Directories never searched for workspaces or locks: build output, git's own
/// data, local mutation-testing copies and agent worktrees. Nothing in them is
/// committed, and each holds whole copies of the tree whose locks are the
/// tree's own.
const NOT_SOURCE_DIRS: &[&str] = &[
    "target",
    ".git",
    "mutants.out",
    "mutants.out.old",
    ".claude",
    "node_modules",
];

/// Every Cargo workspace root and every Cargo.lock under `root`, as paths
/// relative to it (`""` for `root` itself): (workspace dirs, lock files).
fn cargo_workspaces_and_locks(root: &std::path::Path) -> (Vec<String>, Vec<String>) {
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        ws: &mut Vec<String>,
        locks: &mut Vec<String>,
    ) {
        let rel = |p: &std::path::Path| {
            p.strip_prefix(root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/")
        };
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let ft = entry.file_type().expect("a file type");
            if ft.is_dir() {
                if !NOT_SOURCE_DIRS.contains(&name.as_ref()) {
                    walk(root, &path, ws, locks);
                }
            } else if name == "Cargo.lock" {
                locks.push(rel(&path));
            } else if name == "Cargo.toml" {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                if text.lines().any(|l| l.trim() == "[workspace]") {
                    ws.push(rel(dir));
                }
            }
        }
    }
    let (mut ws, mut locks) = (Vec::new(), Vec::new());
    walk(root, root, &mut ws, &mut locks);
    ws.sort();
    locks.sort();
    (ws, locks)
}

fn lock_of(dir: &str) -> String {
    if dir.is_empty() {
        "Cargo.lock".to_string()
    } else {
        format!("{dir}/Cargo.lock")
    }
}

fn git_ok(root: &std::path::Path, args: &[&str]) -> bool {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git runs");
    out.status.success()
}

/// What is wrong with the locks under the git work tree `root`: a workspace
/// with no Cargo.lock, a Cargo.lock git does not track, or one a .gitignore
/// (any of them, or the global excludes) would ignore.
fn lockfile_findings(root: &std::path::Path) -> Vec<String> {
    let (ws, locks) = cargo_workspaces_and_locks(root);
    let mut wanted: Vec<String> = ws.iter().map(|d| lock_of(d)).collect();
    wanted.extend(locks);
    wanted.sort();
    wanted.dedup();
    let mut bad = Vec::new();
    for lock in &wanted {
        if !root.join(lock).is_file() {
            bad.push(format!("{lock}: a workspace with no Cargo.lock"));
            continue;
        }
        if !git_ok(root, &["ls-files", "--error-unmatch", "--", lock]) {
            bad.push(format!("{lock}: not tracked by git"));
        }
        // --no-index: judge the ignore rules themselves, not the index, so a
        // lock that is tracked but would be ignored if re-added is still found.
        if git_ok(root, &["check-ignore", "-q", "--no-index", "--", lock]) {
            bad.push(format!("{lock}: matched by a .gitignore rule"));
        }
    }
    bad
}

// rivet: verifies REQ-LOCKED-001
#[test]
fn every_cargo_lock_is_committed_and_none_is_ignored() {
    let root = repo_root();
    let (ws, locks) = cargo_workspaces_and_locks(&root);
    assert!(
        ws.contains(&String::new()) && ws.contains(&"fuzz".to_string()),
        "the workspace scan did not find the root and fuzz/ workspaces ({ws:?}): it reads nothing"
    );
    assert!(
        !locks.is_empty(),
        "no Cargo.lock found: the scan reads nothing"
    );
    let bad = lockfile_findings(&root);
    assert!(
        bad.is_empty(),
        "every Cargo.lock must be committed (REQ-LOCKED-001); a lock that is not \
         resolves fresh in CI on every run:\n  {}",
        bad.join("\n  ")
    );
}

/// Negative control: an ignored, untracked lock, and a workspace with none,
/// are both found; a committed one is not.
// rivet: verifies REQ-LOCKED-001
#[test]
fn the_lockfile_scan_flags_an_ignored_untracked_or_missing_lock() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path();
    let git = |args: &[&str]| assert!(git_ok(root, args), "git {args:?} failed");
    git(&["init", "-q"]);
    std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::create_dir_all(root.join("fuzz")).unwrap();
    std::fs::write(root.join("fuzz/Cargo.toml"), "[package]\n\n[workspace]\n").unwrap();
    std::fs::write(root.join("fuzz/Cargo.lock"), "version = 4\n").unwrap();
    std::fs::create_dir_all(root.join("other")).unwrap();
    std::fs::write(root.join("other/Cargo.toml"), "[workspace]\n").unwrap();
    // A build directory's lock is not source.
    std::fs::create_dir_all(root.join("target/x")).unwrap();
    std::fs::write(root.join("target/x/Cargo.lock"), "").unwrap();
    std::fs::write(root.join(".gitignore"), "fuzz/Cargo.lock\n/target\n").unwrap();
    git(&["add", "Cargo.toml", "Cargo.lock", ".gitignore"]);

    let bad = lockfile_findings(root);
    let has = |needle: &str| bad.iter().any(|b| b.contains(needle));
    assert!(has("fuzz/Cargo.lock: not tracked"), "{bad:?}");
    assert!(has("fuzz/Cargo.lock: matched by a .gitignore"), "{bad:?}");
    assert!(
        has("other/Cargo.lock: a workspace with no Cargo.lock"),
        "{bad:?}"
    );
    assert_eq!(bad.len(), 3, "only those three: {bad:?}");

    // Fixed: committed, not ignored, the stray workspace given its lock.
    std::fs::write(root.join(".gitignore"), "/target\n").unwrap();
    std::fs::write(root.join("other/Cargo.lock"), "version = 4\n").unwrap();
    git(&["add", ".gitignore", "fuzz/Cargo.lock", "other/Cargo.lock"]);
    assert_eq!(lockfile_findings(root), Vec::<String>::new());
}

/// cargo subcommands that resolve the dependency graph and must therefore
/// carry --locked (or --frozen, which implies it) in CI.
const RESOLVING_SUBCOMMANDS: &[&str] = &[
    "build", "test", "clippy", "run", "llvm-cov", "doc", "fuzz", "install", "deny", "package",
    "publish",
];

/// The cargo invocations that cannot take --locked, each with what the same
/// file must run instead so the lock is still proved current, as (file, the
/// invocation's text, compensating texts that must appear in that file's runs).
const LOCKED_EXEMPT: &[(&str, &str, &[&str])] = &[(
    // cargo-fuzz 0.13.1 has no --locked and forwards none: it runs `cargo
    // build --manifest-path fuzz/Cargo.toml --target <triple>`, and every
    // argument after `--` goes to libFuzzer, not cargo (src/project.rs, `fn
    // cargo`). So the job proves the lock current with the same nightly cargo
    // before the build, and proves the build left it untouched after.
    "fuzz.yml",
    "cargo +nightly fuzz run",
    &[
        "cargo +nightly fetch --locked --manifest-path fuzz/Cargo.toml",
        "git diff --exit-code -- fuzz/Cargo.lock",
    ],
)];

/// Shell lines with their `\` continuations joined, comment lines dropped.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if cur.is_empty() && line.trim_start().starts_with('#') {
            continue;
        }
        match line.trim_end().strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(line);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every resolving cargo invocation in the shell `text` (from `file`) that
/// carries neither --locked nor --frozen, as (count seen, offending lines).
/// Only cargo's own arguments count: they end at ` -- ` (what follows goes to
/// the program) or at a shell separator.
fn unlocked_cargo(file: &str, text: &str) -> (usize, Vec<String>) {
    let re = regex::Regex::new(&format!(
        r"(?:^|[\s;&|(])cargo(?:\s+\+\S+)?\s+({})(?:\s|$)",
        RESOLVING_SUBCOMMANDS
            .iter()
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|")
    ))
    .expect("a valid regex");
    let mut seen = 0;
    let mut bad = Vec::new();
    for line in logical_lines(text) {
        // Text inside quotes is a message (`echo "... cargo package ..."`),
        // not an invocation; masked to `_` so offsets stay put. A command run
        // through `sh -c "cargo ..."` is missed by this; none exists today.
        let mut quote = None;
        let line: String = line
            .chars()
            .map(|c| match (quote, c) {
                (None, '"' | '\'') => {
                    quote = Some(c);
                    c
                }
                (Some(q), _) if c == q => {
                    quote = None;
                    c
                }
                (Some(_), _) => '_',
                (None, _) => c,
            })
            .collect();
        for m in re.find_iter(&line) {
            seen += 1;
            let rest = &line[m.start()..];
            let end = [" -- ", "|", "&&", ";", ")", ">"]
                .iter()
                .filter_map(|s| rest.find(s))
                .min()
                .unwrap_or(rest.len());
            let args = &rest[..end];
            let locked = args
                .split_whitespace()
                .any(|a| a == "--locked" || a == "--frozen");
            let exempt = LOCKED_EXEMPT
                .iter()
                .any(|(f, inv, _)| *f == file && args.contains(inv));
            if !locked && !exempt {
                bad.push(format!("{file}: {}", line.trim()));
            }
        }
    }
    (seen, bad)
}

/// Every file whose cargo invocations CI runs: every workflow (not only the PR
/// ones: a release or deposit build that re-resolves ships bytes no PR
/// tested), and every shell script under tools/, which the workflows call.
fn ci_cargo_sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out = Vec::new();
    let wf_dir = root.join(".github/workflows");
    for entry in std::fs::read_dir(&wf_dir).expect("the workflow directory") {
        let path = entry.expect("an entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            let text = workflow(&name);
            let runs: Vec<String> = step_runs(&name, &text)
                .into_iter()
                .map(|(_, r)| r)
                .collect();
            out.push((name, runs.join("\n")));
        }
    }
    fn sh(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("a tools directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                sh(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "sh") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.push((rel, std::fs::read_to_string(&path).expect("a script")));
            }
        }
    }
    sh(&root.join("tools"), &root, &mut out);
    out.sort();
    out
}

// rivet: verifies REQ-LOCKED-001
#[test]
fn every_ci_cargo_build_runs_locked() {
    let sources = ci_cargo_sources();
    let mut seen = 0;
    let mut bad = Vec::new();
    for (file, text) in &sources {
        let (n, b) = unlocked_cargo(file, text);
        seen += n;
        bad.extend(b);
    }
    assert!(
        seen > 20,
        "only {seen} cargo invocations found: the scan reads nothing"
    );
    assert!(
        bad.is_empty(),
        "cargo invocations that may silently re-resolve a stale lock; add --locked \
         (REQ-LOCKED-001), or an entry in LOCKED_EXEMPT with what proves the lock instead:\n  {}",
        bad.join("\n  ")
    );
    // Each exemption must still be needed, and its compensation present.
    for (file, inv, needs) in LOCKED_EXEMPT {
        let text = &sources
            .iter()
            .find(|(f, _)| f == file)
            .unwrap_or_else(|| panic!("LOCKED_EXEMPT names {file}, which does not exist"))
            .1;
        assert!(
            text.contains(inv),
            "LOCKED_EXEMPT entry `{inv}` matches nothing in {file}: remove it"
        );
        for need in *needs {
            assert!(
                text.contains(need),
                "{file} runs `{inv}` without --locked, and no longer runs `{need}`, which \
                 is what proved the lock instead"
            );
        }
    }
}

/// Negative and positive controls for `unlocked_cargo`.
// rivet: verifies REQ-LOCKED-001
#[test]
fn the_locked_scan_flags_a_cargo_build_without_locked() {
    let unlocked = [
        "cargo build --release -p varve",
        "cargo +nightly test --workspace",
        "  cargo clippy --workspace -- -D warnings --locked",
        "cargo run -q -p varve -- --locked",
        "VAR=1 cargo test -p x \\\n  --test y",
        "(cd \"$repo\" && cargo build --release -p varve)",
        "cargo llvm-cov --workspace --lcov",
        "cargo doc --no-deps -p x",
        "cargo deny check",
        "cargo +nightly fuzz run t -- -max_total_time=60",
    ];
    for text in unlocked {
        let (n, bad) = unlocked_cargo("t.yml", text);
        assert_eq!((n, bad.len()), (1, 1), "not flagged: {text}");
    }
    let locked = [
        "cargo build --release --locked -p varve",
        "cargo test -p x \\\n  --locked --test y -- --exact z",
        "cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories",
        "cargo build --frozen",
        "# cargo build in a comment",
        "cargo fmt --all --check",
        "cargo mutants --list",
        "echo \"::error::cargo package embeds the dep version\"; exit 1",
    ];
    for text in locked {
        let (_, bad) = unlocked_cargo("t.yml", text);
        assert!(bad.is_empty(), "flagged: {text}: {bad:?}");
    }
    // The exemption is per file: the same invocation elsewhere is flagged.
    let fuzz = "cargo +nightly fuzz run t --target x -- -max_total_time=60";
    assert!(unlocked_cargo("fuzz.yml", fuzz).1.is_empty());
    assert_eq!(unlocked_cargo("ci.yml", fuzz).1.len(), 1);
}

/// The required job that audits the dependency graph, by its check name.
const AUDIT_JOB_NAME: &str = "cargo deny (supply-chain audit)";

/// The `run:` texts of the job named `AUDIT_JOB_NAME` in the workflow `text`.
fn audit_job_runs(workflow: &str, text: &str) -> Vec<String> {
    let doc = parse(workflow, text);
    let mut out = Vec::new();
    if let Some(Yaml::Hash(jobs)) = get(&doc, "jobs") {
        for job in jobs.values() {
            if get(job, "name").and_then(Yaml::as_str) != Some(AUDIT_JOB_NAME) {
                continue;
            }
            if let Some(Yaml::Array(steps)) = get(job, "steps") {
                for step in steps {
                    if let Some(Yaml::String(run)) = get(step, "run") {
                        out.push(run.clone());
                    }
                }
            }
        }
    }
    out
}

/// Which of the locks in `lock_dirs` (workspace dirs relative to the root, `""`
/// for the root) no `cargo deny` line in `runs` audits for advisories, against
/// the committed lock (--locked), at that workspace.
fn unaudited_locks(runs: &[String], lock_dirs: &[String]) -> Vec<String> {
    let lines: Vec<String> = runs
        .iter()
        .flat_map(|r| logical_lines(r))
        .filter(|l| l.contains("cargo deny"))
        .collect();
    let audits = |line: &str, dir: &str| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let manifest = words
            .iter()
            .position(|w| *w == "--manifest-path")
            .and_then(|i| words.get(i + 1).copied())
            .or_else(|| {
                words
                    .iter()
                    .find_map(|w| w.strip_prefix("--manifest-path="))
            });
        let at_dir = match manifest {
            None => dir.is_empty(),
            Some(m) => {
                let m = m.trim_start_matches("./");
                m == format!("{dir}/Cargo.toml") || (dir.is_empty() && m == "Cargo.toml")
            }
        };
        let locked = words.iter().any(|w| *w == "--locked" || *w == "--frozen");
        let Some(check) = words.iter().position(|w| *w == "check") else {
            return false;
        };
        // `check` alone runs every check; otherwise advisories must be named.
        let checks: Vec<&str> = words[check + 1..]
            .iter()
            .copied()
            .filter(|w| !w.starts_with('-'))
            .collect();
        let advisories = checks.is_empty() || checks.contains(&"advisories");
        at_dir && locked && advisories
    };
    lock_dirs
        .iter()
        .filter(|d| !lines.iter().any(|l| audits(l, d)))
        .map(|d| lock_of(d))
        .collect()
}

// rivet: verifies REQ-LOCKED-001
#[test]
fn every_cargo_lock_is_audited_for_advisories() {
    let root = repo_root();
    let (_, locks) = cargo_workspaces_and_locks(&root);
    let dirs: Vec<String> = locks
        .iter()
        .map(|l| {
            l.strip_suffix("Cargo.lock")
                .unwrap()
                .trim_end_matches('/')
                .to_string()
        })
        .collect();
    assert!(
        dirs.len() >= 2,
        "expected the root and fuzz/ locks, found {locks:?}"
    );
    let runs = audit_job_runs("ci.yml", &workflow("ci.yml"));
    assert!(
        !runs.is_empty(),
        "ci.yml has no job named `{AUDIT_JOB_NAME}`: the scan reads nothing"
    );
    let missing = unaudited_locks(&runs, &dirs);
    assert!(
        missing.is_empty(),
        "locks the `{AUDIT_JOB_NAME}` job does not audit for advisories as committed \
         (`cargo deny --locked [--manifest-path <dir>/Cargo.toml] check [advisories ...]`, \
         REQ-LOCKED-001): {missing:?}"
    );
}

/// Negative and positive controls for `unaudited_locks`.
// rivet: verifies REQ-LOCKED-001
#[test]
fn the_audit_scan_flags_a_lock_no_deny_step_audits() {
    let dirs = vec![String::new(), "fuzz".to_string()];
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    // Only the root audited: fuzz/ is flagged.
    assert_eq!(
        unaudited_locks(&s(&["cargo deny --locked check"]), &dirs),
        vec!["fuzz/Cargo.lock"]
    );
    // Unlocked audits audit a re-resolved graph: both flagged.
    assert_eq!(
        unaudited_locks(
            &s(&[
                "cargo deny check",
                "cargo deny --manifest-path fuzz/Cargo.toml check"
            ]),
            &dirs
        ),
        vec!["Cargo.lock", "fuzz/Cargo.lock"]
    );
    // An audit that skips advisories does not count.
    assert_eq!(
        unaudited_locks(
            &s(&[
                "cargo deny --locked check",
                "cargo deny --locked --manifest-path fuzz/Cargo.toml check licenses"
            ]),
            &dirs
        ),
        vec!["fuzz/Cargo.lock"]
    );
    // Both audited.
    assert!(
        unaudited_locks(
            &s(&[
                "cargo deny --locked check",
                "cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories bans sources"
            ]),
            &dirs
        )
        .is_empty()
    );
}
