//! What may run on OUR machines, and what may not.
//!
//! The PR gates moved to the organisation's self-hosted pool because the
//! GitHub-hosted queue was holding every check for 30-70 minutes while the
//! self-hosted classes picked work up immediately (measured 2026-09-23: inside
//! one rivet CI run, every `self-hosted` job had completed while every
//! `ubuntu-latest` job was still queued).
//!
//! Speed is not a reason to move everything, and for one job shape the pool
//! is SLOWER: the five `cargo mutants` shards run 21-39 minutes each, five
//! wide, and a shared host can only serialise them — measured at hours per
//! pull request, with one shard sitting unassigned for 3h39m before being
//! cancelled. They run on hosted VMs, where the five run at once.
//!
//! Three workflows must stay on GitHub-hosted runners for a different and
//! stronger reason — varve's own product:
//!
//! * `release.yml` produces the SLSA build provenance that varve's ingestion
//!   ladder accepts as rung 2. That attestation's worth comes from binding an
//!   artifact to a workflow running on an ephemeral, attested VM that the
//!   repository's owners do not administer. Produced on a long-lived box we
//!   run ourselves, it asserts the same sentence with much less behind it —
//!   and varve would be asking consumers to accept evidence it would not
//!   accept from an upstream.
//! * `publish-crates.yml` publishes to crates.io through OIDC trusted
//!   publishing, which is the same argument.
//! * `deposit-layer.yml` signs a layer with the realm's key from secrets. A
//!   self-hosted runner is a machine with a filesystem that outlives the job.
//!
//! This is therefore a trust boundary, not a performance preference, and it is
//! exactly the kind of line that gets crossed in an unrelated edit by someone
//! making CI faster — the same motivation that produced this very change.

fn workflow(name: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The three workflows that mint signed or attested artifacts run on runners
/// we do not administer.
// rivet: verifies REQ-NOKEYDISK-001
#[test]
fn signing_and_attesting_workflows_never_run_on_our_own_machines() {
    for name in ["release.yml", "publish-crates.yml", "deposit-layer.yml"] {
        let w = workflow(name);
        assert!(
            !w.contains("self-hosted"),
            "{name} runs on a self-hosted runner. It mints signed or attested \
             artifacts, and that evidence is worth what the machine is worth: \
             an attestation from a box we administer says far less than one \
             from an ephemeral hosted VM, and a signing key reaches a disk we \
             keep. If this was deliberate, the requirement is what has to \
             change first."
        );
    }
}

/// And the converse, so the change does not silently undo itself: the gates
/// that were moved must still be on the pool. A revert to `ubuntu-latest`
/// would not fail anything — it would just be slow again, and nobody would
/// notice for weeks.
// rivet: verifies REQ-CIGATE-001
#[test]
fn the_pr_gates_run_on_the_pool_and_name_a_class() {
    for (name, want) in [
        // 8, not 9: the five mutation shards went BACK to hosted runners after
        // measurement — 21-39 minutes each, five wide, serialised two at a
        // time on a shared host, with one shard never getting a runner at all.
        // The aggregator that reads their result stays on the pool, because it
        // is three lines of shell.
        ("ci.yml", 8usize),
        ("systest.yml", 6),
        ("fuzz.yml", 1),
        ("mutants.yml", 1),
    ] {
        let w = workflow(name);
        // Two spellings of "this job runs on the pool and names its class":
        // the literal list, and the fork-routing expression (#296), whose
        // same-repo branch is the same list as JSON. A fork PR goes to a
        // hosted runner; everything else still waits on the pool, and that is
        // what this counts. A job reverted to a bare `ubuntu-latest` matches
        // neither, which is the regression this test exists for.
        let n = w
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                l.starts_with("runs-on: [self-hosted, linux, x64,")
                    || (l.starts_with("runs-on: ${{")
                        && l.contains(r#"fromJSON('["self-hosted","linux","x64","#))
            })
            .count();
        assert!(
            n >= want,
            "{name} has {n} jobs on the self-hosted pool, expected at least \
             {want} — a gate moved back to the hosted queue, where it waits \
             behind everyone else's builds"
        );
    }
}

/// `lean-mem` is the memory-constrained class, and the organisation's runbook
/// says never to route a job there without a per-process cap.
///
/// varve has its own reason: shard `varve-core (trust)` was KILLED at 23
/// minutes with exit 143 under a 60-minute cap. That is a resource
/// termination, not a timeout, and it reports NOTHING — so a gate that exists
/// to prove "no mutant survived" could not tell that from "nothing ran". The
/// cap turns a runaway mutant into a failed allocation that gets REPORTED.
// rivet: verifies REQ-MUTATE-001
#[test]
fn every_lean_mem_job_caps_its_address_space() {
    for name in ["ci.yml", "mutants.yml"] {
        let w = workflow(name);
        if !w.contains("lean-mem") {
            continue;
        }
        assert!(
            w.contains("ulimit -v "),
            "{name} routes a job to the lean-mem class with no per-process \
             address-space cap. A memory-runaway mutant then OOM-kills the \
             whole job, and the gate reports nothing at all"
        );
    }
}

/// Hosted jobs name an Ubuntu release, never `ubuntu-latest`.
///
/// GitHub moves that label to a new release on its own schedule (24.04 to
/// 26.04 between 2026-10-19 and 2026-11-19), which changes apt packages,
/// Python and preinstalled tools under every hosted job with no diff here.
/// For `release.yml` it also moves the glibc the shipped Linux binaries link
/// against, which is a published compatibility floor. Moving to a newer
/// release is a reviewed edit to this pin, run advisory first.
///
/// The one exempt line is ci.yml's `- os: ubuntu-latest`: it is only the
/// platform label in the required check name `fmt · clippy · test
/// (ubuntu-latest)`, not a runner.
#[test]
fn hosted_jobs_pin_an_ubuntu_release() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    names.sort();
    assert!(
        names.len() >= 9,
        "only {} workflows found in {}",
        names.len(),
        dir.display()
    );
    let mut offenders = Vec::new();
    for name in &names {
        for (i, line) in workflow(name).lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with('#') {
                continue;
            }
            let code = code.split(" #").next().unwrap_or(code);
            if name == "ci.yml" && code == "- os: ubuntu-latest" {
                continue;
            }
            if code.contains("ubuntu-latest") {
                offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these lines run on `ubuntu-latest`, which GitHub re-points without a \
         diff here; name the release (ubuntu-24.04):\n{}",
        offenders.join("\n")
    );
}

use yaml_rust2::{Yaml, YamlLoader};

const FORK_GUARD: &str = "github.event.pull_request.head.repo.full_name == github.repository";

fn yaml_get<'a>(m: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    match m {
        Yaml::Hash(h) => h.get(&Yaml::String(key.to_string())),
        _ => None,
    }
}

/// Every scalar under `y`, keys included, as text.
fn scalars(y: &Yaml, out: &mut Vec<String>) {
    match y {
        Yaml::String(s) | Yaml::Real(s) => out.push(s.clone()),
        Yaml::Integer(i) => out.push(i.to_string()),
        Yaml::Boolean(b) => out.push(b.to_string()),
        Yaml::Array(a) => a.iter().for_each(|e| scalars(e, out)),
        Yaml::Hash(h) => h.iter().for_each(|(k, v)| {
            scalars(k, out);
            scalars(v, out);
        }),
        _ => {}
    }
}

/// Whether the workflow runs on pull requests, from its `on:` key in any of
/// its spellings: a string, a list, or a map (a YAML 1.1 reader turns the key
/// into `true`; both are handled).
fn triggers_on_pull_request(doc: &Yaml) -> bool {
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

/// The jobs of a pull_request-triggered workflow that can reach the
/// self-hosted pool without the fork guard, as `<workflow>: job <id>: …`.
/// A job reaches the pool when its `runs-on`, in any spelling (string, flow or
/// block list, `group`/`labels` map), names `self-hosted`, or names `matrix.`
/// while the job's matrix names `self-hosted`. It is guarded only when
/// `runs-on` is ONE expression string carrying the guard: a list or a map
/// cannot carry a condition, so it always reaches the pool.
fn unguarded_pool_jobs(workflow: &str, text: &str) -> Option<Vec<String>> {
    let mut docs = YamlLoader::load_from_str(text)
        .unwrap_or_else(|e| panic!("{workflow} is not parseable YAML: {e}"));
    assert_eq!(docs.len(), 1, "{workflow}: expected one YAML document");
    let doc = docs.remove(0);
    if !triggers_on_pull_request(&doc) {
        return None;
    }
    let mut out = Vec::new();
    let Some(Yaml::Hash(jobs)) = yaml_get(&doc, "jobs") else {
        return Some(out);
    };
    for (id, job) in jobs {
        let Some(runs_on) = yaml_get(job, "runs-on") else {
            continue;
        };
        let mut named = Vec::new();
        scalars(runs_on, &mut named);
        let matrix_pool = yaml_get(job, "strategy")
            .and_then(|s| yaml_get(s, "matrix"))
            .is_some_and(|m| {
                let mut v = Vec::new();
                scalars(m, &mut v);
                v.iter().any(|x| x.contains("self-hosted"))
            });
        let reaches_pool = named.iter().any(|x| x.contains("self-hosted"))
            || (matrix_pool && named.iter().any(|x| x.contains("matrix.")));
        if !reaches_pool {
            continue;
        }
        let guarded = matches!(runs_on, Yaml::String(s) if s.contains(FORK_GUARD));
        if !guarded {
            out.push(format!(
                "{workflow}: job {}: runs-on {named:?}",
                id.as_str().unwrap_or("?")
            ));
        }
    }
    Some(out)
}

/// A job in a workflow a pull request can trigger reaches the self-hosted pool
/// only through the fail-closed fork guard: the head repository must BE this
/// repository. A literal `[self-hosted, …]` list hands the pool to any fork,
/// and it runs the PR's own checkout (the `changes` jobs ran the PR's
/// `tools/ci/detect-changes.sh` there; found by the v0.48.0 clean-room review).
/// Parsed as YAML: the line scan this replaces missed a block-list `runs-on`,
/// a matrix-supplied runner and the `on: pull_request` / `on: [..]` triggers
/// (v0.48.0 second review). The guard lives in a file a fork PR can edit, so
/// the boundary that holds against a hostile fork is the org's runner-group
/// and fork-approval policy (pulseengine/warte#35); this keeps our own edits
/// from dropping the guard.
#[test]
fn no_pull_request_job_reaches_the_pool_without_the_fork_guard() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut offenders = Vec::new();
    let mut pr_workflows = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        if let Some(found) = unguarded_pool_jobs(&name, &workflow(&name)) {
            pr_workflows += 1;
            offenders.extend(found);
        }
    }
    assert!(
        pr_workflows >= 3,
        "only {pr_workflows} pull_request workflows found"
    );
    assert!(
        offenders.is_empty(),
        "these pull_request-triggered jobs reach the self-hosted pool with no fork guard, \
         so a fork PR runs its own code there:\n{}",
        offenders.join("\n")
    );
}

/// Controls for the scan above: each spelling that reaches the pool is
/// flagged, the guarded expression and a workflow no pull request runs are not.
#[test]
fn the_fork_guard_scan_flags_every_spelling_of_the_pool() {
    let guarded = format!(
        "runs-on: ${{{{ (github.event_name != 'pull_request' || {FORK_GUARD}) && \
         fromJSON('[\"self-hosted\",\"linux\"]') || 'ubuntu-24.04' }}}}"
    );
    let flagged = |label: &str, on: &str, job: &str| {
        let text = format!("on: {on}\njobs:\n  j:\n{job}\n    steps: []\n");
        let got = unguarded_pool_jobs(label, &text).expect("triggers on pull_request");
        assert_eq!(got.len(), 1, "{label} not flagged:\n{text}");
    };
    flagged(
        "flow list",
        "pull_request",
        "    runs-on: [self-hosted, linux]",
    );
    flagged(
        "block list",
        "[push, pull_request]",
        "    runs-on:\n      - self-hosted\n      - linux",
    );
    flagged(
        "labels map",
        "\n  pull_request_target:",
        "    runs-on:\n      group: pool\n      labels: [self-hosted]",
    );
    flagged(
        "matrix runner",
        "\n  pull_request:\n    branches: [main]",
        "    strategy:\n      matrix:\n        runner: [[self-hosted, linux]]\n    runs-on: ${{ matrix.runner }}",
    );
    flagged(
        "guard in a list",
        "pull_request",
        &format!("    runs-on: [self-hosted, \"{FORK_GUARD}\"]"),
    );
    let text = format!("on: pull_request\njobs:\n  j:\n    {guarded}\n    steps: []\n");
    assert_eq!(
        unguarded_pool_jobs("guarded", &text),
        Some(Vec::new()),
        "{text}"
    );
    let text = "on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps: []\n";
    assert_eq!(unguarded_pool_jobs("hosted", text), Some(Vec::new()));
    let text = "on:\n  push:\njobs:\n  j:\n    runs-on: [self-hosted]\n    steps: []\n";
    assert_eq!(unguarded_pool_jobs("push only", text), None);
}
