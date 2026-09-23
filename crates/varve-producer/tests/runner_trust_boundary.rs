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
        let n = w.matches("runs-on: [self-hosted, linux, x64,").count();
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
