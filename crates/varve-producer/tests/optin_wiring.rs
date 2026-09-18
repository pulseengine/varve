//! The deposit path takes its opt-ins from the MANIFEST, not only from the air.
//!
//! varve refused to deposit `pulseengine-wasm` layer 2026.09.0 with:
//!
//!   bytecodealliance/wac v0.11.0 offers no ingestion proof this assembler
//!   accepts … To ingest it anyway you must say why …
//!     UNVERIFIED_INGEST="bytecodealliance/wac=<why …>"
//!
//! while layer.toml already carried `unverified-reason` for that repository and
//! `varve-producer plan` printed "3 release(s) carry NO proof of origin (opt-in
//! recorded)". Two code paths decided one thing: plan read the manifest, deposit
//! read an environment variable. The field parsed, displayed, and was inert at
//! the only moment it decides anything.
//!
//! A unit test of `optins_in_force` cannot catch that — the defect was never in
//! the merge, it was in what the deposit command passed to it. So this reads the
//! wiring at the source level, the way release_track.rs reads release.yml.

fn main_rs() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// rivet: verifies REQ-INGEST-001
#[test]
fn the_deposit_command_builds_its_optins_from_the_plan_and_the_environment() {
    let s = main_rs();
    let call = s
        .split("let optins =")
        .nth(1)
        .expect("the deposit command no longer builds an opt-in set at all");
    let call = call.split(";\n").next().expect("the statement");
    assert!(
        call.contains("optins_in_force"),
        "the deposit does not use the one function that merges both sources:\n{call}"
    );
    assert!(
        call.contains("unverified_reason"),
        "the deposit ignores the manifest's reasons — a realm that states why in layer.toml \
         is told to set an environment variable instead:\n{call}"
    );
    assert!(
        call.contains("UNVERIFIED_INGEST"),
        "the environment opt-in is gone; the legacy path and one-off recoveries need it:\n{call}"
    );
}

/// `plan` says "opt-in recorded" from the same field. If the two ever disagree
/// again, they disagree about whether a deposit is about to refuse.
// rivet: verifies REQ-INGEST-001
#[test]
fn plan_and_deposit_read_the_same_field() {
    let s = main_rs();
    assert!(
        s.matches("unverified_reason").count() >= 2,
        "only one command consults unverified_reason; the other decides differently"
    );
}
