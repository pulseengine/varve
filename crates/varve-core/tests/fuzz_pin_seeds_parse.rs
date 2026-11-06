//! The `pin` fuzz target's deep branch is reachable because its corpus holds
//! pins that PARSE (#319, item 2).
//!
//! The target asserts a property only inside `if let Ok(pin) = Pin::parse(..)`.
//! Measured on main at a89dba6a: none of the 3,126 corpus files contained
//! `manifest-version` or `[toolchain]`, and a `panic!` planted in that branch
//! was never reached in a CI-length run. The fuzzer was only ever exercising
//! the error path. The `seed-*.toml` files are valid pins taken from
//! `pin.rs`'s own tests, so mutation starts from inside the branch.
//!
//! This test keeps them valid. A seed that stops parsing, because the pin
//! format moved, would quietly put the fuzzer back on the error path.

use std::path::Path;
use varve_core::Pin;

// rivet: verifies REQ-PIN-001
#[test]
fn every_pin_fuzz_seed_is_a_pin_that_parses() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/pin");
    let mut seeds: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seed-"))
        })
        .collect();
    seeds.sort();
    assert!(
        seeds.len() >= 4,
        "expected the pin fuzz seeds in {}, found {seeds:?}",
        dir.display()
    );
    for seed in &seeds {
        let text = std::fs::read_to_string(seed).unwrap();
        if let Err(e) = Pin::parse(&text, &seed.display().to_string()) {
            panic!(
                "{} no longer parses, so it no longer seeds the fuzzer's \
                 deep branch: {e}",
                seed.display()
            );
        }
    }
}
