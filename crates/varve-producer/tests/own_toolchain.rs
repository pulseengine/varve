//! varve pins the tools its own loop uses, in ONE place (varve#106).
//!
//! rivet used to be declared four times: `RIVET_VERSION` in `ci.yml`, the same
//! variable again in `release.yml`, the layer varve itself publishes, and
//! whatever sat on a maintainer's PATH. They disagreed by six minor versions,
//! and it was not theoretical — `release.yml` gained a `rivet release notes`
//! step that worked locally and did nothing in CI, because CI's rivet was old
//! enough not to have the subcommand. The release shipped with a warning in
//! the log and a release note nobody wrote.
//!
//! The evidence varve ships — `rivet validate`, the coverage report, the ReqIF
//! export in every release — was produced by an ambient tool whose version the
//! artifact never recorded. "Which toolchain produced this evidence?" is the
//! question varve exists to answer, and varve could not answer it about
//! itself.

fn read(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

fn workflows() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "yml").then(|| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read_to_string(&p).unwrap(),
                )
            })
        })
        .collect()
}

/// The pin exists and names a real layer of a real realm.
// rivet: verifies REQ-BOOTSTRAP-001
#[test]
fn varve_pins_its_own_toolchain() {
    let pin = read("varve.toml");
    for needle in ["[toolchain]", "realm", "channel", "layer"] {
        assert!(pin.contains(needle), "varve.toml has no {needle}:\n{pin}");
    }
    // The realm must be one the shipped realms file defines, or the pin
    // resolves to nothing on a fresh machine.
    let realms = read("varve-realms.toml");
    let realm = pin
        .lines()
        .find_map(|l| l.trim().strip_prefix("realm"))
        .and_then(|l| l.split('"').nth(1))
        .expect("the pin names no realm");
    assert!(
        realms.contains(&format!("[realm.{realm}]")),
        "varve.toml pins realm '{realm}', which varve-realms.toml does not define"
    );
}

/// No workflow may name a tool version the pin is supposed to decide.
// rivet: verifies REQ-BOOTSTRAP-001
#[test]
fn no_workflow_declares_a_tool_version_the_pin_owns() {
    // Each of these was a second source of truth for a tool the layer carries.
    // `cargo install <tool>` is the same defect wearing different clothes: it
    // resolves whatever crates.io serves that minute.
    for (name, text) in workflows() {
        for forbidden in ["RIVET_VERSION", "ORDEAL_VERSION"] {
            assert!(
                !text.contains(forbidden),
                "{name} declares {forbidden} — the pin in varve.toml is supposed to be the \
                 single declaration, and a second one drifts from it silently (varve#106)"
            );
        }
    }
}

/// The pin must not be read as covering the binary under test.
///
/// varve's CI cannot pin the `varve` it is testing — that one has to be the
/// build from the working tree, or the gate proves nothing. Saying so in the
/// file is the difference between a true claim and one that sounds stronger.
// rivet: verifies REQ-BOOTSTRAP-001
#[test]
fn the_pin_says_what_it_does_not_cover() {
    let pin = read("varve.toml");
    let lower = pin.to_lowercase();
    assert!(
        lower.contains("under test") || lower.contains("does not cover"),
        "varve.toml does not say that the pin excludes the varve binary being tested — \
         without that, 'varve pins its toolchain' reads as a stronger claim than is true"
    );
}
