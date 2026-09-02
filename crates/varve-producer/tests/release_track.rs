//! The assembler's release track, asserted against the workflow that
//! implements it (REQ-PRODUCERSHIP-001).
//!
//! Every clause of this requirement is discharged by `release.yml`, not by
//! library code, so no `// rivet: verifies` marker in a source file can reach
//! it. Without something like this the requirement's evidence is a CI run
//! nobody re-reads, and a gate deleted in an unrelated edit would go unnoticed
//! until a layers repository failed to find a download.
//!
//! This is not a substitute for the release actually publishing the archives —
//! that is the real oracle, and it runs on a tag. It is a guard against the
//! workflow quietly ceasing to say what this requirement says it says.

fn workflow() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/release.yml");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Clause 1 — built on every leg that builds varve, native and cross alike.
/// A producer built only on native targets would ship for two platforms of the
/// four and the count gate would then fail the release, which is the right
/// outcome but a confusing way to discover it.
// rivet: verifies REQ-PRODUCERSHIP-001
#[test]
fn the_assembler_is_built_wherever_varve_is() {
    let w = workflow();
    assert!(
        w.contains(
            "cargo build --release --locked --target ${{ matrix.target }} -p varve-producer"
        ),
        "no native build of varve-producer"
    );
    assert!(
        w.contains(
            "cross build --release --locked --target ${{ matrix.target }} -p varve-producer"
        ),
        "no cross build of varve-producer"
    );
}

/// Clause 1 — a separate archive. Bundling it into varve's tarball would hand
/// every varve user, via install.sh, a binary that fetches over the network:
/// the precise thing varve's "contacts no network" claim promises it is not.
// rivet: verifies REQ-PRODUCERSHIP-001
#[test]
fn the_assembler_ships_in_its_own_archive_and_not_inside_varves() {
    let w = workflow();
    assert!(
        w.contains(r#"PRODUCER="varve-producer-${VERSION}-${TARGET}.tar.gz""#),
        "the producer has no archive of its own"
    );
    // varve's staging directory must contain varve and not the producer.
    let staging = w
        .split(r#"cp "target/${TARGET}/release/varve" staging/"#)
        .nth(1)
        .expect("varve's staging step");
    let varve_tar = staging
        .split(r#"tar -czf "$ARCHIVE" -C staging ."#)
        .next()
        .expect("varve's tar step");
    assert!(
        !varve_tar.contains("varve-producer"),
        "the producer is being copied into varve's archive:\n{varve_tar}"
    );

    // install.sh must not reach for it either.
    let install = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh"),
    )
    .expect("install.sh");
    assert!(
        !install.contains("varve-producer"),
        "install.sh installs the assembler onto every user's machine"
    );
}

/// Clause 3 — the gate. "The assembler is released" is exactly the kind of
/// claim that rots quietly, so its absence must fail a release rather than
/// surface in another repository hours later as a missing download.
// rivet: verifies REQ-PRODUCERSHIP-001
#[test]
fn a_release_missing_the_assembler_is_refused() {
    let w = workflow();
    let gate = w
        .split("Assert the assembler ships with the toolchain")
        .nth(1)
        .expect("the gate step is gone");
    let gate = gate.split("- name:").next().expect("gate body");
    assert!(
        gate.contains("varve-producer-"),
        "the gate counts nothing:\n{gate}"
    );
    assert!(
        gate.contains("exit 1"),
        "the gate reports but does not refuse:\n{gate}"
    );
    // Both failure modes: none at all, and fewer than varve's.
    assert!(
        gate.contains(r#"[ "$prod_n" -eq 0 ]"#),
        "no check for a release with no assembler at all:\n{gate}"
    );
    assert!(
        gate.contains(r#"[ "$prod_n" -ne "$varve_n" ]"#),
        "no check for a build leg that dropped its assembler:\n{gate}"
    );
}

/// Clause 4 — not on crates.io. Two independent guards, because one of them is
/// a line in a workflow that someone could reasonably add a crate to.
// rivet: verifies REQ-PRODUCERSHIP-001
#[test]
fn the_assembler_is_not_published_to_crates_io() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("Cargo.toml");
    assert!(
        manifest.contains("publish = false"),
        "the crate does not refuse publication"
    );
    let pub_wf = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.github/workflows/publish-crates.yml"),
    )
    .expect("publish-crates.yml");
    assert!(
        !pub_wf.contains("publish varve-producer"),
        "the publish workflow names the assembler"
    );
}

/// Clause 5 — the version assertion, including the reported NAME. A binary
/// that calls itself something else cannot appear in evidence about which
/// assembler built a layer.
// rivet: verifies REQ-PRODUCERSHIP-001
#[test]
fn the_release_checks_the_assembler_reports_its_own_name_and_version() {
    let w = workflow();
    let step = w
        .split("Assert varve-producer reports the tag version")
        .nth(1)
        .expect("the version assertion is gone");
    let step = step.split("- name:").next().expect("step body");
    assert!(
        step.contains(r#"[ "$NAME" != "varve-producer" ]"#),
        "the name is not checked:\n{step}"
    );
    assert!(
        step.contains(r#"[ "${VERSION#v}" != "$REPORTED" ]"#),
        "the version is not checked:\n{step}"
    );
}
