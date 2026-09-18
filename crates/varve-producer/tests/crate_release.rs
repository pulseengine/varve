//! The release carries the crates it publishes, under the same signature as
//! every other asset (REQ-CRATEPAYLOAD-001 clause 4).
//!
//! A crate payload in the pulseengine layer is ingested from a varve RELEASE,
//! not from crates.io: cosign over SHA256SUMS.txt is then the proof for a
//! `.crate` exactly as it is for a binary archive, and a crate does not acquire
//! a second, different trust path because it also lives in a package registry.
//!
//! That only works if the release's bytes ARE crates.io's bytes. Measured on
//! 2026-09-17 before anything here was written: `cargo package` of tag v0.35.0
//! on a developer machine produced varve-core and varve tarballs whose sha256
//! equals the `cksum` crates.io's index records for 0.35.0, byte for byte. The
//! `crate-identity` job re-checks that on every tag, because it is a property
//! of cargo that a toolchain change could remove.
//!
//! Which crates is decided in several places — each Cargo.toml's `publish`, the
//! release's package step and its two loops, and the publish workflow — so the tests below
//! compare them all rather than any one against a list written here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The workspace members Cargo will publish: every member whose manifest does
/// not say `publish = false`. Read from the manifests, not listed here.
fn publishable() -> BTreeSet<String> {
    let ws: toml::Table = read("Cargo.toml").parse().expect("workspace Cargo.toml");
    let members = ws["workspace"]["members"].as_array().expect("members");
    members
        .iter()
        .filter_map(|m| {
            let rel = format!("{}/Cargo.toml", m.as_str().expect("member path"));
            let manifest: toml::Table = read(&rel).parse().expect("member Cargo.toml");
            let package = manifest["package"].as_table().expect("[package]");
            let refuses = package.get("publish").and_then(|p| p.as_bool()) == Some(false);
            (!refuses).then(|| package["name"].as_str().expect("name").to_string())
        })
        .collect()
}

/// The crates `release.yml` packages, read from its `cargo package` line.
fn released() -> BTreeSet<String> {
    let w = read(".github/workflows/release.yml");
    let line = w
        .lines()
        .find(|l| l.trim_start().starts_with("cargo package "))
        .expect("release.yml packages no crate");
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .filter(|p| p[0] == "-p")
        .map(|p| p[1].to_string())
        .collect()
}

/// The crates `publish-crates.yml` publishes, read from its `publish <crate>`
/// calls.
fn published() -> BTreeSet<String> {
    read(".github/workflows/publish-crates.yml")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("publish "))
        .map(|c| c.trim().to_string())
        .collect()
}

// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn the_release_carries_exactly_the_crates_cargo_publishes() {
    let cargo = publishable();
    assert!(
        cargo.contains("varve-core"),
        "the consumer crate is not publishable: {cargo:?}"
    );
    assert_eq!(
        released(),
        cargo,
        "release.yml packages a different set of crates from the ones Cargo publishes"
    );
}

// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn the_release_and_the_registry_carry_the_same_crates() {
    assert_eq!(
        released(),
        published(),
        "a crate on crates.io is missing from the release, or the reverse"
    );
}

/// `--workspace` would also package varve-producer and varve-serve, which are
/// `publish = false`: a `.crate` no registry has, offered as though one did.
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn the_package_step_names_its_crates_rather_than_the_whole_workspace() {
    let w = read(".github/workflows/release.yml");
    let line = w
        .lines()
        .find(|l| l.trim_start().starts_with("cargo package "))
        .expect("release.yml packages no crate");
    assert!(!line.contains("--workspace"), "{line}");
    assert!(line.contains("--locked"), "unlocked packaging: {line}");
}

/// Clause 4: the crate is covered by the signature only if it exists before the
/// sums are taken.
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn the_crates_exist_before_the_checksums_are_taken() {
    let w = read(".github/workflows/release.yml");
    let pkg = w
        .find("- name: Package the published crates")
        .expect("the crate packaging step is gone");
    let sums = w
        .find("- name: Generate SHA256 checksums")
        .expect("the checksum step is gone");
    assert!(
        pkg < sums,
        "the crates are packaged after the sums, so nothing signs them"
    );
    let body = &w[pkg..sums];
    assert!(
        body.contains(r#"cp "$f" release-assets/"#),
        "the packaged crates never reach the release assets:\n{body}"
    );
}

/// The release's `.crate` must be the registry's `.crate`. Compared against the
/// index `cksum`, which is what cargo itself checks a download against — not
/// against a second `cargo package` run, which would only show cargo agreeing
/// with itself.
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn a_tag_checks_the_released_crate_is_the_registrys_crate() {
    let w = read(".github/workflows/release.yml");
    let job = w
        .split("\n  crate-identity:")
        .nth(1)
        .expect("no crate-identity job");
    assert!(
        job.contains("index.crates.io"),
        "not compared against the index:\n{job}"
    );
    assert!(
        job.contains("cksum"),
        "not compared against the index cksum:\n{job}"
    );
    assert!(
        job.contains("SHA256SUMS.txt"),
        "not compared against the signed release sums:\n{job}"
    );
}

/// The shell loops that copy the crates and compare them with the index each
/// name the crates again. A crate added to `cargo package` but not to a loop
/// would be packaged and then silently never shipped, or never checked.
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn every_crate_loop_in_the_release_names_the_same_crates() {
    let w = read(".github/workflows/release.yml");
    let loops: Vec<BTreeSet<String>> = w
        .lines()
        .filter_map(|l| l.trim().strip_prefix("for c in "))
        .map(|rest| {
            rest.split(';')
                .next()
                .expect("loop list")
                .split_whitespace()
                .map(str::to_string)
                .collect()
        })
        .collect();
    assert_eq!(
        loops.len(),
        3,
        "expected the copy loop, the rustdoc loop and the identity loop: {loops:?}"
    );
    for l in &loops {
        assert_eq!(
            l,
            &released(),
            "a crate loop disagrees with the package step"
        );
    }
}

/// Each published crate's API documentation ships beside it, as a `rustdoc`
/// docs payload a layer can carry (REQ-LAYERDOCS-001). Before the sums, like
/// every asset the signature has to cover.
///
/// One archive per crate, not one for the workspace: a docs payload is to name
/// the crate it documents, and a bundle of two crates documents neither. Each
/// crate is built into its own target directory, because `target/doc` is
/// shared and a second `cargo doc` would sweep the first crate into its tarball.
// rivet: partially-verifies REQ-LAYERDOCS-001
#[test]
fn each_published_crate_ships_its_rustdoc_before_the_sums() {
    let w = read(".github/workflows/release.yml");
    let doc = w
        .find("- name: Build the API documentation (rustdoc)")
        .expect("no rustdoc step");
    let sums = w
        .find("- name: Generate SHA256 checksums")
        .expect("the checksum step is gone");
    assert!(
        doc < sums,
        "rustdoc is built after the sums, so nothing signs it"
    );
    let step = &w[doc..sums];
    assert!(step.contains("cargo doc --no-deps --locked"), "{step}");
    assert!(
        step.contains(r#"--target-dir "target/rustdoc-$c""#),
        "crates share a doc directory, so one tarball carries another's pages:\n{step}"
    );
    assert!(
        step.contains(r#"release-assets/${c}-${BARE}-rustdoc.tar.gz"#),
        "the rustdoc archive never reaches the release assets:\n{step}"
    );
    // The entry a layer.toml will declare must exist, or the deposit refuses
    // it later in someone else's repository.
    assert!(
        step.contains("index.html"),
        "the entry point is not checked:\n{step}"
    );
}

/// The crates are packaged before anything writes into the working tree.
///
/// v0.36.0's first Release run died here, after crates.io had already
/// published: `cargo cyclonedx` writes `crates/<name>/<name>.cdx.json` into
/// the tree, and `cargo package` refuses a dirty tree — "1 files in the working
/// directory contain changes that were not yet committed into git".
///
/// The refusal is right, which is why the fix is ORDER and not `--allow-dirty`:
/// packaging a dirty tree would produce bytes that are not the tag's, and
/// "these are the bytes crates.io serves" is the whole reason the asset exists.
/// Asserted against the SBOM step by name rather than against a general notion
/// of dirtiness, because that step is the one that does it.
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn the_crates_are_packaged_before_the_sbom_dirties_the_tree() {
    let w = read(".github/workflows/release.yml");
    let pkg = w
        .find("- name: Package the published crates")
        .expect("the crate packaging step is gone");
    let cyclonedx = w
        .find("cargo cyclonedx")
        .expect("the SBOM step is gone — this guard would pass vacuously");
    assert!(
        pkg < cyclonedx,
        "cargo package runs after cargo cyclonedx, which writes a .cdx.json into the \
         working tree; `cargo package` then refuses the dirty tree and the release dies \
         with the crates already published"
    );
    assert!(
        !w[pkg..].contains("--allow-dirty"),
        "packaging with --allow-dirty would ship bytes that are not the tag's"
    );
}
