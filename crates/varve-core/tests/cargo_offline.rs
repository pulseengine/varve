//! REQ-CRATE-001 end-to-end oracle: a crate exported into a varve local
//! registry builds OFFLINE through a real Cargo, with the cksum Cargo verifies
//! being exactly varve's signed digest of the `.crate`.
//!
//! This shells out to `cargo` twice (package a producer crate, build a
//! consumer against the exported registry). It is the honest verification of
//! the claim "builds offline through Cargo" — the unit tests cover the
//! registry layout; this proves Cargo actually accepts it.
//!
//! SCOPE (REQ-SYSTEST-001 clause 3) — this fixture is ONE synthetic crate
//! with no dependencies and no features, and therefore CANNOT exercise:
//! dependency resolution (the index's `deps` array is never consulted),
//! feature resolution (`features` never read — varve#73, `"features":{}`
//! breaking every real consumer, was invisible here BY CONSTRUCTION),
//! multiple versions of one name, build scripts, or proc macros. Do not
//! cite these tests as evidence that a real dependency graph builds. That
//! claim is carried by the self-hosting system gate — varve's own
//! Cargo.lock (250 packages, 14 names at more than one version) through
//! `tools/systest/selfhost.sh` in `.github/workflows/systest.yml`.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use varve_core::crateexport::{
    CrateEntry, cargo_config_toml, export_local_registry, export_vendor_dir, vendored_config_toml,
};

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

// rivet: verifies REQ-CRATE-001
#[test]
fn a_varve_exported_crate_builds_offline_through_cargo() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Isolate cargo state so the test never touches the developer's caches.
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();

    // 1. A zero-dependency producer crate, packaged into a real `.crate`.
    let producer = root.join("vdemo");
    write(
        &producer.join("Cargo.toml"),
        "[package]\nname = \"vdemo\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"varve export-cargo oracle fixture\"\n",
    );
    write(
        &producer.join("src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    );
    let pkg = Command::new("cargo")
        .args(["package", "--no-verify", "--allow-dirty"])
        .current_dir(&producer)
        .env("CARGO_HOME", &cargo_home)
        .output()
        .expect("cargo package runs");
    assert!(
        pkg.status.success(),
        "cargo package failed: {}",
        String::from_utf8_lossy(&pkg.stderr)
    );
    let crate_file = producer.join("target/package/vdemo-0.1.0.crate");
    let bytes = std::fs::read(&crate_file).expect("the .crate was produced");

    // 2. The cksum Cargo will verify IS varve's signed digest of the bytes.
    let cksum = hex::encode(Sha256::digest(&bytes));
    let registry = root.join("registry");
    export_local_registry(
        &[CrateEntry {
            name: "vdemo".into(),
            version: "0.1.0".into(),
            cksum,
            bytes,
        }],
        &registry,
    )
    .unwrap();

    // 3. A consumer that depends on vdemo, wired to the varve registry only.
    let consumer = root.join("consumer");
    write(
        &consumer.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nvdemo = \"0.1.0\"\n",
    );
    write(
        &consumer.join("src/main.rs"),
        "fn main() { assert_eq!(vdemo::answer(), 42); }\n",
    );
    write(
        &consumer.join(".cargo/config.toml"),
        &cargo_config_toml(&registry),
    );

    // 4. Build OFFLINE. If Cargo resolves and checksum-verifies vdemo from the
    //    varve registry with no network, the claim holds.
    let build = Command::new("cargo")
        .args(["build", "--offline"])
        .current_dir(&consumer)
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_TARGET_DIR", root.join("consumer-target"))
        .output()
        .expect("cargo build runs");
    assert!(
        build.status.success(),
        "offline build against the varve registry failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
}

// rivet: verifies REQ-VENDOR-001
#[test]
fn a_varve_vendored_crate_builds_offline_through_cargo() {
    // The vendored path: a cargo-vendor-shaped directory bare Cargo (and
    // Corrosion) consume natively. Same producer, same signed digest as the
    // cksum — but UNPACKED trees + [source.vendored-sources].
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();

    let producer = root.join("wdemo");
    write(
        &producer.join("Cargo.toml"),
        "[package]\nname = \"wdemo\"\nversion = \"0.2.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"varve export-crates-vendor oracle fixture\"\n",
    );
    write(&producer.join("src/lib.rs"), "pub fn two() -> u32 { 2 }\n");
    let pkg = Command::new("cargo")
        .args(["package", "--no-verify", "--allow-dirty"])
        .current_dir(&producer)
        .env("CARGO_HOME", &cargo_home)
        .output()
        .expect("cargo package runs");
    assert!(
        pkg.status.success(),
        "cargo package failed: {}",
        String::from_utf8_lossy(&pkg.stderr)
    );
    let bytes = std::fs::read(producer.join("target/package/wdemo-0.2.0.crate")).unwrap();
    let cksum = hex::encode(Sha256::digest(&bytes));

    let vendor = root.join("vendor");
    export_vendor_dir(
        &[CrateEntry {
            name: "wdemo".into(),
            version: "0.2.0".into(),
            cksum,
            bytes,
        }],
        &vendor,
    )
    .unwrap();

    let consumer = root.join("consumer");
    write(
        &consumer.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nwdemo = \"0.2.0\"\n",
    );
    write(
        &consumer.join("src/main.rs"),
        "fn main() { assert_eq!(wdemo::two(), 2); }\n",
    );
    write(
        &consumer.join(".cargo/config.toml"),
        &vendored_config_toml(&vendor),
    );

    let build = Command::new("cargo")
        .args(["build", "--offline"])
        .current_dir(&consumer)
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_TARGET_DIR", root.join("consumer-target"))
        .output()
        .expect("cargo build runs");
    assert!(
        build.status.success(),
        "offline build against the varve VENDORED dir failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
}
