//! REQ-CRATE-001 end-to-end oracle: a crate exported into a varve local
//! registry builds OFFLINE through a real Cargo, with the cksum Cargo verifies
//! being exactly varve's signed digest of the `.crate`.
//!
//! This shells out to `cargo` twice (package a producer crate, build a
//! consumer against the exported registry). It is the honest verification of
//! the claim "builds offline through Cargo" — the unit tests cover the
//! registry layout; this proves Cargo actually accepts it.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use varve_core::crateexport::{CrateEntry, cargo_config_toml, export_local_registry};

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
