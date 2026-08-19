//! REQ-CORROSION-001 end-to-end: a crate vendored by varve's REAL
//! `export_vendor_dir` builds OFFLINE under a real Corrosion/CMake build.
//!
//! This test invokes `cmake` (which fetches Corrosion via FetchContent — a
//! network step) and `cargo`, so it is OPT-IN: it runs only when
//! `VARVE_CORROSION_TEST=1` is set AND `cmake` is on PATH. The normal
//! `cargo test` suite stays hermetic and offline. A dedicated CI job installs
//! cmake and sets the env var. Verified locally 2026-08-12: Corrosion compiled
//! the vendored `cdep` from `vendor/cdep-0.1.0/` offline and produced libapp.a.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use varve_core::crateexport::{CrateEntry, export_vendor_dir, vendored_config_toml};

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// rivet: verifies REQ-CORROSION-001
#[test]
fn corrosion_builds_a_varve_vendored_crate_offline() {
    if std::env::var("VARVE_CORROSION_TEST").is_err() {
        eprintln!("skipping: set VARVE_CORROSION_TEST=1 (needs cmake + network for Corrosion)");
        return;
    }
    assert!(
        have("cmake"),
        "VARVE_CORROSION_TEST set but cmake is not on PATH"
    );

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    // The consumer's own directory IS the export root: `varve
    // export-crates-vendor --out <project>` puts `vendor/` beside
    // `.cargo/config.toml`, and the config names `vendor` RELATIVELY — Cargo
    // resolves such a path against the directory holding `.cargo/`
    // (REQ-REPRO-001 clause 1), which is where Corrosion's `cargo metadata`
    // finds the config from too.
    let consumer = root.join("consumer");

    // 1. A real producer crate -> a real .crate.
    let producer = root.join("cdep");
    write(
        &producer.join("Cargo.toml"),
        "[package]\nname = \"cdep\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\ndescription = \"corrosion oracle dep\"\n",
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
        "package failed: {}",
        String::from_utf8_lossy(&pkg.stderr)
    );
    let bytes = std::fs::read(producer.join("target/package/cdep-0.1.0.crate")).unwrap();
    let cksum = hex::encode(Sha256::digest(&bytes));

    // 2. Vendor it with VARVE'S REAL export code.
    // The vendored tree sits beside the consumer's `.cargo/`, because the
    // generated config names it RELATIVELY — Cargo resolves such a path
    // against the directory holding `.cargo/`, not the cwd (REQ-REPRO-001).
    let vendor = consumer.join(varve_core::crateexport::VENDOR_SUBDIR);
    export_vendor_dir(
        &[CrateEntry {
            name: "cdep".into(),
            version: "0.1.0".into(),
            cksum,
            bytes,
        }],
        &vendor,
    )
    .unwrap();

    // 3. A Rust staticlib consumer depending on the vendored crate, wired to
    //    varve's vendored source, with an offline-generated lockfile.
    write(
        &consumer.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"staticlib\"]\n\n[dependencies]\ncdep = \"0.1.0\"\n",
    );
    write(
        &consumer.join("src/lib.rs"),
        "#[unsafe(no_mangle)] pub extern \"C\" fn app_answer() -> u32 { cdep::answer() }\n",
    );
    write(
        &consumer.join(".cargo/config.toml"),
        &vendored_config_toml(varve_core::crateexport::VENDOR_SUBDIR),
    );
    let lock = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(&consumer)
        .env("CARGO_HOME", &cargo_home)
        .output()
        .expect("generate-lockfile runs");
    assert!(
        lock.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock.stderr)
    );

    // 4. Corrosion builds the consumer OFFLINE (FROZEN = --locked --offline).
    write(
        &root.join("CMakeLists.txt"),
        "cmake_minimum_required(VERSION 3.22)\n\
         project(varve_corrosion_oracle NONE)\n\
         include(FetchContent)\n\
         FetchContent_Declare(Corrosion GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git GIT_TAG v0.5.1)\n\
         FetchContent_MakeAvailable(Corrosion)\n\
         corrosion_import_crate(MANIFEST_PATH consumer/Cargo.toml FROZEN)\n",
    );
    let cfg = Command::new("cmake")
        .args(["-S", ".", "-B", "build"])
        .current_dir(root)
        .env("CARGO_HOME", &cargo_home)
        .output()
        .expect("cmake configure runs");
    assert!(
        cfg.status.success(),
        "cmake configure failed:\n{}",
        String::from_utf8_lossy(&cfg.stderr)
    );
    let build = Command::new("cmake")
        .args(["--build", "build"])
        .current_dir(root)
        .env("CARGO_HOME", &cargo_home)
        .output()
        .expect("cmake build runs");
    assert!(
        build.status.success(),
        "Corrosion offline build against varve's vendored dep failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    // The staticlib exists, and the vendored cdep was compiled into it.
    assert!(
        root.join("build/libapp.a").is_file(),
        "libapp.a was not produced"
    );
    let cdep_compiled = walk(&root.join("build")).iter().any(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("libcdep"))
    });
    assert!(
        cdep_compiled,
        "the vendored cdep dependency was not compiled — Corrosion did not consume the vendor dir"
    );
}

/// Recursively list files under `dir` (small trees only — build output).
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}
