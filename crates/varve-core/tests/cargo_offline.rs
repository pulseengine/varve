//! REQ-CRATE-001 / REQ-CRATEIDX-001 / REQ-REPRO-001 end-to-end oracle: crates
//! exported into a varve local registry build OFFLINE through a real Cargo,
//! with the cksum Cargo verifies being exactly varve's signed digest of the
//! `.crate`.
//!
//! The fixture is deliberately a REAL GRAPH (REQ-CRATEIDX-001 clause 3). Until
//! v0.27.0 this file passed with ONE dependency-free crate, which held the
//! single degree of freedom separating a working export from a broken one at
//! zero: `export-cargo` wrote `"deps":[]` and `"features":{}` for every crate
//! while Cargo resolves the graph FROM the index, and no test could see it.
//! The graph below has transitive dependencies, features requested of a
//! dependency, `default-features = false`, a renamed dependency, and TWO
//! versions of one name — and the assertion is on the BUILT ARTIFACT's
//! behaviour, because the worst observed outcome of the stub was a build that
//! exits 0 with a crate compiled featureless.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};
use varve_core::crateexport::{
    CrateEntry, REGISTRY_SUBDIR, VENDOR_SUBDIR, cargo_config_toml, export_local_registry,
    export_vendor_dir, vendored_config_toml,
};

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// `cargo package` a producer directory and return the `.crate` bytes.
fn package(dir: &Path, cargo_home: &Path, name: &str, version: &str) -> Vec<u8> {
    let pkg = Command::new("cargo")
        .args(["package", "--no-verify", "--allow-dirty", "--offline"])
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("cargo package runs");
    assert!(
        pkg.status.success(),
        "cargo package {name} {version} failed: {}",
        String::from_utf8_lossy(&pkg.stderr)
    );
    std::fs::read(dir.join(format!("target/package/{name}-{version}.crate")))
        .unwrap_or_else(|e| panic!("the .crate for {name} {version} was produced: {e}"))
}

/// A `CrateEntry` whose cksum is the sha256 varve signs — the same number
/// Cargo re-checks the tarball against.
fn entry(name: &str, version: &str, bytes: Vec<u8>) -> CrateEntry {
    CrateEntry {
        name: name.into(),
        version: version.into(),
        cksum: hex::encode(Sha256::digest(&bytes)),
        bytes,
    }
}

/// Lay out the four producer crates of the oracle graph and package them.
///
/// ```text
/// consumer -> vtop 0.1 --------> vmid 0.1 -> vleaf 0.1 (features=["extra"], default-features=false)
///                    \-> vleaf 0.2 (default features on)
///                     \-> `aliased` = vleaf 0.1  (a RENAMED dependency)
/// ```
fn producer_graph(root: &Path, cargo_home: &Path) -> Vec<CrateEntry> {
    // Two versions of one name, semver-incompatible so BOTH must be present.
    for (dir, version, tag) in [("vleaf01", "0.1.0", 1u32), ("vleaf02", "0.2.0", 2)] {
        let d = root.join(dir);
        write(
            &d.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"vleaf\"\nversion = \"{version}\"\nedition = \"2021\"\n\
                 license = \"MIT\"\ndescription = \"varve export oracle leaf\"\n\
                 rust-version = \"1.70\"\n\n\
                 [features]\ndefault = [\"std\"]\nstd = []\nextra = []\n"
            ),
        );
        // `width` is the SILENT case made visible: with `default` missing from
        // the index the crate compiles with no features at all and returns 8,
        // and the build still exits 0.
        write(
            &d.join("src/lib.rs"),
            &format!(
                "#[cfg(feature = \"std\")]\npub fn width() -> u32 {{ 64 }}\n\
                 #[cfg(not(feature = \"std\"))]\npub fn width() -> u32 {{ 8 }}\n\
                 #[cfg(feature = \"extra\")]\npub fn extra() -> u32 {{ 7 }}\n\
                 pub fn version_tag() -> u32 {{ {tag} }}\n"
            ),
        );
    }

    // A middle crate: a TRANSITIVE dependency that asks for a non-default
    // feature of its own dependency and turns the defaults OFF.
    let mid = root.join("vmid");
    write(
        &mid.join("Cargo.toml"),
        "[package]\nname = \"vmid\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         license = \"MIT\"\ndescription = \"varve export oracle middle\"\n\n\
         [dependencies]\n\
         vleaf = { path = \"../vleaf01\", version = \"0.1\", features = [\"extra\"], \
         default-features = false }\n\n\
         [dev-dependencies]\n\
         vleaf = { path = \"../vleaf01\", version = \"0.1\" }\n",
    );
    // 7 + 8: `extra` on (asked for), `std` off (defaults refused).
    write(
        &mid.join("src/lib.rs"),
        "pub fn mid() -> u32 { vleaf::extra() + vleaf::width() }\n",
    );

    let top = root.join("vtop");
    write(
        &top.join("Cargo.toml"),
        "[package]\nname = \"vtop\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         license = \"MIT\"\ndescription = \"varve export oracle top\"\n\n\
         [dependencies]\n\
         vmid = { path = \"../vmid\", version = \"0.1\" }\n\
         vleaf = { path = \"../vleaf02\", version = \"0.2\" }\n\
         aliased = { path = \"../vleaf01\", version = \"0.1\", package = \"vleaf\", \
         default-features = false }\n\n\
         [features]\ndefault = [\"wide\"]\nwide = []\n",
    );
    write(
        &top.join("src/lib.rs"),
        "pub fn top() -> u32 {\n\
        \x20   let mut n = vmid::mid() * 100 + vleaf::width();\n\
        \x20   if cfg!(feature = \"wide\") { n += 10000; }\n\
        \x20   n\n\
         }\n\
         pub fn leaf_major() -> u32 { vleaf::version_tag() }\n\
         pub fn aliased_major() -> u32 { aliased::version_tag() }\n",
    );

    // `cargo package` strips the `path` from each dependency and then RESOLVES
    // the remaining version requirement, so a crate cannot be packaged before
    // its dependencies exist in a registry. Build the graph bottom-up into a
    // scratch registry — which is itself another use of the relative
    // `local-registry` path, from four different working directories.
    let scratch = root.join(REGISTRY_SUBDIR);
    write(
        &root.join(".cargo/config.toml"),
        &cargo_config_toml(REGISTRY_SUBDIR),
    );
    let mut built: Vec<CrateEntry> = Vec::new();
    for (dir, name, version) in [
        ("vleaf01", "vleaf", "0.1.0"),
        ("vleaf02", "vleaf", "0.2.0"),
        ("vmid", "vmid", "0.1.0"),
        ("vtop", "vtop", "0.1.0"),
    ] {
        let bytes = package(&root.join(dir), cargo_home, name, version);
        built.push(entry(name, version, bytes));
        // Re-export the whole set: the next crate up resolves against it.
        export_local_registry(&built, &scratch).unwrap();
    }
    built
}

// rivet: verifies REQ-CRATE-001, REQ-CRATEIDX-001, REQ-REPRO-001
#[test]
fn a_varve_exported_registry_resolves_a_real_graph_and_builds_it_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Isolate cargo state so the test never touches the developer's caches.
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let producers = root.join("producers");
    let crates = producer_graph(&producers, &cargo_home);

    // The EXPORT ROOT, laid out exactly as `varve export-cargo --out` does:
    // `registry/` beside `.cargo/config.toml`.
    let export = root.join("export");
    let registry = export.join(REGISTRY_SUBDIR);
    export_local_registry(&crates, &registry).unwrap();
    write(
        &export.join(".cargo/config.toml"),
        &cargo_config_toml(REGISTRY_SUBDIR),
    );

    // The consumer lives in a SUBDIRECTORY of the export root, so its cwd is
    // not the config's directory. This is the empirical question REQ-REPRO-001
    // clause 1 required settling before anything changed: Cargo resolves a
    // relative `local-registry` against the directory that HOLDS `.cargo/`,
    // never against the cwd. The negative control is below.
    let consumer = export.join("consumer");
    write(
        &consumer.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nvtop = \"0.1\"\n",
    );
    // The assertions are on BEHAVIOUR, not on a count of files:
    //   vmid::mid()      = extra(7) + width(8)   = 15   -> vleaf 0.1 built with
    //                                                     `extra` on, defaults off
    //   vleaf::width()   = 64                            -> vleaf 0.2 built with its
    //                                                     `default` feature, the case
    //                                                     that otherwise exits 0 wrong
    //   +10000                                           -> vtop's own `default`
    //   leaf_major()=2, aliased_major()=1                -> two versions of one name,
    //                                                     one of them RENAMED
    write(
        &consumer.join("src/main.rs"),
        "fn main() {\n\
        \x20   assert_eq!(vtop::top(), 11564, \"the index under-reported deps or features\");\n\
        \x20   assert_eq!(vtop::leaf_major(), 2, \"the wrong version of vleaf was linked\");\n\
        \x20   assert_eq!(vtop::aliased_major(), 1, \"the renamed dependency was lost\");\n\
         }\n",
    );

    // Negative control for the path question, checked before the build so a
    // pass cannot be explained by a registry that happened to be reachable
    // from the cwd or from `.cargo/` itself.
    assert!(
        !consumer.join(REGISTRY_SUBDIR).exists(),
        "no registry may exist at the CWD-relative location"
    );
    assert!(
        !export.join(".cargo").join(REGISTRY_SUBDIR).exists(),
        "no registry may exist beside the config file itself"
    );

    // RUN it, not merely build it: the failure this oracle exists to catch
    // compiles cleanly and produces the wrong program.
    let run = Command::new("cargo")
        .args(["run", "--offline"])
        .current_dir(&consumer)
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_TARGET_DIR", root.join("consumer-target"))
        .output()
        .expect("cargo run runs");
    assert!(
        run.status.success(),
        "offline build+run against the varve registry failed:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // Cargo resolved through the index varve wrote: the lockfile it produced
    // must name every crate of the graph, each at its own version.
    let lock = std::fs::read_to_string(consumer.join("Cargo.lock")).unwrap();
    for (name, version) in [
        ("vleaf", "0.1.0"),
        ("vleaf", "0.2.0"),
        ("vmid", "0.1.0"),
        ("vtop", "0.1.0"),
    ] {
        assert!(
            lock.contains(&format!("name = \"{name}\""))
                && lock.contains(&format!("version = \"{version}\"")),
            "{name} {version} missing from the resolved lockfile:\n{lock}"
        );
    }
}

// rivet: verifies REQ-CRATEIDX-001
#[test]
fn an_index_entry_varve_wrote_is_the_entry_cargo_reads() {
    // The line itself, read back from the registry Cargo consumes. The
    // end-to-end test above proves Cargo ACCEPTS it; this pins WHAT it says,
    // so a regression names the field rather than a build failure five layers
    // away from the cause.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let crates = producer_graph(&root.join("producers"), &cargo_home);
    let registry = root.join("registry");
    export_local_registry(&crates, &registry).unwrap();

    let read = |name: &str, path: &str| -> Vec<serde_json::Value> {
        std::fs::read_to_string(registry.join("index").join(path))
            .unwrap_or_else(|e| panic!("index for {name}: {e}"))
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("Cargo parses one JSON object per line"))
            .collect()
    };

    let leaf = read("vleaf", "vl/ea/vleaf");
    assert_eq!(leaf.len(), 2, "both versions of vleaf must be offered");
    for line in &leaf {
        assert_eq!(line["features"]["default"], serde_json::json!(["std"]));
        assert_eq!(line["rust_version"], "1.70");
    }

    let mid = &read("vmid", "vm/id/vmid")[0];
    let deps = mid["deps"].as_array().unwrap();
    let normal = deps
        .iter()
        .find(|d| d["name"] == "vleaf" && d["kind"] == "normal")
        .expect("vmid's normal dependency on vleaf");
    assert_eq!(normal["req"], "0.1");
    assert_eq!(normal["features"], serde_json::json!(["extra"]));
    assert_eq!(normal["default_features"], false);
    // Its dev-dependency travels too, exactly as crates.io records one.
    assert!(
        deps.iter().any(|d| d["kind"] == "dev"),
        "the dev-dependency must not be dropped: {deps:?}"
    );

    let top = &read("vtop", "vt/op/vtop")[0];
    let aliased = top["deps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "aliased")
        .expect("the renamed dependency keeps its local name");
    assert_eq!(
        aliased["package"], "vleaf",
        "a rename must carry the real package name"
    );
    assert_eq!(top["features"]["default"], serde_json::json!(["wide"]));
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
    let bytes = package(&producer, &cargo_home, "wdemo", "0.2.0");

    // The export root: `vendor/` beside `.cargo/config.toml`, as the adapter
    // lays it out, and the consumer in a subdirectory of it.
    let export = root.join("export");
    let vendor = export.join(VENDOR_SUBDIR);
    export_vendor_dir(&[entry("wdemo", "0.2.0", bytes)], &vendor).unwrap();
    write(
        &export.join(".cargo/config.toml"),
        &vendored_config_toml(VENDOR_SUBDIR),
    );

    let consumer = export.join("consumer");
    write(
        &consumer.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nwdemo = \"0.2.0\"\n",
    );
    write(
        &consumer.join("src/main.rs"),
        "fn main() { assert_eq!(wdemo::two(), 2); }\n",
    );
    assert!(
        !consumer.join(VENDOR_SUBDIR).exists(),
        "no vendor tree may exist at the CWD-relative location"
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
