//! `varve seed` (REQ-SEED-001), at the boundary a user touches.
//!
//! The scenario is the one the requirement came from: a host store already
//! holds a composed layer, a container's store (a separate one) has installed
//! this realm before and now has its pin changed — and must not go back to the
//! registry, which here is a port nothing listens on, with no credential in the
//! environment.
//!
//! Two stores share nothing but the realm's public key and the seed directory.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

/// Where nothing listens: connection refused, immediately.
const DEAD: &str = "oci+http://127.0.0.1:1/acme/layers";

struct World {
    tmp: tempfile::TempDir,
    key: PathBuf,
    root_hex: String,
}

/// One generation of the realm: an upstream layer and a root layer composing
/// it, each a deposited layout.
struct Gen {
    root_layout: PathBuf,
    root_digest: String,
    up_layout: PathBuf,
    root_layer: String,
}

impl World {
    fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("acme.key");
        let pubf = tmp.path().join("acme.pub");
        let w = World {
            tmp,
            key,
            root_hex: String::new(),
        };
        w.varve(&w.path("scratch-root"), &w.path("scratch-project"))
            .args(["keygen", "--out"])
            .arg(&w.key)
            .arg("--pub")
            .arg(&pubf)
            .assert()
            .success();
        let root_hex = std::fs::read_to_string(&pubf).unwrap().trim().to_string();
        World { root_hex, ..w }
    }

    fn path(&self, name: &str) -> PathBuf {
        let p = self.tmp.path().join(name);
        if name.ends_with("project") {
            std::fs::create_dir_all(&p).unwrap();
        }
        p
    }

    /// The binary, in a given store and project, with no registry credential
    /// and a PATH that holds nothing of the developer's.
    fn varve(&self, root: &Path, project: &Path) -> Command {
        std::fs::create_dir_all(project).unwrap();
        let mut cmd = Command::cargo_bin("varve").unwrap();
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.tmp.path())
            .env("VARVE_ROOT", root)
            .current_dir(project);
        cmd
    }

    /// Deposit one layer; returns (layout, manifest digest).
    fn deposit(
        &self,
        layer: &str,
        counter: u64,
        include: Option<(&str, &str)>,
    ) -> (PathBuf, String) {
        let tool = self.path(&format!("tool-{layer}"));
        std::fs::write(&tool, format!("#!/bin/sh\necho {layer}\n")).unwrap();
        let mut spec = format!(
            "layer = \"{layer}\"\nchannel = \"qualified\"\ncounter = {counter}\n\n\
             [[tool]]\nname = \"tool-{layer}\"\nversion = \"1.0.0\"\npath = \"{}\"\n",
            tool.display()
        );
        if let Some((digest, name)) = include {
            spec.push_str(&format!(
                "\n[[include]]\ndigest = \"{digest}\"\nrealm = \"acme\"\nlayer = \"{name}\"\n"
            ));
        }
        let spec_path = self.path(&format!("spec-{layer}.toml"));
        std::fs::write(&spec_path, spec).unwrap();
        let layout = self.path(&format!("layout-{layer}"));
        let out = self
            .varve(&self.path("scratch-root"), &self.path("scratch-project"))
            .args(["deposit", "--json", "--spec"])
            .arg(&spec_path)
            .args(["--issued-at", "2026-09-01T00:00:00Z", "--key"])
            .arg(&self.key)
            .args(["--key-id", "acme-root", "--out"])
            .arg(&layout)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        (
            layout,
            json["manifest_digest"].as_str().unwrap().to_string(),
        )
    }

    /// An upstream layer (line 2026.09) and a root layer (line 2026.08)
    /// composing it, `n` apart so that generation 2 is newer than 1.
    fn generation(&self, n: u64) -> Gen {
        let up_layer = format!("2026.09.{}", n - 1);
        let root_layer = format!("2026.08.{}", n - 1);
        let (up_layout, up_digest) = self.deposit(&up_layer, n, None);
        let (root_layout, root_digest) =
            self.deposit(&root_layer, n, Some((&up_digest, &up_layer)));
        Gen {
            root_layout,
            root_digest,
            up_layout,
            root_layer,
        }
    }

    /// Write the project's realm file and pin.
    fn project(&self, project: &Path, registry: &str, mirrors: &[&Path], layer: &str, extra: &str) {
        std::fs::create_dir_all(project).unwrap();
        let mirrors = mirrors
            .iter()
            .map(|m| format!("\"{}\"", m.display()))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            project.join("varve-realms.toml"),
            format!(
                "[realm.acme]\nregistry = \"{registry}\"\nmirrors = [{mirrors}]\n\
                 trust-root = \"{}\"\n{extra}",
                self.root_hex
            ),
        )
        .unwrap();
        std::fs::write(
            project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{layer}\"\n"
            ),
        )
        .unwrap();
    }

    /// Install generation `g` into `root`, from the layouts alone (the upstream
    /// layout is the realm's primary, the root layer comes `--from` its own).
    fn install_gen(&self, root: &Path, project: &Path, g: &Gen) {
        self.project(
            project,
            &g.up_layout.display().to_string(),
            &[],
            &g.root_layer,
            "",
        );
        self.varve(root, project)
            .args(["install", "--from"])
            .arg(&g.root_layout)
            .assert()
            .success();
    }
}

fn read_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap()) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    !n.is_empty() && haystack.windows(n.len()).any(|w| w == n)
}

/// Flip one bit of one byte of a file.
fn flip(path: &Path, at: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[at] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
}

/// The seed layouts a `varve seed --json` run reports, keyed by layer id.
fn mirrors_of(stdout: &[u8]) -> std::collections::BTreeMap<String, PathBuf> {
    let json: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    json["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["layer"].as_str().unwrap().to_string(),
                PathBuf::from(l["mirror"].as_str().unwrap()),
            )
        })
        .collect()
}

/// The whole story: the host holds generation 2, the container store holds
/// generation 1, its pin moves to generation 2 — and the registry is gone.
// rivet: verifies REQ-SEED-001
#[test]
fn a_container_store_installs_a_composed_layer_from_a_seed_with_no_network() {
    let w = World::new();
    let g1 = w.generation(1);
    let g2 = w.generation(2);

    // The host store: everything installed, from layouts.
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g2);

    // Seed from the host. The default is the pin and what it composes.
    let seed = w.path("seed");
    let out = w
        .varve(&host, &host_project)
        .args(["seed", "--json"])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mirrors = mirrors_of(&out);
    assert_eq!(
        mirrors.keys().map(String::as_str).collect::<Vec<_>>(),
        ["2026.08.1", "2026.09.1"],
        "the pin AND the layer it composes"
    );
    for dir in mirrors.values() {
        assert!(dir.starts_with(&seed) && dir.is_absolute());
        assert!(dir.join("oci-layout").is_file(), "{}", dir.display());
    }

    // The container: a separate store that has been here before (generation
    // 1, from layouts), now with the registry unreachable, the seed as the
    // realm's mirrors, and the pin moved forward.
    let container = w.path("container-root");
    let container_project = w.path("container-project");
    w.install_gen(&container, &container_project, &g1);
    // Control: without the seed this pin change needs the registry, and the
    // registry is gone — so what follows is the seed's doing and nothing else.
    w.project(&container_project, DEAD, &[], &g2.root_layer, "");
    w.varve(&container, &container_project)
        .arg("install")
        .assert()
        .failure();
    let mirror_paths: Vec<&Path> = mirrors.values().map(PathBuf::as_path).collect();
    w.project(&container_project, DEAD, &mirror_paths, &g2.root_layer, "");

    w.varve(&container, &container_project)
        .arg("install")
        .assert()
        .success()
        .stdout(predicate::str::contains("installed layer 2026.08.1"))
        .stdout(predicate::str::contains("fetched composed layer 2026.09.1"));
    // Not merely "exited 0": the layer is the host's, by digest, and verifies.
    w.varve(&container, &container_project)
        .arg("verify")
        .assert()
        .success();
    w.varve(&container, &container_project)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&g2.root_digest));
}

/// A fresh store, nothing but the seed as its only source: the other half of
/// "no network and no credential", and the case a CI cache hits.
// rivet: verifies REQ-SEED-001
#[test]
fn a_fresh_store_installs_from_one_seeded_layout_and_verifies() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    let out = w
        .varve(&host, &host_project)
        .args(["seed", "--json"])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mirrors = mirrors_of(&out);

    let fresh = w.path("fresh-root");
    let fresh_project = w.path("fresh-project");
    // The upstream layer's layout is the realm's primary (a directory: no
    // network), the root layer is named with --from.
    w.project(
        &fresh_project,
        &mirrors["2026.09.0"].display().to_string(),
        &[],
        "2026.08.0",
        "",
    );
    w.varve(&fresh, &fresh_project)
        .args(["install", "--from"])
        .arg(&mirrors["2026.08.0"])
        .assert()
        .success();
    w.varve(&fresh, &fresh_project)
        .args(["verify", "--all"])
        .assert()
        .success();
}

/// The limit, pinned so the docs cannot drift from it: a store that has NEVER
/// installed a line does not take it from a MIRROR, seed or not, because a
/// mirror cannot prove it is current (install.rs, first contact). A seed is
/// that store's PRIMARY or the store installs once from the registry first.
// rivet: verifies REQ-SEED-001
#[test]
fn a_never_installed_store_does_not_take_a_seed_through_mirrors() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    let out = w
        .varve(&host, &host_project)
        .args(["seed", "--json"])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mirrors = mirrors_of(&out);
    let mirror_paths: Vec<&Path> = mirrors.values().map(PathBuf::as_path).collect();

    let fresh = w.path("fresh-root");
    let fresh_project = w.path("fresh-project");
    w.project(&fresh_project, DEAD, &mirror_paths, "2026.08.0", "");
    w.varve(&fresh, &fresh_project)
        .arg("install")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("first contact"))
        .stderr(predicate::str::contains("needs the realm's primary"));
}

// rivet: verifies REQ-SEED-001
#[test]
fn a_seed_is_transport_not_authority_one_flipped_byte_is_refused() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    let out = w
        .varve(&host, &host_project)
        .args(["seed", "--json"])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let layout = mirrors_of(&out)["2026.09.0"].clone();
    let attempt = |name: &str| {
        let root = w.path(&format!("{name}-root"));
        let project = w.path(&format!("{name}-project"));
        w.project(
            &project,
            &layout.display().to_string(),
            &[],
            "2026.09.0",
            "",
        );
        let mut cmd = w.varve(&root, &project);
        cmd.args(["install", "--from"]).arg(&layout);
        cmd
    };

    // Control: the untouched seed installs, so the failures below are the
    // flipped byte and nothing else.
    attempt("control").assert().success();

    // Which blob is the payload, which the envelope: by what they ARE.
    let blobs = layout.join("blobs/sha256");
    let payload_blob = std::fs::read_dir(&blobs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| std::fs::read(p).unwrap().starts_with(b"#!/bin/sh"))
        .expect("the tool payload is in the seed");
    let envelope_blob = std::fs::read_dir(&blobs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| contains(&std::fs::read(p).unwrap(), "\"signatures\""))
        .expect("the manifest envelope is in the seed");

    flip(&payload_blob, 3);
    attempt("bad-payload")
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match its signed digest"));
    flip(&payload_blob, 3);

    let text = std::fs::read_to_string(&envelope_blob).unwrap();
    let key_at = text.find("\"sig\"").expect("a `sig` key");
    let colon = key_at + text[key_at..].find(':').unwrap();
    let sig_at = colon + text[colon..].find('"').unwrap() + 1 + 4;
    flip(&envelope_blob, sig_at);
    attempt("bad-envelope")
        .assert()
        .failure()
        .stderr(predicate::str::contains("signature"));
    flip(&envelope_blob, sig_at);
    attempt("restored").assert().success();
}

/// Clause 3: nothing in a seed holds the store's absolute path, and the test
/// can fail — the host store really does hold files that carry it.
// rivet: verifies REQ-SEED-001
#[test]
fn a_seed_holds_no_absolute_path_of_the_store_it_came_from() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    // What bakes the store's path into files: shims and the env script.
    w.varve(&host, &host_project)
        .args(["shim", "install"])
        .assert()
        .success();

    let host_str = host.display().to_string();
    let host_canon = std::fs::canonicalize(&host).unwrap().display().to_string();
    let in_store = |t: &[(PathBuf, Vec<u8>)]| {
        t.iter()
            .filter(|(_, b)| contains(b, &host_str) || contains(b, &host_canon))
            .count()
    };
    let store_files = read_tree(&host);
    let shim_links = std::fs::read_dir(host.join("shims")).unwrap().count();
    // Shims are links to the varve binary, so they prove nothing about the
    // store's path. A FILE of the store must carry it, or the scan below
    // could not fail.
    assert!(shim_links > 0, "shim install wrote no shims");
    assert!(
        in_store(&store_files) > 0,
        "no file in the source store holds its path, so the scan could not fail"
    );

    let seed = w.path("seed");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .success();
    let seeded = read_tree(&seed);
    assert!(seeded.len() >= 8, "the scan needs a seed to scan");
    assert_eq!(in_store(&seeded), 0, "a seed file carries the store's path");
    for (p, _) in &seeded {
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(name != "env" && !p.starts_with(seed.join("shims")));
    }
    // And no symlink: a link would be a path by another name.
    fn links(dir: &Path, found: &mut usize) {
        for e in std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()) {
            let p = e.path();
            if e.file_type().unwrap().is_symlink() {
                *found += 1;
            } else if p.is_dir() {
                links(&p, found);
            }
        }
    }
    let mut found = 0;
    links(&seed, &mut found);
    assert_eq!(found, 0);
}

// rivet: verifies REQ-SEED-001
#[test]
fn a_relative_directory_is_refused_before_anything_is_written() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    w.varve(&host, &host_project)
        .args(["seed", "seed-here"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not an absolute path"))
        .stderr(predicate::str::contains("mirrors"));
    assert!(!host_project.join("seed-here").exists());
}

// rivet: verifies REQ-SEED-001
#[test]
fn a_non_empty_directory_that_is_not_a_seed_is_refused_untouched() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let foreign = w.path("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::write(foreign.join("notes.txt"), "mine").unwrap();
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&foreign)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not a varve seed"));
    assert_eq!(read_tree(&foreign).len(), 1, "nothing was written");

    // A previous seed, by contrast, is accepted again.
    let seed = w.path("seed");
    for _ in 0..2 {
        w.varve(&host, &host_project)
            .arg("seed")
            .arg(&seed)
            .assert()
            .success();
    }
}

/// A realm that requires a signed index cannot be satisfied by a seed made
/// without one, and the store never makes one up.
// rivet: verifies REQ-SEED-001
#[test]
fn a_realm_requiring_a_signed_index_refuses_a_seed_that_could_not_carry_it() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    // The realm now declares the obligation; this store never held an index.
    w.project(
        &host_project,
        &g.up_layout.display().to_string(),
        &[],
        &g.root_layer,
        "signed-index = true\n",
    );
    let seed = w.path("seed");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("signed-index = true"))
        .stderr(predicate::str::contains("signed line index"));
    assert!(!seed.exists(), "a refusal leaves nothing behind");
}

// rivet: verifies REQ-SEED-001
#[test]
fn one_layer_can_be_named_by_id_and_digest() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    // The wrong id for a real digest is refused: a seed never relabels.
    w.varve(&host, &host_project)
        .args(["seed", "--layer", "2026.08.9", "--digest", &g.root_digest])
        .arg(&seed)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not 2026.08.9"));
    // A digest that is not installed is refused.
    w.varve(&host, &host_project)
        .args(["seed", "--layer", "2026.08.0", "--digest"])
        .arg(format!("sha256:{}", "0".repeat(64)))
        .arg(&seed)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("not installed"));
    // The real pair is seeded, with what it composes.
    let out = w
        .varve(&host, &host_project)
        .args([
            "seed",
            "--json",
            "--layer",
            "2026.08.0",
            "--digest",
            &g.root_digest,
        ])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(mirrors_of(&out).len(), 2);
    // --layer and --digest go together.
    w.varve(&host, &host_project)
        .args(["seed", "--layer", "2026.08.0"])
        .arg(&seed)
        .assert()
        .failure()
        .code(2);
}

// rivet: verifies REQ-SEED-001
#[test]
fn a_composed_layer_missing_from_the_store_is_named_not_skipped() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    // Remove the included layer's directory from the store.
    let core = host.join("realms");
    let mut removed = 0;
    for part in std::fs::read_dir(&core).unwrap().map(|e| e.unwrap().path()) {
        for layer in std::fs::read_dir(part.join("core"))
            .unwrap()
            .map(|e| e.unwrap().path())
        {
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(layer.join("layer.json")).unwrap()).unwrap();
            if manifest["annotations"]["eu.pulseengine.varve.layer"] == "2026.09.0" {
                std::fs::remove_dir_all(&layer).unwrap();
                removed += 1;
            }
        }
    }
    assert_eq!(
        removed, 1,
        "the fixture must have removed the upstream layer"
    );
    let seed = w.path("seed");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("2026.09.0"))
        .stderr(predicate::str::contains("not installed"));
    assert!(!seed.exists());
}

#[test]
fn help_exits_zero_and_an_unknown_flag_exits_two() {
    let w = World::new();
    let root = w.path("r");
    let project = w.path("p-project");
    w.varve(&root, &project)
        .args(["seed", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mirrors"));
    w.varve(&root, &project)
        .args(["seed", "--bogus", "/x"])
        .assert()
        .failure()
        .code(2);
}

/// Every file under `root` whose name is `name`.
fn find_named(root: &Path, name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap()) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == name) {
                out.push(p);
            }
        }
    }
    out
}

/// Names of the entries directly inside `dir`, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A re-seed must not follow anything a previous seed's directory now holds.
// rivet: verifies REQ-SEED-001
#[cfg(unix)]
#[test]
fn a_reseed_does_not_follow_symlinks_planted_in_the_previous_seed() {
    use std::os::unix::fs::symlink;
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    let out = w
        .varve(&host, &host_project)
        .args(["seed", "--json"])
        .arg(&seed)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mirrors = mirrors_of(&out);
    let a = mirrors["2026.08.0"].clone();
    let b = mirrors["2026.09.0"].clone();

    let victim_file = w.path("victim-file");
    std::fs::write(&victim_file, "precious").unwrap();
    let victim_dir = w.path("victim-dir");
    std::fs::create_dir(&victim_dir).unwrap();
    std::fs::remove_file(a.join("index.json")).unwrap();
    symlink(&victim_file, a.join("index.json")).unwrap();
    std::fs::remove_dir_all(&b).unwrap();
    symlink(&victim_dir, &b).unwrap();

    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .success();
    assert_eq!(std::fs::read(&victim_file).unwrap(), b"precious");
    assert!(
        entries(&victim_dir).is_empty(),
        "nothing may be written through a planted directory symlink: {:?}",
        entries(&victim_dir)
    );
    for layout in [&a, &b] {
        let meta = std::fs::symlink_metadata(layout).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        let idx = std::fs::symlink_metadata(layout.join("index.json")).unwrap();
        assert!(idx.is_file() && !idx.file_type().is_symlink());
    }

    // A seed directory that is itself a symlink is refused outright.
    let real = w.path("real-seed");
    std::fs::create_dir(&real).unwrap();
    let link = w.path("link-seed");
    symlink(&real, &link).unwrap();
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&link)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("symbolic link"));
    assert!(entries(&real).is_empty());
}
/// Tamper the installed tool payload of `layer` in the host store.
fn tamper_installed_tool(host: &Path, layer: &str) {
    let found = find_named(&host.join("realms"), &format!("tool-{layer}"));
    assert!(!found.is_empty(), "no installed payload for {layer}");
    for p in found {
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&p, perm).unwrap();
        std::fs::write(&p, b"#!/bin/sh\necho tampered\n").unwrap();
    }
}

/// A refusal in a later layer leaves nothing of the earlier ones behind.
// rivet: verifies REQ-SEED-001
#[test]
fn a_later_layer_refusal_writes_no_layer_and_keeps_a_previous_seed() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);

    // The upstream (composed) layer is written second; tamper it.
    tamper_installed_tool(&host, "2026.09.0");

    let fresh = w.path("fresh-seed");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&fresh)
        .assert()
        .failure()
        .code(1);
    assert!(
        !fresh.exists(),
        "a failed seed into a new directory left {:?}",
        entries(&fresh)
    );
}

/// A previous good seed survives a failed re-seed unchanged.
// rivet: verifies REQ-SEED-001
#[test]
fn a_failed_reseed_leaves_the_previous_seed_unchanged() {
    let w = World::new();
    let g = w.generation(1);
    let host = w.path("host-root");
    let host_project = w.path("host-project");
    w.install_gen(&host, &host_project, &g);
    let seed = w.path("seed");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .success();
    let before = read_tree(&seed);
    assert!(!before.is_empty());

    tamper_installed_tool(&host, "2026.09.0");
    w.varve(&host, &host_project)
        .arg("seed")
        .arg(&seed)
        .assert()
        .failure()
        .code(1);
    assert_eq!(read_tree(&seed), before, "the previous seed was altered");
    assert!(
        entries(&seed)
            .iter()
            .all(|n| !n.starts_with(".varve-seed-staging")),
        "{:?}",
        entries(&seed)
    );
}
