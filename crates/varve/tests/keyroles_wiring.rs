//! REQ-KEYROLES-001, end to end: a consumer verifies BY ROLE.
//!
//! The producer CLI makes the artifacts (`keyroles_producer.rs` covers its own
//! refusals) and the consumer CLI reads them in a project that pins a realm
//! declaring `key-roles = true`. The same artifacts are then read in a realm
//! declaring no roles, which behaves exactly as it always did.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

struct Key {
    pk: Vec<u8>,
    file: PathBuf,
}

struct World {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    project: PathBuf,
    root: Key,
    layer: Key,
    status: Key,
    delegation: PathBuf,
}

fn key(dir: &Path, name: &str) -> Key {
    let (sk, pk) = varve_core::generate_root_keypair();
    let file = dir.join(format!("{name}.key"));
    std::fs::write(&file, hex::encode(&sk)).unwrap();
    Key { pk, file }
}

fn varve(w: &World) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", w.dir.join("varve-root"))
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&w.project);
    cmd
}

/// A project pinning realm `r`. With `roles` the realm declares key roles and
/// points at a root-signed delegation naming one LAYER and one STATUS key;
/// without, it is a flat realm that trusts its root alone.
fn world(roles: bool) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let root = key(&dir, "root");
    let layer = key(&dir, "layer");
    let status = key(&dir, "status");
    let doc = serde_json::json!({
        "realm-root": hex::encode(&root.pk),
        "counter": 1,
        "issued-at": "2026-11-05T00:00:00Z",
        "roles": {
            "layer": {"threshold": 1, "keys": [{"key": hex::encode(&layer.pk), "keyid": "layer-1"}]},
            "status": {"threshold": 1, "keys": [{"key": hex::encode(&status.pk), "keyid": "status-1"}]},
        }
    });
    std::fs::write(dir.join("delegation.json"), doc.to_string()).unwrap();
    let delegation = project.join("r.delegation.dsse");
    let w = World {
        _tmp: tmp,
        dir: dir.clone(),
        project: project.clone(),
        root,
        layer,
        status,
        delegation: delegation.clone(),
    };
    varve(&w)
        .args(["sign-delegation", "--file"])
        .arg(dir.join("delegation.json"))
        .arg("--key")
        .arg(&w.root.file)
        .arg("--out")
        .arg(&delegation)
        .assert()
        .success();
    let extra = if roles {
        "key-roles = true\ndelegation-file = \"r.delegation.dsse\"\n"
    } else {
        ""
    };
    std::fs::write(
        project.join("varve-realms.toml"),
        format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n{extra}",
            hex::encode(&w.root.pk)
        ),
    )
    .unwrap();
    std::fs::write(
        project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"r\"\nchannel = \"qualified\"\n\
         layer = \"2026.08.0\"\n",
    )
    .unwrap();
    w
}

/// Deposit layer 2026.08.0 signed by `signer`, into `<dir>/layout-<name>`.
fn deposit(w: &World, signer: &Key, name: &str) -> PathBuf {
    let tool = w.dir.join("synth-bin");
    std::fs::write(&tool, b"synth-bytes").unwrap();
    let out = w.dir.join(format!("layout-{name}"));
    varve(w)
        .args(["deposit", "--layer", "2026.08.0", "--channel", "qualified"])
        .args(["--counter", "1", "--issued-at", "2026-08-07T00:00:00Z"])
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .arg("--tool")
        .arg(format!("synth@0.45.0={}", tool.display()))
        .assert()
        .success();
    out
}

fn status_doc(w: &World, yanked: bool) -> PathBuf {
    let yanks = if yanked {
        r#"{"2026.08.0":"CVE-2026-0001"}"#
    } else {
        "{}"
    };
    let p = w.dir.join(format!("status-{yanked}.json"));
    std::fs::write(
        &p,
        format!(
            r#"{{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z",
                "support-until":"2028-07-31","yanked":{yanks},"known-problems":[]}}"#
        ),
    )
    .unwrap();
    p
}

/// Sign a line-status with `signer` and NO delegation: how a flat realm signs,
/// and how an attacker holding only a LAYER key would.
fn sign_status(w: &World, signer: &Key, yanked: bool, name: &str) -> PathBuf {
    let out = w.dir.join(format!("status-{name}.dsse"));
    varve(w)
        .args(["sign-status", "--force", "--file"])
        .arg(status_doc(w, yanked))
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    out
}

fn install(w: &World, layout: &Path) -> assert_cmd::assert::Assert {
    varve(w).args(["install", "--from"]).arg(layout).assert()
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_installs_a_layer_signed_layer() {
    let w = world(true);
    let layout = deposit(&w, &w.layer, "layer");
    install(&w, &layout)
        .success()
        .stdout(predicate::str::contains("2026.08.0"));
    varve(&w).arg("verify").assert().success();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_refuses_a_root_signed_layer_and_a_status_signed_one() {
    let w = world(true);
    let by_root = deposit(&w, &w.root, "root");
    install(&w, &by_root)
        .failure()
        .stderr(predicate::str::contains("signed by this realm's ROOT key"));
    let by_status = deposit(&w, &w.status, "status");
    install(&w, &by_status)
        .failure()
        .stderr(predicate::str::contains(
            "signed by this realm's STATUS key",
        ));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_reads_a_status_signed_line_status_and_refuses_a_layer_signed_one() {
    let w = world(true);
    let layout = deposit(&w, &w.layer, "layer");
    install(&w, &layout).success();

    // The STATUS key's document is read (and cached).
    let good = sign_status(&w, &w.status, false, "by-status");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&good)
        .assert()
        .success()
        .stdout(predicate::str::contains("not yanked"));

    // A yank signed by the LAYER key, the depositor's, is valid cryptography
    // and out of role: refused, and what the machine holds is not displaced.
    let yank = sign_status(&w, &w.layer, true, "by-layer");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&yank)
        .assert()
        .failure()
        .stderr(predicate::str::contains("signed by this realm's LAYER key"));
    // The ROOT is out of role for a status too.
    let by_root = sign_status(&w, &w.root, true, "by-root");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&by_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains("signed by this realm's ROOT key"));
    varve(&w)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not yanked"));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_realm_declaring_no_roles_behaves_as_it_always_did() {
    let w = world(false);
    // Root-signed layer and root-signed status are accepted.
    let layout = deposit(&w, &w.root, "root");
    install(&w, &layout).success();
    let yank = sign_status(&w, &w.root, true, "by-root");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&yank)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("YANKED"));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_realm_declaring_no_roles_trusts_its_root_alone() {
    // Negative control: the delegation file exists beside the realm and names a
    // LAYER key, but a realm that does not opt in never consults it, so the
    // LAYER key is just a stranger there.
    let w = world(false);
    assert!(w.delegation.exists());
    let by_layer = deposit(&w, &w.layer, "layer");
    install(&w, &by_layer).failure();
    let status = sign_status(&w, &w.layer, true, "by-layer");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&status)
        .assert()
        .failure();
}
