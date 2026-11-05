//! The producer CLI signs BY ROLE (REQ-KEYROLES-001, DD-041): the command
//! implies the role, a delegation says which keys may play it, and a key out of
//! role is refused BEFORE anything is signed or written.
//!
//! Without `--delegation` every signing command behaves as it always did; that
//! is the existing suites' job (cli.rs, producer.rs) and one control here.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use varve_core::keyroles::{Delegation, RealmTrust};

struct Key {
    pk: Vec<u8>,
    file: PathBuf,
}

struct Realm {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    root: Key,
    layer: Key,
    status: Key,
    /// The root-signed delegation envelope, made by `varve sign-delegation`.
    delegation: PathBuf,
}

fn key(dir: &Path, name: &str) -> Key {
    let (sk, pk) = varve_core::generate_root_keypair();
    let file = dir.join(format!("{name}.key"));
    std::fs::write(&file, hex::encode(&sk)).unwrap();
    Key { pk, file }
}

fn varve(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", dir.join("varve-root"))
        .current_dir(dir);
    cmd
}

fn realm() -> Realm {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let root = key(&dir, "root");
    let layer = key(&dir, "layer");
    let status = key(&dir, "status");
    let doc = serde_json::json!({
        "realm-root": hex::encode(&root.pk),
        "counter": 7,
        "issued-at": "2026-11-05T00:00:00Z",
        "roles": {
            "layer": {"threshold": 1, "keys": [{"key": hex::encode(&layer.pk), "keyid": "layer-1"}]},
            "status": {"threshold": 1, "keys": [{"key": hex::encode(&status.pk), "keyid": "status-1"}]},
        }
    });
    std::fs::write(dir.join("delegation.json"), doc.to_string()).unwrap();
    let delegation = dir.join("delegation.dsse");
    varve(&dir)
        .args(["sign-delegation", "--file"])
        .arg(dir.join("delegation.json"))
        .arg("--key")
        .arg(&root.file)
        .arg("--out")
        .arg(&delegation)
        .assert()
        .success();
    Realm {
        _tmp: tmp,
        dir,
        root,
        layer,
        status,
        delegation,
    }
}

fn status_doc(dir: &Path) -> PathBuf {
    let p = dir.join("status.json");
    std::fs::write(
        &p,
        r#"{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z",
            "support-until":"2028-07-31","yanked":{},"known-problems":[]}"#,
    )
    .unwrap();
    p
}

fn index_doc(dir: &Path) -> PathBuf {
    let p = dir.join("index.json");
    std::fs::write(
        &p,
        r#"{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z","layers":[]}"#,
    )
    .unwrap();
    p
}

fn tool(dir: &Path) -> String {
    let p = dir.join("synth-bin");
    std::fs::write(&p, b"synth-bytes").unwrap();
    format!("synth@0.45.0={}", p.display())
}

fn deposit(r: &Realm, key: &Key, out: &Path) -> Command {
    let mut c = varve(&r.dir);
    c.args(["deposit", "--layer", "2026.08.0", "--channel", "qualified"])
        .args(["--counter", "1", "--issued-at", "2026-08-07T00:00:00Z"])
        .arg("--key")
        .arg(&key.file)
        .arg("--out")
        .arg(out)
        .arg("--tool")
        .arg(tool(&r.dir));
    c
}

fn trust(r: &Realm) -> RealmTrust {
    let bytes = std::fs::read(&r.delegation).unwrap();
    let d = Delegation::from_envelope(&bytes, &r.root.pk).unwrap();
    RealmTrust::with_roles(&r.root.pk, d).unwrap()
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn sign_delegation_round_trips_into_the_consumers_parser() {
    let r = realm();
    let bytes = std::fs::read(&r.delegation).unwrap();
    let d = Delegation::from_envelope(&bytes, &r.root.pk).unwrap();
    assert_eq!(d.counter(), 7);
    assert_eq!(d.issued_at(), "2026-11-05T00:00:00Z");
    // Pinned to a different root, the very same file is refused.
    assert!(Delegation::from_envelope(&bytes, &r.layer.pk).is_err());
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn sign_delegation_refuses_a_key_that_is_not_the_named_root_and_writes_nothing() {
    let r = realm();
    let out = r.dir.join("forged.dsse");
    varve(&r.dir)
        .args(["sign-delegation", "--file"])
        .arg(r.dir.join("delegation.json"))
        .arg("--key")
        .arg(&r.layer.file)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("different realm-root"));
    assert!(!out.exists());
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn sign_status_with_a_layer_key_and_a_delegation_is_refused_and_writes_nothing() {
    let r = realm();
    let out = r.dir.join("status.dsse");
    varve(&r.dir)
        .args(["sign-status", "--file"])
        .arg(status_doc(&r.dir))
        .arg("--key")
        .arg(&r.layer.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "delegated to the LAYER role, not STATUS",
        ));
    assert!(!out.exists(), "a refused signing must leave no envelope");
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn sign_status_with_the_status_key_signs_and_takes_its_key_id_from_the_delegation() {
    let r = realm();
    let out = r.dir.join("status.dsse");
    varve(&r.dir)
        .args(["sign-status", "--json", "--file"])
        .arg(status_doc(&r.dir))
        .arg("--key")
        .arg(&r.status.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"key_id\": \"status-1\""));
    let env = std::fs::read(&out).unwrap();
    varve_core::LineStatus::verify_and_parse(&env, &RealmTrust::root_only(&r.status.pk).unwrap())
        .unwrap();
    // An explicit --key-id still wins over the delegation's hint.
    varve(&r.dir)
        .args(["sign-status", "--json", "--key-id", "mine", "--file"])
        .arg(status_doc(&r.dir))
        .arg("--key")
        .arg(&r.status.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"key_id\": \"mine\""));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn the_realm_root_is_refused_every_signing_command_in_a_roles_realm() {
    let r = realm();
    let out = r.dir.join("never.out");
    let sums = r.dir.join("SHA256SUMS.txt");
    std::fs::write(&sums, "abc  file\n").unwrap();
    let refused = |args: Vec<std::ffi::OsString>| {
        varve(&r.dir)
            .args(args)
            .arg("--key")
            .arg(&r.root.file)
            .arg("--delegation")
            .arg(&r.delegation)
            .arg("--out")
            .arg(&out)
            .assert()
            .failure()
            .stderr(predicate::str::contains("the root signs only delegations"));
        assert!(!out.exists());
    };
    refused(vec![
        "sign-status".into(),
        "--file".into(),
        status_doc(&r.dir).into(),
    ]);
    refused(vec![
        "sign-index".into(),
        "--file".into(),
        index_doc(&r.dir).into(),
    ]);
    refused(vec![
        "sign-sums".into(),
        "--sums".into(),
        sums.clone().into(),
    ]);
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn deposit_with_the_root_key_and_a_delegation_is_refused_before_the_layout_exists() {
    let r = realm();
    let out = r.dir.join("layout");
    deposit(&r, &r.root, &out)
        .arg("--delegation")
        .arg(&r.delegation)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "this key is the realm root; in a roles realm the root signs only delegations",
        ));
    assert!(!out.exists());
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn deposit_with_a_status_key_is_refused_and_with_the_layer_key_is_signed_by_layer() {
    let r = realm();
    let out = r.dir.join("layout");
    deposit(&r, &r.status, &out)
        .arg("--delegation")
        .arg(&r.delegation)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "delegated to the STATUS role, not LAYER",
        ));
    assert!(!out.exists());

    deposit(&r, &r.layer, &out)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"key_id\": \"layer-1\""));
    // The layout carries a manifest the realm's roles verify: signed by LAYER.
    let manifest = std::fs::read_dir(out.join("blobs/sha256"))
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .find(|b| {
            trust(&r)
                .verify_bytes(b, varve_core::LAYER_PAYLOAD_TYPE)
                .is_ok()
        });
    assert!(
        manifest.is_some(),
        "no blob verifies as a LAYER-signed manifest"
    );
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn sign_sums_and_sign_index_follow_their_roles() {
    let r = realm();
    let sums = r.dir.join("SHA256SUMS.txt");
    std::fs::write(&sums, "abc  file\n").unwrap();
    let out = r.dir.join("o");
    // Release sums are the LAYER role's.
    varve(&r.dir)
        .args(["sign-sums", "--sums"])
        .arg(&sums)
        .arg("--key")
        .arg(&r.status.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure();
    assert!(!out.exists());
    varve(&r.dir)
        .args(["sign-sums", "--sums"])
        .arg(&sums)
        .arg("--key")
        .arg(&r.layer.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    // The line-index is the STATUS role's.
    std::fs::remove_file(&out).unwrap();
    varve(&r.dir)
        .args(["sign-index", "--file"])
        .arg(index_doc(&r.dir))
        .arg("--key")
        .arg(&r.layer.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .failure();
    assert!(!out.exists());
    varve(&r.dir)
        .args(["sign-index", "--file"])
        .arg(index_doc(&r.dir))
        .arg("--key")
        .arg(&r.status.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    trust(&r)
        .verify_bytes(
            &std::fs::read(&out).unwrap(),
            varve_core::lineindex::LINE_INDEX_PAYLOAD_TYPE,
        )
        .unwrap();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_deposit_publishes_no_baseline_status() {
    let r = realm();
    let out = r.dir.join("layout");
    deposit(&r, &r.layer, &out)
        .arg("--delegation")
        .arg(&r.delegation)
        .assert()
        .success();
    // Even a properly STATUS-signed document is not attached as a baseline.
    let env = r.dir.join("status.dsse");
    varve(&r.dir)
        .args(["sign-status", "--file"])
        .arg(status_doc(&r.dir))
        .arg("--key")
        .arg(&r.status.file)
        .arg("--delegation")
        .arg(&r.delegation)
        .arg("--out")
        .arg(&env)
        .assert()
        .success();
    varve(&r.dir)
        .args(["attach-status", "--layout"])
        .arg(&out)
        .arg("--status")
        .arg(&env)
        .arg("--delegation")
        .arg(&r.delegation)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "publishes no baseline line-status",
        ));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn without_a_delegation_any_key_signs_exactly_as_before() {
    let r = realm();
    let out = r.dir.join("status.dsse");
    // The root key signs a status, and a layer key signs a status: a realm
    // declaring no roles is not told which key may sign what.
    for k in [&r.root, &r.layer] {
        varve(&r.dir)
            .args(["sign-status", "--json", "--file"])
            .arg(status_doc(&r.dir))
            .arg("--key")
            .arg(&k.file)
            .arg("--out")
            .arg(&out)
            .assert()
            .success()
            .stdout(predicate::str::contains("\"key_id\": \"varve-root-1\""));
        varve_core::LineStatus::verify_and_parse(
            &std::fs::read(&out).unwrap(),
            &RealmTrust::root_only(&k.pk).unwrap(),
        )
        .unwrap();
        std::fs::remove_file(&out).unwrap();
    }
    let layout = r.dir.join("layout");
    deposit(&r, &r.root, &layout).assert().success();
}
