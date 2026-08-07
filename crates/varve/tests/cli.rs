//! CLI-level behavior: the fail-closed rules hold at the boundary users
//! actually touch, not only in the library.

use assert_cmd::Command;
use predicates::prelude::*;

const MANIFEST_JULY: &str = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {
    "eu.pulseengine.varve.layer": "2026.07.0",
    "eu.pulseengine.varve.channel": "qualified"
  },
  "manifests": []
}"#;

const PIN_JULY: &str =
    "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n";

struct Fixture {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    project: std::path::PathBuf,
}

/// (tool name, tool bytes) pairs for one laid-down layer.
type LayerTools<'a> = &'a [(&'a str, &'a [u8])];

fn fixture(pin: Option<&str>, layers: &[(&str, LayerTools)]) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("varve-root");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    if let Some(pin) = pin {
        std::fs::write(project.join("varve.toml"), pin).unwrap();
    }
    let store = varve_core::Store::at(&root);
    for (manifest, tools) in layers {
        store.lay_down(manifest.as_bytes(), tools).unwrap();
    }
    Fixture {
        _tmp: tmp,
        root,
        project,
    }
}

fn varve(fx: &Fixture) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("VARVE_ROOT", &fx.root).current_dir(&fx.project);
    cmd
}

// rivet: verifies REQ-PIN-001
#[test]
fn which_prints_the_resolved_binary_and_its_layer() {
    let fx = fixture(Some(PIN_JULY), &[(MANIFEST_JULY, &[("synth", b"s")])]);
    varve(&fx)
        .args(["which", "synth"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bin/synth")
                .and(predicate::str::contains("2026.07.0"))
                .and(predicate::str::contains("sha256:")),
        );
}

// rivet: verifies REQ-PIN-001
#[test]
fn which_fails_closed_when_the_pinned_layer_is_not_installed() {
    let fx = fixture(Some(PIN_JULY), &[]);
    varve(&fx)
        .args(["which", "synth"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("2026.07.0").and(predicate::str::contains("varve install")),
        );
}

// rivet: verifies REQ-PIN-001
#[test]
fn which_fails_closed_when_no_pin_exists() {
    let fx = fixture(None, &[(MANIFEST_JULY, &[("synth", b"s")])]);
    varve(&fx)
        .args(["which", "synth"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("varve.toml"));
}

// rivet: verifies REQ-PIN-001
#[test]
fn which_fails_closed_when_the_tool_is_missing_from_the_layer() {
    let fx = fixture(Some(PIN_JULY), &[(MANIFEST_JULY, &[("rivet", b"r")])]);
    varve(&fx)
        .args(["which", "synth"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("synth"));
}

// rivet: verifies REQ-COEXIST-001
#[test]
fn list_shows_every_installed_layer() {
    let august = MANIFEST_JULY.replace("2026.07.0", "2026.08.0");
    let fx = fixture(
        Some(PIN_JULY),
        &[
            (MANIFEST_JULY, &[("synth", b"a")]),
            (august.as_str(), &[("synth", b"b")]),
        ],
    );
    varve(&fx).arg("list").assert().success().stdout(
        predicate::str::contains("2026.07.0")
            .and(predicate::str::contains("2026.08.0"))
            .and(predicate::str::contains("qualified")),
    );
}

/// Signed-layer fixture material for the install/verify tests.
struct SignedLayer {
    archive: std::path::PathBuf,
    trust_root: std::path::PathBuf,
    wrong_root: std::path::PathBuf,
}

fn signed_layer_fixture(fx: &Fixture, layer: &str, counter: u64) -> SignedLayer {
    let (sk, pk) = varve_core::generate_root_keypair();
    let (_, wrong_pk) = varve_core::generate_root_keypair();
    let tool_bytes = format!("{layer}-synth-binary").into_bytes();
    let blob_digest = varve_core::manifest_digest(&tool_bytes);
    let line = &layer[..layer.rfind('.').unwrap()];
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.line": "{line}",
    "eu.pulseengine.varve.channel": "qualified",
    "eu.pulseengine.varve.counter": "{counter}",
    "org.opencontainers.image.created": "2026-07-31T09:14:00Z"
  }},
  "manifests": [
    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{blob_digest}",
      "size": 0,
      "annotations": {{ "eu.pulseengine.tool": "synth" }}
    }}
  ]
}}"#
    );
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "test-root").unwrap();
    let archive = fx
        .project
        .parent()
        .unwrap()
        .join(format!("archive-{layer}-{counter}"));
    let dir = varve_core::DirSource::at(&archive);
    dir.put(
        envelope.as_bytes(),
        &[(blob_digest.as_str(), tool_bytes.as_slice())],
    )
    .unwrap();
    let trust_root = fx
        .project
        .parent()
        .unwrap()
        .join(format!("root-{layer}-{counter}.pub"));
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let wrong_root = fx
        .project
        .parent()
        .unwrap()
        .join(format!("wrong-{layer}-{counter}.pub"));
    std::fs::write(&wrong_root, hex::encode(&wrong_pk)).unwrap();
    SignedLayer {
        archive,
        trust_root,
        wrong_root,
    }
}

// rivet: verifies REQ-VERIFY-001
#[test]
fn install_verifies_lays_down_and_verify_repeats_the_verdict() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.07.0"));
    varve(&fx)
        .args(["which", "synth"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bin/synth"));
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

// rivet: verifies REQ-VERIFY-001
#[test]
fn install_refuses_a_layer_signed_by_the_wrong_root() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.wrong_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .failure()
        .stderr(predicate::str::contains("signature"));
    varve(&fx)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("no layers"));
}

// rivet: verifies REQ-VERIFY-001
#[test]
fn install_without_a_trust_root_fails_closed() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust root"));
}

// rivet: verifies REQ-VERIFY-001
#[test]
fn verify_detects_a_tampered_binary() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    // Corrupt the installed tool, then re-verify.
    let core = fx.root.join("core");
    let entry = std::fs::read_dir(&core)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(entry.join("bin/synth"), b"EVIL").unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("synth"));
}

// rivet: verifies REQ-ROLLBACK-001
#[test]
fn a_rolled_back_layer_is_refused_by_the_cli() {
    // Install the patched layer (counter 2) first…
    let fx = fixture(
        Some("manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.1\"\n"),
        &[],
    );
    let newer = signed_layer_fixture(&fx, "2026.07.1", 2);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &newer.trust_root)
        .args(["install", "--from"])
        .arg(&newer.archive)
        .assert()
        .success();
    // …then repoint the pin at the base layer (counter 1): refused as rollback.
    std::fs::write(fx.project.join("varve.toml"), PIN_JULY).unwrap();
    let older = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &older.trust_root)
        .args(["install", "--from"])
        .arg(&older.archive)
        .assert()
        .failure()
        .stderr(predicate::str::contains("rollback").or(predicate::str::contains("high-water")));
}

// rivet: verifies REQ-COEXIST-001
#[test]
fn list_with_an_empty_core_succeeds_and_says_so() {
    let fx = fixture(None, &[]);
    varve(&fx)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("no layers"));
}
