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
