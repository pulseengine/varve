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

// rivet: verifies REQ-EXPORT-SYNC-001
#[test]
fn verify_export_hard_fails_on_a_stale_stamp() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    // An export dir stamped from a DIFFERENT layer digest than the pin resolves.
    let export = fx.project.join("vendored");
    std::fs::create_dir_all(&export).unwrap();
    std::fs::write(
        export.join(".varve-export.json"),
        r#"{"layer":"2026.06.0","manifest_digest":"sha256:deadbeef","kind":"cargo"}"#,
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--export"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("STALE").or(predicate::str::contains("stale")));
}

// rivet: verifies REQ-EXPORT-SYNC-001
#[test]
fn verify_export_passes_when_the_stamp_matches_the_pin() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    // Learn the installed layer's manifest digest from verify's own output.
    let out = varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .arg("verify")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    let digest = stdout
        .split_whitespace()
        .find(|w| w.starts_with("sha256:"))
        .expect("verify prints the layer digest");
    // A stamp naming exactly that digest is fresh — the gate passes.
    let export = fx.project.join("vendored");
    std::fs::create_dir_all(&export).unwrap();
    std::fs::write(
        export.join(".varve-export.json"),
        format!(r#"{{"layer":"2026.07.0","manifest_digest":"{digest}","kind":"cargo"}}"#),
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--export"])
        .arg(&export)
        .assert()
        .success()
        .stdout(predicate::str::contains("fresh"));
}

// rivet: verifies REQ-EXPORT-SYNC-001
#[test]
fn verify_export_hard_fails_when_the_stamp_is_missing() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    // A directory with no stamp is not a verified export — that is a failure.
    let export = fx.project.join("hand-assembled");
    std::fs::create_dir_all(&export).unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--export"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no export stamp"));
}

// rivet: verifies REQ-EXPORT-SYNC-001
#[test]
fn verify_export_hard_fails_on_a_malformed_stamp() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    // A stamp that is not valid JSON is not a verified export — a failure.
    let export = fx.project.join("corrupt");
    std::fs::create_dir_all(&export).unwrap();
    std::fs::write(export.join(".varve-export.json"), b"{not json").unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--export"])
        .arg(&export)
        .assert()
        .failure()
        .stderr(predicate::str::contains("malformed"));
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

// rivet: verifies REQ-OFFLINE-001
#[test]
fn archive_then_offline_install_round_trips_with_verification_unchanged() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();

    // Export the installed layer as an oci-layout archive.
    let exported = fx.project.parent().unwrap().join("core-2026.07.0");
    varve(&fx)
        .args(["archive", "2026.07.0"])
        .arg(&exported)
        .assert()
        .success()
        .stdout(predicate::str::contains("oci-layout"));
    assert!(exported.join("oci-layout").is_file());
    assert!(exported.join("index.json").is_file());

    // A fresh machine (fresh VARVE_ROOT), no registry: install from the
    // archive with the same trust root, then re-verify offline.
    let fresh_root = fx.project.parent().unwrap().join("fresh-root");
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("VARVE_ROOT", &fresh_root)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .current_dir(&fx.project)
        .args(["install", "--from"])
        .arg(&exported)
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.07.0"));
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("VARVE_ROOT", &fresh_root)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .current_dir(&fx.project)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

// rivet: verifies REQ-OFFLINE-001
#[test]
fn archive_of_an_uninstalled_layer_fails_with_guidance() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let dest = fx.project.parent().unwrap().join("nowhere");
    varve(&fx)
        .args(["archive", "2026.07.0"])
        .arg(&dest)
        .assert()
        .failure()
        .stderr(predicate::str::contains("2026.07.0"));
}

/// Lay down a layer whose "tool" is a script that prints the provenance
/// environment and exits with a chosen code.
fn probe_layer(fx: &Fixture, layer: &str, exit: u8) -> String {
    let script = format!(
        "#!/bin/sh\necho \"layer=$VARVE_LAYER digest=$VARVE_LAYER_MANIFEST_DIGEST\"\nexit {exit}\n"
    );
    let manifest = MANIFEST_JULY.replace("2026.07.0", layer);
    let store = varve_core::Store::at(&fx.root);
    store
        .lay_down(manifest.as_bytes(), &[("probe", script.as_bytes())])
        .unwrap()
}

// rivet: partially-verifies REQ-PROV-001
#[test]
fn run_dispatches_with_the_layer_identity_in_the_environment() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let digest = probe_layer(&fx, "2026.07.0", 0);
    varve(&fx)
        .args(["run", "--", "probe"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("layer=2026.07.0")
                .and(predicate::str::contains(format!("digest={digest}"))),
        );
}

// rivet: partially-verifies REQ-PROV-001
#[test]
fn run_propagates_the_tool_exit_code() {
    let fx = fixture(Some(PIN_JULY), &[]);
    probe_layer(&fx, "2026.07.0", 7);
    let output = varve(&fx).args(["run", "--", "probe"]).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "the tool's exit code is varve's"
    );
}

// rivet: verifies REQ-NOUPDATE-001
#[test]
fn run_with_an_explicit_layer_override_does_not_touch_the_pin() {
    let fx = fixture(Some(PIN_JULY), &[]);
    probe_layer(&fx, "2026.07.0", 0);
    probe_layer(&fx, "2026.09.0", 0);
    // One-off override runs the other layer…
    varve(&fx)
        .args(["run", "--varve", "2026.09.0", "--", "probe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("layer=2026.09.0"));
    // …while the pin, and plain run, remain on July.
    varve(&fx)
        .args(["run", "--", "probe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("layer=2026.07.0"));
    let pin = std::fs::read_to_string(fx.project.join("varve.toml")).unwrap();
    assert!(pin.contains("2026.07.0"), "the checked-in pin is untouched");
}

// rivet: verifies REQ-PIN-001
#[test]
fn run_fails_closed_like_everything_else() {
    let fx = fixture(Some(PIN_JULY), &[]);
    varve(&fx)
        .args(["run", "--", "probe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("varve install"));
}

// rivet: verifies REQ-DEPOSIT-001
#[test]
fn deposit_creates_a_layer_the_standard_pipeline_installs() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    // Root keypair on disk, as CI would hold it.
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    // A tool binary to deposit.
    let tool_path = parent.join("synth-bin");
    std::fs::write(&tool_path, b"deposited-synth").unwrap();
    let dest = parent.join("deposited");

    varve(&fx)
        .args(["deposit", "--layer", "2026.07.0", "--channel", "qualified"])
        .args(["--counter", "1", "--issued-at", "2026-08-07T00:00:00Z"])
        .args(["--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&dest)
        .args(["--tool"])
        .arg(format!("synth@0.45.0={}", tool_path.display()))
        .assert()
        .success()
        .stdout(predicate::str::contains("sha256:"));

    // The deposit installs through the very same pipeline.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.07.0"));
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success();
}

// rivet: verifies REQ-STATUS-DIST-001
#[test]
fn an_attached_baseline_makes_status_work_after_an_offline_install() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let tool_path = parent.join("synth-bin");
    std::fs::write(&tool_path, b"deposited-synth").unwrap();
    let dest = parent.join("deposited");

    varve(&fx)
        .args(["deposit", "--layer", "2026.07.0", "--channel", "qualified"])
        .args(["--counter", "1", "--issued-at", "2026-08-07T00:00:00Z"])
        .args(["--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&dest)
        .args(["--tool"])
        .arg(format!("synth@0.45.0={}", tool_path.display()))
        .assert()
        .success();

    // CI signs a baseline line-status with the SAME root and attaches it.
    let doc_path = parent.join("baseline.json");
    let env_path = parent.join("baseline.dsse.json");
    std::fs::write(&doc_path, status_doc_json("2026.07", 1)).unwrap();
    varve(&fx)
        .args(["sign-status", "--file"])
        .arg(&doc_path)
        .args(["--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&env_path)
        .assert()
        .success();
    varve(&fx)
        .args(["attach-status", "--layout"])
        .arg(&dest)
        .args(["--status"])
        .arg(&env_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("attached baseline line-status #1"));

    // Install from the layout — the baseline is auto-cached, no --from-file.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("cached baseline line-status #1"));

    // `varve status` works OFFLINE with nothing but the install behind it.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("status")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("YANKED").and(predicate::str::contains("1 known problem")),
        );
}

// rivet: verifies REQ-CRATE-001, REQ-KIND-001
#[test]
fn deposit_a_crate_kind_entry_and_export_a_cargo_registry() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // A stand-in .crate blob (export-cargo does not parse it; the offline
    // build oracle covers real crates). Its sha256 is the cksum Cargo checks.
    let crate_bytes = b"a-dot-crate-tarballs-bytes";
    let crate_path = parent.join("demo-crate.crate");
    std::fs::write(&crate_path, crate_bytes).unwrap();

    // Deposit it as a `crate`-kind entry via a spec file (only the spec path
    // carries kind).
    let spec = parent.join("deposit-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"demo-crate\"\nversion = \"0.1.0\"\nkind = \"crate\"\n\
             path = \"{}\"\n",
            crate_path.display()
        ),
    )
    .unwrap();
    let dest = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-08-07T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&dest)
        .assert()
        .success();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success();

    // Export a Cargo registry from the verified layer.
    let out = parent.join("cargo-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("1 verified crate"));

    // The .crate is the verified bytes; the config redirects crates.io; the
    // index cksum is varve's signed digest.
    assert_eq!(
        std::fs::read(out.join("registry/demo-crate-0.1.0.crate")).unwrap(),
        crate_bytes
    );
    let config = std::fs::read_to_string(out.join(".cargo/config.toml")).unwrap();
    assert!(config.contains("replace-with = \"varve\""));
    let idx = std::fs::read_to_string(out.join("registry/index/de/mo/demo-crate")).unwrap();
    // A cksum is recorded (its correctness vs. real Cargo is proven by the
    // cargo_offline oracle); here we prove the CLI wiring end to end.
    assert!(
        idx.contains(r#""cksum":"#) && idx.contains(r#""vers":"0.1.0""#),
        "{idx}"
    );
}

// rivet: verifies REQ-VENDOR-001
#[test]
fn deposit_a_crate_kind_entry_and_export_crates_vendor() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // A REAL .crate-shaped gzip tar (export-crates-vendor unpacks it).
    let crate_bytes = {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, body) in [
            (
                "vend-0.1.0/Cargo.toml",
                "[package]\nname=\"vend\"\nversion=\"0.1.0\"\n",
            ),
            ("vend-0.1.0/src/lib.rs", "pub fn v() {}\n"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    };
    let crate_path = parent.join("vend.crate");
    std::fs::write(&crate_path, &crate_bytes).unwrap();

    let spec = parent.join("deposit-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"vend\"\nversion = \"0.1.0\"\nkind = \"crate\"\npath = \"{}\"\n",
            crate_path.display()
        ),
    )
    .unwrap();
    let dest = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-08-07T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&dest)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success();

    let out = parent.join("vendor-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-crates-vendor", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("vendored 1 verified crate"));

    // The crate is UNPACKED with its checksum; the config uses a directory source.
    assert!(out.join("vendor/vend-0.1.0/Cargo.toml").is_file());
    let checksum =
        std::fs::read_to_string(out.join("vendor/vend-0.1.0/.cargo-checksum.json")).unwrap();
    assert!(checksum.contains(r#""package":"#), "{checksum}");
    let config = std::fs::read_to_string(out.join(".cargo/config.toml")).unwrap();
    assert!(config.contains("replace-with = \"vendored-sources\""));
}

fn status_doc_json(line: &str, counter: u64) -> String {
    format!(
        r#"{{
  "line": "{line}",
  "counter": {counter},
  "issued-at": "2026-08-07T00:00:00Z",
  "support-until": "2028-07-31",
  "yanked": {{ "{line}.0": "CVE-2026-0001 in synth" }},
  "known-problems": [
    {{ "id": "KP-1", "title": "fusion regression", "severity": "medium",
       "affected": ["{line}.0"], "workaround": "disable mla fusion" }}
  ]
}}"#
    )
}

// rivet: verifies REQ-KP-001
#[test]
fn status_reports_yank_and_known_problems_from_attached_evidence() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();

    // CI signs a status document…
    let (sk_path, doc_path, env_path) = (
        parent.join("status-root.key"),
        parent.join("status.json"),
        parent.join("status.dsse.json"),
    );
    // …with the SAME root the layer was signed by: reuse the fixture's key
    // is not possible (it is internal), so re-sign layer + status with one
    // key here instead.
    let (sk, pk) = varve_core::generate_root_keypair();
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust = parent.join("one-root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();
    std::fs::write(&doc_path, status_doc_json("2026.07", 1)).unwrap();
    varve(&fx)
        .args(["sign-status", "--file"])
        .arg(&doc_path)
        .args(["--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&env_path)
        .assert()
        .success();

    // status ingests the envelope, caches it, and reports for the pin.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&env_path)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("YANKED")
                .and(predicate::str::contains("CVE-2026-0001"))
                .and(predicate::str::contains("1 known problem"))
                .and(predicate::str::contains("2028-07-31")),
        );

    // Cached: no --from-file needed on the second ask.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("YANKED"));
}

// rivet: verifies REQ-KP-001
#[test]
fn status_refuses_a_stale_document_and_keeps_the_newer_cache() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("k.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust = parent.join("k.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    let sign = |counter: u64, out: &std::path::Path| {
        let doc = parent.join(format!("doc-{counter}.json"));
        std::fs::write(&doc, status_doc_json("2026.07", counter)).unwrap();
        varve(&fx)
            .args(["sign-status", "--file"])
            .arg(&doc)
            .args(["--key"])
            .arg(&sk_path)
            .args(["--out"])
            .arg(out)
            .assert()
            .success();
    };
    let newer = parent.join("newer.dsse.json");
    sign(3, &newer);
    let older = parent.join("older.dsse.json");
    sign(2, &older);

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&newer)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&older)
        .assert()
        .failure()
        .stderr(predicate::str::contains("stale"));
}

// rivet: verifies REQ-SELF-001
#[test]
fn self_verify_accepts_a_signed_release_file_and_refuses_a_tampered_one() {
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust = parent.join("release-root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    let archive = parent.join("varve-v9.9.9-x.tar.gz");
    std::fs::write(&archive, b"tarball-bytes").unwrap();
    let digest = varve_core::manifest_digest(b"tarball-bytes");
    let sums = format!(
        "{}  ./varve-v9.9.9-x.tar.gz\n",
        digest.strip_prefix("sha256:").unwrap()
    );
    let envelope = varve_core::sign_release_sums(sums.as_bytes(), &sk, "k").unwrap();
    let env_path = parent.join("SHA256SUMS.txt.dsse.json");
    std::fs::write(&env_path, envelope).unwrap();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["self-verify", "--archive"])
        .arg(&archive)
        .args(["--envelope"])
        .arg(&env_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));

    std::fs::write(&archive, b"tampered!").unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["self-verify", "--archive"])
        .arg(&archive)
        .args(["--envelope"])
        .arg(&env_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not match"));
}

// rivet: verifies REQ-SELF-001
#[test]
fn sign_sums_produces_an_envelope_self_verify_accepts() {
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("r.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust = parent.join("r.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    let archive = parent.join("varve-v9.9.9-y.tar.gz");
    std::fs::write(&archive, b"bytes").unwrap();
    let digest = varve_core::manifest_digest(b"bytes");
    let sums_path = parent.join("SHA256SUMS.txt");
    std::fs::write(
        &sums_path,
        format!(
            "{}  ./varve-v9.9.9-y.tar.gz\n",
            digest.strip_prefix("sha256:").unwrap()
        ),
    )
    .unwrap();
    let env_path = parent.join("SHA256SUMS.txt.dsse.json");

    varve(&fx)
        .args(["sign-sums", "--sums"])
        .arg(&sums_path)
        .args(["--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&env_path)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["self-verify", "--archive"])
        .arg(&archive)
        .args(["--envelope"])
        .arg(&env_path)
        .assert()
        .success();
}

// rivet: verifies REQ-SHIM-002
#[cfg(unix)]
#[test]
fn a_shim_passes_non_utf8_arguments_through_byte_for_byte() {
    // A shim must hand the tool the EXACT bytes the caller typed: unix
    // arguments are arbitrary byte strings, and a filename is a common one.
    // Rewriting them lossily would corrupt data silently — the opposite of
    // this tool's contract.
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let fx = fixture(Some(PIN_JULY), &[]);
    let store = varve_core::Store::at(&fx.root);
    // A probe that writes its argument's raw bytes out for comparison.
    let probe = b"#!/bin/sh\nprintf '%s' \"$1\" > \"$VARVE_ARG_OUT\"\n";
    store
        .lay_down(MANIFEST_JULY.as_bytes(), &[("probe", probe.as_slice())])
        .unwrap();
    varve(&fx).args(["shim", "install"]).assert().success();

    let out_file = fx.project.join("arg.bin");
    let nasty = OsStr::from_bytes(b"bad\xff\xfename");
    let status = std::process::Command::new(fx.root.join("shims").join("probe"))
        .arg(nasty)
        .current_dir(&fx.project)
        .env("VARVE_ROOT", &fx.root)
        .env("VARVE_ARG_OUT", &out_file)
        .status()
        .unwrap();
    assert!(status.success(), "shim dispatch failed");
    let got = std::fs::read(&out_file).unwrap();
    assert_eq!(
        got.as_slice(),
        b"bad\xff\xfename",
        "the shim rewrote the argument instead of passing it through"
    );
}

// rivet: verifies REQ-SHIM-002
#[cfg(unix)]
#[test]
fn a_shim_is_varve_itself_not_a_shell_script() {
    // REQ-SHIM-002: no /bin/sh on the dispatch path, and no string handed to a
    // shell parser. The shim must BE the varve binary, reached by a link.
    let fx = fixture(Some(PIN_JULY), &[(MANIFEST_JULY, &[("synth", b"s")])]);
    varve(&fx).args(["shim", "install"]).assert().success();
    let shim = fx.root.join("shims").join("synth");
    let bytes = std::fs::read(&shim).unwrap();
    assert!(
        !bytes.starts_with(b"#!"),
        "the shim is still a script: {}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(80)])
    );
    #[cfg(unix)]
    {
        let meta = std::fs::symlink_metadata(&shim).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "on unix a shim should be a symlink to varve, so it tracks self-update"
        );
        // …and it must point at a real varve binary.
        let target = std::fs::read_link(&shim).unwrap();
        assert!(
            target
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("varve"),
            "shim points at {target:?}, not the varve binary"
        );
    }
}

// rivet: verifies REQ-SHIM-001, REQ-SHIM-002
#[cfg(unix)]
#[test]
fn shims_resolve_per_invocation_so_switching_projects_is_cd() {
    let fx = fixture(Some(PIN_JULY), &[]);
    // Two layers, each with a `probe` tool that names itself.
    let store = varve_core::Store::at(&fx.root);
    for (layer, marker) in [("2026.07.0", "i-am-july"), ("2026.09.0", "i-am-september")] {
        let manifest = MANIFEST_JULY.replace("2026.07.0", layer);
        let script = format!("#!/bin/sh\necho {marker} layer=$VARVE_LAYER\n");
        store
            .lay_down(manifest.as_bytes(), &[("probe", script.as_bytes())])
            .unwrap();
    }
    // Two projects pinning different layers.
    let parent = fx.project.parent().unwrap();
    let project_sep = parent.join("project-sep");
    std::fs::create_dir_all(&project_sep).unwrap();
    std::fs::write(
        project_sep.join("varve.toml"),
        PIN_JULY.replace("2026.07.0", "2026.09.0"),
    )
    .unwrap();

    // Install shims once, from the July project.
    varve(&fx)
        .args(["shim", "install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("shims"));
    let shim = fx.root.join("shims").join("probe");
    assert!(shim.is_file(), "shim written at {}", shim.display());

    // The SAME shim binary, invoked from each project dir, runs that
    // project's layer — switching toolchains is cd.
    let run_shim = |dir: &std::path::Path| {
        let out = std::process::Command::new(&shim)
            .current_dir(dir)
            .env("VARVE_ROOT", &fx.root)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };
    let (ok_july, out_july) = run_shim(&fx.project);
    assert!(ok_july, "july project shim run failed: {out_july}");
    assert!(
        out_july.contains("i-am-july") && out_july.contains("layer=2026.07.0"),
        "{out_july}"
    );
    let (ok_sep, out_sep) = run_shim(&project_sep);
    assert!(ok_sep, "september project shim run failed: {out_sep}");
    assert!(
        out_sep.contains("i-am-september") && out_sep.contains("layer=2026.09.0"),
        "{out_sep}"
    );

    // No pin, no fallback: from a pinless directory the shim fails closed.
    let bare = parent.join("no-pin-here");
    std::fs::create_dir_all(&bare).unwrap();
    let out = std::process::Command::new(&shim)
        .current_dir(&bare)
        .env("VARVE_ROOT", &fx.root)
        .output()
        .unwrap();
    assert!(!out.status.success(), "a pinless dir must not resolve");
    assert!(String::from_utf8_lossy(&out.stderr).contains("varve.toml"));
}

// rivet: verifies REQ-ENV-001
#[cfg(unix)]
#[test]
fn env_is_evaluable_and_idempotent() {
    let fx = fixture(None, &[]);
    let out = varve(&fx).arg("env").output().unwrap();
    assert!(out.status.success());
    let script = String::from_utf8(out.stdout).unwrap();
    let shims = fx.root.join("shims");
    assert!(script.contains(shims.to_str().unwrap()), "{script}");

    // Evaluating twice must not stack duplicate PATH entries.
    let shell = format!(
        "eval \"$VARVE_ENV\"; eval \"$VARVE_ENV\"; printf '%s' \"$PATH\" | tr ':' '\\n' | grep -cx '{}'",
        shims.display()
    );
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(&shell)
        .env("VARVE_ENV", &script)
        .env("PATH", std::env::var("PATH").unwrap())
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1",
        "shim dir must appear exactly once after double eval"
    );
}

// rivet: verifies REQ-ENV-001
#[cfg(unix)]
#[test]
fn shim_install_writes_a_sourceable_env_file() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let store = varve_core::Store::at(&fx.root);
    let script = "#!/bin/sh\necho from-the-layer\n";
    store
        .lay_down(MANIFEST_JULY.as_bytes(), &[("probe", script.as_bytes())])
        .unwrap();
    varve(&fx)
        .args(["shim", "install"])
        .assert()
        .success()
        .stdout(predicate::str::contains("env"));
    let env_file = fx.root.join("env");
    assert!(
        env_file.is_file(),
        "shim install must write {}",
        env_file.display()
    );

    // Sourcing the file makes the shim resolvable and runnable.
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            ". '{}' && cd '{}' && probe",
            env_file.display(),
            fx.project.display()
        ))
        .env("VARVE_ROOT", &fx.root)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("from-the-layer"),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// rivet: verifies REQ-ENV-001
#[test]
fn completions_emit_per_shell_scripts() {
    let fx = fixture(None, &[]);
    varve(&fx)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef varve"));
    varve(&fx)
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
    varve(&fx)
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c varve"));
}

// rivet: verifies REQ-BAZEL-001
#[test]
fn spec_deposit_then_export_bazel_compiles_a_signature_anchored_registry() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust = parent.join("root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    // Tool binary + a deposit spec carrying its source provenance.
    let host = varve_core::host_platform();
    let tool_path = parent.join("rivet-bin");
    std::fs::write(&tool_path, b"rivet-binary-bytes").unwrap();
    let spec_path = parent.join("deposit.toml");
    std::fs::write(
        &spec_path,
        format!(
            r#"layer = "2026.07.0"
channel = "qualified"
counter = 1

[[tool]]
name = "rivet"
version = "0.32.0"
platform = "{host}"
path = "{tool}"

[tool.source]
repo = "pulseengine/rivet"
release = "v0.32.0"
asset = "rivet-v0.32.0-{host}.tar.gz"
sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#,
            tool = tool_path.display()
        ),
    )
    .unwrap();

    let dest = parent.join("spec-deposit");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec_path)
        .args(["--issued-at", "2026-08-07T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&dest)
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.07.0"));

    // Install, then compile the Bazel registry from the verified layer.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success();
    let out_dir = parent.join("bazel-registry");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["export-bazel", "--layer", "2026.07.0", "--out"])
        .arg(&out_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("rivet.json"));
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("rivet.json")).unwrap()).unwrap();
    assert_eq!(json["github_repo"], "pulseengine/rivet");
    let key = varve_core::bazel::bazel_platform_key(&host).unwrap();
    assert_eq!(
        json["versions"]["0.32.0"]["platforms"][key]["sha256"],
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    assert!(
        json["_generated_by"]
            .as_str()
            .unwrap()
            .contains("Do not hand-edit")
    );
}

// rivet: verifies REQ-BAZEL-001
#[test]
fn export_bazel_refuses_without_a_trust_root() {
    let fx = fixture(Some(PIN_JULY), &[]);
    varve(&fx)
        .args(["export-bazel", "--layer", "2026.07.0", "--out"])
        .arg(fx.project.parent().unwrap().join("nowhere"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust root"));
}

// rivet: verifies REQ-REALM-001
#[cfg(unix)]
#[test]
fn two_realms_same_layer_name_zero_cross_talk() {
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();

    // Two universes: same layer name and counter, different roots, and a
    // `probe` tool that names its universe.
    let mut realms_toml = String::new();
    let mut archives = std::collections::BTreeMap::new();
    for org in ["pulseengine", "acme"] {
        let (sk, pk) = varve_core::generate_root_keypair();
        let tool = format!("#!/bin/sh\necho universe={org} layer=$VARVE_LAYER\n");
        let digest = varve_core::manifest_digest(tool.as_bytes());
        let host = varve_core::host_platform();
        let payload = format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "2026.08.0",
    "eu.pulseengine.varve.line": "2026.08",
    "eu.pulseengine.varve.channel": "rolling",
    "eu.pulseengine.varve.counter": "5",
    "org.opencontainers.image.created": "2026-08-07T00:00:00Z"
  }},
  "manifests": [
    {{ "mediaType": "application/vnd.oci.image.manifest.v1+json",
       "digest": "{digest}", "size": 0,
       "annotations": {{ "eu.pulseengine.tool": "probe", "eu.pulseengine.platform": "{host}" }} }}
  ]
}}"#
        );
        let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "k").unwrap();
        let archive = parent.join(format!("archive-{org}"));
        varve_core::DirSource::at(&archive)
            .put(envelope.as_bytes(), &[(digest.as_str(), tool.as_bytes())])
            .unwrap();
        archives.insert(org.to_string(), archive);
        realms_toml.push_str(&format!(
            "[realm.{org}]\nregistry = \"oci://example.invalid/{org}\"\ntrust-root = \"{}\"\n\n",
            hex::encode(&pk)
        ));
    }
    std::fs::write(parent.join("varve-realms.toml"), realms_toml).unwrap();

    // Two projects pinning the SAME layer name in DIFFERENT realms.
    for org in ["pulseengine", "acme"] {
        let proj = parent.join(format!("proj-{org}"));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"{org}\"\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n"
            ),
        )
        .unwrap();
        // Install from each realm's archive; NO VARVE_TRUST_ROOT env — the
        // realm is authoritative and self-contained.
        let mut cmd = Command::cargo_bin("varve").unwrap();
        cmd.env("VARVE_ROOT", &fx.root)
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&proj)
            .args(["install", "--from"])
            .arg(&archives[org])
            .assert()
            .success()
            .stdout(predicate::str::contains("2026.08.0"));
    }

    // One shim serves both universes: per-invocation resolution.
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("VARVE_ROOT", &fx.root)
        .current_dir(parent.join("proj-pulseengine"))
        .args(["shim", "install"])
        .assert()
        .success();
    let shim = fx.root.join("shims").join("probe");
    for (org, expect) in [
        ("pulseengine", "universe=pulseengine"),
        ("acme", "universe=acme"),
    ] {
        let out = std::process::Command::new(&shim)
            .current_dir(parent.join(format!("proj-{org}")))
            .env("VARVE_ROOT", &fx.root)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains(expect),
            "{org}: {stdout}"
        );
    }

    // Cross-acceptance impossible: acme's archive can NEVER install into the
    // pulseengine project (realm root refuses the signature).
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("VARVE_ROOT", &fx.root)
        .current_dir(parent.join("proj-pulseengine"))
        .args(["install", "--from"])
        .arg(&archives["acme"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("signature"));
}

// rivet: verifies REQ-RUNNER-001
#[cfg(unix)]
#[test]
fn portable_wasm_entries_dispatch_through_their_layer_runner() {
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust = parent.join("root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();

    // A "runtime" that prints exactly how it was invoked, and a "wasm" blob.
    let runtime = parent.join("kilnd-double");
    std::fs::write(&runtime, "#!/bin/sh\necho invoked: \"$@\"\n").unwrap();
    let module = parent.join("scry.core.wasm");
    std::fs::write(&module, b"fake-wasm-bytes").unwrap();

    // Deposit: native runner + portable wasm entry carrying the contract.
    let host = varve_core::host_platform();
    let spec = parent.join("deposit.toml");
    std::fs::write(
        &spec,
        format!(
            r#"layer = "2026.09.0"
channel = "rolling"
counter = 1

[[tool]]
name = "kilnd"
version = "0.4.4"
platform = "{host}"
path = "{runtime}"

[[tool]]
name = "scry"
version = "3.2.4"
platform = "wasm32-wasip2"
path = "{module}"

[tool.runner]
tool = "kilnd"
args = ["--wasi", "--wasi-version", "preview2"]
arg-prefix = "--wasi-arg"
"#,
            runtime = runtime.display(),
            module = module.display()
        ),
    )
    .unwrap();
    let dest = parent.join("runner-deposit");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-08-08T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&dest)
        .assert()
        .success();

    // Install on THIS host: the wasm entry rides along (portable).
    std::fs::write(
        fx.project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.09.0\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["install", "--from"])
        .arg(&dest)
        .assert()
        .success();

    // Dispatch: varve run -- scry --version x  →  the runner receives its
    // prefix args, then the module path, then per-arg-prefixed user args.
    varve(&fx)
        .args(["run", "--", "scry", "--version", "x"])
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(
                r"invoked: --wasi --wasi-version preview2 .*bin/scry --wasi-arg --version --wasi-arg x",
            )
            .unwrap(),
        );
}

// rivet: verifies REQ-ONBOARD-001
#[test]
fn install_auto_caches_a_layout_carried_line_status_so_status_just_works() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust = parent.join("root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    // Deposit a layer, then attach a signed line-status to its oci-layout.
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let tool = parent.join("t");
    std::fs::write(&tool, b"toolbytes").unwrap();
    let spec = parent.join("d.toml");
    let host = varve_core::host_platform();
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n[[tool]]\nname = \"synth\"\nversion = \"1\"\nplatform = \"{host}\"\npath = \"{}\"\n",
            tool.display()
        ),
    )
    .unwrap();
    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-08-07T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&layout)
        .assert()
        .success();

    // Sign a line-status and attach it to the layout via the library.
    let status_json = r#"{"line":"2026.07","counter":1,"issued-at":"2026-08-07T00:00:00Z","support-until":"2028-07-31","yanked":{},"known-problems":[]}"#;
    let doc: varve_core::LineStatus = serde_json::from_str(status_json).unwrap();
    let envelope = doc
        .sign(
            &hex::decode(std::fs::read_to_string(&sk_path).unwrap().trim()).unwrap(),
            "k",
        )
        .unwrap();
    let line = "2026.07.0"
        .parse::<varve_core::LayerId>()
        .unwrap()
        .line()
        .clone();
    varve_core::attach_status_to_layout(&layout, &line, envelope.as_bytes()).unwrap();

    // Install — and then `varve status` works with NO --from-file (varve#34).
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("supported until 2028-07-31"));
}

// rivet: verifies REQ-ONBOARD-001
#[test]
fn the_trust_root_error_points_to_the_realm_path() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("realm")
                .and(predicate::str::contains("rolling.pub"))
                .and(predicate::str::contains("Getting started")),
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
