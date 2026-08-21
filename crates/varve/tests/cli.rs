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
    cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
    cmd.env("VARVE_ROOT", &fx.root).current_dir(&fx.project);
    // A hermetic PATH. Without it these tests inherit the developer's, and
    // REQ-SHADOW-001 correctly reported a real conflict — a `cargo install`ed
    // `synth` in ~/.cargo/bin shadowing the fixture's pinned one — turning
    // three unrelated tests red on one machine and green on another. That is
    // the check doing its job; a suite whose result depends on what the person
    // running it happens to have installed is the defect.
    cmd.env("PATH", "/usr/bin:/bin");
    cmd
}

// rivet: verifies REQ-SHADOW-001
#[test]
fn verify_fails_when_path_runs_a_different_binary_than_the_pin() {
    // The reported bug (varve#66), end to end. Every individual answer was
    // correct and the composite was false: `which` printed the store path,
    // `verify` called the layer perfect — it WAS perfect — and the shell ran
    // something else. varve's headline claim in the README is `varve which
    // synth  # which binary runs here`.
    // A genuinely signed, installed layer — verify must have a trust root, and
    // the point of this test is that a PERFECT layer still fails the check.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let tool = parent.join("synth-bin");
    std::fs::write(&tool, "#!/bin/sh\n").unwrap();
    let spec = parent.join("spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0.0\"\npath = \"{}\"\n",
            tool.display()
        ),
    )
    .unwrap();
    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "k", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    let elsewhere = fx.project.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let impostor = elsewhere.join("synth");
    std::fs::write(&impostor, "#!/bin/sh\necho WRONG\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let shadowed_path = format!("{}:/usr/bin:/bin", elsewhere.display());

    // verify FAILS and says which binary actually wins, and how to fix it.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .env("PATH", &shadowed_path)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not what your PATH runs"))
        .stderr(predicate::str::contains("varve shim install"));

    // `which` keeps printing the dispatched path on STDOUT so scripts still
    // work, and warns on STDERR.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .env("PATH", &shadowed_path)
        .args(["which", "synth"])
        .assert()
        .success()
        .stdout(predicate::str::contains("/bin/synth"))
        .stderr(predicate::str::contains("on your PATH"));

    // With nothing shadowing it, verify passes — the check must not fire on a
    // machine that simply has not installed the shims yet.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .env("PATH", "/usr/bin:/bin")
        .arg("verify")
        .assert()
        .success();
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
    /// The hex-encoded SECRET half, for tests that must sign something else
    /// under the same root (attestation statements).
    secret_key: std::path::PathBuf,
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
    let secret_key = fx
        .project
        .parent()
        .unwrap()
        .join(format!("secret-{layer}-{counter}.hex"));
    std::fs::write(&secret_key, hex::encode(&sk)).unwrap();
    SignedLayer {
        archive,
        trust_root,
        wrong_root,
        secret_key,
    }
}

/// A REAL `.crate`-shaped gzip tar: `<name>-<version>/Cargo.toml` plus a source
/// file, with `extra` appended to the manifest.
///
/// Every crate fixture here is one now. Opaque bytes used to be enough because
/// `export-cargo` never opened the tarball — it wrote `"deps":[]` for every
/// crate (varve#73), so a fixture that could not have deps was indistinguishable
/// from one whose deps were dropped. The index is READ from these bytes now, so
/// the fixture has to be able to tell the truth.
fn dot_crate(name: &str, version: &str, extra_manifest: &str) -> Vec<u8> {
    let manifest = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n{extra_manifest}"
    );
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, body) in [
        (format!("{name}-{version}/Cargo.toml"), manifest),
        (
            format!("{name}-{version}/src/lib.rs"),
            "pub fn f() {}\n".to_string(),
        ),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, &path, body.as_bytes()).unwrap();
    }
    b.into_inner().unwrap().finish().unwrap()
}

/// A manifest whose entries are tools, plus optional composed layers.
fn manifest_with_includes(layer: &str, tools: &[&str], includes: &[&str]) -> String {
    let mut entries: Vec<String> = tools
        .iter()
        .map(|t| {
            format!(r#"{{"digest":"sha256:{t}","annotations":{{"eu.pulseengine.tool":"{t}"}}}}"#)
        })
        .collect();
    for d in includes {
        entries.push(format!(
            r#"{{"digest":"{d}","annotations":{{"eu.pulseengine.varve.kind":"layer","eu.pulseengine.varve.include.realm":"bytecodealliance"}}}}"#
        ));
    }
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"qualified"}},"manifests":[{}]}}"#,
        entries.join(",")
    )
}

// rivet: verifies REQ-KEYGEN-001, REQ-PRODUCER-001, REQ-STORE-001
#[test]
fn an_organisation_can_stand_up_its_own_realm() {
    // The path a ten-persona audit found CLOSED: four of five blocked personas
    // could not get from a signing key to the trust-root a realm demands.
    // keygen -> deposit under our own key -> our own realms file -> pin ->
    // install -> verify against OUR root.
    let fx = fixture(None, &[]);
    let dir = fx.project.clone();
    let key = dir.join("acme.key");
    let pubf = dir.join("acme.pub");
    varve(&fx)
        .args(["keygen", "--out"])
        .arg(&key)
        .arg("--pub")
        .arg(&pubf)
        .assert()
        .success()
        .stdout(predicate::str::contains("trust-root"));

    // pubkey re-prints the same value, bare, so it composes into a config.
    let printed = varve(&fx)
        .args(["pubkey"])
        .arg(&key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let printed = String::from_utf8(printed).unwrap().trim().to_string();
    let from_file = std::fs::read_to_string(&pubf).unwrap().trim().to_string();
    assert_eq!(printed, from_file);
    assert_eq!(printed.len(), 64, "a trust-root is 64 hex characters");

    // Deposit a layer signed with our key.
    let tool = dir.join("acme-tool");
    std::fs::write(&tool, b"#!/bin/sh\necho acme\n").unwrap();
    let layout = dir.join("layout");
    varve(&fx)
        .args([
            "deposit",
            "--layer",
            "2026.08.0",
            "--channel",
            "qualified",
            "--counter",
            "1",
            "--issued-at",
            "2026-08-01T00:00:00Z",
            "--key",
        ])
        .arg(&key)
        .arg("--out")
        .arg(&layout)
        .arg("--tool")
        .arg(format!("acme-tool@1.0.0={}", tool.display()))
        .assert()
        .success();

    // Our own realm, pinned by our own project, verified against OUR root.
    std::fs::write(
        dir.join("varve-realms.toml"),
        format!(
            "[realm.acme]\nregistry = \"oci://example.invalid/acme\"\ntrust-root = \"{printed}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\nlayer = \"2026.08.0\"\n",
    )
    .unwrap();
    varve(&fx)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
    varve(&fx).args(["which", "acme-tool"]).assert().success();

    // REQ-STORE-001: a layer `which` resolves must be a layer `list` can see.
    // `list` read only the top-level core, so after a realm install it printed
    // "no layers installed" with exit 0 — contradicted a second later by
    // verify, which, run and sbom. Three personas reported it.
    varve(&fx)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.08.0"));

    // …and an explicit --layer must find it too. This is the README's
    // headline example, and it failed on the realm path.
    varve(&fx)
        .args(["sbom", "--layer", "2026.08.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CycloneDX"));
}

// rivet: verifies REQ-PRODUCER-001
#[test]
fn deposit_refuses_a_key_that_would_sign_unverifiably() {
    // varve accepted 64 bytes of entropy and emitted a signed layer no trust
    // root on earth could verify, exit 0. The produce side now fails closed
    // like the consume side.
    let fx = fixture(None, &[]);
    let dir = fx.project.clone();
    let tool = dir.join("t");
    std::fs::write(&tool, b"x").unwrap();

    let entropy = dir.join("entropy.key");
    std::fs::write(&entropy, "ab".repeat(64)).unwrap();
    varve(&fx)
        .args([
            "deposit",
            "--layer",
            "2026.08.0",
            "--channel",
            "qualified",
            "--counter",
            "1",
            "--issued-at",
            "2026-08-01T00:00:00Z",
            "--key",
        ])
        .arg(&entropy)
        .arg("--out")
        .arg(dir.join("out1"))
        .arg("--tool")
        .arg(format!("t@1.0.0={}", tool.display()))
        .assert()
        .failure()
        .stderr(predicate::str::contains("NO trust root can verify"));

    // A 32-byte secret — what the old --key help text described — names both
    // lengths and the command that mints a real one.
    let short = dir.join("short.key");
    std::fs::write(&short, "ab".repeat(32)).unwrap();
    varve(&fx)
        .args([
            "deposit",
            "--layer",
            "2026.08.0",
            "--channel",
            "qualified",
            "--counter",
            "1",
            "--issued-at",
            "2026-08-01T00:00:00Z",
            "--key",
        ])
        .arg(&short)
        .arg("--out")
        .arg(dir.join("out2"))
        .arg("--tool")
        .arg(format!("t@1.0.0={}", tool.display()))
        .assert()
        .failure()
        .stderr(predicate::str::contains("128").and(predicate::str::contains("varve keygen")));
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn one_pin_resolves_tools_from_a_composed_layer() {
    // varve#52: relay needs the PulseEngine tools that CHECK its work and the
    // upstream tools that BUILD it. One pin, two layers, both resolvable.
    let fx = fixture(Some(PIN_JULY), &[]);
    let store = varve_core::Store::at(&fx.root);
    // The upstream layer, laid down first so we can learn its digest.
    let upstream = manifest_with_includes("2026.08.0", &["wasm-tools", "cargo-component"], &[]);
    let up_digest = store
        .lay_down(
            upstream.as_bytes(),
            &[("wasm-tools", b"w"), ("cargo-component", b"c")],
        )
        .unwrap();
    // The pinned layer composes it.
    let root = manifest_with_includes("2026.07.0", &["rivet"], &[&up_digest]);
    store.lay_down(root.as_bytes(), &[("rivet", b"r")]).unwrap();

    // The checking half still resolves…
    varve(&fx)
        .args(["which", "rivet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bin/rivet"));
    // …and now so does the PRODUCING half, through one pin.
    varve(&fx)
        .args(["which", "wasm-tools"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bin/wasm-tools"));
    varve(&fx)
        .args(["which", "cargo-component"])
        .assert()
        .success();
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn verify_refuses_a_composition_whose_included_layer_is_unsigned() {
    // Clean-room review demonstrated this exactly: an included layer laid down
    // with NO signature envelope dispatched its tools and `varve verify` still
    // exited 0, because verify only checked the root layer. A composition is
    // only as trustworthy as every layer in it — the included layer's tools are
    // on PATH exactly like the root's.
    let fx = fixture(Some(PIN_JULY), &[]);
    let (sk, pk) = varve_core::generate_root_keypair();
    let store = varve_core::Store::at(&fx.root);

    // An UNSIGNED upstream layer, laid straight into the store.
    let upstream = manifest_with_includes("2026.08.0", &["wasm-tools"], &[]);
    let up = store
        .lay_down(upstream.as_bytes(), &[("wasm-tools", b"unsigned")])
        .unwrap();

    // A properly signed root layer that composes it.
    let tool_bytes: &[u8] = b"synth-binary";
    let blob = varve_core::manifest_digest(tool_bytes);
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "2026.07.0",
    "eu.pulseengine.varve.line": "2026.07",
    "eu.pulseengine.varve.channel": "qualified",
    "eu.pulseengine.varve.counter": "1",
    "org.opencontainers.image.created": "2026-07-31T09:14:00Z"
  }},
  "manifests": [
    {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{blob}","size":0,
      "annotations":{{"eu.pulseengine.tool":"synth"}}}},
    {{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"{up}","size":0,
      "annotations":{{"eu.pulseengine.varve.kind":"layer"}}}}
  ]
}}"#
    );
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "test-root").unwrap();
    let archive = fx.project.parent().unwrap().join("composed-archive");
    varve_core::DirSource::at(&archive)
        .put(envelope.as_bytes(), &[(blob.as_str(), tool_bytes)])
        .unwrap();
    let root = fx.project.parent().unwrap().join("composed-root.pub");
    std::fs::write(&root, hex::encode(&pk)).unwrap();

    // Install must ACCEPT the composed layer (it used to reject the include).
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["install", "--from"])
        .arg(&archive)
        .assert()
        .success();

    // …and verify must now REFUSE, because the included layer is unsigned.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("composed layer").or(predicate::str::contains("2026.08.0")),
        );
}

// rivet: verifies REQ-PRODUCE-002
#[test]
fn install_refuses_a_composition_whose_include_is_not_installed() {
    // An independent review changed the guard to `if false && !missing…` and
    // the whole suite stayed green: the test cited as this clause's evidence
    // contains no composition at all, and the one composition CLI test
    // exercises `which`, not `install`. Unguarded, install exits 0 on a
    // composition `verify` rejects, and `run` then executes a tool from an
    // unverified included layer.
    let fx = fixture(Some(PIN_JULY), &[]);
    let (sk, pk) = varve_core::generate_root_keypair();
    let tool_bytes = b"synth-bytes";
    let blob = varve_core::manifest_digest(tool_bytes);
    // An include that names a realm and a layer, and is NOT installed anywhere.
    let payload = format!(
        r#"{{
  "schemaVersion":2,
  "mediaType":"application/vnd.oci.image.index.v1+json",
  "artifactType":"application/vnd.pulseengine.varve.layer.v1+json",
  "annotations":{{"eu.pulseengine.varve.layer":"2026.07.0",
    "eu.pulseengine.varve.line":"2026.07",
    "eu.pulseengine.varve.channel":"qualified",
    "eu.pulseengine.varve.counter":"1",
    "org.opencontainers.image.created":"2026-07-31T09:14:00Z"}},
  "manifests":[
    {{"mediaType":"application/octet-stream","digest":"{blob}","size":{size},
      "annotations":{{"eu.pulseengine.tool":"synth"}}}},
    {{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":0,
      "annotations":{{"eu.pulseengine.varve.kind":"layer",
        "eu.pulseengine.varve.include.realm":"bytecodealliance",
        "eu.pulseengine.varve.include.layer":"2026.05.0"}}}}
  ]
}}"#,
        size = tool_bytes.len()
    );
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "test-root").unwrap();
    let archive = fx.project.parent().unwrap().join("missing-include-archive");
    varve_core::DirSource::at(&archive)
        .put(envelope.as_bytes(), &[(blob.as_str(), tool_bytes)])
        .unwrap();
    let root = fx.project.parent().unwrap().join("mi-root.pub");
    std::fs::write(&root, hex::encode(&pk)).unwrap();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["install", "--from"])
        .arg(&archive)
        .assert()
        .failure()
        // names the missing layer…
        .stderr(predicate::str::contains("2026.05.0"))
        // …and the realm it must come from, which is the whole point: the same
        // layer id under another realm is a different layer…
        .stderr(predicate::str::contains("bytecodealliance"))
        // …and how to get it. `varve install` alone takes no layer or digest,
        // so advice naming only that is a no-op loop.
        .stderr(predicate::str::contains("varve.toml"));
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_composed_layer_that_is_not_installed_names_itself() {
    // Transitive fetch is deliberately out of scope: the error must name the
    // missing layer and its corrective install, as a missing pin already does.
    let fx = fixture(Some(PIN_JULY), &[]);
    let store = varve_core::Store::at(&fx.root);
    let root = manifest_with_includes("2026.07.0", &["rivet"], &["sha256:notinstalled"]);
    store.lay_down(root.as_bytes(), &[("rivet", b"r")]).unwrap();
    varve(&fx)
        .args(["which", "rivet"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not installed")
                .and(predicate::str::contains("varve install")),
        );
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_tool_in_two_composed_layers_refuses_to_resolve() {
    // varve does not pick a winner — the same rule as an ambiguous pin.
    let fx = fixture(Some(PIN_JULY), &[]);
    let store = varve_core::Store::at(&fx.root);
    let upstream = manifest_with_includes("2026.08.0", &["wasm-tools"], &[]);
    let up = store
        .lay_down(upstream.as_bytes(), &[("wasm-tools", b"u")])
        .unwrap();
    let root = manifest_with_includes("2026.07.0", &["wasm-tools"], &[&up]);
    store
        .lay_down(root.as_bytes(), &[("wasm-tools", b"r")])
        .unwrap();
    varve(&fx)
        .args(["which", "wasm-tools"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("more than one layer"));
}

// rivet: verifies REQ-LOCKPIN-001
#[test]
fn verify_lockfile_refuses_a_file_it_could_not_read() {
    // A ten-persona docs audit found this exiting 0 on a path that does not
    // exist, printing "pins no crates — nothing to check" for a file it had
    // never opened. This gate is sold as the CI check for REQ-LOCKPIN-001, so
    // a typo'd path would have been green forever. A gate that cannot fail is
    // not a gate — and varve had just shipped one.
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--lockfile"])
        .arg(fx.project.join("no-such-file.lock"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read lockfile"));
    // And a lockfile that exists but is malformed must also fail, even when
    // the layer pins no crates — the file was read, so it must parse.
    let bad = fx.project.join("Cargo.lock");
    std::fs::write(&bad, "not toml {{{").unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["verify", "--lockfile"])
        .arg(&bad)
        .assert()
        .failure();
}

// rivet: verifies REQ-LOCKPIN-001
#[test]
fn verify_lockfile_fails_when_a_pinned_crate_disagrees() {
    // The first version of this test asserted .success() twice and never tested
    // a disagreement — a test whose NAME claimed the opposite of what it did
    // (found by clean-room review). It now exercises the failing path, against
    // a SIGNED layer, because the gate is trust-first and refuses to check
    // against a layer it cannot verify.
    let fx = fixture(Some(PIN_JULY), &[]);
    let (sk, pk) = varve_core::generate_root_keypair();
    let crate_bytes: &[u8] = b"fake-crate-tarball";
    let blob = varve_core::manifest_digest(crate_bytes);
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "2026.07.0",
    "eu.pulseengine.varve.line": "2026.07",
    "eu.pulseengine.varve.channel": "qualified",
    "eu.pulseengine.varve.counter": "1",
    "org.opencontainers.image.created": "2026-07-31T09:14:00Z"
  }},
  "manifests": [
    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{blob}",
      "size": 0,
      "annotations": {{
        "eu.pulseengine.tool": "wit-bindgen-rt",
        "eu.pulseengine.tool.version": "0.58.0",
        "eu.pulseengine.varve.kind": "crate"
      }}
    }}
  ]
}}"#
    );
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "test-root").unwrap();
    let archive = fx.project.parent().unwrap().join("crate-archive");
    varve_core::DirSource::at(&archive)
        .put(envelope.as_bytes(), &[(blob.as_str(), crate_bytes)])
        .unwrap();
    let root = fx.project.parent().unwrap().join("crate-root.pub");
    std::fs::write(&root, hex::encode(&pk)).unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["install", "--from"])
        .arg(&archive)
        .assert()
        .success();

    let lock = fx.project.join("Cargo.lock");
    // The consumer's actual drift: the layer pins 0.58.0, the project resolves 0.41.0.
    std::fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"wit-bindgen-rt\"\nversion = \"0.41.0\"\nchecksum = \"aaaa\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("0.58.0")
                .and(predicate::str::contains("0.41.0"))
                .and(predicate::str::contains("disagree")),
        );

    // Agreement passes, and says what it actually checked.
    std::fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"wit-bindgen-rt\"\nversion = \"0.58.0\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .success()
        .stdout(predicate::str::contains("agrees with layer"));

    // A malformed lockfile must FAIL, never silently pass.
    std::fs::write(&lock, "not toml {{{").unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .failure();
}
// rivet: verifies REQ-ATTEST-001
#[test]
fn an_attestation_binds_to_its_layer_and_nothing_else() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();

    // An SBOM of the pinned layer, then a signed statement binding it.
    let sbom = fx.project.join("layer.cdx.json");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sbom", "--out"])
        .arg(&sbom)
        .assert()
        .success();
    let stmt = fx.project.join("sbom.statement.dsse");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args([
            "sign-attestation",
            "--kind",
            "sbom",
            "--producer",
            "varve",
            "--file",
        ])
        .arg(&sbom)
        .arg("--key")
        .arg(&signed.secret_key)
        .arg("--key-id")
        .arg("test-root")
        .arg("--out")
        .arg(&stmt)
        .assert()
        .success();

    // It checks out against the pinned layer.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["check-attestation", "--statement"])
        .arg(&stmt)
        .arg("--file")
        .arg(&sbom)
        .assert()
        .success()
        .stdout(predicate::str::contains("attestation OK"));

    // Swap the bytes: the statement pins them, so this must be refused.
    let tampered = fx.project.join("tampered.cdx.json");
    std::fs::write(
        &tampered,
        b"{\"bomFormat\":\"CycloneDX\",\"components\":[]}",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["check-attestation", "--statement"])
        .arg(&stmt)
        .arg("--file")
        .arg(&tampered)
        .assert()
        .failure();

    // A statement signed by another root cannot vouch for anything here.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.wrong_root)
        .args(["check-attestation", "--statement"])
        .arg(&stmt)
        .arg("--file")
        .arg(&sbom)
        .assert()
        .failure();

    // An unknown kind is refused, not guessed.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sign-attestation", "--kind", "vibes", "--file"])
        .arg(&sbom)
        .arg("--key")
        .arg(&signed.secret_key)
        .arg("--out")
        .arg(fx.project.join("nope.dsse"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown attestation kind"));
}

// rivet: verifies REQ-ATTEST-001
#[test]
fn check_attestation_refuses_a_tampered_layer() {
    // Clean-room review found check-attestation reporting "attestation OK" over
    // a store state `varve verify` rejects: it checked the statement signature
    // but never re-verified the LAYER, whose name and digest are local labels
    // until its retained envelope is re-checked. This is the command the
    // disconnected consumer runs; it must not be the trusting one.
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    let sbom = fx.project.join("l.cdx.json");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sbom", "--out"])
        .arg(&sbom)
        .assert()
        .success();
    let stmt = fx.project.join("s.dsse");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sign-attestation", "--kind", "sbom", "--file"])
        .arg(&sbom)
        .arg("--key")
        .arg(&signed.secret_key)
        .arg("--key-id")
        .arg("test-root")
        .arg("--out")
        .arg(&stmt)
        .assert()
        .success();
    // Now alter an installed tool binary — the layer no longer verifies.
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
        .failure();
    // check-attestation must reach the same verdict, not report OK.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["check-attestation", "--statement"])
        .arg(&stmt)
        .arg("--file")
        .arg(&sbom)
        .assert()
        .failure();
}

// rivet: verifies REQ-ATTEST-002
#[test]
fn an_attestation_travels_through_deposit_archive_and_an_offline_install() {
    // The carriage half, at the boundary a user actually touches. v0.22.0
    // shipped BINDING and a review found REQ-ATTEST-001 marked verified with
    // this half unimplemented: a statement that stays in the producer's CI is
    // not evidence anyone has. Registries publish this material and mirrors
    // drop it — bandersnatch and Verdaccio carry none, every BCR attestation
    // URL points at github.com — so an air-gapped consumer receives the bytes
    // and none of the accountability, with no error saying so.
    //
    // Three cores, sharing nothing but the pinned root: the producer's, the
    // consumer's, and the disconnected site's on the far side of `archive`.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap().to_path_buf();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("attcarry-root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("attcarry-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let tool = parent.join("attcarry-synth");
    std::fs::write(&tool, "#!/bin/sh\n").unwrap();
    let spec = parent.join("attcarry-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0.0\"\npath = \"{}\"\n",
            tool.display()
        ),
    )
    .unwrap();

    // 1. CI deposits the layer as an oci-layout.
    let layout = parent.join("attcarry-layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "test-root", "--out"])
        .arg(&layout)
        .assert()
        .success();

    // 2. …installs it once to produce an SBOM transcribed from the signed
    // manifest, and signs a statement binding that SBOM to the layer, ATTACHING
    // both to the layout as referrer artifacts. This is the step that did not
    // exist: without it the statement is written to a file and reaches nobody.
    let producer_root = parent.join("producer-root");
    let sbom = parent.join("layer.cdx.json");
    let stmt = parent.join("sbom.statement.dsse");
    varve(&fx)
        .env("VARVE_ROOT", &producer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_ROOT", &producer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["sbom", "--out"])
        .arg(&sbom)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_ROOT", &producer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args([
            "sign-attestation",
            "--kind",
            "sbom",
            "--producer",
            "acme-ci",
            "--file",
        ])
        .arg(&sbom)
        .arg("--key")
        .arg(&sk_path)
        .args(["--key-id", "test-root", "--out"])
        .arg(&stmt)
        .arg("--attach-to")
        .arg(&layout)
        .assert()
        .success()
        .stdout(predicate::str::contains("attached to layout"));

    // 3. A consumer installs from that layout into a core of its own: the
    // evidence travels with the layer, and `verify` says what it is and that
    // it still binds.
    let consumer_root = parent.join("consumer-root");
    varve(&fx)
        .env("VARVE_ROOT", &consumer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success()
        .stdout(predicate::str::contains("carried 1 attestation(s)"));
    varve(&fx)
        .env("VARVE_ROOT", &consumer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("carries 1 attestation(s)"))
        .stdout(predicate::str::contains(
            "sbom by acme-ci: binds to this layer",
        ));

    // 4. That consumer archives the layer for a disconnected site. The archive
    // must re-emit the attestation as referrer entries — this is the mirror
    // boundary, and dropping it here is exactly the bug.
    let air_gapped = parent.join("attcarry-archive");
    varve(&fx)
        .env("VARVE_ROOT", &consumer_root)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["archive", "2026.07.0"])
        .arg(&air_gapped)
        .assert()
        .success();

    // 5. The far side: a FRESH core, offline, nothing but the archive and the
    // pinned root. The evidence is there and still binds.
    let far_side = parent.join("far-side-root");
    varve(&fx)
        .env("VARVE_ROOT", &far_side)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&air_gapped)
        .assert()
        .success()
        .stdout(predicate::str::contains("carried 1 attestation(s)"));
    varve(&fx)
        .env("VARVE_ROOT", &far_side)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "sbom by acme-ci: binds to this layer",
        ));

    // 6. Reporting, not refusal — deliberately. Corrupt the carried statement
    // in the far-side core: `verify` must say the attestation no longer binds
    // and still PASS the layer, whose own signature and digests are untouched.
    // Failing here would make varve's verdict depend on a third party's
    // release cadence, in the one tool whose purpose is frozen toolchains.
    let store_dir = std::fs::read_dir(far_side.join("core"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("attestations");
    for e in std::fs::read_dir(&store_dir).unwrap() {
        let p = e.unwrap().path();
        if p.to_string_lossy().ends_with(".statement.json") {
            std::fs::write(&p, b"{\"payload\":\"bm90LWEtc3RhdGVtZW50\"}").unwrap();
        }
    }
    varve(&fx)
        .env("VARVE_ROOT", &far_side)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified: signature OK"))
        .stdout(predicate::str::contains("DOES NOT BIND"));
}

// rivet: verifies REQ-SBOM-001
#[test]
fn sbom_fails_closed_on_a_layer_it_cannot_verify() {
    // REQ-SBOM-001 says the command "shall fail closed". An SBOM for an
    // unverifiable layer is worse than none, because it looks authoritative.
    // Clean-room review noted this was asserted in prose but never tested.
    let fx = fixture(Some(PIN_JULY), &[]);
    let signed = signed_layer_fixture(&fx, "2026.07.0", 1);
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["install", "--from"])
        .arg(&signed.archive)
        .assert()
        .success();
    let out = fx.project.join("sbom.cdx.json");

    // 1. No trust root at all: refuse.
    varve(&fx)
        .args(["sbom", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("trust root"));
    assert!(!out.exists(), "nothing may be written without a trust root");

    // 2. The WRONG trust root: refuse.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.wrong_root)
        .args(["sbom", "--out"])
        .arg(&out)
        .assert()
        .failure();
    assert!(!out.exists(), "nothing may be written under the wrong root");

    // 3. The right root: a document, and it names the layer it describes.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sbom", "--out"])
        .arg(&out)
        .assert()
        .success();
    let doc = std::fs::read_to_string(&out).unwrap();
    assert!(
        doc.contains("CycloneDX") && doc.contains("2026.07.0"),
        "{doc}"
    );

    // 4. An unknown format is refused before anything is verified or written.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .args(["sbom", "--format", "spdx"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown SBOM format"));
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

/// Deposit one layer of a line under a caller-supplied key, so several layers
/// share ONE trust root — `signed_layer_fixture` mints a fresh keypair per
/// call, and anti-rollback is a property of a line, which needs two layers a
/// single `verify` can check against a single root.
fn deposit_under(
    fx: &Fixture,
    key: &std::path::Path,
    layer: &str,
    counter: u64,
) -> std::path::PathBuf {
    let dir = fx.project.parent().unwrap();
    let tool = dir.join(format!("synth-{layer}"));
    std::fs::write(&tool, format!("#!/bin/sh\necho {layer}\n")).unwrap();
    let layout = dir.join(format!("layout-{layer}"));
    varve(fx)
        .args([
            "deposit",
            "--layer",
            layer,
            "--channel",
            "qualified",
            "--counter",
            &counter.to_string(),
            "--issued-at",
            "2026-08-01T00:00:00Z",
            "--key",
        ])
        .arg(key)
        .arg("--out")
        .arg(&layout)
        .arg("--tool")
        .arg(format!("synth@1.0.0={}", tool.display()))
        .assert()
        .success();
    layout
}

// rivet: verifies REQ-ROLLBACK-001, REQ-VERIFY-001
#[test]
fn verify_refuses_a_pin_that_resolves_below_the_lines_high_water_mark() {
    // varve#76. `verify` called itself "the install-time verdict, repeated
    // offline" and was not: the install-time verdict includes anti-rollback
    // and verify's did not. So a pin edited back to an already-installed
    // OLDER layer verified clean, exit 0 — and the docs tell people to run
    // `verify` in CI AS THE GATE, so the downgrade passed the gate. The layer
    // is genuinely signed and its digests genuinely match; every individual
    // answer was true and the composite was false.
    let fx = fixture(None, &[]);
    let dir = fx.project.parent().unwrap();
    let key = dir.join("root.key");
    let pubf = dir.join("root.pub");
    varve(&fx)
        .args(["keygen", "--out"])
        .arg(&key)
        .arg("--pub")
        .arg(&pubf)
        .assert()
        .success();

    let old = deposit_under(&fx, &key, "2026.08.0", 1);
    let new = deposit_under(&fx, &key, "2026.08.5", 5);
    let pin = |layer: &str| {
        std::fs::write(
            fx.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
            ),
        )
        .unwrap()
    };

    // Install the old one, then the new one: the line's high-water mark rises
    // to 5 while BOTH layers stay on disk, which is legitimate — a consumer
    // may keep an older layer around.
    pin("2026.08.0");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &pubf)
        .args(["install", "--from"])
        .arg(&old)
        .assert()
        .success();
    pin("2026.08.5");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &pubf)
        .args(["install", "--from"])
        .arg(&new)
        .assert()
        .success();

    // At the mark, verify passes — the check must not fire on a correct
    // setup, or it becomes a check people switch off.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &pubf)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));

    // Edit the pin back to the older, already-installed layer. Nothing about
    // the layer is wrong; what is wrong is that the pin now DISPATCHES it.
    pin("2026.08.0");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &pubf)
        .arg("verify")
        .assert()
        .failure()
        // Both counters, so the reader can see the gap and not just the
        // verdict — and the layer it resolved to, so they know which pin.
        .stderr(
            predicate::str::contains("2026.08.0")
                .and(predicate::str::contains("counter 1"))
                .and(predicate::str::contains("high-water mark is 5")),
        );

    // …and `install` refuses the same downgrade, which is the verdict verify
    // now repeats. The two commands must not disagree.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &pubf)
        .args(["install", "--from"])
        .arg(&old)
        .assert()
        .failure();
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
    cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
    cmd.env("VARVE_ROOT", &fresh_root)
        .env("VARVE_TRUST_ROOT", &signed.trust_root)
        .current_dir(&fx.project)
        .args(["install", "--from"])
        .arg(&exported)
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.07.0"));
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
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
    // Exit 3, not 0: this fixture's baseline YANKS the pinned layer, and since
    // v0.28.0 that is the exit code rather than a word on stdout
    // (REQ-CIGATE-001 clause 1, BREAKING). The report is unchanged.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("status")
        .assert()
        .code(3)
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

    // A REAL `.crate` whose Cargo.toml declares a dependency and a feature:
    // `export-cargo` reads both out of the tarball for the index entry
    // (REQ-CRATEIDX-001), so a blob with nothing in it would not exercise it.
    let crate_bytes = dot_crate(
        "demo-crate",
        "0.1.0",
        "[dependencies]\ncfg-if = \"1\"\n\n[features]\ndefault = [\"std\"]\nstd = []\n",
    );
    let crate_path = parent.join("demo-crate.crate");
    std::fs::write(&crate_path, &crate_bytes).unwrap();

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
    let line: serde_json::Value = serde_json::from_str(idx.trim()).expect("{idx}");
    assert!(
        line["cksum"].is_string() && line["vers"] == "0.1.0",
        "{idx}"
    );
    // …and the wiring carries the DEPS and FEATURES out of the tarball, not a
    // stub: the CLI is where varve#73 was observed.
    assert_eq!(line["deps"][0]["name"], "cfg-if", "{idx}");
    assert_eq!(
        line["features"]["default"],
        serde_json::json!(["std"]),
        "{idx}"
    );
}

// rivet: verifies REQ-STORE-002
#[test]
fn a_layer_holding_two_versions_of_one_crate_deposits_installs_verifies_and_exports_both() {
    // varve#69 end to end, at the boundary the user touches. `deposit` refused
    // the layer outright ("duplicate tool name 'serde'"), so a real dependency
    // graph — varve's own has 14 names at more than one version — could not be
    // expressed at all. And had only the deposit check been relaxed, the two
    // payloads would have landed on ONE path in the store: the wrong bytes
    // under the right name, with `verify` failing on the other entry.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // Two versions of ONE crate, plus a tool — the mixed layer, so the two
    // identity rules are exercised side by side.
    let old_bytes = dot_crate("serde", "1.0.200", "");
    let new_bytes = dot_crate("serde", "1.0.210", "[features]\nderive = []\n");
    let old_path = parent.join("serde-1.0.200.crate");
    let new_path = parent.join("serde-1.0.210.crate");
    let tool_path = parent.join("synth-bin");
    std::fs::write(&old_path, &old_bytes).unwrap();
    std::fs::write(&new_path, &new_bytes).unwrap();
    std::fs::write(&tool_path, b"#!/bin/sh\n").unwrap();

    let spec = parent.join("spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"serde\"\nversion = \"1.0.200\"\nkind = \"crate\"\npath = \"{old}\"\n\n\
             [[tool]]\nname = \"serde\"\nversion = \"1.0.210\"\nkind = \"crate\"\npath = \"{new}\"\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"0.45.0\"\npath = \"{tool}\"\n",
            old = old_path.display(),
            new = new_path.display(),
            tool = tool_path.display(),
        ),
    )
    .unwrap();
    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .assert()
        .success();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    // The layer verifies as a whole: three payloads, each against its own
    // signed digest.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success();

    // The exported registry OFFERS BOTH versions — a lockfile naming two
    // majors needs both present to build offline.
    let out = parent.join("cargo-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("2 verified crate"));
    assert_eq!(
        std::fs::read(out.join("registry/serde-1.0.200.crate")).unwrap(),
        old_bytes
    );
    assert_eq!(
        std::fs::read(out.join("registry/serde-1.0.210.crate")).unwrap(),
        new_bytes,
        "each version must export ITS OWN bytes"
    );
    let idx = std::fs::read_to_string(out.join("registry/index/se/rd/serde")).unwrap();
    let versions: Vec<String> = idx
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("Cargo-parseable index line");
            v["vers"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(versions.len(), 2, "index: {idx}");
    assert!(versions.contains(&"1.0.200".to_string()) && versions.contains(&"1.0.210".to_string()));

    // The lockfile gate agrees with a lockfile that resolves both — before
    // this, comparing every pinned entry against every locked package of the
    // same name reported 1.0.200-vs-1.0.210 as drift.
    let lock = fx.project.join("Cargo.lock");
    std::fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\n\
         [[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .success();

    // And the whole layer still crosses an air gap: archive it, install into a
    // fresh core from that archive alone, and verify there.
    let archive = parent.join("archive");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["archive", "2026.07.0"])
        .arg(&archive)
        .assert()
        .success();
    let far_side = parent.join("far-side");
    varve(&fx)
        .env("VARVE_ROOT", &far_side)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&archive)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_ROOT", &far_side)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success();
}

// rivet: verifies REQ-STORE-002
#[test]
fn two_versions_of_one_tool_are_still_refused_and_the_error_names_both() {
    // The other half of clause 1, at the boundary: dispatch is by name, so
    // `varve run synth` must have exactly one answer. Relaxing the rule for
    // everything would have made the shims ambiguous.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let bin = parent.join("synth-bin");
    std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
    let spec = parent.join("spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"0.45.0\"\npath = \"{p}\"\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"0.46.0\"\npath = \"{p}\"\n",
            p = bin.display(),
        ),
    )
    .unwrap();
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "k", "--out"])
        .arg(parent.join("layout"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("synth")
                .and(predicate::str::contains("0.45.0"))
                .and(predicate::str::contains("0.46.0")),
        );
}

// rivet: verifies REQ-VSIX-001, REQ-STORE-002
#[test]
fn a_per_platform_payload_exports_the_hosts_bytes_not_another_platforms_digest() {
    // Found by building the REAL pulseengine layer: spar ships one .vsix per
    // platform, and a layer carrying them could be deposited and installed but
    // NOT exported — `export-vsix` failed with "on-disk bytes do not match the
    // signed digest".
    //
    // `install` platform-filters, laying down only the host's payload.
    // `payloads_of_layer` did not filter at all, so it walked every platform's
    // manifest entry, resolved each to the ONE on-disk file (the payload path
    // is name/version and carries no platform), and compared the host's bytes
    // against a foreign platform's signed digest. The mismatch was real; the
    // conclusion drawn from it was wrong.
    //
    // This is latent for every per-platform non-tool payload, not just vsix —
    // it stayed hidden because no layer had carried one until now.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("pp-root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("pp-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let host = varve_core::host_platform();
    let other = if host == "x86_64-unknown-linux-gnu" {
        "aarch64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    };

    // One extension, one version, DIFFERENT bytes per platform — so exporting
    // the wrong platform's digest cannot accidentally agree.
    let mut spec_text =
        String::from("layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n");
    for plat in [host.as_str(), other] {
        let path = parent.join(format!("spar-aadl-{plat}.vsix"));
        std::fs::write(&path, format!("vsix-bytes-for-{plat}")).unwrap();
        spec_text.push_str(&format!(
            "\n[[tool]]\nname = \"spar-aadl\"\nversion = \"0.36.0\"\nkind = \"vsix\"\n\
             platform = \"{plat}\"\npath = \"{}\"\n",
            path.display()
        ));
    }
    let spec = parent.join("pp-spec.toml");
    std::fs::write(&spec, &spec_text).unwrap();

    let layout = parent.join("pp-layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-31T09:14:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "test-1", "--out"])
        .arg(&layout)
        .assert()
        .success();
    install_pinned(&fx, &trust_root, "2026.07.0", &layout);

    let out = parent.join("pp-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-vsix", "--out"])
        .arg(&out)
        .assert()
        .success();
    // Exactly one file — the host's — carrying the host's bytes.
    let exported: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".vsix"))
        .collect();
    assert_eq!(exported.len(), 1, "one platform's vsix, got {exported:?}");
    let body = std::fs::read_to_string(out.join(&exported[0])).unwrap();
    assert_eq!(
        body,
        format!("vsix-bytes-for-{host}"),
        "the exported bytes are not the host's"
    );
}

// rivet: verifies REQ-VSIX-001
#[test]
fn vsix_extensions_deposit_install_verify_and_export_for_code() {
    // varve#68 end to end, at the boundary the user touches. Two extensions,
    // one of them at TWO versions (REQ-STORE-002's identity rule, inherited
    // rather than re-implemented), through deposit -> install -> verify ->
    // export-vsix, and out the other side as files `code --install-extension`
    // consumes directly.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // Stand-in .vsix zips — varve never looks inside one; the bytes are
    // anchored by the signed digest and the NAME comes from the manifest.
    let payloads: [(&str, &str, &[u8]); 3] = [
        ("rust-lang.rust-analyzer", "0.3.2260", b"ra-old-zip-bytes"),
        ("rust-lang.rust-analyzer", "0.3.2300", b"ra-new-zip-bytes"),
        ("vadimcn.vscode-lldb", "1.11.4", b"lldb-zip-bytes"),
    ];
    let mut spec_text =
        String::from("layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n");
    for (name, version, bytes) in payloads {
        let path = parent.join(format!("{name}-{version}.vsix"));
        std::fs::write(&path, bytes).unwrap();
        spec_text.push_str(&format!(
            "\n[[tool]]\nname = \"{name}\"\nversion = \"{version}\"\nkind = \"vsix\"\n\
             path = \"{}\"\n",
            path.display()
        ));
    }
    let spec = parent.join("vsix-spec.toml");
    std::fs::write(&spec, &spec_text).unwrap();

    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .assert()
        .success();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    // Every entry verifies against its own signed digest — the digest check is
    // kind-agnostic (DD-003), so a `vsix` needed nothing new here (clause 1).
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success();

    // Clause 2 + clause 4 IN THE STORE: three distinct files, each holding its
    // own bytes, none of them executable.
    let store = varve_core::Store::at(&fx.root);
    let installed = store
        .list()
        .unwrap()
        .into_iter()
        .find(|l| l.layer.to_string() == "2026.07.0")
        .expect("the layer is installed");
    for (name, version, bytes) in payloads {
        let path = installed.root.join("payloads").join(name).join(version);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "{name}@{version} must be stored under its own path with its own bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o111,
                0,
                "clause 2: a .vsix is an archive, not a program — {name}@{version} \
                 was laid down mode {mode:o}"
            );
        }
        // …and it is NOT dispatchable: nothing landed in bin/ under its name.
        assert!(
            !installed.root.join("bin").join(name).exists(),
            "an extension must never occupy a dispatch path"
        );
    }
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["which", "rust-lang.rust-analyzer"])
        .assert()
        .failure();

    // Clause 3: export for `code`.
    let out = parent.join("extensions");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-vsix", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("3 verified VS Code extension(s)")
                .and(predicate::str::contains("code --install-extension")),
        );

    for (name, version, bytes) in payloads {
        // The marketplace's own asset name: `code` dispatches on the .vsix
        // suffix, and a human tells two versions apart by this name alone.
        let file = out.join(format!("{name}-{version}.vsix"));
        assert_eq!(
            std::fs::read(&file).unwrap(),
            bytes,
            "{} must hold ITS OWN verified bytes",
            file.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o111,
                0,
                "clause 2 must survive the export too: {} is mode {mode:o}",
                file.display()
            );
        }
    }

    // Clause 3's second half: the stamp, so `verify --export` catches drift.
    let stamp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join(".varve-export.json")).unwrap()).unwrap();
    assert_eq!(stamp["kind"], "vsix");
    assert_eq!(stamp["layer"], "2026.07.0");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["verify", "--export"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("fresh"));

    // And it goes STALE when the pin moves — the whole reason for the stamp.
    std::fs::write(
        out.join(".varve-export.json"),
        r#"{"layer":"2026.06.0","manifest_digest":"sha256:0000","kind":"vsix"}"#,
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["verify", "--export"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("STALE"));
}

// rivet: verifies REQ-VSIX-001
#[test]
fn export_vsix_refuses_a_layer_with_no_extensions_rather_than_writing_an_empty_directory() {
    // An export directory that exists and is empty is worse than an error: a
    // consumer installs from it, gets nothing, and believes the pin carries no
    // extensions. Every other adapter fails closed here; so does this one.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let bin = parent.join("synth-bin");
    std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
    let spec = parent.join("spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"0.45.0\"\npath = \"{}\"\n",
            bin.display()
        ),
    )
    .unwrap();
    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    let out = parent.join("extensions");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-vsix", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("carries no `vsix` entries"));
    assert!(
        !out.join(".varve-export.json").exists(),
        "a refused export must not be stamped as one"
    );
}

// rivet: verifies REQ-PRODUCE-002, REQ-REPRO-001
#[test]
fn a_relative_out_is_resolved_not_embedded_verbatim() {
    // CORRECTED IN v0.27.0 (REQ-REPRO-001 clause 1). This test used to demand
    // an ABSOLUTE path in the generated config. The bug it was written for was
    // real — an independent review made absolute_export_dir return its argument
    // verbatim and the whole suite stayed GREEN, because every other export
    // test passes an absolute --out — but "absolute" was the wrong fix for it.
    // An absolute path makes the export unreproducible (varve#72: the same
    // layer exported twice differs) and breaks the moment the export is moved.
    //
    // Settled EMPIRICALLY against a real Cargo before changing anything (the
    // `cargo_offline` oracle now pins it): Cargo resolves a relative
    // `local-registry` against the directory that HOLDS `.cargo/`, never
    // against the invoking cwd. So a bare subdirectory name is correct, stays
    // correct when the export is copied, and is identical between two runs.
    //
    // What the original bug actually was — a relative --out embedded VERBATIM,
    // and so resolved against whatever cwd the build later ran in — is still
    // pinned here: the emitted string must not be the user's `./cargo-out`.
    // This test passes a RELATIVE --out, as a user does.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let crate_bytes = dot_crate("demo-crate", "0.1.0", "");
    let crate_path = parent.join("demo-crate-0.1.0.crate");
    std::fs::write(&crate_path, &crate_bytes).unwrap();
    let spec = parent.join("spec.toml");
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
    let layout = parent.join("layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "k", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    // The user's own working directory, and a RELATIVE --out inside it.
    let workdir = parent.join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();
    varve(&fx)
        .current_dir(&workdir)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args([
            "export-cargo",
            "--layer",
            "2026.07.0",
            "--out",
            "./cargo-out",
        ])
        .assert()
        .success();

    let out = workdir.join("cargo-out");
    let config = std::fs::read_to_string(out.join(".cargo/config.toml")).unwrap();
    let registry_line = config
        .lines()
        .find(|l| l.contains("local-registry"))
        .unwrap_or_else(|| panic!("no local-registry in:\n{config}"));
    let path = registry_line
        .split('"')
        .nth(1)
        .unwrap_or_else(|| panic!("unquoted path: {registry_line}"));

    // NOT the user's argument, verbatim or prefixed — that was the real bug.
    assert!(
        path != "./cargo-out" && !path.starts_with("./") && !path.contains("/./"),
        "the user's --out must not be embedded verbatim: {registry_line}"
    );
    // A bare relative subdirectory: nothing machine-specific, so two exports of
    // one layer are byte-identical (REQ-REPRO-001 clause 1).
    assert!(
        !std::path::Path::new(path).is_absolute() && !path.contains('/'),
        "the config must carry a bare relative subdirectory: {registry_line}"
    );
    // …and it must NAME something, resolved the way Cargo resolves it: against
    // the directory holding `.cargo/`, which is the export root.
    assert!(
        out.join(path).join("index").is_dir(),
        "the config names {path}, which must be the registry inside {}",
        out.display()
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

    // status ingests the envelope, caches it, and reports for the pin. Exit 3
    // since v0.28.0 — the pinned layer is yanked, and the verdict IS the exit
    // code (REQ-CIGATE-001 clause 1, BREAKING). The report is unchanged, so
    // every assertion below it is the same as before.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&env_path)
        .assert()
        .code(3)
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
        .code(3)
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

    // Code 3: the document ingests fine and the layer it describes is yanked —
    // which is the ANSWER, not a failure (REQ-CIGATE-001).
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&newer)
        .assert()
        .code(3);
    // A stale document is a genuine refusal, and stays code 1 — the two must
    // not collapse into one code, or a pipeline cannot tell "your toolchain is
    // yanked" from "your evidence is bad".
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&older)
        .assert()
        .code(1)
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

// rivet: verifies REQ-VERIFYALL-001
#[cfg(unix)]
#[test]
fn verify_all_covers_every_realm_not_only_the_pinned_one() {
    // varve#84, the auditor's scenario reproduced. `verify --all --help` says
    // "Verify every installed layer instead of only the pinned one"; it walked
    // only the PINNED project's realm partition. A security auditor planted a
    // backdoored binary in a SECOND realm's installed layer, ran `verify
    // --all`, got exit 0, and then executed the backdoor.
    //
    // `docs recovery` sends readers here as THE store-wide integrity check, so
    // the docs, the help text and the operator all agree and only the code
    // dissents. Realm separation is preserved in WHICH KEY verifies WHAT, not
    // in what gets looked at.
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();

    let mut realms_toml = String::new();
    let mut archives = std::collections::BTreeMap::new();
    for org in ["pulseengine", "acme"] {
        let (sk, pk) = varve_core::generate_root_keypair();
        let tool = format!("#!/bin/sh\necho universe={org}\n");
        let digest = varve_core::manifest_digest(tool.as_bytes());
        let host = varve_core::host_platform();
        let payload = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"2026.08.0","eu.pulseengine.varve.line":"2026.08","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"5","org.opencontainers.image.created":"2026-08-07T00:00:00Z"}},"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{digest}","size":0,"annotations":{{"eu.pulseengine.tool":"probe","eu.pulseengine.platform":"{host}"}}}}]}}"#
        );
        let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "k").unwrap();
        let archive = parent.join(format!("va-archive-{org}"));
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

    for org in ["pulseengine", "acme"] {
        let proj = parent.join(format!("va-proj-{org}"));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"{org}\"\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n"
            ),
        )
        .unwrap();
        let mut cmd = Command::cargo_bin("varve").unwrap();
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.env("VARVE_ROOT", &fx.root)
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&proj)
            .args(["install", "--from"])
            .arg(&archives[org])
            .assert()
            .success();
    }

    // Both realms clean: --all passes and SAYS what it covered, so a future
    // scoping regression is visible in the output rather than silent.
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("VARVE_ROOT", &fx.root)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(parent.join("va-proj-pulseengine"))
        .args(["verify", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 of 2"));

    // Now plant the backdoor in the realm the pin does NOT name.
    let store = varve_core::Store::at(&fx.root);
    let acme = varve_core::resolve_realm(&parent.join("va-proj-acme"), "acme").unwrap();
    let acme_store = varve_core::Store::at(acme.effective_root(&fx.root));
    let planted = acme_store
        .list()
        .unwrap()
        .into_iter()
        .next()
        .expect("acme layer installed");
    let probe = acme_store
        .tool_path(&planted, "probe")
        .expect("probe is dispatchable");
    std::fs::write(&probe, b"#!/bin/sh\necho PWNED\n").unwrap();
    let _ = store; // the top-level partition is empty here; both layers are realm-scoped

    // The whole finding: this used to exit 0 while pinned to `pulseengine`.
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("VARVE_ROOT", &fx.root)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(parent.join("va-proj-pulseengine"))
        .args(["verify", "--all"])
        .assert()
        .failure()
        // Names the layer AND where it lives — "which one" is the first
        // question an operator asks.
        .stderr(
            predicate::str::contains("2026.08.0").and(predicate::str::contains(acme.fingerprint())),
        );
}

// rivet: verifies REQ-VERIFYALL-001
#[cfg(unix)]
#[test]
fn verify_all_reports_every_failure_and_refuses_to_skip_an_undefined_realm() {
    // Clauses 2 and 5, which the headline test does not reach.
    //
    // Clause 2: it was FAIL-FAST. With two damaged layers an operator saw one,
    // fixed it, re-ran, and met the next — and in one observed run the only
    // layer id on screen belonged to a different, HEALTHY layer.
    //
    // Clause 5: a partition whose realm varve-realms.toml no longer defines
    // cannot be checked by anything. Skipping it silently is the worst of the
    // three options: an unverifiable layer sitting in the store is precisely
    // what a store-wide check exists to surface.
    let fx = fixture(None, &[]);
    let parent = fx.project.parent().unwrap();

    let mut realms_toml = String::new();
    let mut archives = std::collections::BTreeMap::new();
    for org in ["alpha", "beta"] {
        let (sk, pk) = varve_core::generate_root_keypair();
        let tool = format!("#!/bin/sh\necho {org}\n");
        let digest = varve_core::manifest_digest(tool.as_bytes());
        let host = varve_core::host_platform();
        let payload = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"2026.08.0","eu.pulseengine.varve.line":"2026.08","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"5","org.opencontainers.image.created":"2026-08-07T00:00:00Z"}},"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{digest}","size":0,"annotations":{{"eu.pulseengine.tool":"probe","eu.pulseengine.platform":"{host}"}}}}]}}"#
        );
        let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "k").unwrap();
        let archive = parent.join(format!("ev-archive-{org}"));
        varve_core::DirSource::at(&archive)
            .put(envelope.as_bytes(), &[(digest.as_str(), tool.as_bytes())])
            .unwrap();
        archives.insert(org.to_string(), archive);
        realms_toml.push_str(&format!(
            "[realm.{org}]\nregistry = \"oci://example.invalid/{org}\"\ntrust-root = \"{}\"\n\n",
            hex::encode(&pk)
        ));
    }
    let realms_path = parent.join("varve-realms.toml");
    std::fs::write(&realms_path, &realms_toml).unwrap();

    for org in ["alpha", "beta"] {
        let proj = parent.join(format!("ev-proj-{org}"));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"{org}\"\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n"
            ),
        )
        .unwrap();
        let mut cmd = Command::cargo_bin("varve").unwrap();
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.env("VARVE_ROOT", &fx.root)
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&proj)
            .args(["install", "--from"])
            .arg(&archives[org])
            .assert()
            .success();
    }

    // Clause 2: damage BOTH layers, and require BOTH to be named in one run.
    for org in ["alpha", "beta"] {
        let realm = varve_core::resolve_realm(&parent.join(format!("ev-proj-{org}")), org).unwrap();
        let st = varve_core::Store::at(realm.effective_root(&fx.root));
        let layer = st.list().unwrap().into_iter().next().unwrap();
        let probe = st.tool_path(&layer, "probe").unwrap();
        std::fs::write(&probe, format!("#!/bin/sh\necho tampered-{org}\n")).unwrap();
    }
    let alpha_fp = varve_core::resolve_realm(&parent.join("ev-proj-alpha"), "alpha")
        .unwrap()
        .fingerprint();
    let beta_fp = varve_core::resolve_realm(&parent.join("ev-proj-beta"), "beta")
        .unwrap()
        .fingerprint();
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin");
    let out = cmd
        .env("VARVE_ROOT", &fx.root)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(parent.join("ev-proj-alpha"))
        .args(["verify", "--all"])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        err.contains(&alpha_fp) && err.contains(&beta_fp),
        "both damaged layers must be named in ONE run, not one per re-run:\n{err}"
    );
    assert!(
        err.contains("2 of 2"),
        "the count must say how many failed of how many exist:\n{err}"
    );

    // Clause 5: drop `beta` from the realms file. Its partition is still on
    // disk and nothing can vouch for it any more.
    let alpha_only = realms_toml
        .split("[realm.beta]")
        .next()
        .unwrap()
        .to_string();
    std::fs::write(&realms_path, alpha_only).unwrap();
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin");
    let out = cmd
        .env("VARVE_ROOT", &fx.root)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(parent.join("ev-proj-alpha"))
        .args(["verify", "--all"])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        err.contains(&beta_fp) && err.contains("does not define"),
        "an undefined realm's partition must be REPORTED, not skipped:\n{err}"
    );
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
        cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
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
    cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
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
    cmd.env("PATH", "/usr/bin:/bin"); // hermetic — see the note on `varve()`
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

// ──────────────── REQ-INDEXAUTH-001 through the shipped binary ────────────
//
// These drive the real `varve` executable, and that is the point. The whole
// requirement was implemented in varve-core, fully unit-tested, and reached
// nobody: the CLI's only `InstallPolicy` hardcoded `index: None`, so every
// clause was skipped at runtime while the suite stayed green. A test that
// constructs an `InstallPolicy` itself cannot detect that the product never
// constructs one — only a test that runs the binary can.

/// A project pinning its own realm, plus a deposited layout of one layer.
/// Returns (fixture, project dir, signing key, layout dir, payload digest).
fn realm_project(
    signed_index: bool,
) -> (
    Fixture,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
) {
    let fx = fixture(None, &[]);
    let dir = fx.project.clone();
    let key = dir.join("root.key");
    let pubf = dir.join("root.pub");
    varve(&fx)
        .args(["keygen", "--out"])
        .arg(&key)
        .arg("--pub")
        .arg(&pubf)
        .assert()
        .success();
    let root = std::fs::read_to_string(&pubf).unwrap().trim().to_string();

    let tool = dir.join("acme-tool");
    std::fs::write(&tool, b"#!/bin/sh\necho acme\n").unwrap();
    let layout = dir.join("layout");
    varve(&fx)
        .args([
            "deposit",
            "--layer",
            "2026.08.0",
            "--channel",
            "qualified",
            "--counter",
            "3",
            "--issued-at",
            "2026-08-01T00:00:00Z",
            "--key",
        ])
        .arg(&key)
        .arg("--out")
        .arg(&layout)
        .arg("--tool")
        .arg(format!("acme-tool@1.0.0={}", tool.display()))
        .assert()
        .success();

    std::fs::write(
        dir.join("varve-realms.toml"),
        format!(
            "[realm.acme]\nregistry = \"oci://example.invalid/acme\"\n\
             trust-root = \"{root}\"\nsigned-index = {signed_index}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\nlayer = \"2026.08.0\"\n",
    )
    .unwrap();

    // The digest the deposited layer will install under — the entry in the
    // layout index that is not the signature.
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.join("index.json")).unwrap()).unwrap();
    let payload_digest = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e.get("artifactType").is_none())
        .and_then(|e| e["digest"].as_str())
        .expect("the layout names the layer manifest")
        .to_string();

    (fx, dir, key, layout, payload_digest)
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn the_binary_verifies_the_realms_index_and_reports_what_the_line_holds() {
    // Clauses 1, 4 and 5 end to end through the executable. The realm declares
    // `signed-index = true`; the source carries a signed index naming both the
    // pinned layer and a NEWER one it does not serve. The install must succeed
    // — the pin stays installable, which is the correction this release made —
    // and must SAY what the realm asserts, so the consumer learns about the
    // layer the source withheld instead of inferring it from silence.
    let (fx, dir, key, layout, payload_digest) = realm_project(true);

    let index_json = dir.join("index-2026.08.json");
    std::fs::write(
        &index_json,
        format!(
            r#"{{
  "line": "2026.08",
  "counter": 2,
  "issued-at": "2026-08-19T00:00:00Z",
  "layers": [
    {{ "layer": "2026.08.0", "digest": "{payload_digest}", "channel": "qualified", "counter": 3 }},
    {{ "layer": "2026.08.7", "digest": "sha256:notserved", "channel": "qualified", "counter": 9 }}
  ]
}}"#
        ),
    )
    .unwrap();
    let envelope = dir.join("index.dsse.json");
    varve(&fx)
        .args(["sign-index", "--file"])
        .arg(&index_json)
        .arg("--key")
        .arg(&key)
        .arg("--out")
        .arg(&envelope)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed line-index #2"));
    varve(&fx)
        .args(["attach-index", "--layout"])
        .arg(&layout)
        .arg("--index")
        .arg(&envelope)
        .assert()
        .success();

    varve(&fx)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "installed layer 2026.08.0 (counter 3)",
        ))
        // Clause 4: REPORTED, naming the realm, the line, and both counters.
        .stdout(predicate::str::contains("realm 'acme'"))
        .stdout(predicate::str::contains("line 2026.08"))
        .stdout(predicate::str::contains("greatest counter 9"))
        .stdout(predicate::str::contains("accepted counter 3"));

    // …and the deliberately-pinned older layer really is installed and usable.
    // An earlier draft of clause 4 raised the ENFORCEMENT mark to 9 here and
    // this install failed with "rollback refused" — a frozen toolchain broken
    // by somebody else publishing.
    varve(&fx).arg("verify").assert().success();
    varve(&fx)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("2026.08.0"));
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn the_binary_refuses_a_declaring_realm_whose_index_is_absent() {
    // Clause 5, the direction that makes the control a control. The realm says
    // it publishes an index; the source carries none. If this passed, an
    // attacker would disable the whole requirement by deleting one file — and
    // it DID pass, silently, for as long as the CLI hardcoded `index: None`.
    let (fx, _dir, _key, layout, _digest) = realm_project(true);
    varve(&fx)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .failure()
        .stderr(predicate::str::contains("acme"))
        .stderr(predicate::str::contains("will not fall back"));
    // Nothing was laid down on the strength of an unauthenticated listing.
    varve(&fx)
        .arg("list")
        .assert()
        .stdout(predicate::str::contains("2026.08.0").not());
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn a_realm_that_never_promised_an_index_installs_exactly_as_before() {
    // The other half of clause 5, and the reason the default is `false`:
    // failing closed by default would break every realm in existence at once.
    // The same layout, the same absent index, and no realm declaration.
    let (fx, _dir, _key, layout, _digest) = realm_project(false);
    varve(&fx)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success()
        .stdout(predicate::str::contains("installed layer 2026.08.0"))
        .stdout(predicate::str::contains("signed index").not());
    varve(&fx).arg("verify").assert().success();
}

// rivet: verifies REQ-OFFLINE-001
#[test]
fn archive_of_a_multi_platform_layer_says_what_it_carries_and_refuses_elsewhere() {
    // varve#80, at the boundary an operator actually touches. A tool name
    // repeats across triples while `install` lays down only the host's, so
    // `archive` used to write ONE host binary under every platform's digest and
    // exit 0 calling it the artifact of record. What matters here is that the
    // command SAYS which platform it carried and how much it left behind — an
    // operator carrying media to a mixed site must learn that before they
    // travel — and that a consumer on another platform is told so plainly.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("mp-root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("mp-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    for (file, bytes) in [("kilnd-a", b"kilnd-for-a"), ("kilnd-b", b"kilnd-for-b")] {
        std::fs::write(parent.join(file), bytes).unwrap();
    }
    let spec = parent.join("mp-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"kilnd\"\nversion = \"1.0.0\"\n\
             platform = \"platform-a\"\npath = \"{a}\"\n\n\
             [[tool]]\nname = \"kilnd\"\nversion = \"1.0.0\"\n\
             platform = \"platform-b\"\npath = \"{b}\"\n",
            a = parent.join("kilnd-a").display(),
            b = parent.join("kilnd-b").display(),
        ),
    )
    .unwrap();
    let layout = parent.join("mp-layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "k", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .args(["--platform", "platform-a"])
        .assert()
        .success();

    // The archive names the platform it carries AND the entries it omits.
    let air_gapped = parent.join("mp-archive");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["archive", "2026.07.0"])
        .arg(&air_gapped)
        .args(["--platform", "platform-a"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("1 payload for platform-a")
                .and(predicate::str::contains("1 entry omitted"))
                .and(predicate::str::contains("platform-b (1)")),
        );

    // Every blob holds the bytes its digest names — CONTENT, not a count.
    for e in std::fs::read_dir(air_gapped.join("blobs/sha256")).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().to_string();
        let bytes = std::fs::read(e.path()).unwrap();
        assert_eq!(
            varve_core::manifest_digest(&bytes),
            format!("sha256:{name}"),
            "blob {name} does not hold the bytes it is named for"
        );
    }

    // And the platform-b consumer is told what this archive is, not accused of
    // tampering — before varve#80 this was `does not match its signed digest`.
    varve(&fx)
        .env("VARVE_ROOT", parent.join("mp-far-root"))
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&air_gapped)
        .args(["--platform", "platform-b"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("carries no payload for platform-b")
                .and(predicate::str::contains("archived for platform-a")),
        );
}

/// Every file under `dir`, keyed by its path RELATIVE to `dir`. The comparison
/// unit for REQ-REPRO-001 clause 3: two exports of one layer to two
/// destinations must agree on this map exactly, including the export stamp.
fn tree(dir: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(
                    p.strip_prefix(dir).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
    }
    out
}

// rivet: verifies REQ-REPRO-001
#[test]
fn every_export_adapter_is_byte_identical_between_two_runs() {
    // Clause 3, made permanent. varve#72 was found by exporting one layer twice
    // and diffing; the only difference was `.cargo/config.toml`, which embedded
    // an ABSOLUTE path. A new adapter is exactly where a stray timestamp or an
    // unordered map iteration will next appear, so every adapter is checked —
    // not the one that happened to be broken.
    //
    // The destinations differ in NAME as well as location, so an adapter that
    // leaked its `--out` anywhere into its output fails here.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // One layer carrying every payload shape the adapters consume: a tool with
    // source provenance (export-bazel), two crates at two versions of one name
    // (export-cargo / -crates-vendor / -bazel-distdir), and two `.vsix`.
    let host = varve_core::host_platform();
    let tool_path = parent.join("rivet-bin");
    std::fs::write(&tool_path, b"rivet-binary-bytes").unwrap();
    let mut spec = format!(
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
    );
    for (name, version, extra) in [
        ("serde", "1.0.200", ""),
        ("serde", "1.0.210", "[features]\nderive = []\n"),
        ("cfg-if", "1.0.0", "[dependencies]\nserde = \"1.0\"\n"),
    ] {
        let p = parent.join(format!("{name}-{version}.crate"));
        std::fs::write(&p, dot_crate(name, version, extra)).unwrap();
        spec.push_str(&format!(
            "\n[[tool]]\nname = \"{name}\"\nversion = \"{version}\"\nkind = \"crate\"\npath = \"{}\"\n",
            p.display()
        ));
    }
    for (name, version) in [
        ("rust-lang.rust-analyzer", "0.3.2260"),
        ("vadimcn.vscode-lldb", "1.11.4"),
    ] {
        let p = parent.join(format!("{name}-{version}.vsix"));
        std::fs::write(&p, format!("{name}-{version}-zip").as_bytes()).unwrap();
        spec.push_str(&format!(
            "\n[[tool]]\nname = \"{name}\"\nversion = \"{version}\"\nkind = \"vsix\"\npath = \"{}\"\n",
            p.display()
        ));
    }
    let spec_path = parent.join("repro-spec.toml");
    std::fs::write(&spec_path, &spec).unwrap();
    let layout = parent.join("repro-layout");
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec_path)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&sk_path)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();

    for adapter in [
        "export-cargo",
        "export-crates-vendor",
        "export-bazel-distdir",
        "export-vsix",
        "export-bazel",
    ] {
        let first = parent.join(format!("{adapter}-alpha"));
        let second = parent.join(format!("{adapter}-a-much-longer-beta-name"));
        for out in [&first, &second] {
            varve(&fx)
                .env("VARVE_TRUST_ROOT", &trust_root)
                .args([adapter, "--layer", "2026.07.0", "--out"])
                .arg(out)
                .assert()
                .success();
        }
        let (a, b) = (tree(&first), tree(&second));
        assert_eq!(
            a.keys().collect::<Vec<_>>(),
            b.keys().collect::<Vec<_>>(),
            "{adapter} wrote a different set of files the second time"
        );
        for (path, bytes) in &a {
            assert_eq!(
                bytes,
                &b[path],
                "{adapter} is not reproducible: {} differs between two runs:\n--- first ---\n{}\n\
                 --- second ---\n{}",
                path.display(),
                String::from_utf8_lossy(bytes),
                String::from_utf8_lossy(&b[path]),
            );
        }
        assert!(
            !a.is_empty(),
            "{adapter} wrote nothing — a vacuous comparison"
        );
    }
}

/// Move the pin to `layer` and install that layer from `archive`. `install`
/// resolves the PIN, so a composition is installed one layer at a time — which
/// is what an extender does when they adopt an upstream realm's layer and then
/// pin their own on top.
fn install_pinned(
    fx: &Fixture,
    trust_root: &std::path::Path,
    layer: &str,
    archive: &std::path::Path,
) {
    std::fs::write(
        fx.project.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
        ),
    )
    .unwrap();
    varve(fx)
        .env("VARVE_TRUST_ROOT", trust_root)
        .args(["install", "--from"])
        .arg(archive)
        .assert()
        .success();
}

/// A SIGNED layer holding `crate`-kind payloads, optionally composing other
/// layers by digest. Returns (archive directory, this layer's manifest digest).
///
/// `includes` is a slice, not an `Option`: a layer composing TWO others is the
/// shape that produces a diamond, and a helper that could only express one
/// include is why no test covered the diamond at the CLI boundary.
fn signed_crate_layer(
    fx: &Fixture,
    tag: &str,
    layer: &str,
    sk: &[u8],
    crates: &[(&str, &str, Vec<u8>)],
    includes: &[&str],
) -> (std::path::PathBuf, String) {
    let payloads: Vec<Payload> = crates
        .iter()
        .map(|(name, version, bytes)| Payload {
            kind: "crate",
            name,
            version,
            platform: None,
            bytes: bytes.clone(),
        })
        .collect();
    signed_payload_layer(fx, tag, layer, sk, &payloads, includes)
}

/// One entry for `signed_payload_layer`. A struct rather than a five-tuple
/// because the two optional fields (kind, platform) are exactly the ones a
/// positional tuple gets wrong.
struct Payload<'a> {
    /// The wire string written into the SIGNED kind annotation — a literal, so
    /// a test can deposit a kind this varve does not know and assert what
    /// happens, which `PayloadKind` would not let it express.
    kind: &'a str,
    name: &'a str,
    version: &'a str,
    /// `None` leaves the entry unstamped, which means any-platform.
    platform: Option<&'a str>,
    bytes: Vec<u8>,
}

/// A SIGNED layer holding payloads of ANY kind, optionally composing other
/// layers by digest. The generalisation of `signed_crate_layer`, which is now a
/// thin wrapper: REQ-INSPECT-001 is about the kinds that are NOT crates, and a
/// fixture that can only express one kind cannot reach them.
fn signed_payload_layer(
    fx: &Fixture,
    tag: &str,
    layer: &str,
    sk: &[u8],
    payloads: &[Payload],
    includes: &[&str],
) -> (std::path::PathBuf, String) {
    let mut entries: Vec<String> = Vec::new();
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    for p in payloads {
        let d = varve_core::manifest_digest(&p.bytes);
        let platform = p
            .platform
            .map(|t| format!(r#","eu.pulseengine.platform":"{t}""#))
            .unwrap_or_default();
        entries.push(format!(
            r#"{{"mediaType":"application/octet-stream","digest":"{d}","size":{size},"annotations":{{"eu.pulseengine.varve.kind":"{kind}","eu.pulseengine.tool":"{name}","eu.pulseengine.tool.version":"{version}"{platform}}}}}"#,
            size = p.bytes.len(),
            kind = p.kind,
            name = p.name,
            version = p.version,
        ));
        blobs.push((d, p.bytes.clone()));
    }
    for d in includes {
        // `digest` or `digest@realm`. An include that names a realm is
        // verified against THAT realm's root, not the includer's — the branch
        // that made composition worth having, and which no test could reach
        // while every fixture emitted realm-less includes.
        let (digest, realm) = match d.split_once('@') {
            Some((dg, r)) => (dg, Some(r)),
            None => (*d, None),
        };
        let realm_ann = realm
            .map(|r| format!(r#","eu.pulseengine.varve.include.realm":"{r}""#))
            .unwrap_or_default();
        entries.push(format!(
            r#"{{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"{digest}","size":0,"annotations":{{"eu.pulseengine.varve.kind":"layer"{realm_ann}}}}}"#
        ));
    }
    let line = &layer[..layer.rfind('.').unwrap()];
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.line":"{line}","eu.pulseengine.varve.channel":"qualified","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-07-31T09:14:00Z"}},"manifests":[{}]}}"#,
        entries.join(",")
    );
    let digest = varve_core::manifest_digest(payload.as_bytes());
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), sk, "test-root").unwrap();
    let archive = fx.project.parent().unwrap().join(format!("archive-{tag}"));
    let refs: Vec<(&str, &[u8])> = blobs
        .iter()
        .map(|(d, b)| (d.as_str(), b.as_slice()))
        .collect();
    varve_core::DirSource::at(&archive)
        .put(envelope.as_bytes(), &refs)
        .unwrap();
    (archive, digest)
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn an_export_follows_the_composition() {
    // varve#79, reproduced at the boundary the user touches. An upstream layer
    // with a crate; a second layer `[[include]]`-ing it; before v0.27.0
    // `export-cargo` showed only the second layer's crate, with NO error — and
    // the build then failed with a missing-crate message pointing nowhere near
    // the cause. This is the topology varve is FOR.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("compose-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // Upstream: `cfg-if 1.0.0` and `serde 1.0.200`.
    let (up_archive, up_digest) = signed_crate_layer(
        &fx,
        "compose-up",
        "2026.08.0",
        &sk,
        &[
            ("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", "")),
            ("serde", "1.0.200", dot_crate("serde", "1.0.200", "")),
        ],
        &[],
    );
    // The pinned layer: its own crate, plus `serde` at a DIFFERENT version —
    // legal, and both must export (clause 2).
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "compose-root",
        "2026.07.0",
        &sk,
        &[
            (
                "rivet-core",
                "0.32.0",
                dot_crate("rivet-core", "0.32.0", ""),
            ),
            ("serde", "1.0.210", dot_crate("serde", "1.0.210", "")),
        ],
        &[&up_digest],
    );
    // `install` follows the pin, so the extender installs the upstream layer
    // under its own pin and then moves the pin to their own — the sequence a
    // consumer of two realms actually performs.
    install_pinned(&fx, &trust_root, "2026.08.0", &up_archive);
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    let out = parent.join("composed-cargo");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--out"])
        .arg(&out)
        .assert()
        .success()
        // Clause 3: it SAYS it followed the composition, rather than producing
        // a quietly incomplete directory.
        .stdout(
            predicate::str::contains("following the composition")
                .and(predicate::str::contains("2026.08.0"))
                .and(predicate::str::contains("4 verified crate")),
        );

    // Every crate of BOTH layers is present — including two versions of one
    // name across the composition boundary.
    for (name, version) in [
        ("cfg-if", "1.0.0"),
        ("serde", "1.0.200"),
        ("serde", "1.0.210"),
        ("rivet-core", "0.32.0"),
    ] {
        assert!(
            out.join(format!("registry/{name}-{version}.crate"))
                .is_file(),
            "{name} {version} missing from the composed export"
        );
    }
    let idx = std::fs::read_to_string(out.join("registry/se/rd/serde"))
        .or_else(|_| std::fs::read_to_string(out.join("registry/index/se/rd/serde")))
        .unwrap();
    assert_eq!(
        idx.lines().filter(|l| !l.trim().is_empty()).count(),
        2,
        "the index must offer BOTH versions of serde: {idx}"
    );

    // …and the vendored adapter follows it too — one adapter fixed is not the
    // requirement.
    let vendor_out = parent.join("composed-vendor");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-crates-vendor", "--out"])
        .arg(&vendor_out)
        .assert()
        .success()
        .stdout(predicate::str::contains("4 verified crate"));
    assert!(vendor_out.join("vendor/cfg-if-1.0.0/Cargo.toml").is_file());
    assert!(
        vendor_out
            .join("vendor/rivet-core-0.32.0/Cargo.toml")
            .is_file()
    );
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn an_export_verifies_a_composed_layer_against_its_own_realms_root() {
    // Clause 1b, which was dead code under test. Every composition-export
    // fixture emitted includes with NO `include.realm`, so `inc.realm` was
    // `None` in all of them and the cross-realm branch never ran. A clean-room
    // review confirmed it twice: swapping in the INCLUDER's verifier (trust
    // widening across realms) and deleting the branch outright both left the
    // whole suite green.
    //
    // Here the included layer is signed by a DIFFERENT key than the root
    // layer. Verifying it against the includer's root cannot succeed, so a
    // passing export is only possible if the realm's own root was used.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (up_sk, up_pk) = varve_core::generate_root_keypair();
    let (root_sk, root_pk) = varve_core::generate_root_keypair();
    assert_ne!(up_pk, root_pk, "the two realms must not share a root");

    // `upstream` is a realm of its own, with its own trust root.
    std::fs::write(
        parent.join("varve-realms.toml"),
        format!(
            "[realm.upstream]\nregistry = \"oci://example.invalid/upstream\"\ntrust-root = \"{}\"\n",
            hex::encode(&up_pk)
        ),
    )
    .unwrap();

    let (up_archive, up_digest) = signed_crate_layer(
        &fx,
        "xrealm-up",
        "2026.08.0",
        &up_sk,
        &[("serde", "1.0.200", dot_crate("serde", "1.0.200", ""))],
        &[],
    );
    // The include NAMES the realm, so the upstream root is the authority.
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "xrealm-root",
        "2026.07.0",
        &root_sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&format!("{up_digest}@upstream")],
    );

    let up_root = parent.join("xrealm-up.pub");
    std::fs::write(&up_root, hex::encode(&up_pk)).unwrap();
    let our_root = parent.join("xrealm-root.pub");
    std::fs::write(&our_root, hex::encode(&root_pk)).unwrap();
    install_pinned(&fx, &up_root, "2026.08.0", &up_archive);
    install_pinned(&fx, &our_root, "2026.07.0", &root_archive);

    let out = parent.join("xrealm-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &our_root)
        .args(["export-cargo", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("following the composition"));
    // The composed realm's crate is present, so its layer really was verified
    // and followed rather than skipped.
    assert!(
        out.join("registry/serde-1.0.200.crate").is_file(),
        "the upstream realm's crate is missing from the composed export"
    );
}

// rivet: verifies REQ-NOSILENT-001
#[test]
fn archive_says_out_loud_that_it_carries_no_baseline_advisory() {
    // varve#88 clause 1. `archive` was verbose about omitted PLATFORM payloads
    // and SILENT about a missing baseline line-status — the inconsistency that
    // hid it. The result is an air-gap artifact whose `varve status` is
    // permanently broken for every consumer of it, and no yank can ever reach
    // them.
    //
    // It warns rather than refusing, deliberately: `archive` is most often run
    // by the CONSUMER exporting their own core, who cannot retroactively add a
    // baseline the producer never published. Refusing was the first cut and it
    // broke four legitimate flows.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("nb-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    let (archive_src, _) = signed_crate_layer(
        &fx,
        "nobaseline",
        "2026.07.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    install_pinned(&fx, &trust_root, "2026.07.0", &archive_src);

    let dest = parent.join("nb-archive");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["archive", "2026.07.0"])
        .arg(&dest)
        .assert()
        .success()
        .stderr(
            predicate::str::contains("no baseline line-status")
                .and(predicate::str::contains("varve status")),
        );

    // …and --allow-no-status silences it, for an archive not meant to receive
    // advisories. Silence must be something you ASK for.
    let dest2 = parent.join("nb-archive-2");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["archive", "2026.07.0"])
        .arg(&dest2)
        .arg("--allow-no-status")
        .assert()
        .success()
        .stderr(predicate::str::contains("no baseline line-status").not());
}

// rivet: verifies REQ-NOSILENT-001
#[test]
fn install_checks_the_whole_composition_and_says_so_before_claiming_success() {
    // varve#88 clauses 3 and 4, which are one defect seen from two sides.
    //
    // Clause 4: the include check at install was DIRECT-ONLY. A chain
    // root -> mid -> leaf with `leaf` missing passed, because root's own
    // includes (just `mid`) were all present. `verify` walks the whole graph
    // and rejects it at depth 2 — so install and verify disagreed, while
    // `docs verify` promises "the CI gate and the install agree".
    //
    // Clause 3: the success line printed BEFORE the check ran, so even when
    // the check did fire the operator saw "installed layer X" and then an
    // error, leaving a layer in `varve list` that no other command would
    // touch.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("chain-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let (leaf_archive, leaf_digest) = signed_crate_layer(
        &fx,
        "chain-leaf",
        "2026.08.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    let (mid_archive, mid_digest) = signed_crate_layer(
        &fx,
        "chain-mid",
        "2026.08.1",
        &sk,
        &[("serde", "1.0.200", dot_crate("serde", "1.0.200", ""))],
        &[&leaf_digest],
    );
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "chain-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&mid_digest],
    );
    install_pinned(&fx, &trust_root, "2026.08.0", &leaf_archive);
    install_pinned(&fx, &trust_root, "2026.08.1", &mid_archive);

    // Remove the LEAF, leaving mid installed. root's direct includes are still
    // satisfied; the graph is not.
    let store = varve_core::Store::at(&fx.root);
    let leaf = store
        .find_anywhere(&leaf_digest)
        .unwrap()
        .map(|(_, e)| e)
        .expect("leaf was installed");
    std::fs::remove_dir_all(&leaf.root).unwrap();

    // `install_pinned` left the pin at the mid layer; point it at the root.
    std::fs::write(
        fx.project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
    )
    .unwrap();
    let out = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&root_archive)
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    // Clause 4: the missing layer is two hops away and must still be named.
    assert!(
        stderr.contains("2026.08.0") || stderr.contains(&leaf_digest),
        "the transitively-missing layer must be named:\nstdout={stdout}\nstderr={stderr}"
    );
    // Clause 3: it must NOT have claimed success first.
    assert!(
        !stdout.contains("installed layer"),
        "install must refuse BEFORE claiming success, not after:\nstdout={stdout}"
    );
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn verify_lockfile_follows_the_composition_not_just_the_root() {
    // REQ-COMPOSEEXPORT-001 clause 1's extension: a lockfile checked against
    // only the ROOT layer silently asserts nothing about the crates the
    // INCLUDED layers pin — varve#79 wearing a different hat.
    //
    // This clause shipped in v0.27.0 with no test naming it. A clean-room
    // review replaced the composition walk with a root-only vec and the ENTIRE
    // workspace suite stayed green; the stub was then swept into a commit by an
    // unrelated `git add -A` and pushed, still green. A clause no test can
    // distinguish from its own absence is indistinguishable from unimplemented.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("lockcompose-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // The crate that will disagree lives ONLY in the included layer.
    let (up_archive, up_digest) = signed_crate_layer(
        &fx,
        "lockcompose-up",
        "2026.08.0",
        &sk,
        &[("serde", "1.0.200", dot_crate("serde", "1.0.200", ""))],
        &[],
    );
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "lockcompose-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&up_digest],
    );
    install_pinned(&fx, &trust_root, "2026.08.0", &up_archive);
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    // The project resolves a DIFFERENT serde than the composed layer pins.
    // Root-only checking cannot see this: the root layer has no serde at all.
    let lock = fx.project.join("Cargo.lock");
    std::fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.99\"\nchecksum = \"aaaa\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("1.0.200")
                .and(predicate::str::contains("1.0.99"))
                .and(predicate::str::contains("disagree")),
        );

    // …and agreement with the COMPOSED layer's crate passes.
    std::fs::write(
        &lock,
        "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["verify", "--lockfile"])
        .arg(&lock)
        .assert()
        .success();
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn verify_walks_a_diamond_once_instead_of_calling_it_a_cycle() {
    // A diamond — two layers sharing a base — is the most ordinary composition
    // there is, and both `docs composition` and `docs layers` promise it is
    // "walked once and is perfectly legal". `compose::walk` was fixed for this
    // in v0.23.0; `verify_composition_inner` is an INDEPENDENT reimplementation
    // in the CLI that kept the bug, so `varve verify` exited 1 on a store that
    // `install`, `run`, `which` and every export handled correctly. Found by a
    // persona audit driving the real binary — no unit test could see it,
    // because the broken walker lives in the binary crate and the correct one
    // in the library.
    //
    // Shape: root composes MID and BASE; MID also composes BASE.
    //   root ─┬─> mid ──> base
    //         └─────────> base
    // BASE is reachable by two paths and is on NEITHER path twice.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("diamond-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let (base_archive, base_digest) = signed_crate_layer(
        &fx,
        "diamond-base",
        "2026.08.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    let (mid_archive, mid_digest) = signed_crate_layer(
        &fx,
        "diamond-mid",
        "2026.08.1",
        &sk,
        &[("serde", "1.0.200", dot_crate("serde", "1.0.200", ""))],
        &[&base_digest],
    );
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "diamond-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&mid_digest, &base_digest],
    );

    // `install` follows the pin, so each layer is installed under its own pin
    // before the pin moves to the root — the sequence a real consumer performs.
    install_pinned(&fx, &trust_root, "2026.08.0", &base_archive);
    install_pinned(&fx, &trust_root, "2026.08.1", &mid_archive);
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    // The whole finding: this exited 1 with "composition cycle while verifying".
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("composes"));
}

// rivet: verifies REQ-COMPOSE-001
#[test]
fn verify_does_not_mistake_a_wide_composition_for_a_deep_one() {
    // The second defect of the same wrong data structure, and the reason the
    // fix is a path rather than a bigger set. `verify` guarded depth with
    // `path.len() > MAX_DEPTH` on an insert-only set, so the counter measured
    // every layer VISITED, not how deep the walk had gone. A root composing
    // MAX_DEPTH+2 sibling layers is one level deep and was refused as "more
    // than 8 layers deep".
    //
    // A cycle, by contrast, is deliberately NOT tested at this boundary: an
    // include is content-addressed, so a layer including itself would need its
    // own digest to depend on its own content, and a hand-edited layer.json is
    // refused earlier by the tamper check ("the core entry was modified after
    // install"). The cycle guard is retained as defence in depth against a
    // future non-content-addressed include, not because a test can reach it.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("wide-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let width = varve_core::compose::MAX_DEPTH + 2;
    let mut archives = Vec::new();
    let mut digests = Vec::new();
    for i in 0..width {
        let (archive, digest) = signed_crate_layer(
            &fx,
            &format!("wide-{i}"),
            // Distinct layer ids so each installs under its own pin.
            &format!("2026.08.{i}"),
            &sk,
            &[(
                "cfg-if",
                &format!("1.0.{i}"),
                dot_crate("cfg-if", &format!("1.0.{i}"), ""),
            )],
            &[],
        );
        archives.push((format!("2026.08.{i}"), archive));
        digests.push(digest);
    }
    let refs: Vec<&str> = digests.iter().map(|d| d.as_str()).collect();
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "wide-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &refs,
    );

    for (layer, archive) in &archives {
        install_pinned(&fx, &trust_root, layer, archive);
    }
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .arg("verify")
        .assert()
        .success();
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn an_export_refuses_a_composed_layer_it_cannot_vouch_for() {
    // Clause 1: each included layer is verified against ITS OWN realm's root,
    // and an export is not a way around that. Trust must not widen because a
    // layer was reached through an include rather than through the pin.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("badcompose-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    // An UNSIGNED upstream layer, laid straight into the store.
    let store = varve_core::Store::at(&fx.root);
    let up_manifest = manifest_with_includes("2026.08.0", &[], &[]);
    let up_digest = store.lay_down(up_manifest.as_bytes(), &[]).unwrap();

    let (root_archive, _) = signed_crate_layer(
        &fx,
        "badcompose-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&up_digest],
    );
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["install", "--from"])
        .arg(&root_archive)
        .assert()
        .success();

    let out = parent.join("badcompose-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("2026.08.0"));
    assert!(
        !out.join("registry").exists(),
        "a refused export must not leave a directory that looks complete"
    );
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn an_export_refuses_two_layers_that_disagree_about_one_crate() {
    // Clause 2's error case at the CLI. The same crate name at DIFFERENT
    // versions is legal and both export (proven above); the same name AND
    // version with DIFFERENT digests is two realms disagreeing about what those
    // bytes are, and varve does not pick a winner.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("clash-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let (up_archive, up_digest) = signed_crate_layer(
        &fx,
        "clash-up",
        "2026.08.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    // Same name, same version, DIFFERENT bytes.
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "clash-root",
        "2026.07.0",
        &sk,
        &[(
            "cfg-if",
            "1.0.0",
            dot_crate("cfg-if", "1.0.0", "[features]\nstd = []\n"),
        )],
        &[&up_digest],
    );
    install_pinned(&fx, &trust_root, "2026.08.0", &up_archive);
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--out"])
        .arg(parent.join("clash-out"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("cfg-if")
                .and(predicate::str::contains("1.0.0"))
                .and(predicate::str::contains("DIFFERENT bytes")),
        );
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn an_export_that_cannot_follow_the_composition_says_so() {
    // Clause 3. `install` refuses a composition whose include is missing, and
    // `resolve` refuses to dispatch one — but an export named with `--layer`
    // takes neither path, so a layer removed from the store AFTER install left
    // the export adapters free to write a directory that is quietly missing an
    // entire layer's crates. That is exactly varve#79's failure mode: no error,
    // and a build that fails later pointing nowhere near the cause.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust_root = parent.join("gone-root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();

    let (up_archive, up_digest) = signed_crate_layer(
        &fx,
        "gone-up",
        "2026.08.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    let (root_archive, _) = signed_crate_layer(
        &fx,
        "gone-root",
        "2026.07.0",
        &sk,
        &[(
            "rivet-core",
            "0.32.0",
            dot_crate("rivet-core", "0.32.0", ""),
        )],
        &[&up_digest],
    );
    install_pinned(&fx, &trust_root, "2026.08.0", &up_archive);
    install_pinned(&fx, &trust_root, "2026.07.0", &root_archive);

    // The composed layer disappears from the core after installation.
    let store = varve_core::Store::at(&fx.root);
    let up = store
        .list()
        .unwrap()
        .into_iter()
        .find(|l| l.layer.to_string() == "2026.08.0")
        .expect("the upstream layer is installed");
    std::fs::remove_dir_all(&up.root).unwrap();

    let out = parent.join("gone-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust_root)
        .args(["export-cargo", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .failure()
        // …naming what is missing and how to fix it, not exiting 0 with one
        // layer's crates.
        .stderr(
            predicate::str::contains("not installed")
                .and(predicate::str::contains("varve install"))
                .and(predicate::str::contains("silently omit")),
        );
    assert!(
        !out.join("registry").exists(),
        "an export that could not follow the composition must not leave a registry"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The library surface the SDK workstream left unwired: `export-sdk`, declared
// exports, the shadowing declaration, and `varve env`. Every test below drives
// the BINARY. A test that builds the policy itself cannot detect that the
// product never builds one — which is exactly how REQ-INDEXAUTH-001 shipped a
// `must` clause that no code path could reach.
// ───────────────────────────────────────────────────────────────────────────

/// The prefix an SDK must have been BUILT for so that `dest` fits inside its
/// relocation budget.
///
/// Not a constant: relocation can only ever SHORTEN a path (the interpreter
/// field is fixed-size), and a temporary directory is long. A hard-coded prefix
/// would make these tests pass or fail on the length of `$TMPDIR`, which is the
/// machine-dependent suite the hermetic PATH exists to prevent.
fn built_prefix_for(dest: &std::path::Path) -> String {
    let need = dest.to_str().expect("a utf-8 temp path").len();
    let mut s = String::from("/opt/poky/4.0.15/sysroots/x86_64-pokysdk-linux");
    while s.len() < need {
        s.push('p');
    }
    s
}

/// A synthetic Yocto SDK as the gzip tar a producer signs: a NUL-padded binary
/// field (the `relocate_sdk.py` half), a text `environment-setup-*` (the
/// `sed -i` half), an absolute symlink, and a `bin/synth` that will shadow the
/// pinned tool once the tree is on PATH.
fn sdk_tarball(built: &str) -> Vec<u8> {
    use std::io::Write;
    // A NUL-padded path field, the way an ELF PT_INTERP segment holds one.
    let field = |s: &str| {
        let mut v = s.as_bytes().to_vec();
        v.resize(s.len() + 8, 0);
        v
    };
    let mut binary = b"\x7fELF".to_vec();
    binary.extend_from_slice(&field(&format!(
        "{built}/sysroots/x86_64/lib/ld-linux.so.2"
    )));
    binary.extend_from_slice(b"\0\0trailer\0");
    // A REAL environment script: after relocation its PATH line points at the
    // export, which is what makes `eval "$(varve env)"` testable end to end.
    let env_setup = format!(
        "export SDKTARGETSYSROOT=\"{built}/sysroots/cortexa53\"\n\
         export PATH=\"{built}/bin:$PATH\"\n\
         export CC=\"aarch64-poky-linux-gcc --sysroot={built}/sysroots/cortexa53\"\n"
    );
    let synth = "#!/bin/sh\necho SDK-SYNTH\n";

    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        b.append_data(&mut dir, "sysroots/", std::io::empty())
            .unwrap();
        for (path, mode, bytes) in [
            (
                "sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc",
                0o755u32,
                binary.as_slice(),
            ),
            (
                "environment-setup-cortexa53-poky-linux",
                0o644,
                env_setup.as_bytes(),
            ),
            ("bin/synth", 0o755, synth.as_bytes()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(mode);
            b.append_data(&mut h, path, bytes).unwrap();
        }
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        // `append_link`, not `set_link_name`: a real SDK's build prefix is
        // routinely past the 100-byte header field, and tar's GNU LongLink
        // record is how that is carried. A fixture that could only express a
        // short target would test a case the requirement is not about.
        b.append_link(
            &mut link,
            "bin/synth-latest",
            std::path::Path::new(&format!("{built}/bin/synth")),
        )
        .unwrap();
        b.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

/// A signed root plus its key files, the two lines every one of these tests
/// starts with.
struct Root {
    key: std::path::PathBuf,
    trust_root: std::path::PathBuf,
}

fn root_at(parent: &std::path::Path) -> Root {
    let (sk, pk) = varve_core::generate_root_keypair();
    let key = parent.join("root.key");
    std::fs::write(&key, hex::encode(&sk)).unwrap();
    let trust_root = parent.join("root.pub");
    std::fs::write(&trust_root, hex::encode(&pk)).unwrap();
    Root { key, trust_root }
}

/// Deposit `spec_text` and install it — every test here needs a real, signed,
/// installed layer, because `export_target` verifies before it exports.
fn deposit_and_install(fx: &Fixture, root: &Root, spec_text: &str, tag: &str) {
    let parent = fx.project.parent().unwrap();
    let spec = parent.join(format!("{tag}-spec.toml"));
    std::fs::write(&spec, spec_text).unwrap();
    let layout = parent.join(format!("{tag}-layout"));
    varve(fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&root.key)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .assert()
        .success();
    varve(fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
}

// rivet: verifies REQ-SDK-001
#[cfg(unix)]
#[test]
fn export_sdk_lays_a_relocated_tree_down_through_the_cli() {
    // REQ-SDK-001 clause 3, at the boundary a user touches. The library could
    // relocate a tree since v0.27.0 and NOTHING could ask it to: there was no
    // subcommand, and no producer path for the signed prefix clause 4 requires.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);

    let out = parent.join("poky");
    std::fs::create_dir_all(&out).unwrap();
    let dest = out.canonicalize().unwrap();
    let built = built_prefix_for(&dest);
    let archive = parent.join("poky-sdk.tar.gz");
    let archive_bytes = sdk_tarball(&built);
    std::fs::write(&archive, &archive_bytes).unwrap();

    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"poky-cortexa53\"\nversion = \"4.0.15\"\nkind = \"sdk\"\n\
             sdk-prefix = \"{built}\"\npath = \"{}\"\n",
            archive.display()
        ),
        "sdk",
    );

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-sdk", "--layer", "2026.07.0", "--out"])
        .arg(&out)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("exported sdk poky-cortexa53@4.0.15")
                .and(predicate::str::contains("field(s) patched in place")),
        );

    // The tree is HERE, relocated: no occurrence of the build prefix survives,
    // and the destination is what the binaries now name.
    let gcc = dest.join("sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc");
    let gcc_bytes = std::fs::read(&gcc).unwrap();
    assert!(
        !String::from_utf8_lossy(&gcc_bytes).contains(&built),
        "the interpreter field still names the build prefix"
    );
    assert!(String::from_utf8_lossy(&gcc_bytes).contains(dest.to_str().unwrap()));
    assert_eq!(
        gcc_bytes.len(),
        archive_len_preserving_probe(&built),
        "a binary field is patched IN PLACE — the file length must not move"
    );
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&gcc).unwrap().permissions().mode() & 0o111,
            0o111,
            "a compiler must survive the export executable"
        );
    }
    let env_script = std::fs::read_to_string(dest.join("environment-setup-cortexa53-poky-linux"))
        .expect("the sourceable script is part of the tree");
    assert!(env_script.contains(dest.to_str().unwrap()));
    assert!(!env_script.contains(&built));
    assert_eq!(
        std::fs::read_link(dest.join("bin/synth-latest")).unwrap(),
        dest.join("bin/synth"),
        "an SDK-internal absolute symlink is re-pointed into the export"
    );

    // Clause 2: the store still holds EXACTLY the bytes the producer signed —
    // nothing on the relocation path writes back into it — so `verify` (which
    // re-hashes that one file) still passes.
    let store = varve_core::Store::at(&fx.root);
    let installed = store
        .list()
        .unwrap()
        .into_iter()
        .find(|l| l.layer.to_string() == "2026.07.0")
        .unwrap();
    let held = installed.root.join("payloads/poky-cortexa53/4.0.15");
    assert_eq!(
        std::fs::read(&held).unwrap(),
        archive_bytes,
        "the store must keep the signed archive, not the relocated tree"
    );
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .success();

    // The stamp says `sdk` EXACTLY — a declaration in varve.toml is compared
    // against this string, and any other spelling reports the declared export
    // as never produced.
    let stamp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dest.join(".varve-export.json")).unwrap()).unwrap();
    assert_eq!(stamp["kind"], "sdk");
    assert_eq!(stamp["layer"], "2026.07.0");
}

/// The synthetic binary's length, recomputed from the same rule the fixture
/// builds it with — asserting a NUMBER here would be asserting the fixture.
fn archive_len_preserving_probe(built: &str) -> usize {
    // b"\x7fELF" + field(interp) + b"\0\0trailer\0"
    4 + (format!("{built}/sysroots/x86_64/lib/ld-linux.so.2").len() + 8) + 10
}

/// The same fixture, plus ONE symlink that is absolute, sits under the build
/// prefix, and climbs out of the export with `..`.
fn sdk_tarball_with_escaping_link(built: &str) -> Vec<u8> {
    use std::io::Write;
    let inner = sdk_tarball(built);
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(inner.as_slice()));
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            let mut h = entry.header().clone();
            let path = entry.path().unwrap().into_owned();
            if let Some(link) = entry.link_name().unwrap() {
                b.append_link(&mut h, &path, &link).unwrap();
            } else {
                let mut bytes = Vec::new();
                {
                    use std::io::Read;
                    let mut e = entry;
                    e.read_to_end(&mut bytes).unwrap();
                }
                h.set_size(bytes.len() as u64);
                b.append_data(&mut h, &path, bytes.as_slice()).unwrap();
            }
        }
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        b.append_link(
            &mut link,
            "bin/escape-abs-dotdot",
            std::path::Path::new(&format!("{built}/../../../../../../../../tmp/varve-pwned")),
        )
        .unwrap();
        b.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

// rivet: verifies REQ-SDK-001
#[test]
fn export_sdk_refuses_an_absolute_symlink_that_climbs_out_of_the_export() {
    // Clause 5 at the boundary that found it. A clean-room review reproduced
    // this end to end through the RELEASE binary: a symlink that is absolute,
    // starts with the SDK's own build prefix, and then climbs out with `..`
    // was re-pointed into the export and reported as "1 symlink(s)
    // re-pointed" — exit 0. The branch that re-points an SDK's internal
    // absolute links stripped the prefix without walking the remainder, while
    // the relative branch beside it had always walked its target.
    //
    // The library test for this lives in sdkexport.rs. It is repeated here
    // because "the invariant was verified in the library while nothing could
    // reach it" is a defect this very release shipped once already.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);
    // Long enough that the clause-4 fit check (destination must be no longer
    // than the build prefix) passes and clause 5 is what actually decides.
    let built = "/opt/poky/3.1/sysroots/x86_64-pokysdk-linux/usr/share/long-enough-prefix/padding";
    let archive = parent.join("escaping-sdk.tar.gz");
    std::fs::write(&archive, sdk_tarball_with_escaping_link(built)).unwrap();
    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"poky\"\nversion = \"4.0\"\nkind = \"sdk\"\n\
             sdk-prefix = \"{built}\"\npath = \"{}\"\n",
            archive.display()
        ),
        "sdk",
    );
    let out = parent.join("escaping-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-sdk", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("escape-abs-dotdot"));
    assert!(
        !out.join(".varve-export.json").exists(),
        "a refused export must not be stamped as one"
    );
}

// rivet: verifies REQ-SDK-001
#[test]
fn export_sdk_refuses_a_destination_the_sdk_cannot_reach_before_writing_anything() {
    // Clause 4 through the CLI: the refusal is EARLY (the archive is never
    // even opened) and names the budget, because "it failed" after relocating
    // thousands of files is not an answer anyone can act on.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);
    let archive = parent.join("poky-sdk.tar.gz");
    std::fs::write(&archive, sdk_tarball("/opt/tiny")).unwrap();
    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"poky\"\nversion = \"4.0\"\nkind = \"sdk\"\n\
             sdk-prefix = \"/opt/tiny\"\npath = \"{}\"\n",
            archive.display()
        ),
        "sdk",
    );
    let out = parent.join("a-destination-far-longer-than-the-build-prefix");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-sdk", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("cannot relocate this sdk")
                .and(predicate::str::contains("/opt/tiny"))
                .and(predicate::str::contains("at most 9 characters")),
        );
    assert!(
        !out.join(".varve-export.json").exists(),
        "a refused export must not be stamped as one"
    );
    assert!(
        !out.join("bin").exists(),
        "the refusal must land before any byte of the tree"
    );
}

// rivet: verifies REQ-SDK-001
#[test]
fn an_sdk_without_the_signed_prefix_cannot_be_deposited_at_all() {
    // Clause 4's producing half. The budget is attributable or it is nothing:
    // an sdk with no signed prefix would install, verify, and be impossible to
    // export — discovered on the far side of an air gap, unfixable without a
    // re-deposit, because the annotation lives inside the signature.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);
    let archive = parent.join("poky-sdk.tar.gz");
    std::fs::write(&archive, sdk_tarball("/opt/poky")).unwrap();
    let spec = parent.join("no-prefix.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"poky\"\nversion = \"4.0\"\nkind = \"sdk\"\npath = \"{}\"\n",
            archive.display()
        ),
    )
    .unwrap();
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&root.key)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(parent.join("nope"))
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("declares no `sdk-prefix`")
                .and(predicate::str::contains("export-sdk")),
        );

    // …and the same field on a payload nobody relocates is refused rather than
    // signed, ignored, and believed.
    let bin = parent.join("synth-bin");
    std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
    let spec = parent.join("prefix-on-a-tool.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0\"\n\
             sdk-prefix = \"/opt/poky\"\npath = \"{}\"\n",
            bin.display()
        ),
    )
    .unwrap();
    varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&root.key)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(parent.join("nope2"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("only a tree payload"));
}

/// A pin that declares exports, written into the project.
fn write_pin(fx: &Fixture, exports: &str) {
    std::fs::write(
        fx.project.join("varve.toml"),
        format!("{PIN_JULY}{exports}"),
    )
    .unwrap();
}

// rivet: verifies REQ-EXPORTDECL-001
#[test]
fn verify_checks_every_declared_export_without_being_told_to() {
    // Clause 3, through the binary. The library could classify a declared
    // export since v0.27.0 and `varve verify` never called it: the set of
    // checked exports still lived in whichever `--export` flags someone
    // remembered to type, which is the "only checks what it is told about"
    // failure the requirement exists to close.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);
    let vsix = parent.join("ext.vsix");
    std::fs::write(&vsix, b"zip-bytes").unwrap();
    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"rust-lang.rust-analyzer\"\nversion = \"0.3.2300\"\n\
             kind = \"vsix\"\npath = \"{}\"\n",
            vsix.display()
        ),
        "decl",
    );

    // TWO declarations, neither generated. Both must be reported: a loop that
    // stops at the first fault checks one export and certifies the rest.
    write_pin(
        &fx,
        "\n[[export]]\nkind = \"vsix\"\nout = \"extensions\"\n\
         \n[[export]]\nkind = \"bazel-registry\"\nout = \"bazel/registries\"\n",
    );
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("2 declared export(s)")
                .and(predicate::str::contains("extensions"))
                .and(predicate::str::contains("bazel/registries"))
                .and(predicate::str::contains("MISSING"))
                // The command that FIXES it, spelled the way it really is:
                // `bazel-registry` is produced by `varve export-bazel`, so the
                // obvious format!("export-{kind}") would print a command that
                // does not exist in the one line whose job is to be run.
                .and(predicate::str::contains("varve export-bazel --out"))
                .and(predicate::str::contains("varve export-vsix --out")),
        );

    // Generate ONE of them: the other is still checked, so this is not a
    // "declared exports exist" check that any single directory satisfies.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-vsix", "--out", "extensions"])
        .assert()
        .success();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("1 declared export(s)")
                .and(predicate::str::contains("bazel/registries")),
        );

    // With only the generated one declared, verify passes — and SAYS it looked,
    // because a silent pass is indistinguishable from a check that was skipped.
    write_pin(&fx, "\n[[export]]\nkind = \"vsix\"\nout = \"extensions\"\n");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("declared export").and(predicate::str::contains("fresh")));

    // The pin moves and the export does not.
    let stamp = fx.project.join("extensions/.varve-export.json");
    std::fs::write(
        &stamp,
        r#"{"layer":"2026.06.0","manifest_digest":"sha256:0000","kind":"vsix"}"#,
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("STALE"));

    // A directory produced by a DIFFERENT adapter: freshness there says nothing
    // about the declared export, which was never produced at all.
    let current: serde_json::Value = {
        varve(&fx)
            .env("VARVE_TRUST_ROOT", &root.trust_root)
            .args(["export-vsix", "--out", "extensions"])
            .assert()
            .success();
        serde_json::from_slice(&std::fs::read(&stamp).unwrap()).unwrap()
    };
    std::fs::write(
        &stamp,
        serde_json::to_vec(&serde_json::json!({
            "layer": current["layer"],
            "manifest_digest": current["manifest_digest"],
            "kind": "cargo",
        }))
        .unwrap(),
    )
    .unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("DECLARED as a vsix export but stamped cargo")
                .and(predicate::str::contains("says nothing about it")),
        );

    // And a declared directory that is simply gone is a FAILURE, not a warning:
    // "I forgot to generate it" and "it is stale" are the same severity to
    // anyone relying on the export.
    std::fs::remove_dir_all(fx.project.join("extensions")).unwrap();
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("MISSING"));
}

// rivet: verifies REQ-EXPORTDECL-001, REQ-SHADOW-001
#[cfg(unix)]
#[test]
fn a_declared_sdk_environment_is_not_reported_as_a_hijack_by_verify() {
    // Clause 5 through the binary, in all three verdicts. Without the
    // declaration consulted here, a legitimately sourced SDK makes `verify`
    // cry wolf — and a check that fires on the setup the project deliberately
    // configured is the one people switch off, which is worse than not
    // checking at all.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);

    let out = fx.project.join("toolchains/poky");
    std::fs::create_dir_all(&out).unwrap();
    let dest = out.canonicalize().unwrap();
    let built = built_prefix_for(&dest);
    let archive = parent.join("poky-sdk.tar.gz");
    std::fs::write(&archive, sdk_tarball(&built)).unwrap();
    let synth_bin = parent.join("synth-bin");
    std::fs::write(&synth_bin, b"#!/bin/sh\necho PINNED\n").unwrap();

    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0.0\"\npath = \"{}\"\n\n\
             [[tool]]\nname = \"poky\"\nversion = \"4.0.15\"\nkind = \"sdk\"\n\
             sdk-prefix = \"{built}\"\npath = \"{}\"\n",
            synth_bin.display(),
            archive.display()
        ),
        "shadow",
    );

    const DECL: &str = "\n[[export]]\nkind = \"sdk\"\nout = \"toolchains/poky\"\n\
                        \n[export.env]\nscript = \"environment-setup-cortexa53-poky-linux\"\n";
    write_pin(&fx, &format!("{DECL}path = \"before-shims\"\n"));
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-sdk", "--out", "toolchains/poky"])
        .assert()
        .success();

    // The SDK's own `synth` is what PATH runs — exactly the condition
    // REQ-SHADOW-001 detects, and exactly what `before-shims` declared.
    let sdk_path = format!("{}:/usr/bin:/bin", dest.join("bin").display());
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .env("PATH", &sdk_path)
        .arg("verify")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("before-shims").and(predicate::str::contains("not a hijack")),
        );

    // The SAME PATH under an `after-shims` declaration is a real fault: the
    // project said varve's pinned tools win, and they do not.
    write_pin(&fx, &format!("{DECL}path = \"after-shims\"\n"));
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .env("PATH", &sdk_path)
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("varve.toml declares that export `after-shims`").and(
                predicate::str::contains("environment-setup-cortexa53-poky-linux"),
            ),
        );

    // …and a binary in no declared export at all is still the ordinary hijack,
    // with the ordinary fix — the declaration must not blunt the check it
    // exists to make usable.
    write_pin(&fx, &format!("{DECL}path = \"before-shims\"\n"));
    let elsewhere = parent.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let impostor = elsewhere.join("synth");
    std::fs::write(&impostor, "#!/bin/sh\necho WRONG\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .env("PATH", format!("{}:/usr/bin:/bin", elsewhere.display()))
        .arg("verify")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not what your PATH runs")
                .and(predicate::str::contains("varve shim install")),
        );
}

// rivet: verifies REQ-EXPORTDECL-001
#[cfg(unix)]
#[test]
fn env_enters_every_declared_environment_in_the_order_that_inverts_the_file() {
    // Clause 4 through the binary. `env_lines` computed the inverted order in
    // the library and `varve env` printed the shim fragment alone, so a project
    // that declared its SDK still had to source it by hand — in whichever order
    // it guessed.
    let fx = fixture(Some(PIN_JULY), &[]);
    // Two sourced exports, one on each side of the shims, so the assertion is
    // about ORDER and not merely about presence.
    write_pin(
        &fx,
        "\n[[export]]\nkind = \"sdk\"\nout = \"sdk-after\"\n\
         \n[export.env]\nscript = \"env-after.sh\"\npath = \"after-shims\"\n\
         \n[[export]]\nkind = \"sdk\"\nout = \"sdk-before\"\n\
         \n[export.env]\nscript = \"env-before.sh\"\npath = \"before-shims\"\n",
    );
    for (dir, marker) in [("sdk-after", "AFTER"), ("sdk-before", "BEFORE")] {
        let d = fx.project.join(dir);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::write(
            d.join(format!("env-{}.sh", marker.to_lowercase())),
            format!("export PATH=\"{}/bin:$PATH\"\n", d.display()),
        )
        .unwrap();
    }

    let out = varve(&fx).arg("env").output().unwrap();
    assert!(out.status.success());
    let script = String::from_utf8(out.stdout).unwrap();
    let at = |needle: &str| {
        script
            .find(needle)
            .unwrap_or_else(|| panic!("`varve env` never mentions {needle}:\n{script}"))
    };
    let shims = fx.root.join("shims");
    assert!(
        at("env-after.sh") < at(shims.to_str().unwrap()),
        "an `after-shims` export must be sourced FIRST, so the shims land ahead \
         of it on PATH:\n{script}"
    );
    assert!(
        at(shims.to_str().unwrap()) < at("env-before.sh"),
        "a `before-shims` export must be sourced LAST, so its own bin wins:\n{script}"
    );

    // …and the emitted script actually produces that PATH when a shell runs it,
    // which is the only claim that matters. Asserting the text alone would
    // verify the formatter.
    let probe = std::process::Command::new("sh")
        .arg("-c")
        .arg("eval \"$VARVE_ENV\"; printf '%s' \"$PATH\"")
        .env("VARVE_ENV", &script)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&fx.project)
        .output()
        .unwrap();
    let path = String::from_utf8_lossy(&probe.stdout);
    let entries: Vec<&str> = path.split(':').collect();
    let idx = |needle: &str| {
        entries
            .iter()
            .position(|e| e.contains(needle))
            .unwrap_or_else(|| panic!("{needle} is not on the resulting PATH: {path}"))
    };
    assert!(
        idx("sdk-before/bin") < idx("shims"),
        "sourcing PREPENDS, so `before-shims` must end up ahead of the shims: {path}"
    );
    assert!(
        idx("shims") < idx("sdk-after/bin"),
        "…and `after-shims` behind them: {path}"
    );

    // fish cannot source a producer's POSIX-sh environment script, so it fails
    // rather than handing back an environment missing what varve.toml declares.
    varve(&fx)
        .args(["env", "--shell", "fish"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("fish cannot source it"));

    // A pin that EXISTS and does not parse is an error, not a fallback: half an
    // environment, exit 0, is how a declared SDK goes missing without anyone
    // noticing. (Outside a project there is no pin at all, and the shims stay
    // the whole answer — `env_is_evaluable_and_idempotent` covers that.)
    std::fs::write(fx.project.join("varve.toml"), "manifest-version = 1\n").unwrap();
    varve(&fx)
        .arg("env")
        .assert()
        .failure()
        .stderr(predicate::str::contains("varve.toml"));
}

// rivet: verifies REQ-PIN-001
#[test]
fn a_schema_mistake_in_the_pin_is_reported_once_not_twice() {
    // varve#7 fixed this for the `Layer` variant and left its siblings alone:
    // every variant that both interpolates `{source}` into its Display AND
    // declares `#[source]` prints its cause twice, glued by a stray `: `. That
    // is eleven lines of output for a one-line problem, on the errors a
    // newcomer hits first — a missing field in varve.toml. Found by a persona
    // audit, which ranked it the highest friction-removed-per-line-changed
    // fix in the tool.
    let fx = fixture(Some(PIN_JULY), &[]);
    std::fs::write(fx.project.join("varve.toml"), "[toolchain]\n").unwrap();
    let out = varve(&fx).arg("which").arg("rivet").assert().failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert_eq!(
        stderr.matches("missing field").count(),
        1,
        "the parse error is printed once, not once per formatter layer:\n{stderr}"
    );
    // …and no orphaned separator left behind by the removed interpolation.
    assert!(
        !stderr.contains("\n: "),
        "stray `: ` gluing a doubled cause:\n{stderr}"
    );
}

// rivet: verifies REQ-SDK-001
#[test]
fn export_sdk_refuses_a_hostile_archive_member_at_the_cli_boundary() {
    // Clause 5 where it now actually runs. The tree's invariants were verified
    // in the library while nothing could reach them; a signed blob is
    // ATTRIBUTABLE, not benign, and this is the boundary a user types.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);

    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut h = tar::Header::new_gnu();
        let payload = b"PWNED";
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        // Written into the header DIRECTLY: `set_path` refuses `..` itself, and
        // an archive built by other software is under no obligation to have
        // used it. The refusal has to be varve's.
        {
            let gnu = h.as_gnu_mut().unwrap();
            let name = b"../../escaped";
            gnu.name[..name.len()].copy_from_slice(name);
        }
        h.set_cksum();
        b.append(&h, &payload[..]).unwrap();
        b.finish().unwrap();
    }
    let archive = parent.join("hostile.tar");
    std::fs::write(&archive, &tar_bytes).unwrap();
    deposit_and_install(
        &fx,
        &root,
        &format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"hostile\"\nversion = \"1.0\"\nkind = \"sdk\"\n\
             sdk-prefix = \"/opt/poky-with-a-prefix-long-enough-for-any-temporary-directory-so-the-fit-check-is-not-what-refuses-this\"\n\
             path = \"{}\"\n",
            archive.display()
        ),
        "hostile",
    );

    let out = parent.join("hostile-out");
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["export-sdk", "--out"])
        .arg(&out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a usable path"));
    assert!(
        !parent.join("escaped").exists() && !out.join("escaped").exists(),
        "a refused tree must leave nothing behind, inside the export or out of it"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// REQ-CIGATE-001 — varve as something a pipeline can gate on.
// REQ-INSPECT-001 — seeing what is in a layer.
// ─────────────────────────────────────────────────────────────────────────

/// A pinned, installed layer plus a signed line-status envelope that YANKS it.
/// Reuses `signed_layer_fixture`'s shape but signs BOTH the layer and the
/// status with one key, which is what makes `status` able to report at all.
fn yanked_project(fx: &Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let sk_path = parent.join("yank-root.key");
    std::fs::write(&sk_path, hex::encode(&sk)).unwrap();
    let trust = parent.join("yank-root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    let (archive, _) = signed_crate_layer(
        fx,
        "yanked",
        "2026.07.0",
        &sk,
        &[("cfg-if", "1.0.0", dot_crate("cfg-if", "1.0.0", ""))],
        &[],
    );
    install_pinned(fx, &trust, "2026.07.0", &archive);

    let doc = parent.join("yank-status.json");
    std::fs::write(&doc, status_doc_json("2026.07", 1)).unwrap();
    let envelope = parent.join("yank-status.dsse.json");
    varve(fx)
        .args(["sign-status", "--file"])
        .arg(&doc)
        .args(["--key"])
        .arg(&sk_path)
        .args(["--out"])
        .arg(&envelope)
        .assert()
        .success();
    (trust, envelope)
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn a_yanked_layer_fails_the_pipeline_instead_of_printing_and_succeeding() {
    // BREAKING, and deliberately so: `varve status` used to print YANKED and
    // exit 0, so the only way to gate a build on a yank was to grep stdout —
    // which two personas of a ten-persona audit independently failed to do.
    // The point of SIGNING a yank is to stop a build.
    let fx = fixture(Some(PIN_JULY), &[]);
    let (trust, envelope) = yanked_project(&fx);

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&envelope)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("YANKED").and(predicate::str::contains("CVE-2026-0001")));

    // …and from the cache, on the second ask, with no envelope to ingest: a
    // gate that only fires on the ingest run is not a gate.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .arg("status")
        .assert()
        .code(3)
        .stdout(predicate::str::contains("YANKED"));
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn docs_grep_fails_on_no_match_so_it_can_gate() {
    let fx = fixture(None, &[]);
    varve(&fx)
        .args(["docs", "--grep", "zzz-no-topic-says-this-zzz"])
        .assert()
        .code(4)
        .stdout(predicate::str::contains("no topic matches"));
    // …and still succeeds when there IS a match, or it gates on everything.
    varve(&fx)
        .args(["docs", "--grep", "trust root"])
        .assert()
        .success();
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn docs_grep_finds_a_topic_by_its_title() {
    // `--grep` searched BODIES only, so the one string a reader is most likely
    // to type — the title they saw in `varve docs` — matched nothing.
    //
    // The needle is the FULL title, em dash and all. A first version of this
    // test used "which binary runs here" and passed before a line of the fix
    // was written: that substring appears verbatim in the BODY of
    // getting-started, so the test never exercised title search at all. The
    // exhaustive, drift-proof form of this check lives in `docs.rs`
    // (`every_topic_title_is_greppable`); this one asserts it at the boundary.
    let fx = fixture(None, &[]);
    varve(&fx)
        .args(["docs", "--grep", "which — which binary runs here"])
        .assert()
        .success()
        // Attributed to the topic whose TITLE it is.
        .stdout(predicate::str::contains("which:"));
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn the_exit_code_contract_is_documented_and_greppable() {
    // `varve docs --grep "exit code"` returned NOTHING across all fifty topics:
    // a pipeline author had no contract to write against.
    let fx = fixture(None, &[]);
    varve(&fx)
        .args(["docs", "--grep", "exit code"])
        .assert()
        .success();
    varve(&fx)
        .args(["docs", "exit-codes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3"));
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn every_documented_exit_code_is_produced_by_a_real_invocation() {
    // Clause 3, and the part that makes it more than a table. The contract is
    // READ OUT OF THE BINARY (`varve exit-codes --json`), and every code in it
    // must then be produced by running varve for real. That is what "cannot
    // drift from the binary" has to mean: rendering a table from a constant
    // proves only that the table agrees with itself.
    //
    // Two ways this fails, both deliberate:
    //   * a code is added to the contract with no scenario → the `other` arm
    //     panics, so a documented code nothing produces cannot ship;
    //   * a code's number changes on either side → the assert_eq fires.
    let fx = fixture(Some(PIN_JULY), &[]);
    let contract: serde_json::Value = serde_json::from_slice(
        &varve(&fx)
            .args(["exit-codes", "--json"])
            .output()
            .unwrap()
            .stdout,
    )
    .expect("`varve exit-codes --json` emits JSON");
    let codes = contract["codes"].as_array().expect("`codes` is an array");
    assert!(
        codes.len() >= 5,
        "the contract must cover at least ok/error/usage/yanked/no-match"
    );

    // A separate project whose pinned layer is genuinely yanked by a signed,
    // verified line-status document — the real path, not a stubbed one.
    let yanked = fixture(Some(PIN_JULY), &[]);
    let (trust, envelope) = yanked_project(&yanked);

    fn code_of(cmd: &mut Command) -> i32 {
        cmd.output()
            .unwrap()
            .status
            .code()
            .expect("varve must exit, not be signalled")
    }

    for entry in codes {
        let documented = entry["code"].as_u64().unwrap();
        let name = entry["name"].as_str().unwrap();
        let observed = match name {
            // A command that simply works.
            "ok" => code_of(varve(&fx).args(["docs", "--list"])),
            // varve fails closed: the pinned layer is not installed.
            "error" => code_of(varve(&fx).args(["which", "synth"])),
            // clap's own code, for a command line that is not one.
            "usage" => code_of(varve(&fx).arg("--no-such-flag-exists")),
            // The verdict this whole requirement exists for.
            "yanked" => code_of(
                varve(&yanked)
                    .env("VARVE_TRUST_ROOT", &trust)
                    .args(["status", "--from-file"])
                    .arg(&envelope),
            ),
            // A search that ran and found nothing.
            "no-match" => {
                code_of(varve(&fx).args(["docs", "--grep", "zzz-no-topic-says-this-zzz"]))
            }
            other => panic!(
                "exit code {documented} (`{other}`) is in the contract and NO scenario here \
                 produces it. A documented code nothing exercises is exactly the drift this \
                 test exists to stop: add a real invocation that returns it."
            ),
        };
        assert_eq!(
            observed as u64, documented,
            "`{name}` is documented as exit code {documented}, but the binary returned {observed}"
        );
    }
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn deposit_reports_the_layer_digest_as_json_instead_of_prose() {
    // The motivating complaint, exactly: "a pipeline scrapes a layer digest out
    // of a prose sentence". `manifest_digest` is what a pin records, what an
    // `[[include]]` names and what an attestation binds to — and the only way
    // to obtain it was to cut an English sentence apart on spaces.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);
    let tool = parent.join("synth-bin");
    std::fs::write(&tool, "#!/bin/sh\n").unwrap();
    let spec = parent.join("json-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 7\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0.0\"\npath = \"{}\"\n",
            tool.display()
        ),
    )
    .unwrap();
    let layout = parent.join("json-layout");
    let out = varve(&fx)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
        .arg(&root.key)
        .args(["--key-id", "varve-root-1", "--out"])
        .arg(&layout)
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("`deposit --json` emits ONE JSON document");
    assert_eq!(v["command"], "deposit");
    assert_eq!(v["layer"], "2026.07.0");
    assert_eq!(v["channel"], "qualified");
    assert_eq!(v["counter"], 7);
    assert_eq!(v["entries"], 1);
    let digest = v["manifest_digest"]
        .as_str()
        .expect("manifest_digest")
        .to_string();
    assert!(digest.starts_with("sha256:"), "{digest}");

    // …and it is the REAL digest, not a plausible-looking string: the store
    // keys the installed layer by it.
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
    varve(&fx)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(digest));
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn every_ci_marked_command_emits_json_a_pipeline_can_parse() {
    // Clause 2 over the whole `(CI)` set, not one command of it. Each of these
    // printed a prose sentence and nothing else; the shapes below are the
    // compatibility promise, so they are asserted field by field rather than
    // "it parsed". The companion check that the SET is complete — that no
    // command tagged (CI) is missing `--json` — is `main.rs`'s
    // `every_ci_marked_subcommand_offers_json`, which enumerates clap itself.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let root = root_at(parent);

    fn json_of(cmd: &mut Command) -> serde_json::Value {
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "--json must emit ONE JSON document on stdout, got {e}:\n{}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    // ── sign-status ────────────────────────────────────────────────────
    let doc = parent.join("cij-status.json");
    std::fs::write(&doc, status_doc_json("2026.07", 4)).unwrap();
    let status_env = parent.join("cij-status.dsse.json");
    let v = json_of(
        varve(&fx)
            .args(["sign-status", "--file"])
            .arg(&doc)
            .args(["--key"])
            .arg(&root.key)
            .args(["--out"])
            .arg(&status_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "sign-status");
    assert_eq!(v["line"], "2026.07");
    assert_eq!(v["counter"], 4);
    assert_eq!(v["known_problems"], 1);

    // ── sign-index ─────────────────────────────────────────────────────
    let index_doc = parent.join("cij-index.json");
    std::fs::write(
        &index_doc,
        r#"{"line":"2026.07","counter":2,"issued-at":"2026-08-07T00:00:00Z","layers":[]}"#,
    )
    .unwrap();
    let index_env = parent.join("cij-index.dsse.json");
    let v = json_of(
        varve(&fx)
            .args(["sign-index", "--file"])
            .arg(&index_doc)
            .args(["--key"])
            .arg(&root.key)
            .args(["--out"])
            .arg(&index_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "sign-index");
    assert_eq!(v["line"], "2026.07");
    assert_eq!(v["counter"], 2);
    assert_eq!(v["layers"], 0);

    // ── sign-sums ──────────────────────────────────────────────────────
    let sums = parent.join("SHA256SUMS.txt");
    std::fs::write(&sums, "aa  varve-x86_64-unknown-linux-gnu.tar.gz\n").unwrap();
    let sums_env = parent.join("SHA256SUMS.txt.dsse.json");
    let v = json_of(
        varve(&fx)
            .args(["sign-sums", "--sums"])
            .arg(&sums)
            .args(["--key"])
            .arg(&root.key)
            .args(["--out"])
            .arg(&sums_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "sign-sums");
    assert!(v["sums_digest"].as_str().unwrap().starts_with("sha256:"));

    // ── deposit (into a layout the attach-* commands then use) ──────────
    let tool = parent.join("cij-tool");
    std::fs::write(&tool, "#!/bin/sh\n").unwrap();
    let spec = parent.join("cij-spec.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.07.0\"\nchannel = \"qualified\"\ncounter = 1\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"1.0.0\"\npath = \"{}\"\n",
            tool.display()
        ),
    )
    .unwrap();
    let layout = parent.join("cij-layout");
    let deposited = json_of(
        varve(&fx)
            .args(["deposit", "--spec"])
            .arg(&spec)
            .args(["--issued-at", "2026-07-01T00:00:00Z", "--key"])
            .arg(&root.key)
            .args(["--key-id", "varve-root-1", "--out"])
            .arg(&layout)
            .arg("--json"),
    );
    assert_eq!(deposited["command"], "deposit");

    // ── attach-status ──────────────────────────────────────────────────
    let v = json_of(
        varve(&fx)
            .args(["attach-status", "--layout"])
            .arg(&layout)
            .args(["--status"])
            .arg(&status_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "attach-status");
    assert_eq!(v["line"], "2026.07");
    assert_eq!(v["counter"], 4);

    // ── attach-index ───────────────────────────────────────────────────
    let v = json_of(
        varve(&fx)
            .args(["attach-index", "--layout"])
            .arg(&layout)
            .args(["--index"])
            .arg(&index_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "attach-index");
    assert_eq!(v["counter"], 2);

    // ── sign-attestation (needs the layer INSTALLED, per `docs ci`) ─────
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &root.trust_root)
        .args(["install", "--from"])
        .arg(&layout)
        .assert()
        .success();
    let att = parent.join("cij-sbom.json");
    std::fs::write(&att, r#"{"bomFormat":"CycloneDX"}"#).unwrap();
    let att_env = parent.join("cij-sbom.dsse.json");
    let v = json_of(
        varve(&fx)
            .env("VARVE_TRUST_ROOT", &root.trust_root)
            .args(["sign-attestation", "--kind", "sbom", "--file"])
            .arg(&att)
            .args(["--producer", "varve", "--key"])
            .arg(&root.key)
            .args(["--out"])
            .arg(&att_env)
            .arg("--json"),
    );
    assert_eq!(v["command"], "sign-attestation");
    assert_eq!(v["kind"], "sbom");
    assert_eq!(v["producer"], "varve");
    assert_eq!(v["layer"], "2026.07.0");
    // The two commands agree on the layer's identity, which is the whole point
    // of emitting it in a shape a pipeline can join on.
    assert_eq!(v["layer_manifest_digest"], deposited["manifest_digest"]);
    assert!(
        v["attestation_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(v["attached_to"].is_null(), "no --attach-to was passed");
}

// rivet: verifies REQ-CIGATE-001
#[test]
fn status_json_carries_the_verdict_that_the_exit_code_carries() {
    let fx = fixture(Some(PIN_JULY), &[]);
    let (trust, envelope) = yanked_project(&fx);
    let out = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["status", "--from-file"])
        .arg(&envelope)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["command"], "status");
    assert_eq!(v["layer"], "2026.07.0");
    assert_eq!(v["yanked"], true);
    assert_eq!(v["yanked_reason"], "CVE-2026-0001 in synth");
    assert_eq!(v["known_problems"], 1);
    // The document and the process must not be able to disagree.
    assert_eq!(v["exit_code"], 3);
}

/// A two-layer composition holding one payload of every shape REQ-INSPECT-001
/// cares about: a DISPATCHED tool, HELD payloads of two kinds, a payload
/// stamped for ANOTHER platform (present in the signed manifest, absent from
/// this store), and a second layer composed in. Returns the trust root.
fn inspectable_composition(fx: &Fixture) -> std::path::PathBuf {
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust = parent.join("inspect-root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();

    // Upstream: a crate and a WIT package — both HELD, neither dispatched.
    let (up_archive, up_digest) = signed_payload_layer(
        fx,
        "inspect-up",
        "2026.08.0",
        &sk,
        &[
            Payload {
                kind: "crate",
                name: "cfg-if",
                version: "1.0.0",
                platform: None,
                bytes: dot_crate("cfg-if", "1.0.0", ""),
            },
            Payload {
                kind: "wit",
                name: "wasi-interfaces",
                version: "0.2.0",
                platform: None,
                bytes: b"package wasi:cli@0.2.0;\n".to_vec(),
            },
        ],
        &[],
    );

    // The pinned layer: a dispatched tool, plus a `.vsix` built for a platform
    // that is NOT this machine — so `install` will not lay it down and
    // `inspect` must say so rather than pretend it is here or drop the row.
    let elsewhere = if varve_core::host_platform().contains("aarch64") {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-apple-darwin"
    };
    let (root_archive, _) = signed_payload_layer(
        fx,
        "inspect-root",
        "2026.07.0",
        &sk,
        &[
            Payload {
                kind: "tool",
                name: "synth",
                version: "1.4.0",
                platform: None,
                bytes: b"#!/bin/sh\necho synth\n".to_vec(),
            },
            Payload {
                kind: "vsix",
                name: "pulseengine.wit-tools",
                version: "0.9.1",
                platform: Some(elsewhere),
                bytes: b"PK\x03\x04not-for-this-machine".to_vec(),
            },
        ],
        &[&up_digest],
    );

    // Installed one at a time, following the pin — the sequence an extender
    // adopting an upstream realm's layer actually performs.
    install_pinned(fx, &trust, "2026.08.0", &up_archive);
    install_pinned(fx, &trust, "2026.07.0", &root_archive);
    trust
}

// rivet: verifies REQ-INSPECT-001
#[test]
fn inspect_reports_name_version_kind_and_platform_for_every_payload() {
    // Clauses 1 and 3. Before this, NOTHING reported a payload's name, version,
    // kind or platform: `list` prints layer ids and `sbom` collapses every
    // non-tool kind to a CycloneDX `library`. The build engineer in the audit
    // chose an export adapter by running all four and reading which errored.
    let fx = fixture(Some(PIN_JULY), &[]);
    let trust = inspectable_composition(&fx);

    let assert = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .arg("inspect")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // Every payload, with all four facts clause 1 names.
    for needle in [
        "synth",
        "1.4.0",
        "tool", // dispatched
        "cfg-if",
        "1.0.0",
        "crate", // held, from the composed layer
        "wasi-interfaces",
        "0.2.0",
        "wit", // held — the kind `which` called absent
        "pulseengine.wit-tools",
        "0.9.1",
        "vsix",
    ] {
        assert!(
            stdout.contains(needle),
            "`varve inspect` does not report `{needle}`:\n{stdout}"
        );
    }
    // Clause 3: the distinction, in the words the requirement uses.
    assert!(
        stdout.contains("DISPATCHED") && stdout.contains("HELD"),
        "inspect must distinguish dispatched payloads from held ones:\n{stdout}"
    );
    // The platform column is real, not decorative: an unstamped entry is
    // any-platform and a stamped one says which.
    assert!(stdout.contains("any"), "an unstamped entry is any-platform");
    assert!(
        stdout.contains("not laid down here"),
        "a payload stamped for another platform is in the signed manifest and NOT in this \
         store; saying nothing would be a quiet lie:\n{stdout}"
    );
}

// rivet: verifies REQ-INSPECT-001
#[test]
fn inspect_json_is_the_shape_a_pipeline_was_promised() {
    // Clauses 2 and 4. `sbom` is composition-blind and that is a known
    // limitation — this must not repeat it, so the composed layer's payloads
    // and the composition block are both asserted here.
    let fx = fixture(Some(PIN_JULY), &[]);
    let trust = inspectable_composition(&fx);

    let out = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["inspect", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("`inspect --json` emits ONE JSON document");

    assert_eq!(v["command"], "inspect");
    assert_eq!(v["layer"], "2026.07.0");
    assert_eq!(v["channel"], "qualified");
    assert!(
        v["manifest_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "the pinned layer's manifest digest is what a pin and an [[include]] name"
    );

    // ── clause 4: the composition ──────────────────────────────────────
    let comp = v["composition"].as_array().unwrap();
    assert_eq!(comp.len(), 2, "both layers of the composition: {comp:#?}");
    let root: Vec<&serde_json::Value> = comp.iter().filter(|c| c["root"] == true).collect();
    assert_eq!(root.len(), 1, "exactly one layer is the pinned root");
    assert_eq!(root[0]["layer"], "2026.07.0");
    assert!(
        comp.iter()
            .any(|c| c["layer"] == "2026.08.0" && c["root"] == false),
        "the COMPOSED layer must appear — its payloads are part of what the pin delivers, \
         and `varve sbom` being blind to that is the limitation this must not repeat"
    );

    // ── clauses 1-3: the payloads ──────────────────────────────────────
    let payloads = v["payloads"].as_array().unwrap();
    assert_eq!(payloads.len(), 4, "{payloads:#?}");
    let find = |name: &str| {
        payloads
            .iter()
            .find(|p| p["name"] == name)
            .unwrap_or_else(|| panic!("`{name}` missing from the report: {payloads:#?}"))
    };

    let synth = find("synth");
    assert_eq!(synth["kind"], "tool");
    assert_eq!(synth["version"], "1.4.0");
    assert_eq!(synth["platform"], "any");
    assert_eq!(synth["dispatch"], "dispatched");
    assert_eq!(synth["present"], true);
    assert_eq!(synth["layer"], "2026.07.0");

    // The payload `varve which` used to call "not part of layer".
    let wit = find("wasi-interfaces");
    assert_eq!(wit["kind"], "wit");
    assert_eq!(wit["version"], "0.2.0");
    assert_eq!(wit["dispatch"], "held");
    // …and it came from the COMPOSED layer, attributed to it.
    assert_eq!(wit["layer"], "2026.08.0");

    let crate_row = find("cfg-if");
    assert_eq!(crate_row["kind"], "crate");
    assert_eq!(crate_row["dispatch"], "held");
    assert_eq!(crate_row["layer"], "2026.08.0");

    // The other platform's entry: signed, reported, and honestly not here.
    let vsix = find("pulseengine.wit-tools");
    assert_eq!(vsix["kind"], "vsix");
    assert_eq!(vsix["dispatch"], "held");
    assert_eq!(vsix["present"], false);
    assert_ne!(
        vsix["platform"], "any",
        "a stamped entry must report the triple it was built for"
    );
    assert_ne!(vsix["platform"], v["host_platform"]);

    // Every payload carries its signed digest, which is what makes the report
    // joinable against a manifest, an SBOM or an attestation.
    for p in payloads {
        assert!(
            p["digest"].as_str().unwrap().starts_with("sha256:"),
            "{p:#?}"
        );
        assert_eq!(p["known_kind"], true);
    }

    let summary = &v["summary"];
    assert_eq!(summary["payloads"], 4);
    assert_eq!(summary["dispatched"], 1);
    assert_eq!(summary["held"], 3);
    assert_eq!(summary["layers"], 2);
}

// rivet: verifies REQ-INSPECT-001
#[test]
fn which_names_a_held_payload_instead_of_claiming_the_layer_lacks_it() {
    // Clause 3, at the surface that was FALSE: `varve which` on a held `wit`
    // payload said "is not part of layer", and the layer holds it. A reader
    // acting on that message re-deposits something that is already there.
    let fx = fixture(Some(PIN_JULY), &[]);
    let trust = inspectable_composition(&fx);

    let assert = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["which", "wasi-interfaces"])
        .assert()
        // Still an error — it is not a dispatched tool, and `which` must not
        // print a path for something varve will never exec.
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("is not part of layer"),
        "the refuted claim must not come back — the layer HOLDS it:\n{stderr}"
    );
    for needle in ["HELD", "wit", "0.2.0", "varve inspect"] {
        assert!(
            stderr.contains(needle),
            "the message must say `{needle}`:\n{stderr}"
        );
    }

    // A name that is genuinely absent still gets the generic refusal — the two
    // answers must not collapse into one.
    let assert = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["which", "no-such-thing"])
        .assert()
        .code(1);
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("is not part of layer"), "{stderr}");
    assert!(!stderr.contains("HELD"), "{stderr}");
}

// rivet: verifies REQ-INSPECT-001
#[test]
fn inspect_reports_a_payload_kind_this_varve_does_not_know() {
    // A layer deposited by a NEWER varve installs and verifies normally: the
    // signed-digest check is kind-independent by design (DD-003). So `inspect`
    // meets kinds it cannot classify, and the choice is report-it-verbatim or
    // lose it. `sbom` labels such an entry rather than dropping it; so does
    // this — a command whose whole job is "what is in here" must not answer by
    // omission.
    let fx = fixture(Some(PIN_JULY), &[]);
    let parent = fx.project.parent().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let trust = parent.join("future-root.pub");
    std::fs::write(&trust, hex::encode(&pk)).unwrap();
    let (archive, _) = signed_payload_layer(
        &fx,
        "future",
        "2026.07.0",
        &sk,
        &[Payload {
            kind: "quantum-blob",
            name: "spooky",
            version: "2.0.0",
            platform: None,
            bytes: b"|0>+|1>".to_vec(),
        }],
        &[],
    );
    install_pinned(&fx, &trust, "2026.07.0", &archive);

    let out = varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["inspect", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "an unknown kind must not make `inspect` fail — the bytes still verify: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let p = &v["payloads"].as_array().unwrap()[0];
    assert_eq!(p["name"], "spooky");
    // Verbatim, as signed — not guessed into a kind this varve happens to know.
    assert_eq!(p["kind"], "quantum-blob");
    assert_eq!(p["known_kind"], false);
    assert_eq!(
        p["dispatch"], "unknown",
        "whether an unknown kind dispatches is not knowable, and claiming `held` would be a \
         guess dressed as a fact"
    );
}

// rivet: verifies REQ-INSPECT-001
#[test]
fn inspect_refuses_a_layer_it_cannot_verify_rather_than_describing_it() {
    // Clause 5 says no network; it does not say no trust. A contents report for
    // a layer nobody vouched for is worse than none, because it looks
    // authoritative — the same reasoning `sbom` fails closed on.
    let fx = fixture(Some(PIN_JULY), &[]);
    let trust = inspectable_composition(&fx);
    let parent = fx.project.parent().unwrap();
    let (_, wrong_pk) = varve_core::generate_root_keypair();
    let wrong = parent.join("wrong-root.pub");
    std::fs::write(&wrong, hex::encode(&wrong_pk)).unwrap();

    varve(&fx)
        .env("VARVE_TRUST_ROOT", &wrong)
        .arg("inspect")
        .assert()
        .code(1);

    // …and it works with no source, no registry and nothing to fetch from:
    // the fixture's realm names no registry and the archives it installed from
    // are not consulted again. The answer comes out of the store (clause 5).
    varve(&fx)
        .env("VARVE_TRUST_ROOT", &trust)
        .args(["inspect", "--layer", "2026.08.0"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wasi-interfaces"));
}
