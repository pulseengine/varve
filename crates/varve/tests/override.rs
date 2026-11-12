//! REQ-OVERRIDE-001 at the boundary a user touches (DD-043): a varve.toml that
//! takes ONE tool from another signed layer of its realm.
//!
//! One realm, `acme`, whose registry is a plain directory holding two layers
//! signed by its root: the pinned 2026.11.0 (synth 0.65, loom) and 2026.08.0
//! (synth 0.57, and a tool the pin does not carry). Every tool is a script
//! that names itself and the identity variables it was run with, and leaves a
//! marker file, so a test can tell WHICH binary ran — and that nothing ran at
//! all when varve refused.

use assert_cmd::Command;
use std::path::{Path, PathBuf};

const PINNED: &str = "2026.11.0";
const OLDER: &str = "2026.08.0";

struct World {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    root: PathBuf,
    project: PathBuf,
    registry: PathBuf,
    sk: Vec<u8>,
    pinned_digest: String,
    older_digest: String,
    /// The SIGNED digest of 2026.08.0's synth blob, for the tamper test.
    older_synth_blob: String,
}

/// A tool script: prints its identity and the variables `run` sets, and drops
/// a marker so "it never ran" can be asserted, not inferred.
fn script(id: &str) -> Vec<u8> {
    format!(
        "#!/bin/sh\necho \"{id} layer=$VARVE_LAYER overrides=$VARVE_OVERRIDES\"\n\
         : > \"$OVERRIDE_TEST_MARKS/{id}\"\n"
    )
    .into_bytes()
}

/// A SIGNED layer of `tools` (name, bytes) and `crates` (name, version,
/// bytes), written into the registry directory. Returns (manifest digest,
/// [(tool, blob digest)]).
fn put_layer(
    registry: &Path,
    sk: &[u8],
    layer: &str,
    tools: &[(&str, Vec<u8>)],
    crates: &[(&str, &str, Vec<u8>)],
) -> (String, Vec<(String, String)>) {
    let mut entries = Vec::new();
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut digests = Vec::new();
    for (name, bytes) in tools {
        let d = varve_core::manifest_digest(bytes);
        entries.push(format!(
            r#"{{"mediaType":"application/octet-stream","digest":"{d}","size":{},"annotations":{{"eu.pulseengine.tool":"{name}","eu.pulseengine.tool.version":"1.0.0"}}}}"#,
            bytes.len()
        ));
        digests.push((name.to_string(), d.clone()));
        blobs.push((d, bytes.clone()));
    }
    for (name, version, bytes) in crates {
        let d = varve_core::manifest_digest(bytes);
        entries.push(format!(
            r#"{{"mediaType":"application/octet-stream","digest":"{d}","size":{},"annotations":{{"eu.pulseengine.varve.kind":"crate","eu.pulseengine.tool":"{name}","eu.pulseengine.tool.version":"{version}"}}}}"#,
            bytes.len()
        ));
        blobs.push((d, bytes.clone()));
    }
    let line = &layer[..layer.rfind('.').unwrap()];
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.line":"{line}","eu.pulseengine.varve.channel":"qualified","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-11-01T00:00:00Z"}},"manifests":[{}]}}"#,
        entries.join(",")
    );
    let digest = varve_core::manifest_digest(payload.as_bytes());
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), sk, "acme-root").unwrap();
    let refs: Vec<(&str, &[u8])> = blobs
        .iter()
        .map(|(d, b)| (d.as_str(), b.as_slice()))
        .collect();
    varve_core::DirSource::at(registry)
        .put(envelope.as_bytes(), &refs)
        .unwrap();
    (digest, digests)
}

/// A real `.crate`: export-cargo opens it.
fn dot_crate(name: &str, version: &str) -> Vec<u8> {
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, body) in [
        (
            format!("{name}-{version}/Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
        ),
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

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let root = dir.join("varve-root");
    let project = dir.join("project");
    let registry = dir.join("acme-registry");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(dir.join("marks")).unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let (pinned_digest, _) = put_layer(
        &registry,
        &sk,
        PINNED,
        &[
            ("synth", script("synth-0.65")),
            ("loom", script("loom-pinned")),
        ],
        &[("acme-core", "1.0.0", dot_crate("acme-core", "1.0.0"))],
    );
    let (older_digest, blobs) = put_layer(
        &registry,
        &sk,
        OLDER,
        &[("synth", script("synth-0.57")), ("extra", script("extra"))],
        &[],
    );
    let older_synth_blob = blobs
        .iter()
        .find(|(n, _)| n == "synth")
        .map(|(_, d)| d.clone())
        .unwrap();
    std::fs::write(
        project.join("varve-realms.toml"),
        format!(
            "[realm.acme]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
            registry.display(),
            hex::encode(&pk)
        ),
    )
    .unwrap();
    std::fs::write(dir.join("acme.key"), hex::encode(&sk)).unwrap();
    let w = World {
        _tmp: tmp,
        dir,
        root,
        project,
        registry,
        sk,
        pinned_digest,
        older_digest,
        older_synth_blob,
    };
    w.pin("");
    w
}

impl World {
    /// Write the project's varve.toml: the pinned layer, plus `extra` verbatim.
    fn pin(&self, extra: &str) {
        std::fs::write(
            self.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{PINNED}\"\n{extra}"
            ),
        )
        .unwrap();
    }

    /// The override gale needs: synth from 2026.08.0.
    fn pin_synth_override(&self) {
        self.pin(&format!(
            "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
            self.older_digest
        ));
    }

    fn marks(&self) -> PathBuf {
        self.dir.join("marks")
    }

    /// Did the tool named `id` run since the marks were last cleared?
    fn ran(&self, id: &str) -> bool {
        self.marks().join(id).exists()
    }

    fn clear_marks(&self) {
        for e in std::fs::read_dir(self.marks()).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
    }
}

fn varve(w: &World) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    let none = w.dir.join("no-user-config");
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("OVERRIDE_TEST_MARKS", w.marks())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_LAYER")
        .env_remove("VARVE_OVERRIDES")
        .env_remove("VARVE_REGISTRY_AUTH")
        .current_dir(&w.project);
    cmd
}

fn stdout(a: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&a.get_output().stdout).into_owned()
}

fn stderr(a: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&a.get_output().stderr).into_owned()
}

/// Install with the override in place, asserting success.
fn installed_mixed() -> World {
    let w = world();
    w.pin_synth_override();
    varve(&w).arg("install").assert().success();
    w
}

/// A refusal: exit 1, the reason on stderr, and NO tool ran.
fn assert_refused(w: &World, args: &[&str], reason: &str) {
    w.clear_marks();
    let a = varve(w).args(args).assert().code(1);
    let err = stderr(&a);
    assert!(
        err.contains(reason),
        "{args:?}: expected {reason:?} in:\n{err}"
    );
    for id in ["synth-0.65", "synth-0.57", "loom-pinned", "extra"] {
        assert!(!w.ran(id), "{args:?} refused but {id} RAN");
    }
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_installs_verified_and_dispatches_only_that_tool() {
    // Clause 1: the binary is fetched and verified exactly like a pinned
    // layer's. `install` lays down BOTH layers from the realm's registry; the
    // overridden tool runs from 2026.08.0, every other tool from the pin.
    let w = world();
    w.pin_synth_override();
    let a = varve(&w).arg("install").assert().success();
    let out = stdout(&a);
    assert!(out.contains(&format!("installed layer {PINNED}")), "{out}");
    assert!(
        out.contains(&format!("override synth: installed layer {OLDER}")),
        "{out}"
    );

    let run = varve(&w).args(["run", "synth"]).assert().success();
    assert!(stdout(&run).starts_with("synth-0.57 "), "{}", stdout(&run));
    assert!(w.ran("synth-0.57") && !w.ran("synth-0.65"));
    let run = varve(&w).args(["run", "loom"]).assert().success();
    assert!(stdout(&run).starts_with("loom-pinned "), "{}", stdout(&run));

    // `which` prints the path; the bytes AT that path are the override
    // layer's signed synth, not the pin's.
    let which = varve(&w).args(["which", "synth"]).assert().success();
    let path = PathBuf::from(stdout(&which).trim());
    assert_eq!(std::fs::read(&path).unwrap(), script("synth-0.57"));
    assert!(path.starts_with(&w.root), "{}", path.display());

    // …and through a SHIM, which is how a build actually reaches it.
    varve(&w).args(["shim", "install"]).assert().success();
    w.clear_marks();
    let shim = w.root.join("shims").join("synth");
    let out = Command::new(&shim)
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", w.dir.join("no-user-config"))
        .env("HOME", w.dir.join("no-user-config"))
        .env("OVERRIDE_TEST_MARKS", w.marks())
        .env_remove("VARVE_OVERRIDES")
        .current_dir(&w.project)
        .assert()
        .success();
    assert!(stdout(&out).starts_with("synth-0.57 "), "{}", stdout(&out));
    assert!(w.ran("synth-0.57") && !w.ran("synth-0.65"));
    // The override layer adds nothing but synth.
    assert_refused(&w, &["run", "extra"], "not part of layer");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_of_a_tool_the_pin_does_not_carry_is_refused() {
    // Clause 4: 2026.08.0 carries `extra`; the pin does not. Install refuses
    // (after laying down only signed, verified layers) and so does every
    // dispatch: an override cannot smuggle a tool in.
    let w = world();
    w.pin(&format!(
        "[toolchain.override.extra]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
    let a = varve(&w).arg("install").assert().code(1);
    assert!(stderr(&a).contains("cannot add one"), "{}", stderr(&a));
    assert_refused(&w, &["run", "extra"], "cannot add one");
    assert_refused(&w, &["which", "extra"], "cannot add one");
    // Not even the tools the pin DOES carry run under a refused pin.
    assert_refused(&w, &["run", "synth"], "cannot add one");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_layer_that_does_not_carry_the_tool_is_refused() {
    let w = world();
    w.pin(&format!(
        "[toolchain.override.loom]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
    let a = varve(&w).arg("install").assert().code(1);
    assert!(
        stderr(&a).contains("does not carry 'loom'"),
        "{}",
        stderr(&a)
    );
    assert_refused(&w, &["run", "loom"], "does not carry 'loom'");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_of_an_override_is_refused() {
    let w = installed_mixed();
    // Nested: an override table inside an override.
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{d}\"\n\
         [toolchain.override.synth.override.loom]\nlayer = \"{OLDER}\"\ndigest = \"{d}\"\n",
        d = w.older_digest
    ));
    assert_refused(&w, &["run", "synth"], "not valid varve.toml");
    // The same tool twice, under two spellings a case-insensitive shim
    // directory cannot tell apart.
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{d}\"\n\
         [toolchain.override.SYNTH]\nlayer = \"{OLDER}\"\ndigest = \"{d}\"\n",
        d = w.older_digest
    ));
    assert_refused(&w, &["run", "synth"], "override one tool");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_needs_both_layer_and_digest() {
    let w = installed_mixed();
    w.pin(&format!(
        "[toolchain.override.synth]\ndigest = \"{}\"\n",
        w.older_digest
    ));
    assert_refused(&w, &["run", "synth"], "is missing layer");
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\n"
    ));
    assert_refused(&w, &["run", "synth"], "is missing digest");
    assert_refused(&w, &["install"], "is missing digest");
    // An unknown key is refused, never read as absent.
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\nversion = \"0.57.0\"\n",
        w.older_digest
    ));
    assert_refused(&w, &["run", "synth"], "not valid varve.toml");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_digest_matching_no_layer_or_another_layer_is_refused() {
    let w = world();
    varve(&w).arg("install").assert().success();
    // A digest no signed layer in the realm has: nothing to fetch, nothing
    // fetched another way, nothing run.
    let nowhere = format!("sha256:{}", "c".repeat(64));
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{nowhere}\"\n"
    ));
    assert_refused(&w, &["install"], "override synth");
    assert_refused(&w, &["run", "synth"], "is not installed");
    // The digest of 2026.08.0 under the name 2026.09.0: the name is a label.
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
    assert_refused(&w, &["install"], "refusing to guess");
    assert_refused(&w, &["run", "synth"], "refusing to guess");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_layer_that_fails_verification_is_refused_and_never_fetched_another_way() {
    // Clause 2. The override layer's synth blob is replaced in the registry:
    // install refuses it, lays nothing of it down, and every dispatch then
    // refuses as "not installed" rather than finding the bytes elsewhere.
    let w = world();
    std::fs::write(
        w.registry
            .join("blobs")
            .join(w.older_synth_blob.replace(':', "-")),
        script("synth-evil"),
    )
    .unwrap();
    w.pin_synth_override();
    let a = varve(&w).arg("install").assert().code(1);
    let err = stderr(&a);
    assert!(err.contains("override synth"), "{err}");
    assert!(
        !w.root.join("realms").exists() || !walk_has(&w.root, &w.older_digest.replace(':', "-")),
        "the refused layer must not be in the store"
    );
    assert_refused(&w, &["run", "synth"], "is not installed");

    // A tampered MANIFEST: a payload that is not what the root signed,
    // carrying the root's signature over the original. Refused on the
    // signature, before any blob is read.
    let w = world();
    let manifests = w.registry.join("manifests");
    let (forged_digest, forged_file) = {
        // Re-sign a changed payload, then put the ORIGINAL signature on it.
        let envelopes: Vec<PathBuf> = std::fs::read_dir(&manifests)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        // Any genuine envelope's signature: it is over another payload.
        let older = envelopes.first().expect("an envelope").clone();
        let forged_payload = format!(
            "{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"artifactType\":\"application/vnd.pulseengine.varve.layer.v1+json\",\"annotations\":{{\"eu.pulseengine.varve.layer\":\"{OLDER}\",\"eu.pulseengine.varve.line\":\"2026.08\",\"eu.pulseengine.varve.channel\":\"qualified\",\"eu.pulseengine.varve.counter\":\"1\",\"org.opencontainers.image.created\":\"2026-11-01T00:00:00Z\"}},\"manifests\":[{{\"mediaType\":\"application/octet-stream\",\"digest\":\"{}\",\"size\":1,\"annotations\":{{\"eu.pulseengine.tool\":\"synth\"}}}}]}}",
            w.older_synth_blob
        );
        let resigned: serde_json::Value = serde_json::from_str(
            &varve_core::sign_layer_manifest(forged_payload.as_bytes(), &w.sk, "acme-root")
                .unwrap(),
        )
        .unwrap();
        let genuine: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&older).unwrap()).unwrap();
        let mut forged = resigned.clone();
        forged["signatures"] = genuine["signatures"].clone();
        let file = manifests.join("forged");
        std::fs::write(&file, forged.to_string()).unwrap();
        (varve_core::manifest_digest(forged_payload.as_bytes()), file)
    };
    assert!(forged_file.exists());
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{forged_digest}\"\n"
    ));
    let a = varve(&w).arg("install").assert().code(1);
    assert!(stderr(&a).contains("signature"), "{}", stderr(&a));
    assert_refused(&w, &["run", "synth"], "is not installed");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_layer_from_another_realm_is_refused() {
    // DD-043: the source layer is in the pin's own realm. (a) A layer signed
    // by another realm's root, placed in this realm's registry, fails this
    // realm's root at install. (b) The same layer installed legitimately
    // under its own realm is not reachable from this pin.
    let w = world();
    varve(&w).arg("install").assert().success();
    let (other_sk, other_pk) = varve_core::generate_root_keypair();
    let (foreign, _) = put_layer(
        &w.registry,
        &other_sk,
        "2026.08.1",
        &[("synth", script("synth-foreign"))],
        &[],
    );
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.08.1\"\ndigest = \"{foreign}\"\n"
    ));
    let a = varve(&w).arg("install").assert().code(1);
    assert!(stderr(&a).contains("signature"), "{}", stderr(&a));
    assert_refused(&w, &["run", "synth"], "is not installed");

    // (b) Installed under realm `beta`, which signed it, from a second project.
    let beta_registry = w.dir.join("beta-registry");
    put_layer(
        &beta_registry,
        &other_sk,
        "2026.08.1",
        &[("synth", script("synth-foreign"))],
        &[],
    );
    let beta = w.dir.join("beta-project");
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(
        beta.join("varve-realms.toml"),
        format!(
            "[realm.beta]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
            beta_registry.display(),
            hex::encode(&other_pk)
        ),
    )
    .unwrap();
    std::fs::write(
        beta.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"beta\"\nchannel = \"qualified\"\n\
         layer = \"2026.08.1\"\n",
    )
    .unwrap();
    varve(&w)
        .current_dir(&beta)
        .arg("install")
        .assert()
        .success();
    assert_refused(&w, &["run", "synth"], "another realm");
    assert!(!w.ran("synth-foreign"));
}

fn walk_has(root: &Path, name: &str) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_name().to_string_lossy() == name {
                return true;
            }
            if e.path().is_dir() {
                stack.push(e.path());
            }
        }
    }
    false
}

/// Sign a line-status for the pinned line with the realm root and ingest it,
/// so `status` has something to report.
fn status_ready(w: &World) -> PathBuf {
    let doc = w.dir.join("status.json");
    std::fs::write(
        &doc,
        r#"{"line":"2026.11","counter":1,"issued-at":"2026-11-01T00:00:00Z","support-until":"2028-11-30","yanked":{},"known-problems":[]}"#,
    )
    .unwrap();
    let env = w.dir.join("status.dsse.json");
    varve(w)
        .args(["sign-status", "--file"])
        .arg(&doc)
        .arg("--key")
        .arg(w.dir.join("acme.key"))
        .arg("--out")
        .arg(&env)
        .assert()
        .success();
    env
}

fn override_record(w: &World) -> String {
    format!("synth={OLDER}@{}", w.older_digest)
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn status_says_mixed_in_text_and_json() {
    let w = installed_mixed();
    let env = status_ready(&w);
    let a = varve(&w)
        .args(["status", "--from-file"])
        .arg(&env)
        .assert()
        .success();
    let out = stdout(&a);
    assert!(
        out.starts_with(&format!("MIXED toolchain {PINNED}+mixed: layer {PINNED}")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "override synth: from layer {OLDER} {}",
            w.older_digest
        )),
        "{out}"
    );
    let a = varve(&w).args(["status", "--json"]).assert().success();
    let j: serde_json::Value = serde_json::from_slice(&a.get_output().stdout).unwrap();
    assert_eq!(j["state"], "mixed");
    assert_eq!(j["identity"], format!("{PINNED}+mixed"));
    assert_eq!(j["overrides"][0]["tool"], "synth");
    assert_eq!(j["overrides"][0]["digest"], w.older_digest.as_str());
    // The pure pin says `pinned`, with the field present.
    w.pin("");
    let a = varve(&w).args(["status", "--json"]).assert().success();
    let j: serde_json::Value = serde_json::from_slice(&a.get_output().stdout).unwrap();
    assert_eq!(j["state"], "pinned");
    assert_eq!(j["identity"], PINNED);
    assert_eq!(j["overrides"], serde_json::json!([]));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn which_names_both_layers_for_an_overridden_tool() {
    let w = installed_mixed();
    let a = varve(&w).args(["which", "synth"]).assert().success();
    let err = stderr(&a);
    assert!(
        err.contains(&format!(
            "MIXED: 'synth' is overridden — it runs from layer {OLDER} (qualified) {}, not from \
             the pinned layer {PINNED} {}",
            w.older_digest, w.pinned_digest
        )),
        "{err}"
    );
    assert!(err.contains(&override_record(&w)), "{err}");
    // stdout stays the path and nothing else (REQ-WHICHSTDOUT-001).
    assert_eq!(stdout(&a).lines().count(), 1);
    // A tool that is NOT overridden still says the toolchain is mixed.
    let a = varve(&w).args(["which", "loom"]).assert().success();
    assert!(stderr(&a).contains("MIXED toolchain"), "{}", stderr(&a));
    assert!(!stderr(&a).contains("is overridden"), "{}", stderr(&a));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn verify_verifies_both_layers_and_says_mixed() {
    let w = installed_mixed();
    let a = varve(&w).arg("verify").assert().success();
    let out = stdout(&a);
    assert!(
        out.contains(&format!(
            "override synth: layer {OLDER} {} verified: signature OK",
            w.older_digest
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!("layer {PINNED} {} verified", w.pinned_digest)),
        "{out}"
    );
    assert!(
        out.trim_end()
            .lines()
            .last()
            .unwrap()
            .starts_with(&format!("MIXED: verified toolchain {PINNED}+mixed")),
        "the last line is the mixed verdict:\n{out}"
    );
    // A tampered override layer fails verify, though the pinned one is intact.
    let bin = walk_find(&w.root, &w.older_digest.replace(':', "-"))
        .unwrap()
        .join("bin")
        .join("synth");
    std::fs::write(&bin, script("synth-evil")).unwrap();
    let a = varve(&w).arg("verify").assert().code(1);
    assert!(stderr(&a).contains("override synth"), "{}", stderr(&a));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn run_states_the_mix_in_the_environment() {
    let w = installed_mixed();
    // VARVE_LAYER stays the pinned layer; VARVE_OVERRIDES names the mix —
    // for the overridden tool and for every other.
    for (tool, id) in [("synth", "synth-0.57"), ("loom", "loom-pinned")] {
        let a = varve(&w).args(["run", tool]).assert().success();
        assert_eq!(
            stdout(&a).trim(),
            format!("{id} layer={PINNED} overrides={}", override_record(&w)),
        );
    }
    // A pure project removes an inherited value instead of passing it on.
    w.pin("");
    let a = varve(&w)
        .env("VARVE_OVERRIDES", "synth=stale@sha256:00")
        .args(["run", "loom"])
        .assert()
        .success();
    assert_eq!(
        stdout(&a).trim(),
        format!("loom-pinned layer={PINNED} overrides=")
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_export_of_a_mixed_toolchain_is_stamped_mixed_and_checked_against_the_mix() {
    let w = installed_mixed();
    let out = w.project.join("vendor-cargo");
    varve(&w)
        .args(["export-cargo", "--out"])
        .arg(&out)
        .assert()
        .success();
    let stamp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join(".varve-export.json")).unwrap()).unwrap();
    assert_eq!(stamp["layer"], format!("{PINNED}+mixed"));
    assert_eq!(stamp["manifest_digest"], w.pinned_digest.as_str());
    assert_eq!(stamp["overrides"][0]["tool"], "synth");
    assert_eq!(stamp["overrides"][0]["digest"], w.older_digest.as_str());

    // `verify --export` is current for this mix…
    varve(&w)
        .args(["verify", "--export"])
        .arg(&out)
        .assert()
        .success();
    // …and STALE once the project is pure again: the export was made with a
    // synth the pure pin does not run.
    w.pin("");
    let a = varve(&w)
        .args(["verify", "--export"])
        .arg(&out)
        .assert()
        .code(1);
    assert!(stderr(&a).contains("STALE"), "{}", stderr(&a));

    // A pure export, declared, is stale for the mixed project.
    let pure = w.project.join("pure-cargo");
    varve(&w)
        .args(["export-cargo", "--out"])
        .arg(&pure)
        .assert()
        .success();
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n\n\
         [[export]]\nkind = \"cargo\"\nout = \"pure-cargo\"\n",
        w.older_digest
    ));
    let a = varve(&w).arg("verify").assert().code(1);
    assert!(stderr(&a).contains("STALE"), "{}", stderr(&a));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn check_attestation_refuses_a_mixed_project_unless_the_statement_records_the_same_mix() {
    let w = installed_mixed();
    let doc = w.dir.join("sbom.json");
    std::fs::write(&doc, br#"{"bomFormat":"CycloneDX"}"#).unwrap();
    let sign = |out: &Path| {
        varve(&w)
            .args(["sign-attestation", "--kind", "sbom", "--file"])
            .arg(&doc)
            .arg("--key")
            .arg(w.dir.join("acme.key"))
            .arg("--out")
            .arg(out)
            .assert()
            .success()
    };
    let check = |st: &Path| {
        varve(&w)
            .args(["check-attestation", "--statement"])
            .arg(st)
            .arg("--file")
            .arg(&doc)
            .assert()
    };
    // Signed in the mixed project: it records the mix, and checks there.
    let mixed_st = w.dir.join("mixed.dsse.json");
    let a = sign(&mixed_st);
    assert!(stdout(&a).contains("MIXED toolchain"), "{}", stdout(&a));
    let a = check(&mixed_st).success();
    assert!(stdout(&a).contains(&override_record(&w)), "{}", stdout(&a));
    // Signed for the pure pin: refused in the mixed project.
    w.pin("");
    let pure_st = w.dir.join("pure.dsse.json");
    sign(&pure_st);
    check(&pure_st).success();
    // The mixed statement is refused for the pure project…
    let a = check(&mixed_st).code(1);
    assert!(stderr(&a).contains("does not describe"), "{}", stderr(&a));
    // …and the pure statement for the mixed one.
    w.pin_synth_override();
    let a = check(&pure_st).code(1);
    assert!(
        stderr(&a).contains("none (the pinned layer alone)"),
        "{}",
        stderr(&a)
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn sbom_of_a_mixed_project_is_refused_rather_than_written_as_the_pinned_layers() {
    let w = installed_mixed();
    let a = varve(&w).arg("sbom").assert().code(1);
    assert!(stderr(&a).contains("MIXED"), "{}", stderr(&a));
    assert!(stdout(&a).is_empty());
    // Each layer by name still works.
    varve(&w)
        .args(["sbom", "--layer", OLDER])
        .assert()
        .success();
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn seed_of_a_mixed_project_carries_the_override_layer() {
    let w = installed_mixed();
    let dest = w.dir.join("seeded");
    let a = varve(&w)
        .args(["seed", "--json"])
        .arg(&dest)
        .assert()
        .success();
    let j: serde_json::Value = serde_json::from_slice(&a.get_output().stdout).unwrap();
    let digests: Vec<&str> = j["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["digest"].as_str().unwrap())
        .collect();
    assert!(digests.contains(&w.pinned_digest.as_str()), "{digests:?}");
    assert!(digests.contains(&w.older_digest.as_str()), "{digests:?}");
}

fn walk_find(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_name().to_string_lossy() == name {
                return Some(e.path());
            }
            if e.path().is_dir() {
                stack.push(e.path());
            }
        }
    }
    None
}
