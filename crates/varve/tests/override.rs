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

/// A SIGNED layer of `tools` (name, bytes) and `crates`, written into the
/// registry directory. Returns (manifest digest, [(tool, blob digest)]).
fn put_layer(
    registry: &Path,
    sk: &[u8],
    layer: &str,
    tools: &[(&str, Vec<u8>)],
    crates: &[(&str, &str, Vec<u8>)],
) -> (String, Vec<(String, String)>) {
    let tools: Vec<(&str, Vec<u8>, &str)> =
        tools.iter().map(|(n, b)| (*n, b.clone(), "")).collect();
    put_layer_full(registry, sk, layer, "qualified", &tools, crates, &[])
}

/// The general form: a channel, an extra annotation string per tool (e.g. a
/// runner contract), and `includes` as (digest, layer id, realm). A tool is
/// stamped for THIS host unless its extra names a platform, and carries
/// source provenance — so `export-bazel` has a checksum to write, the sha256
/// of its bytes — unless its extra contains the marker `!nosource`.
fn put_layer_full(
    registry: &Path,
    sk: &[u8],
    layer: &str,
    channel: &str,
    tools: &[(&str, Vec<u8>, &str)],
    crates: &[(&str, &str, Vec<u8>)],
    includes: &[(&str, &str, &str)],
) -> (String, Vec<(String, String)>) {
    let host = varve_core::host_platform();
    let mut entries = Vec::new();
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut digests = Vec::new();
    for (name, bytes, extra) in tools {
        let d = varve_core::manifest_digest(bytes);
        let platform = if extra.contains("eu.pulseengine.platform") {
            String::new()
        } else {
            format!(r#","eu.pulseengine.platform":"{host}""#)
        };
        let source = if extra.contains("!nosource") {
            String::new()
        } else {
            format!(
                r#","eu.pulseengine.source.repo":"acme/{name}","eu.pulseengine.source.asset":"{name}-{layer}.tar.gz","eu.pulseengine.source.sha256":"{d}""#
            )
        };
        let extra = extra.replace("!nosource", "");
        entries.push(format!(
            r#"{{"mediaType":"application/octet-stream","digest":"{d}","size":{},"annotations":{{"eu.pulseengine.tool":"{name}","eu.pulseengine.tool.version":"1.0.0"{platform}{source}{extra}}}}}"#,
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
    for (digest, inc_layer, realm) in includes {
        entries.push(format!(
            r#"{{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"{digest}","size":0,"annotations":{{"eu.pulseengine.varve.kind":"layer","eu.pulseengine.varve.include.realm":"{realm}","eu.pulseengine.varve.include.layer":"{inc_layer}"}}}}"#
        ));
    }
    let line = &layer[..layer.rfind('.').unwrap()];
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.line":"{line}","eu.pulseengine.varve.channel":"{channel}","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-11-01T00:00:00Z"}},"manifests":[{}]}}"#,
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
    // With 2026.08.0 installed (by the synth override), dispatch refuses too.
    w.pin_synth_override();
    varve(&w).arg("install").assert().success();
    w.pin(&format!(
        "[toolchain.override.loom]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
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
    // Refused on the verified manifest: nothing was laid down for it.
    assert_refused(&w, &["run", "synth"], "is not installed");
    // With 2026.08.0 installed, the same mislabelled override is refused at
    // dispatch too.
    w.pin_synth_override();
    varve(&w).arg("install").assert().success();
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
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

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_layer_installed_for_another_platform_is_refused_everywhere() {
    // Parity with the pinned entry: an override layer whose payloads were
    // selected for another platform is refused by every consumer, naming the
    // platform — never dispatched, verified, exported or attested here.
    let w = installed_mixed();
    let root = walk_find(&w.root, &w.older_digest.replace(':', "-")).unwrap();
    varve_core::store::record_install_platform(&root, "riscv64-unknown-linux-gnu").unwrap();
    let why = "installed for riscv64-unknown-linux-gnu";
    assert_refused(&w, &["run", "synth"], why);
    assert_refused(&w, &["run", "loom"], why);
    assert_refused(&w, &["which", "synth"], why);
    assert_refused(&w, &["verify"], why);
    assert_refused(&w, &["export-cargo", "--out", "x"], why);
    assert_refused(&w, &["sbom"], why);
    // The fix the refusal names works: install lays it down for this host.
    varve(&w).arg("install").assert().success();
    let run = varve(&w).args(["run", "synth"]).assert().success();
    assert!(stdout(&run).starts_with("synth-0.57 "), "{}", stdout(&run));
}

fn marks_file(w: &World) -> PathBuf {
    walk_find(&w.root, "high-water-marks.json").expect("an install has recorded marks")
}

/// Raise line `line`'s mark to `to` in the realm partition.
fn raise_mark(w: &World, line: &str, to: u64) {
    let path = marks_file(w);
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v[line] = serde_json::json!(to);
    std::fs::write(&path, v.to_string()).unwrap();
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_qualified_address_of_an_overridden_tool_runs_the_override() {
    // H1: `acme/synth` is the same tool as `synth`.
    let w = installed_mixed();
    w.clear_marks();
    let a = varve(&w).args(["run", "acme/synth"]).assert().success();
    assert!(stdout(&a).starts_with("synth-0.57 "), "{}", stdout(&a));
    assert!(w.ran("synth-0.57") && !w.ran("synth-0.65"));
    let a = varve(&w).args(["which", "acme/synth"]).assert().success();
    let path = PathBuf::from(stdout(&a).trim());
    assert_eq!(std::fs::read(&path).unwrap(), script("synth-0.57"));
    assert!(
        stderr(&a).contains(&format!("provided by realm 'acme' layer {OLDER}")),
        "{}",
        stderr(&a)
    );
    // Another realm's address of the tool is refused, naming the override.
    assert_refused(&w, &["run", "beta/synth"], "overridden");
    assert_refused(&w, &["which", "beta/synth"], "overridden");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn the_runner_contract_comes_from_the_layer_whose_binary_runs() {
    let w = world();
    let runner = r#","eu.pulseengine.runner":"wasmrun""#;
    let wasmrun = b"#!/bin/sh\necho \"wasmrun $@\"\n".to_vec();
    // Pinned 2026.10.0 runs synth through wasmrun; the plain 0.57 override
    // must run DIRECTLY, not be handed to the pin's runner.
    let (pinned_runner, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.10.0",
        "qualified",
        &[
            ("synth", script("synth-wasm"), runner),
            ("wasmrun", wasmrun.clone(), ""),
        ],
        &[],
        &[],
    );
    let _ = pinned_runner;
    let pin = |layer: &str, ov_layer: &str, ov_digest: &str| {
        std::fs::write(
            w.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{layer}\"\n[toolchain.override.synth]\nlayer = \"{ov_layer}\"\n\
                 digest = \"{ov_digest}\"\n"
            ),
        )
        .unwrap();
    };
    pin("2026.10.0", OLDER, &w.older_digest);
    varve(&w).arg("install").assert().success();
    let a = varve(&w).args(["run", "synth"]).assert().success();
    assert!(
        stdout(&a).starts_with("synth-0.57 "),
        "ran through the pin's runner: {}",
        stdout(&a)
    );

    // Pinned 2026.12.0 runs synth natively; an override whose synth carries a
    // runner contract runs through it, with the OVERRIDE's binary.
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-native"), ""),
            ("wasmrun", wasmrun, ""),
        ],
        &[],
        &[],
    );
    // REQ-RUNNER-001: the runner is the OVERRIDE layer's own wasmrun, not
    // the pin's — the pin's prints "wasmrun", this one "wasmrun-0.60".
    let (wrapped, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[
            ("synth", script("synth-0.60-wasm"), runner),
            (
                "wasmrun",
                b"#!/bin/sh\necho \"wasmrun-0.60 $@\"\n".to_vec(),
                "",
            ),
        ],
        &[],
        &[],
    );
    pin("2026.12.0", "2026.09.0", &wrapped);
    varve(&w).arg("install").assert().success();
    let a = varve(&w).args(["run", "synth"]).assert().success();
    let out = stdout(&a);
    assert!(
        out.starts_with("wasmrun-0.60 "),
        "the override layer's runner: {out}"
    );
    assert!(
        out.contains(&wrapped.replace(':', "-")),
        "the override's bytes: {out}"
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_whose_runner_its_layer_does_not_carry_is_refused() {
    // The override layer's synth names the runner wasmrun, which only the
    // PIN carries. Pairing them would run bytes no single layer vouched for
    // together: refused at install (before lay-down) and at dispatch.
    let w = world();
    let runner = r#","eu.pulseengine.runner":"wasmrun""#;
    let wasmrun = b"#!/bin/sh\necho \"wasmrun $@\"\n".to_vec();
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-native"), ""),
            ("wasmrun", wasmrun, ""),
        ],
        &[],
        &[],
    );
    let (alone, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.06.0",
        "qualified",
        &[("synth", script("synth-wasm-alone"), runner)],
        &[],
        &[],
    );
    let pin_to = |extra: &str, layer: &str| {
        std::fs::write(
            w.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{layer}\"\n{extra}"
            ),
        )
        .unwrap();
    };
    let ov = format!("[toolchain.override.synth]\nlayer = \"2026.06.0\"\ndigest = \"{alone}\"\n");
    // Install the pin alone first, so the refusal below is the override's.
    pin_to("", "2026.12.0");
    varve(&w).arg("install").assert().success();
    pin_to(&ov, "2026.12.0");
    assert_refused(&w, &["install"], "runner 'wasmrun'");
    assert!(!walk_has(&w.root, &alone.replace(':', "-")), "laid down");
    // With 2026.06.0 installed by pinning it directly, dispatch refuses too,
    // naming the layer and the runner, and runs nothing.
    pin_to("", "2026.06.0");
    // Pinned directly, with no override, nothing pairs it with a runner: it
    // installs, which is what puts it in the store for the refusal below.
    varve(&w).arg("install").assert().success();
    assert!(
        walk_has(&w.root, &alone.replace(':', "-")),
        "installed directly"
    );
    pin_to(&ov, "2026.12.0");
    w.clear_marks();
    let a = varve(&w).args(["run", "synth"]).assert().code(1);
    let err = stderr(&a);
    assert!(
        err.contains("layer 2026.06.0 runs 'synth' through the runner 'wasmrun'"),
        "{err}"
    );
    assert!(!w.ran("synth-wasm-alone") && !w.ran("synth-native"));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn export_bazel_writes_the_override_layers_checksum_for_the_overridden_tool() {
    // H2: a Bazel registry for a mixed toolchain must fetch the synth that
    // `varve run synth` runs, not the pin's.
    let w = installed_mixed();
    let out = w.project.join("bazel");
    varve(&w)
        .args(["export-bazel", "--out"])
        .arg(&out)
        .assert()
        .success();
    let synth = std::fs::read_to_string(out.join("synth.json")).unwrap();
    let older_hex = varve_core::manifest_digest(&script("synth-0.57"));
    let pinned_hex = varve_core::manifest_digest(&script("synth-0.65"));
    let strip = |d: &str| d.strip_prefix("sha256:").unwrap().to_string();
    assert!(synth.contains(&strip(&older_hex)), "{synth}");
    assert!(!synth.contains(&strip(&pinned_hex)), "{synth}");
    let loom = std::fs::read_to_string(out.join("loom.json")).unwrap();
    assert!(
        loom.contains(&strip(&varve_core::manifest_digest(&script("loom-pinned")))),
        "{loom}"
    );
    assert!(
        !out.join("extra.json").exists(),
        "the override adds nothing else"
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn inspect_reports_which_layer_dispatches_an_overridden_tool() {
    // M1.
    let w = installed_mixed();
    let a = varve(&w).arg("inspect").assert().success();
    let out = stdout(&a);
    assert!(
        out.contains(&format!("MIXED toolchain {PINNED}+mixed")),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "synth is dispatched from layer {OLDER} {}",
            w.older_digest
        )),
        "{out}"
    );
    let a = varve(&w).args(["inspect", "--json"]).assert().success();
    let j: serde_json::Value = serde_json::from_slice(&a.get_output().stdout).unwrap();
    assert_eq!(j["state"], "mixed");
    assert_eq!(j["overrides"][0]["digest"], w.older_digest.as_str());
    let synths: Vec<&serde_json::Value> = j["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["name"] == "synth")
        .collect();
    let by_layer = |l: &str| synths.iter().find(|p| p["layer"] == l).unwrap()["dispatch"].clone();
    assert_eq!(by_layer(OLDER), "dispatched");
    assert_eq!(by_layer(PINNED), "overridden");
    assert!(
        !j["payloads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "extra"),
        "only the overridden tool of the override layer is listed"
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn verify_reports_a_carried_attestation_made_under_a_mix() {
    // M2: a carried statement that records overrides is reported as made
    // under that mix, and as not matching a toolchain with other overrides.
    let w = installed_mixed();
    let doc = w.dir.join("prov.json");
    std::fs::write(&doc, br#"{"_type":"x"}"#).unwrap();
    let st = w.dir.join("prov.dsse.json");
    varve(&w)
        .args(["sign-attestation", "--kind", "provenance", "--file"])
        .arg(&doc)
        .arg("--key")
        .arg(w.dir.join("acme.key"))
        .arg("--out")
        .arg(&st)
        .assert()
        .success();
    let envelope = std::fs::read(&st).unwrap();
    let root = walk_find(&w.root, &w.pinned_digest.replace(':', "-")).unwrap();
    varve_core::attestcarry::persist(
        &root,
        &[varve_core::attestcarry::CarriedAttestation {
            statement_digest: varve_core::manifest_digest(&envelope),
            statement: envelope,
            bytes: std::fs::read(&doc).unwrap(),
        }],
    )
    .unwrap();
    let a = varve(&w).arg("verify").assert().success();
    let out = stdout(&a);
    assert!(
        out.contains(&format!(
            "made under MIXED toolchain {}",
            override_record(&w)
        )),
        "{out}"
    );
    assert!(out.contains("matches this project's toolchain"), "{out}");
    w.pin("");
    let a = varve(&w).arg("verify").assert().success();
    let out = stdout(&a);
    assert!(
        out.contains("does NOT match this project's toolchain"),
        "{out}"
    );
    assert!(out.contains("none (the pinned layer alone)"), "{out}");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_on_another_channel_is_refused_and_leaves_no_mark() {
    // M3 and M4: refused on the verified manifest, before anything is laid
    // down or marked.
    let w = world();
    varve(&w).arg("install").assert().success();
    let before = std::fs::read(marks_file(&w)).unwrap();
    let (rolling, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "rolling",
        &[("synth", script("synth-rolling"), "")],
        &[],
        &[],
    );
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{rolling}\"\n"
    ));
    assert_refused(&w, &["install"], "channel 'rolling'");
    assert_eq!(std::fs::read(marks_file(&w)).unwrap(), before, "mark moved");
    assert!(!walk_has(&w.root, &rolling.replace(':', "-")), "laid down");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_refused_override_is_refused_before_it_is_fetched_or_marked() {
    // M4. Clause 4 is decided from the pin and the pinned layer: no fetch.
    // The digest names nothing the registry has — a fetch would fail with
    // "could not be installed", so the clause-4 message proves none happened.
    let w = world();
    varve(&w).arg("install").assert().success();
    let before = std::fs::read(marks_file(&w)).unwrap();
    let nowhere = format!("sha256:{}", "d".repeat(64));
    w.pin(&format!(
        "[toolchain.override.extra]\nlayer = \"{OLDER}\"\ndigest = \"{nowhere}\"\n"
    ));
    let a = varve(&w).arg("install").assert().code(1);
    assert!(stderr(&a).contains("cannot add one"), "{}", stderr(&a));
    assert!(
        !stderr(&a).contains("could not be installed"),
        "{}",
        stderr(&a)
    );
    // A refusal that needs the source manifest (the layer does not carry
    // loom) leaves no layer and no mark behind.
    w.pin(&format!(
        "[toolchain.override.loom]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
    assert_refused(&w, &["install"], "does not carry 'loom'");
    assert_eq!(std::fs::read(marks_file(&w)).unwrap(), before, "mark moved");
    assert!(
        !walk_has(&w.root, &w.older_digest.replace(':', "-")),
        "laid down"
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_below_its_lines_mark_is_refused_by_install_and_by_verify() {
    // Install: the override's digest is not consent to go below the mark.
    let w = world();
    varve(&w).arg("install").assert().success();
    raise_mark(&w, "2026.08", 9);
    w.pin_synth_override();
    assert_refused(&w, &["install"], "rollback refused");
    // Verify: a mark raised after the override was installed.
    let w = installed_mixed();
    varve(&w).arg("verify").assert().success();
    raise_mark(&w, "2026.08", 9);
    assert_refused(
        &w,
        &["verify"],
        "override synth: layer 2026.08.0 presents counter 1",
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_export_refuses_a_tampered_override_layer() {
    // export_target verifies the override layer's bytes itself: resolve
    // does not read them, so nothing earlier would stop this.
    let w = installed_mixed();
    let bin = walk_find(&w.root, &w.older_digest.replace(':', "-"))
        .unwrap()
        .join("bin")
        .join("synth");
    std::fs::write(&bin, script("synth-evil")).unwrap();
    assert_refused(&w, &["export-cargo", "--out", "c"], "override synth");
    assert!(!w.project.join("c").join(".varve-export.json").exists());
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_realmless_store_vouches_for_the_override_layer_too() {
    // With no realm, dispatch checks each layer's retained signature against
    // VARVE_TRUST_ROOT. An override layer re-signed by another key is not
    // vouched for, though the pinned layer is.
    let w = world();
    let pk = w.dir.join("acme.pub");
    let realms: String = std::fs::read_to_string(w.project.join("varve-realms.toml")).unwrap();
    let hexkey = realms
        .split("trust-root = \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    std::fs::write(&pk, hexkey).unwrap();
    std::fs::write(
        w.project.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{PINNED}\"\n\
             [toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
            w.older_digest
        ),
    )
    .unwrap();
    varve(&w)
        .env("VARVE_TRUST_ROOT", &pk)
        .args(["install", "--from"])
        .arg(&w.registry)
        .assert()
        .success();
    let a = varve(&w)
        .env("VARVE_TRUST_ROOT", &pk)
        .args(["run", "synth"])
        .assert()
        .success();
    assert!(stdout(&a).starts_with("synth-0.57 "), "{}", stdout(&a));
    // Re-sign the override layer's retained envelope with a stranger's key.
    let root = w.root.join("core").join(w.older_digest.replace(':', "-"));
    let payload = std::fs::read(root.join("layer.json")).unwrap();
    let (stranger, _) = varve_core::generate_root_keypair();
    std::fs::write(
        root.join("layer.dsse.json"),
        varve_core::sign_layer_manifest(&payload, &stranger, "stranger").unwrap(),
    )
    .unwrap();
    w.clear_marks();
    let a = varve(&w)
        .env("VARVE_TRUST_ROOT", &pk)
        .args(["run", "synth"])
        .assert()
        .code(1);
    assert!(
        stderr(&a).contains(&format!("layer {OLDER}")),
        "{}",
        stderr(&a)
    );
    assert!(!w.ran("synth-0.57"));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_one_off_layer_beside_the_projects_overrides_is_refused() {
    let w = installed_mixed();
    assert_refused(&w, &["run", "--varve", OLDER, "--", "synth"], "--varve");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn verify_all_says_the_project_is_mixed() {
    let w = installed_mixed();
    let a = varve(&w).args(["verify", "--all"]).assert().success();
    assert!(
        stdout(&a).contains(&format!(
            "MIXED: this project's toolchain is {PINNED}+mixed"
        )),
        "{}",
        stdout(&a)
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn install_fetches_what_an_override_layer_composes_and_seed_carries_it() {
    let w = world();
    let (base, _) = put_layer(
        &w.registry,
        &w.sk,
        "2026.07.0",
        &[("base", script("base"))],
        &[],
    );
    let (composing, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("synth", script("synth-0.60"), "")],
        &[],
        &[(base.as_str(), "2026.07.0", "acme")],
    );
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{composing}\"\n"
    ));
    let a = varve(&w).arg("install").assert().success();
    let out = stdout(&a);
    assert!(out.contains("fetched composed layer 2026.07.0"), "{out}");
    // Counted as the OVERRIDE's, not as what the pinned layer composes.
    assert!(
        out.contains("the override layer(s) compose 1 further installed layer(s)"),
        "{out}"
    );
    assert!(!out.contains("  composes 1 installed layer(s)"), "{out}");
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
    assert!(
        digests.contains(&composing.as_str()) && digests.contains(&base.as_str()),
        "{digests:?}"
    );
}

/// Another platform than this host, with a Bazel key either way.
fn other_platform() -> &'static str {
    if varve_core::host_platform() == "x86_64-unknown-linux-gnu" {
        "aarch64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn install_for_another_platform_decides_clause_four_without_the_host() {
    // The pin exposes loom, which only this host has a build of; installing
    // for another platform must not be refused because loom is not laid down.
    let w = world();
    let other = other_platform();
    let on_other = format!(r#","eu.pulseengine.platform":"{other}""#);
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-host"), ""),
            ("synth", script("synth-other"), on_other.as_str()),
            ("loom", script("loom-host"), ""),
        ],
        &[],
        &[],
    );
    let (ov, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[
            ("synth", script("synth-0.60-host"), ""),
            ("synth", script("synth-0.60-other"), on_other.as_str()),
        ],
        &[],
        &[],
    );
    let pin_with = |tool: &str| {
        std::fs::write(
            w.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"2026.12.0\"\ntools = [\"synth\", \"loom\"]\n\
                 [toolchain.override.{tool}]\nlayer = \"2026.09.0\"\ndigest = \"{ov}\"\n"
            ),
        )
        .unwrap();
    };
    pin_with("synth");
    let a = varve(&w)
        .args(["install", "--platform", other])
        .assert()
        .success();
    assert!(
        stdout(&a).contains("override synth: installed layer 2026.09.0"),
        "{}",
        stdout(&a)
    );
    // Clause 4 still holds for another platform: a tool the pin does not have.
    pin_with("extra");
    let a = varve(&w)
        .args(["install", "--platform", other])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("cannot add one"), "{}", stderr(&a));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn export_bazel_writes_no_registry_for_an_override_without_provenance() {
    let w = world();
    varve(&w).arg("install").assert().success();
    let (bare, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("synth", script("synth-0.60"), "!nosource")],
        &[],
        &[],
    );
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{bare}\"\n"
    ));
    varve(&w).arg("install").assert().success();
    let out = w.project.join("bazel");
    let a = varve(&w)
        .args(["export-bazel", "--out"])
        .arg(&out)
        .assert()
        .success();
    assert!(stderr(&a).contains("skipped synth"), "{}", stderr(&a));
    assert!(!out.join("synth.json").exists(), "never the pinned layer's");
    assert!(out.join("loom.json").exists());
}

/// A pinned layer that composes a layer of realm `beta` shipping its own
/// synth, with the pin choosing acme's synth and overriding it.
fn two_realm_world() -> World {
    let w = world();
    let (beta_sk, beta_pk) = varve_core::generate_root_keypair();
    let beta_registry = w.dir.join("beta-registry");
    let (beta, _) = put_layer_full(
        &beta_registry,
        &beta_sk,
        "2026.05.0",
        "qualified",
        &[("synth", script("synth-beta"), "")],
        &[],
        &[],
    );
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-pinned"), ""),
            ("loom", script("loom-pinned"), ""),
        ],
        &[],
        &[(beta.as_str(), "2026.05.0", "beta")],
    );
    let realms = std::fs::read_to_string(w.project.join("varve-realms.toml")).unwrap();
    std::fs::write(
        w.project.join("varve-realms.toml"),
        format!(
            "{realms}[realm.beta]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
            beta_registry.display(),
            hex::encode(&beta_pk)
        ),
    )
    .unwrap();
    std::fs::write(
        w.project.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
             layer = \"2026.12.0\"\ntools = [\"acme/synth\", \"loom\"]\n\
             [toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
            w.older_digest
        ),
    )
    .unwrap();
    varve(&w).arg("install").assert().success();
    w
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn another_realms_real_provider_of_an_overridden_tool_is_refused() {
    let w = two_realm_world();
    assert_refused(&w, &["run", "beta/synth"], "has overridden");
    assert_refused(&w, &["which", "beta/synth"], "has overridden");
    let a = varve(&w).args(["run", "beta/synth"]).assert().code(1);
    assert!(
        stderr(&a).contains(&w.older_digest),
        "names the override: {}",
        stderr(&a)
    );
    assert!(!w.ran("synth-beta"));
    // The pin's own address runs the override.
    w.clear_marks();
    let a = varve(&w).args(["run", "acme/synth"]).assert().success();
    assert!(stdout(&a).starts_with("synth-0.57 "), "{}", stdout(&a));
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn export_bazel_does_not_refuse_a_composition_conflict_over_an_overridden_tool() {
    // acme and beta both describe synth, differently: without the override
    // that is a refusal. The override replaces synth, so it is not.
    let w = two_realm_world();
    let out = w.project.join("bazel");
    varve(&w)
        .args(["export-bazel", "--out"])
        .arg(&out)
        .assert()
        .success();
    let synth = std::fs::read_to_string(out.join("synth.json")).unwrap();
    let older = varve_core::manifest_digest(&script("synth-0.57"));
    assert!(
        synth.contains(older.strip_prefix("sha256:").unwrap()),
        "{synth}"
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_reexport_never_leaves_the_pins_registry_for_an_overridden_tool() {
    // HIGH (third review): an export-bazel made while the project was pure
    // wrote the pinned synth.json. Re-exported with an override whose layer
    // records no provenance for synth, that file must not survive under a
    // MIXED stamp: Bazel would fetch the pinned synth.
    let w = world();
    varve(&w).arg("install").assert().success();
    let out = w.project.join("bazel");
    varve(&w)
        .args(["export-bazel", "--out"])
        .arg(&out)
        .assert()
        .success();
    assert!(out.join("synth.json").exists(), "the pure export wrote it");
    let (bare, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("synth", script("synth-0.60"), "!nosource")],
        &[],
        &[],
    );
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"2026.09.0\"\ndigest = \"{bare}\"\n"
    ));
    varve(&w).arg("install").assert().success();
    let a = varve(&w)
        .args(["export-bazel", "--out"])
        .arg(&out)
        .assert()
        .success();
    assert!(stderr(&a).contains("removed synth.json"), "{}", stderr(&a));
    assert!(
        !out.join("synth.json").exists(),
        "the pinned registry survived"
    );
    let stamp: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join(".varve-export.json")).unwrap()).unwrap();
    assert!(
        !stamp["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["path"] == "synth.json"),
        "the stamp vouches for a stale registry: {stamp}"
    );
    varve(&w)
        .args(["verify", "--export"])
        .arg(&out)
        .assert()
        .success();
    // A synth.json no earlier export of ours wrote is not ours to delete:
    // refused, rather than sealed under the stamp.
    let foreign = w.project.join("bazel-foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("synth.json"), b"{}").unwrap();
    assert_refused(
        &w,
        &["export-bazel", "--out", "bazel-foreign"],
        "synth.json",
    );
    assert!(!foreign.join(".varve-export.json").exists());
}

/// A world whose pinned layer 2026.12.0 ships synth and wasmrun for this
/// host AND another platform, and whose install for that other platform has
/// already happened (marks recorded). Returns the marks' bytes.
fn other_platform_pin(w: &World) -> Vec<u8> {
    let other = other_platform();
    let on_other = format!(r#","eu.pulseengine.platform":"{other}""#);
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-host"), ""),
            ("synth", script("synth-other"), on_other.as_str()),
            ("wasmrun", script("wasmrun-other"), on_other.as_str()),
        ],
        &[],
        &[],
    );
    std::fs::write(
        w.project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
         layer = \"2026.12.0\"\n",
    )
    .unwrap();
    varve(w)
        .args(["install", "--platform", other])
        .assert()
        .success();
    std::fs::read(marks_file(w)).unwrap()
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_subset_name_the_layer_never_carried_is_refused_before_any_fetch() {
    // MEDIUM (third review): `tools = ["ghost"]` plus an override of ghost.
    // The pinned layer carries no ghost, so the override would ADD one.
    for platform in [None, Some(other_platform())] {
        let w = world();
        let before = match platform {
            None => {
                varve(&w).arg("install").assert().success();
                std::fs::read(marks_file(&w)).unwrap()
            }
            Some(_) => other_platform_pin(&w),
        };
        let pinned = if platform.is_some() {
            "2026.12.0"
        } else {
            PINNED
        };
        let on_other = format!(r#","eu.pulseengine.platform":"{}""#, other_platform());
        let (ghost, _) = put_layer_full(
            &w.registry,
            &w.sk,
            "2026.09.0",
            "qualified",
            &[
                ("ghost", script("ghost"), ""),
                ("ghost", script("ghost-other"), on_other.as_str()),
            ],
            &[],
            &[],
        );
        std::fs::write(
            w.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{pinned}\"\ntools = [\"ghost\"]\n\
                 [toolchain.override.ghost]\nlayer = \"2026.09.0\"\ndigest = \"{ghost}\"\n"
            ),
        )
        .unwrap();
        let mut args = vec!["install"];
        if let Some(p) = platform {
            args.extend(["--platform", p]);
        }
        assert_refused(&w, &args, "cannot add one");
        assert_eq!(
            std::fs::read(marks_file(&w)).unwrap(),
            before,
            "{platform:?}: mark moved"
        );
        assert!(
            !walk_has(&w.root, &ghost.replace(':', "-")),
            "{platform:?}: laid down"
        );
    }
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_of_a_held_payloads_name_is_refused_for_any_platform() {
    // The pinned layer HOLDS a crate named acme-core; it does not dispatch
    // it. An override layer shipping a TOOL of that name would add one.
    let w = world();
    let other = other_platform();
    varve(&w)
        .args(["install", "--platform", other])
        .assert()
        .success();
    let before = std::fs::read(marks_file(&w)).unwrap();
    let on_other = format!(r#","eu.pulseengine.platform":"{other}""#);
    let (tool, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("acme-core", script("acme-core-tool"), on_other.as_str())],
        &[],
        &[],
    );
    w.pin(&format!(
        "[toolchain.override.acme-core]\nlayer = \"2026.09.0\"\ndigest = \"{tool}\"\n"
    ));
    assert_refused(&w, &["install", "--platform", other], "cannot add one");
    assert_eq!(std::fs::read(marks_file(&w)).unwrap(), before, "mark moved");
    assert!(!walk_has(&w.root, &tool.replace(':', "-")), "laid down");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn an_override_layer_already_installed_is_still_checked() {
    // Installed earlier by pinning it directly, for another platform: the
    // override's manifest checks (here: its runner) still apply, and on
    // another platform nothing after them would.
    let w = world();
    other_platform_pin(&w);
    let other = other_platform();
    let on_other =
        format!(r#","eu.pulseengine.platform":"{other}","eu.pulseengine.runner":"wasmrun""#);
    let (alone, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.06.0",
        "qualified",
        &[("synth", script("synth-wasm-alone"), on_other.as_str())],
        &[],
        &[],
    );
    std::fs::write(
        w.project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
         layer = \"2026.06.0\"\n",
    )
    .unwrap();
    varve(&w)
        .args(["install", "--platform", other])
        .assert()
        .success();
    std::fs::write(
        w.project.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
             layer = \"2026.12.0\"\n[toolchain.override.synth]\nlayer = \"2026.06.0\"\n\
             digest = \"{alone}\"\n"
        ),
    )
    .unwrap();
    assert_refused(&w, &["install", "--platform", other], "runner 'wasmrun'");
}

/// Pinned 2026.12.0 whose OWN synth records no provenance (so a pure export
/// writes no synth.json) and whose loom does. Installed, pinned pure.
fn no_provenance_pin_world() -> World {
    let w = world();
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-pinned"), "!nosource"),
            ("loom", script("loom-pinned"), ""),
        ],
        &[],
        &[],
    );
    w.pin_layer("2026.12.0", "");
    varve(&w).arg("install").assert().success();
    w
}

impl World {
    fn pin_layer(&self, layer: &str, extra: &str) {
        std::fs::write(
            self.project.join("varve.toml"),
            format!(
                "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
                 layer = \"{layer}\"\n{extra}"
            ),
        )
        .unwrap();
    }
}

fn export_bazel(w: &World) -> assert_cmd::assert::Assert {
    varve(w).args(["export-bazel", "--out", "bazel"]).assert()
}

fn sha_hex(bytes: &[u8]) -> String {
    varve_core::manifest_digest(bytes)
        .strip_prefix("sha256:")
        .unwrap()
        .to_string()
}

fn override_synth_older(w: &World) -> String {
    format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    )
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn removing_an_override_removes_its_registry_from_the_next_export() {
    // Round 5 #1: the override's synth.json was written by the mixed export;
    // with the override gone and the pin's synth carrying no provenance,
    // nothing writes synth.json — so the old one must go, or the pure stamp
    // seals the override's synth for Bazel to fetch.
    let w = no_provenance_pin_world();
    w.pin_layer("2026.12.0", &override_synth_older(&w));
    varve(&w).arg("install").assert().success();
    export_bazel(&w).success();
    let synth = w.project.join("bazel").join("synth.json");
    assert!(
        std::fs::read_to_string(&synth)
            .unwrap()
            .contains(&sha_hex(&script("synth-0.57")))
    );
    w.pin_layer("2026.12.0", "");
    let a = export_bazel(&w).success();
    assert!(stderr(&a).contains("removed synth.json"), "{}", stderr(&a));
    assert!(
        !synth.exists(),
        "the override's registry survived its override"
    );
    varve(&w)
        .args(["verify", "--export", "bazel"])
        .assert()
        .success();
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn swapping_one_override_for_another_removes_the_first_ones_registry() {
    let w = no_provenance_pin_world();
    w.pin_layer("2026.12.0", &override_synth_older(&w));
    varve(&w).arg("install").assert().success();
    export_bazel(&w).success();
    let (ov, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("loom", script("loom-0.60"), "")],
        &[],
        &[],
    );
    w.pin_layer(
        "2026.12.0",
        &format!("[toolchain.override.loom]\nlayer = \"2026.09.0\"\ndigest = \"{ov}\"\n"),
    );
    varve(&w).arg("install").assert().success();
    export_bazel(&w).success();
    let out = w.project.join("bazel");
    assert!(
        !out.join("synth.json").exists(),
        "the swapped-out override's registry survived"
    );
    assert!(
        std::fs::read_to_string(out.join("loom.json"))
            .unwrap()
            .contains(&sha_hex(&script("loom-0.60")))
    );
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_refused_reexport_leaves_the_directory_as_it_was() {
    // Round 5 #5: every removal and refusal is decided before anything is
    // deleted, and "nothing exported" is decided first of all.
    let w = no_provenance_pin_world();
    w.pin_layer("2026.12.0", &override_synth_older(&w));
    varve(&w).arg("install").assert().success();
    export_bazel(&w).success();
    let out = w.project.join("bazel");
    let snapshot = |d: &Path| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    };
    // (a) A foreign registry: refused, and synth.json (stale once the
    // override is gone) is NOT deleted first.
    std::fs::write(out.join("foo.json"), b"{}").unwrap();
    w.pin_layer("2026.12.0", "");
    let before = snapshot(&out);
    assert_refused(&w, &["export-bazel", "--out", "bazel"], "foo.json");
    assert_eq!(
        snapshot(&out),
        before,
        "the directory changed before the refusal"
    );
    std::fs::remove_file(out.join("foo.json")).unwrap();
    // (b) A recorded registry edited by hand: refused, not deleted.
    std::fs::write(out.join("synth.json"), b"{\"edited\":true}").unwrap();
    let before = snapshot(&out);
    assert_refused(&w, &["export-bazel", "--out", "bazel"], "modified");
    assert_eq!(snapshot(&out), before);
    // (c) Nothing to export at all (loom overridden by a layer with no
    // provenance either): refused before any registry is removed.
    let (bare, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("loom", script("loom-bare"), "!nosource")],
        &[],
        &[],
    );
    w.pin_layer(
        "2026.12.0",
        &format!("[toolchain.override.loom]\nlayer = \"2026.09.0\"\ndigest = \"{bare}\"\n"),
    );
    varve(&w).arg("install").assert().success();
    let before = snapshot(&out);
    assert_refused(&w, &["export-bazel", "--out", "bazel"], "nothing exported");
    assert_eq!(snapshot(&out), before, "removed before 'nothing exported'");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn a_pinned_tool_for_another_platform_only_is_refused_before_any_fetch() {
    // Round 5 #2: the pinned layer ships loom only for another platform;
    // on this host the pin has no loom, so an override of it adds one.
    let w = world();
    let other = other_platform();
    put_layer_full(
        &w.registry,
        &w.sk,
        "2026.12.0",
        "qualified",
        &[
            ("synth", script("synth-host"), ""),
            (
                "loom",
                script("loom-other"),
                &format!(r#","eu.pulseengine.platform":"{other}""#),
            ),
        ],
        &[],
        &[],
    );
    w.pin_layer("2026.12.0", "");
    varve(&w).arg("install").assert().success();
    let before = std::fs::read(marks_file(&w)).unwrap();
    let (ov, _) = put_layer_full(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("loom", script("loom-host"), "")],
        &[],
        &[],
    );
    w.pin_layer(
        "2026.12.0",
        &format!("[toolchain.override.loom]\nlayer = \"2026.09.0\"\ndigest = \"{ov}\"\n"),
    );
    assert_refused(&w, &["install"], "cannot add one");
    assert_eq!(std::fs::read(marks_file(&w)).unwrap(), before, "mark moved");
    assert!(!walk_has(&w.root, &ov.replace(':', "-")), "laid down");
}
