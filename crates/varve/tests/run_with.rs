//! REQ-RUNWITH-001 at the boundary a user touches (DD-043 (7)):
//! `varve run --with <tool>@<version> -- <tool>` runs one command with that
//! tool from another INSTALLED layer of the pin's realm, and nothing persists.
//!
//! One realm, `acme`, whose registry is a plain directory of layers signed by
//! its root: the pinned 2026.11.0 (synth 0.65.0, loom 1.0.0) and 2026.08.0
//! (synth 0.57.0, loom 0.9.0, and a tool the pin does not carry). Every tool
//! is a script that prints which binary it is and the identity variables it
//! was run with, and leaves a marker, so a test can tell WHICH binary ran —
//! and that nothing ran when varve refused.

use assert_cmd::Command;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const PINNED: &str = "2026.11.0";
const OLDER: &str = "2026.08.0";

struct World {
    _tmp: tempfile::TempDir,
    /// varve's TMPDIR, under /tmp: a --with run refuses a TMPDIR with any
    /// parent others can write without the sticky bit, and the test world
    /// itself may live under one (a shared volume, a CI work disk).
    vtmp: tempfile::TempDir,
    dir: PathBuf,
    root: PathBuf,
    project: PathBuf,
    registry: PathBuf,
    realms: String,
    sk: Vec<u8>,
    older_digest: String,
}

fn script(id: &str) -> Vec<u8> {
    format!(
        "#!/bin/sh\necho \"{id} layer=$VARVE_LAYER overrides=$VARVE_OVERRIDES with=$VARVE_WITH\"\n\
         : > \"$RUNWITH_TEST_MARKS/{id}\"\n"
    )
    .into_bytes()
}

/// A SIGNED layer of (tool, version, bytes) on `channel`, written into the
/// registry directory, stamped for this host. Returns its manifest digest.
fn put_layer(
    registry: &Path,
    sk: &[u8],
    layer: &str,
    channel: &str,
    tools: &[(&str, &str, Vec<u8>)],
) -> String {
    let host = varve_core::host_platform();
    let mut entries = Vec::new();
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, version, bytes) in tools {
        let d = varve_core::manifest_digest(bytes);
        entries.push(format!(
            r#"{{"mediaType":"application/octet-stream","digest":"{d}","size":{},"annotations":{{"eu.pulseengine.tool":"{name}","eu.pulseengine.tool.version":"{version}","eu.pulseengine.platform":"{host}"}}}}"#,
            bytes.len()
        ));
        blobs.push((d, bytes.clone()));
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
    digest
}

/// The pinned layer and 2026.08.0 BOTH installed, the pin pure: 2026.08.0 got
/// into the store the only way anything does, through `varve install` (here
/// under a temporary override), and the override was then removed.
fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let root = dir.join("varve-root");
    let project = dir.join("project");
    let registry = dir.join("acme-registry");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(dir.join("marks")).unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    put_layer(
        &registry,
        &sk,
        PINNED,
        "qualified",
        &[
            ("synth", "0.65.0", script("synth-0.65")),
            ("loom", "1.0.0", script("loom-1.0")),
        ],
    );
    let older_digest = put_layer(
        &registry,
        &sk,
        OLDER,
        "qualified",
        &[
            ("synth", "0.57.0", script("synth-0.57")),
            ("loom", "0.9.0", script("loom-0.9")),
            ("extra", "1.0.0", script("extra")),
        ],
    );
    let realms = format!(
        "[realm.acme]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
        registry.display(),
        hex::encode(&pk)
    );
    std::fs::write(project.join("varve-realms.toml"), &realms).unwrap();
    let vtmp = tempfile::Builder::new()
        .prefix("varve-test-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    let w = World {
        _tmp: tmp,
        vtmp,
        dir,
        root,
        project,
        registry,
        realms,
        sk,
        older_digest,
    };
    w.install_also(OLDER, &w.older_digest.clone());
    w
}

impl World {
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

    /// Install `layer` into this realm's store through `varve install`, then
    /// leave the pin pure again.
    fn install_also(&self, layer: &str, digest: &str) {
        self.pin(&format!(
            "[toolchain.override.synth]\nlayer = \"{layer}\"\ndigest = \"{digest}\"\n"
        ));
        varve(self).arg("install").assert().success();
        self.pin("");
    }

    /// varve's TMPDIR: outside the varve root and the project, so a --with
    /// shim directory is visible to the tests and never in the snapshot.
    fn tmp(&self) -> PathBuf {
        // Canonical: varve makes its directory in the canonical TMPDIR
        // (/tmp is /private/tmp on macOS).
        std::fs::canonicalize(self.vtmp.path()).unwrap()
    }

    /// Nothing left in varve's TMPDIR.
    fn tmp_is_empty(&self) -> bool {
        std::fs::read_dir(self.tmp()).unwrap().next().is_none()
    }

    fn marks(&self) -> PathBuf {
        self.dir.join("marks")
    }

    fn ran(&self, id: &str) -> bool {
        self.marks().join(id).exists()
    }

    fn clear_marks(&self) {
        for e in std::fs::read_dir(self.marks()).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
    }

    /// Every file and symlink under the varve root and the project, with its
    /// bytes (or link target) and mode: "nothing persists" is compared on
    /// this, not inferred.
    fn snapshot(&self) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
        let mut out = BTreeMap::new();
        for top in [&self.root, &self.project] {
            let mut stack = vec![top.to_path_buf()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).unwrap() {
                    let p = e.unwrap().path();
                    let meta = std::fs::symlink_metadata(&p).unwrap();
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    if meta.file_type().is_symlink() {
                        let target = std::fs::read_link(&p).unwrap();
                        out.insert(p, (target.into_os_string().into_encoded_bytes(), mode));
                    } else if meta.is_dir() {
                        out.insert(p.clone(), (b"<dir>".to_vec(), mode));
                        stack.push(p);
                    } else {
                        out.insert(p.clone(), (std::fs::read(&p).unwrap(), mode));
                    }
                }
            }
        }
        out
    }
}

fn varve(w: &World) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    let none = w.dir.join("no-user-config");
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_LAYER")
        .env_remove("VARVE_OVERRIDES")
        .env_remove("VARVE_WITH")
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

/// A refusal: exit 1, the reason on stderr, NO tool ran, and the store and
/// project are byte-identical afterwards. Returns stderr.
fn assert_refused(w: &World, args: &[&str], reason: &str) -> String {
    w.clear_marks();
    let before = w.snapshot();
    let a = varve(w).args(args).assert().code(1);
    let err = stderr(&a);
    assert!(
        err.contains(reason),
        "{args:?}: expected {reason:?} in:\n{err}"
    );
    let ran: Vec<_> = std::fs::read_dir(w.marks())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(ran.is_empty(), "{args:?} refused but {ran:?} RAN");
    assert!(
        before == w.snapshot(),
        "{args:?} changed the store or project"
    );
    assert!(w.tmp_is_empty(), "{args:?} left a shim directory");
    err
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn one_command_runs_with_that_version_and_nothing_persists() {
    let w = world();
    let before = w.snapshot();
    // Clause 1: synth from the installed layer that carries 0.57.0, the rest
    // from the pin. Clause 3: the environment states the override.
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert_eq!(
        stdout(&a).trim(),
        format!(
            "synth-0.57 layer={PINNED} overrides=synth={OLDER}@{} with=synth@0.57.0",
            w.older_digest
        )
    );
    assert!(w.ran("synth-0.57") && !w.ran("synth-0.65"));
    // Another tool in the same invocation is the pin's, and the environment
    // still says what the run was given.
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "loom"])
        .assert()
        .success();
    assert!(stdout(&a).starts_with("loom-1.0 "), "{}", stdout(&a));
    assert!(stdout(&a).contains("with=synth@0.57.0"), "{}", stdout(&a));
    // Clause 2: the pin, the store, the rollback marks and project state are
    // byte-identical, and the next command runs the pin.
    assert!(
        before == w.snapshot(),
        "--with changed the store or project"
    );
    w.clear_marks();
    let a = varve(&w)
        .args(["run", "--", "synth"])
        .env("VARVE_WITH", "synth@inherited")
        .env("VARVE_OVERRIDES", "synth=inherited")
        .assert()
        .success();
    assert_eq!(
        stdout(&a).trim(),
        format!("synth-0.65 layer={PINNED} overrides= with="),
        "an inherited VARVE_WITH never describes a run without --with"
    );
    let which = varve(&w).args(["which", "synth"]).assert().success();
    let path = PathBuf::from(stdout(&which).trim());
    assert_eq!(std::fs::read(&path).unwrap(), script("synth-0.65"));
    assert!(
        !stderr(&which).contains("MIXED"),
        "the project is not left mixed: {}",
        stderr(&which)
    );
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn several_with_one_per_tool_and_beside_a_varve_toml_override_of_another_tool() {
    let w = world();
    let a = varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--with",
            "loom@0.9.0",
            "--",
            "loom",
        ])
        .assert()
        .success();
    let d = &w.older_digest;
    assert_eq!(
        stdout(&a).trim(),
        format!(
            "loom-0.9 layer={PINNED} overrides=loom={OLDER}@{d},synth={OLDER}@{d} \
             with=loom@0.9.0,synth@0.57.0"
        )
    );
    // varve.toml overrides loom; --with adds synth for one command.
    w.pin(&format!(
        "[toolchain.override.loom]\nlayer = \"{OLDER}\"\ndigest = \"{d}\"\n"
    ));
    let before = w.snapshot();
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert_eq!(
        stdout(&a).trim(),
        format!(
            "synth-0.57 layer={PINNED} overrides=loom={OLDER}@{d},synth={OLDER}@{d} \
             with=synth@0.57.0"
        )
    );
    assert!(before == w.snapshot());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn every_refusal_runs_nothing_and_changes_nothing() {
    let w = world();
    // Syntax.
    assert_refused(
        &w,
        &["run", "--with", "synth", "--", "synth"],
        "expected <tool>@<version>",
    );
    assert_refused(
        &w,
        &["run", "--with", "acme/synth@0.57.0", "--", "synth"],
        "bare tool name",
    );
    // The same tool twice.
    assert_refused(
        &w,
        &[
            "run",
            "--with",
            "synth@0.57.0",
            "--with",
            "SYNTH@0.65.0",
            "--",
            "synth",
        ],
        "both name",
    );
    // Beside --varve: one layer swapped whole plus a tool from another.
    assert_refused(
        &w,
        &[
            "run",
            "--varve",
            OLDER,
            "--with",
            "synth@0.57.0",
            "--",
            "synth",
        ],
        "nobody declared",
    );
    // A version no installed layer carries: says so, names what is
    // installed, never fetches.
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.99.0", "--", "synth"],
        "no layer installed from realm acme carries synth 0.99.0",
    );
    assert!(err.contains("0.57.0 (layer 2026.08.0"), "{err}");
    assert!(err.contains("0.65.0 (layer 2026.11.0"), "{err}");
    assert!(err.contains("never fetches"), "{err}");
    // A tool the pin does not carry: --with replaces, it never adds
    // (REQ-OVERRIDE-001 clause 4), although 2026.08.0 carries it.
    assert_refused(
        &w,
        &["run", "--with", "extra@1.0.0", "--", "extra"],
        "cannot add one",
    );
    // The same tool already overridden in varve.toml: refused, not replaced.
    w.pin(&format!(
        "[toolchain.override.synth]\nlayer = \"{OLDER}\"\ndigest = \"{}\"\n",
        w.older_digest
    ));
    assert_refused(
        &w,
        &["run", "--with", "synth@0.57.0", "--", "synth"],
        "override of an override",
    );
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn layers_carrying_the_version_pick_one_only_when_they_run_the_same_bytes() {
    let w = world();
    // 2026.09.0 ships the SAME synth 0.57.0 bytes: either layer runs the same
    // thing, so the least (layer id, digest) is chosen — 2026.08.0.
    let same = put_layer(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[
            ("synth", "0.57.0", script("synth-0.57")),
            ("loom", "0.9.1", script("loom-0.9.1")),
        ],
    );
    w.install_also("2026.09.0", &same);
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert!(
        stdout(&a).contains(&format!("overrides=synth={OLDER}@{}", w.older_digest)),
        "{}",
        stdout(&a)
    );
    // 2026.07.0, the least layer id, is installed LAST and still chosen: the
    // choice does not follow install order.
    let least = put_layer(
        &w.registry,
        &w.sk,
        "2026.07.0",
        "qualified",
        &[("synth", "0.57.0", script("synth-0.57"))],
    );
    w.install_also("2026.07.0", &least);
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert!(
        stdout(&a).contains(&format!("overrides=synth=2026.07.0@{least}")),
        "{}",
        stdout(&a)
    );
    // 2026.10.0 ships DIFFERENT bytes under the same version: refused, listing
    // every candidate.
    let other = put_layer(
        &w.registry,
        &w.sk,
        "2026.10.0",
        "qualified",
        &[("synth", "0.57.0", script("synth-0.57-rebuilt"))],
    );
    w.install_also("2026.10.0", &other);
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.57.0", "--", "synth"],
        "do not run the same bytes",
    );
    for part in [&w.older_digest, &same, &other, &least] {
        assert!(err.contains(part.as_str()), "missing {part}: {err}");
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_version_installed_only_under_another_realm_prints_the_lines_that_would_install_it() {
    let w = world();
    let (beta_sk, beta_pk) = varve_core::generate_root_keypair();
    let beta_registry = w.dir.join("beta-registry");
    let foreign = put_layer(
        &beta_registry,
        &beta_sk,
        "2026.07.0",
        "qualified",
        &[("synth", "0.50.0", script("synth-foreign"))],
    );
    let beta = w.dir.join("beta-project");
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(
        beta.join("varve-realms.toml"),
        format!(
            "[realm.beta]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
            beta_registry.display(),
            hex::encode(&beta_pk)
        ),
    )
    .unwrap();
    std::fs::write(
        beta.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"beta\"\nchannel = \"qualified\"\n\
         layer = \"2026.07.0\"\n",
    )
    .unwrap();
    varve(&w)
        .current_dir(&beta)
        .arg("install")
        .assert()
        .success();
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.50.0", "--", "synth"],
        "installed only outside realm acme's store",
    );
    assert!(
        err.contains(&format!(
            "[toolchain.override.synth]\nlayer = \"2026.07.0\"\ndigest = \"{foreign}\"\n"
        )),
        "the exact varve.toml lines: {err}"
    );
    assert!(!w.ran("synth-foreign"));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_layer_on_another_channel_is_no_candidate() {
    // A rolling layer of the same realm, installed by a project pinned to it,
    // carries synth 0.60.0. This qualified pin cannot take an override from
    // it, so --with names it and why, and runs nothing.
    let w = world();
    let rolling = put_layer(
        &w.registry,
        &w.sk,
        "2026.10.0",
        "rolling",
        &[("synth", "0.60.0", script("synth-0.60"))],
    );
    let other = w.dir.join("rolling-project");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("varve-realms.toml"), &w.realms).unwrap();
    std::fs::write(
        other.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\n\
         layer = \"2026.10.0\"\n",
    )
    .unwrap();
    varve(&w)
        .current_dir(&other)
        .arg("install")
        .assert()
        .success();
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.60.0", "--", "synth"],
        "cannot take an override from",
    );
    assert!(
        err.contains(&rolling) && err.contains("channel 'rolling'"),
        "{err}"
    );
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn the_chosen_layer_meets_every_rule_an_override_in_varve_toml_meets() {
    // --with is an override for one command: once a layer is chosen, resolve
    // applies the same checks. Here the chosen layer's synth binary has gone
    // from the store — the refusal is resolve's, naming the in-memory override.
    let w = world();
    let bin = w
        .root
        .join("realms")
        .read_dir()
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.join("core")
                .join(w.older_digest.replace(':', "-"))
                .exists()
        })
        .unwrap()
        .join("core")
        .join(w.older_digest.replace(':', "-"))
        .join("bin")
        .join("synth");
    std::fs::remove_file(&bin).unwrap();
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.57.0", "--", "synth"],
        "--with synth@0.57.0 is applied as an in-memory override",
    );
    assert!(err.contains("does not carry 'synth'"), "{err}");
    assert!(err.contains(&w.older_digest), "{err}");
}

// ---- the command is spawned with a private shim directory first on PATH ----

/// The project's regular shims, so a script's call to a tool `--with` does not
/// override reaches the pin, as on a developer's PATH.
fn with_regular_shims(w: &World) -> String {
    varve(w).args(["shim", "install"]).assert().success();
    format!("{}:/usr/bin:/bin", w.root.join("shims").display())
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_script_calling_the_tool_by_name_gets_the_override_and_nothing_persists() {
    let w = world();
    let path = with_regular_shims(&w);
    let before = w.snapshot();
    // A script, not a layer tool: `synth` by bare name gets 0.57.0 through the
    // private shim, nested shells too; `loom` reaches the pin's regular shim.
    let a = varve(&w)
        .env("PATH", &path)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "echo \"script with=$VARVE_WITH overrides=$VARVE_OVERRIDES\"; synth; \
             sh -c 'sh -c synth'; loom",
        ])
        .assert()
        .success();
    let out = stdout(&a);
    let d = &w.older_digest;
    let synth = format!("synth-0.57 layer={PINNED} overrides=synth={OLDER}@{d} with=synth@0.57.0");
    let expected = vec![
        format!("script with=synth@0.57.0 overrides=synth={OLDER}@{d}"),
        synth.clone(),
        synth,
        format!("loom-1.0 layer={PINNED} overrides=synth={OLDER}@{d} with=synth@0.57.0"),
    ];
    let lines: Vec<String> = out.lines().map(str::to_string).collect();
    assert_eq!(lines, expected, "{out}");
    assert!(!w.ran("synth-0.65"));
    assert!(w.tmp_is_empty(), "the shim directory is removed");
    assert!(
        before == w.snapshot(),
        "--with changed the store or project"
    );
    // Without --with, a bare `synth` is the pin's.
    let a = varve(&w)
        .env("PATH", &path)
        .args(["run", "--", "synth"])
        .assert()
        .success();
    assert!(stdout(&a).starts_with("synth-0.65 "), "{}", stdout(&a));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn the_exit_status_passes_through_and_the_directory_goes_either_way() {
    let w = world();
    // A non-zero exit.
    varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "synth; exit 7",
        ])
        .assert()
        .code(7);
    assert!(w.tmp_is_empty());
    // A layer tool run directly, under --with.
    varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .code(0);
    assert!(w.tmp_is_empty());
    // A child that dies of SIGTERM: varve dies of SIGTERM too.
    varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "kill -TERM $$",
        ])
        .assert()
        .failure();
    {
        use std::os::unix::process::ExitStatusExt;
        let status = varve(&w)
            .args([
                "run",
                "--with",
                "synth@0.57.0",
                "--",
                "sh",
                "-c",
                "kill -TERM $$",
            ])
            .output()
            .unwrap()
            .status;
        assert_eq!(
            status.signal(),
            Some(15),
            "varve dies of the child's signal: {status:?}"
        );
    }
    assert!(w.tmp_is_empty());
    // A command that cannot be started: refused, directory gone.
    varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "no-such-command-anywhere",
        ])
        .assert()
        .code(1);
    assert!(w.tmp_is_empty());
}

/// Start `varve run --with synth@0.57.0 -- sh -c <script>` in the background.
fn spawn_varve(w: &World, script: &str) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let none = w.dir.join("no-user-config");
    std::process::Command::new(assert_cmd::cargo::cargo_bin("varve"))
        .args(["run", "--with", "synth@0.57.0", "--", "sh", "-c", script])
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_WITH")
        .env_remove("VARVE_OVERRIDES")
        .current_dir(&w.project)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap()
}

/// Wait (bounded, 30 s) for the script to write a line to `file`.
fn wait_for(file: &Path) -> String {
    for _ in 0..600 {
        if let Ok(text) = std::fs::read_to_string(file)
            && text.ends_with('\n')
        {
            return text;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("{} never appeared", file.display());
}

/// Signal a whole process group, as a terminal does.
fn send_group(sig: &str, pgid: u32) {
    let ok = std::process::Command::new("kill")
        .args([sig, "--", &format!("-{pgid}")])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill {sig} -{pgid}");
}

fn send(sig: &str, pid: u32) {
    let ok = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok, "kill {sig} {pid}");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_signal_to_varve_is_forwarded_and_the_directory_is_removed() {
    // TERM sent to varve alone is forwarded. INT and HUP come from a terminal
    // to the whole process group, so the child has them already: varve does
    // not forward them, and survives them to clean up.
    for (sig, n, group) in [("-TERM", 15, false), ("-INT", 2, true), ("-HUP", 1, true)] {
        let w = world();
        let ready = w.dir.join("ready");
        // `exec sleep`: the child IS the sleep, so a forwarded signal ends it.
        let script = format!(
            "echo \"${{PATH%%:*}}\" > '{}'; exec sleep 30",
            ready.display()
        );
        let mut child = spawn_varve(&w, &script);
        let dir = PathBuf::from(wait_for(&ready).trim());
        assert!(
            dir.is_dir() && dir.starts_with(w.tmp()),
            "{}",
            dir.display()
        );
        if group {
            send_group(sig, child.id());
        } else {
            send(sig, child.id());
        }
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(n),
            "{sig}: varve dies of it: {status:?}"
        );
        assert!(!dir.exists(), "{sig}: the shim directory is removed");
        assert!(w.tmp_is_empty(), "{sig}");
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_shim_directory_leaked_by_sigkill_grants_nothing_even_when_edited() {
    let w = world();
    let ready = w.dir.join("ready");
    let script = format!(
        "echo \"${{PATH%%:*}} $$\" > '{}'; exec sleep 30",
        ready.display()
    );
    let mut child = spawn_varve(&w, &script);
    let text = wait_for(&ready);
    let (dir, sleeper) = text.trim().split_once(' ').unwrap();
    let dir = PathBuf::from(dir);
    // SIGKILL cannot be caught: the directory leaks.
    send("-KILL", child.id());
    child.wait().unwrap();
    send("-KILL", sleeper.parse().unwrap());
    assert!(dir.is_dir(), "a SIGKILL leaks the directory");
    // Its shim is refused: the varve run that made it is gone.
    let shim = dir.join("synth");
    let run_shim = || {
        let none = w.dir.join("no-user-config");
        Command::new(&shim)
            .env("PATH", "/usr/bin:/bin")
            .env("VARVE_ROOT", &w.root)
            .env("XDG_CONFIG_HOME", &none)
            .env("HOME", &none)
            .env("RUNWITH_TEST_MARKS", w.marks())
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&w.project)
            .assert()
            .code(1)
    };
    w.clear_marks();
    let a = run_shim();
    assert!(stderr(&a).contains("outlived"), "{}", stderr(&a));
    // An edited record changes nothing: it is never read.
    let record = dir.join(".v").join("with.json");
    assert!(record.is_file());
    std::fs::write(&record, "{\"forged\": true}").unwrap();
    let a = run_shim();
    assert!(stderr(&a).contains("outlived"), "{}", stderr(&a));
    for id in ["synth-0.57", "synth-0.65"] {
        assert!(!w.ran(id), "{id} ran from a leaked directory");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn an_edited_record_in_a_live_directory_is_reverified_not_trusted() {
    // While the run lives, its own script rewrites the record: to a digest no
    // installed layer has, and to ANOTHER installed layer that carries synth
    // at another version. Either would make VARVE_WITH lie, so the private
    // shim refuses both and runs nothing.
    let w = world();
    let other = put_layer(
        &w.registry,
        &w.sk,
        "2026.09.0",
        "qualified",
        &[("synth", "0.60.0", script("synth-0.60"))],
    );
    w.install_also("2026.09.0", &other);
    let forged = format!("sha256:{}", "0".repeat(64));
    for (layer, digest) in [(OLDER, forged.as_str()), ("2026.09.0", other.as_str())] {
        let script = format!(
            "rec=\"${{PATH%%:*}}/.v/with.json\"; \
             sed -e 's/{}/{digest}/' -e 's/\"{OLDER}\"/\"{layer}\"/' \"$rec\" > \"$rec.new\" \
             && mv \"$rec.new\" \"$rec\"; synth",
            w.older_digest
        );
        w.clear_marks();
        let a = varve(&w)
            .args(["run", "--with", "synth@0.57.0", "--", "sh", "-c", &script])
            .assert()
            .code(1);
        assert!(
            stderr(&a).contains("does not match"),
            "{layer}: {}",
            stderr(&a)
        );
        for id in ["synth-0.57", "synth-0.60", "synth-0.65"] {
            assert!(!w.ran(id), "{layer}: {id} ran");
        }
        assert!(w.tmp_is_empty());
    }
}

// ---- review findings (feat/run-with review, 2026-11-14) ----

/// Spawn varve and SIGKILL it with its child, leaking its shim directory.
fn leak_a_shim_dir(w: &World) -> PathBuf {
    let ready = w.dir.join("ready");
    let script = format!(
        "echo \"${{PATH%%:*}} $$\" > '{}'; exec sleep 60",
        ready.display()
    );
    let mut child = spawn_varve(w, &script);
    let text = wait_for(&ready);
    let (dir, sleeper) = text.trim().split_once(' ').unwrap();
    send("-KILL", child.id());
    child.wait().unwrap();
    send("-KILL", sleeper.parse().unwrap());
    std::fs::remove_file(&ready).unwrap();
    PathBuf::from(dir)
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn concurrent_shims_into_a_leaked_directory_are_all_refused() {
    // Finding 1: a liveness probe that takes the lock itself makes a leaked
    // directory look alive to every other prober at that instant.
    let w = world();
    let dir = leak_a_shim_dir(&w);
    w.clear_marks();
    let shim = dir.join("synth");
    let none = w.dir.join("no-user-config");
    let mut honoured = 0;
    for _ in 0..40 {
        let kids: Vec<_> = (0..8)
            .map(|_| {
                std::process::Command::new(&shim)
                    .env("PATH", "/usr/bin:/bin")
                    .env("VARVE_ROOT", &w.root)
                    .env("XDG_CONFIG_HOME", &none)
                    .env("HOME", &none)
                    .env("RUNWITH_TEST_MARKS", w.marks())
                    .env_remove("VARVE_TRUST_ROOT")
                    .current_dir(&w.project)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for k in kids {
            if k.wait_with_output().unwrap().status.success() {
                honoured += 1;
            }
        }
    }
    assert_eq!(honoured, 0, "a leaked directory granted the override");
    assert!(!w.ran("synth-0.57"));
    std::fs::remove_dir_all(&dir).unwrap();
}

fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_qualified_name_that_does_not_resolve_never_runs_a_project_file() {
    // Finding 2: `zzz/loom` is a selector, not a path. Plain `run` refuses it;
    // so must --with, instead of running ./zzz/loom from the project tree.
    let w = world();
    executable(
        &w.project.join("zzz").join("loom"),
        "#!/bin/sh\necho PROJECT-FILE-RAN\n",
    );
    let err = assert_refused(
        &w,
        &["run", "--with", "synth@0.57.0", "--", "zzz/loom"],
        "not part of layer",
    );
    assert!(!err.contains("PROJECT-FILE-RAN"));
    // An explicit path is a path: it runs, as the user wrote it.
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "./zzz/loom"])
        .assert()
        .success();
    assert_eq!(stdout(&a).trim(), "PROJECT-FILE-RAN");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_non_ascii_name_never_runs_an_ambient_binary() {
    // Finding 3: U+017F folds onto `synth` on a case-insensitive filesystem;
    // without an ASCII rule an ambient synth runs where the layer carries one.
    let w = world();
    let amb = w.dir.join("amb");
    executable(&amb.join("synth"), "#!/bin/sh\necho AMBIENT-SYNTH-RAN\n");
    let path = format!("/usr/bin:/bin:{}", amb.display());
    let a = varve(&w)
        .env("PATH", &path)
        .args(["run", "--with", "loom@0.9.0", "--", "\u{17f}ynth"])
        .assert()
        .code(1);
    assert!(!stdout(&a).contains("AMBIENT"), "{}", stdout(&a));
    assert!(stderr(&a).contains("not part of layer"), "{}", stderr(&a));
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_temp_parent_others_can_write_without_the_sticky_bit_is_refused() {
    // Finding 4: in such a parent the directory can be swapped, and PATH then
    // runs a foreign binary without ever reaching the wrapper.
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    let open = w.tmp().join("open-tmp");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    w.clear_marks();
    let a = varve(&w)
        .env("TMPDIR", &open)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("others can write"), "{}", stderr(&a));
    assert!(!w.ran("synth-0.57"));
    assert!(std::fs::read_dir(&open).unwrap().next().is_none());
    // The sticky bit (as /tmp has) is what makes such a parent safe.
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
    varve(&w)
        .env("TMPDIR", &open)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert!(std::fs::read_dir(&open).unwrap().next().is_none());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_temp_dir_inside_the_project_or_the_varve_root_is_refused() {
    // Finding 5: "never under VARVE_ROOT or the project" is enforced, not
    // claimed. Refused, not moved elsewhere: TMPDIR is the user's choice, and
    // a guessed fallback would be a second place with its own checks.
    let w = world();
    for inside in [w.project.join("tmp"), w.root.join("tmp")] {
        std::fs::create_dir_all(&inside).unwrap();
        let before = w.snapshot();
        w.clear_marks();
        let a = varve(&w)
            .env("TMPDIR", &inside)
            .args(["run", "--with", "synth@0.57.0", "--", "synth"])
            .assert()
            .code(1);
        assert!(stderr(&a).contains("inside"), "{}", stderr(&a));
        assert!(!w.ran("synth-0.57"));
        assert!(before == w.snapshot(), "{}", inside.display());
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_nested_with_is_refused() {
    // Finding 7: an inner --with inside an outer one would report only its
    // own override while bare calls still get the outer's (clause 3).
    let w = world();
    let inner = format!(
        "{} run --with loom@0.9.0 -- sh -c 'echo inner-ran; synth'",
        assert_cmd::cargo::cargo_bin("varve").display()
    );
    w.clear_marks();
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "sh", "-c", &inner])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("nested"), "{}", stderr(&a));
    assert!(!stdout(&a).contains("inner-ran"), "{}", stdout(&a));
    assert!(!w.ran("synth-0.57") && !w.ran("loom-0.9"));
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_directory_that_cannot_be_removed_warns_and_keeps_the_childs_status() {
    let w = world();
    let a = varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "chmod 500 \"${PATH%%:*}\"; exit 3",
        ])
        .assert()
        .code(3);
    assert!(
        stderr(&a).contains("warning") && stderr(&a).contains("could not remove"),
        "{}",
        stderr(&a)
    );
    use std::os::unix::fs::PermissionsExt;
    for e in std::fs::read_dir(w.tmp()).unwrap() {
        let p = e.unwrap().path();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&p).unwrap();
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn in_another_project_the_wrapper_falls_through_like_a_regular_shim() {
    // A command that cds into another project gets what a regular shim gives
    // there — passthrough included — never the outer override, and the PATH
    // search skips the private directory, so it cannot loop into it.
    let w = world();
    let bare = put_layer(
        &w.registry,
        &w.sk,
        "2026.06.0",
        "qualified",
        &[("loom", "0.8.0", script("loom-0.8"))],
    );
    let other = w.dir.join("other-project");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("varve-realms.toml"), &w.realms).unwrap();
    std::fs::write(
        other.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
             layer = \"2026.06.0\"\ndigest = \"{bare}\"\n"
        ),
    )
    .unwrap();
    varve(&w)
        .current_dir(&other)
        .arg("install")
        .assert()
        .success();
    let cfg = w.dir.join("cfg");
    std::fs::create_dir_all(cfg.join("varve")).unwrap();
    std::fs::write(
        cfg.join("varve").join("config.toml"),
        "[shim]\npassthrough = [\"synth\"]\n",
    )
    .unwrap();
    let amb = w.dir.join("amb");
    executable(&amb.join("synth"), "#!/bin/sh\necho AMBIENT-SYNTH-RAN\n");
    let a = varve(&w)
        .env("XDG_CONFIG_HOME", &cfg)
        .env("PATH", format!("/usr/bin:/bin:{}", amb.display()))
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            &format!("cd '{}' && synth", other.display()),
        ])
        .assert()
        .success();
    assert_eq!(stdout(&a).trim(), "AMBIENT-SYNTH-RAN", "{}", stderr(&a));
    assert!(stderr(&a).contains("passthrough"), "{}", stderr(&a));
    assert!(!w.ran("synth-0.57"));
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tmpdir_below_a_directory_others_can_write_is_refused() {
    // A foreign-writable, non-sticky ANCESTOR lets someone replace a whole
    // path component above TMPDIR, however private TMPDIR itself is.
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    let above = w.tmp().join("open-above");
    let inner = above.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o777)).unwrap();
    w.clear_marks();
    let a = varve(&w)
        .env("TMPDIR", &inner)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .code(1);
    let err = stderr(&a);
    assert!(
        err.contains("others can write") && err.contains("open-above"),
        "{err}"
    );
    assert!(!w.ran("synth-0.57"));
    assert!(std::fs::read_dir(&inner).unwrap().next().is_none());
    // Sticky, as /tmp is: accepted.
    std::fs::set_permissions(&above, std::fs::Permissions::from_mode(0o1777)).unwrap();
    varve(&w)
        .env("TMPDIR", &inner)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert!(std::fs::read_dir(&inner).unwrap().next().is_none());
}

// ---- second review (2026-11-14): signal semantics and the outer tree ----

/// `/bin/sh -c <outer>` in its own process group, with varve as `$VARVE`.
fn spawn_sh(w: &World, outer: &str) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let none = w.dir.join("no-user-config");
    std::process::Command::new("/bin/sh")
        .args(["-c", outer])
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE", assert_cmd::cargo::cargo_bin("varve"))
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_WITH")
        .env_remove("VARVE_OVERRIDES")
        .current_dir(&w.project)
        .process_group(0)
        .spawn()
        .unwrap()
}

/// Wait (bounded, 60 s) for a process to exit.
fn wait_exit(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    for _ in 0..1200 {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    None
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_signal_ignored_when_varve_starts_stays_ignored_in_the_child() {
    // `nohup`, `trap '' HUP`, `cmd &` in a non-interactive shell: an ignored
    // signal survives exec into the command, as it would without varve.
    for sig in ["HUP", "INT"] {
        let w = world();
        let ready = w.dir.join("ready");
        let stop = w.dir.join("stop");
        let survived = w.dir.join("survived");
        let outer = format!(
            "trap '' {sig}; exec \"$VARVE\" run --with synth@0.57.0 -- sh -c \
             \"echo r > '{}'; while [ ! -e '{}' ]; do sleep 0.05; done; echo s > '{}'\"",
            ready.display(),
            stop.display(),
            survived.display()
        );
        let mut child = spawn_sh(&w, &outer);
        wait_for(&ready);
        send_group(&format!("-{sig}"), child.id());
        // Give a would-be death every chance, then let a survivor finish.
        let early = {
            let mut done = None;
            for _ in 0..20 {
                if let Some(status) = child.try_wait().unwrap() {
                    done = Some(status);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            done
        };
        std::fs::write(&stop, "").unwrap();
        let status = early
            .or_else(|| wait_exit(&mut child))
            .expect("varve never exited");
        assert!(
            survived.exists(),
            "{sig}: the child died of a signal its parent ignored ({status:?})"
        );
        assert_eq!(status.code(), Some(0), "{sig}");
        assert!(w.tmp_is_empty(), "{sig}");
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn ctrl_c_stops_a_shell_loop_around_with() {
    // bash aborts a loop on Ctrl-C only if the foreground child died OF
    // SIGINT; varve, after cleaning up, dies of the signal its child died of.
    let w = world();
    let log = w.dir.join("log");
    let stop = w.dir.join("stop");
    let bash = format!(
        "exec bash -c 'for i in 1 2; do \"$VARVE\" run --with synth@0.57.0 -- sh -c \
         \"echo r$i >> {l}; while [ ! -e {s} ]; do sleep 0.05; done\"; done; echo finished >> {l}'",
        l = log.display(),
        s = stop.display()
    );
    let mut child = spawn_sh(&w, &bash);
    wait_for(&log);
    send_group("-INT", child.id());
    // Either bash stops, or it starts round 2 (the failure); never hang.
    let mut status = None;
    for _ in 0..1200 {
        if let Some(s) = child.try_wait().unwrap() {
            status = Some(s);
            break;
        }
        if std::fs::read_to_string(&log).unwrap().contains("r2") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::fs::write(&stop, "").unwrap();
    let status = status.or_else(|| wait_exit(&mut child));
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text, "r1\n", "Ctrl-C did not stop the loop ({status:?})");
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_terminal_signal_sent_to_varve_alone_never_reaches_the_child() {
    // INT, QUIT and HUP reach a child through the terminal's process group,
    // never from varve: sent to varve's pid alone, the child must not see
    // them (a forwarding varve would hand them on). varve survives them and
    // the child finishes normally.
    let w = world();
    let ready = w.dir.join("ready");
    let stop = w.dir.join("stop");
    let seen = w.dir.join("seen");
    let script = format!(
        "for s in INT QUIT HUP; do trap \"echo $s >> '{seen}'\" $s; done; \
         echo r > '{ready}'; while [ ! -e '{stop}' ]; do sleep 0.05; done; echo done >> '{seen}'",
        seen = seen.display(),
        ready = ready.display(),
        stop = stop.display()
    );
    let mut child = spawn_varve(&w, &script);
    wait_for(&ready);
    for sig in ["-INT", "-QUIT", "-HUP"] {
        send(sig, child.id());
    }
    // A forwarded signal arrives in microseconds; two seconds is generous.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(
        child.try_wait().unwrap().is_none(),
        "varve died of a terminal signal"
    );
    std::fs::write(&stop, "").unwrap();
    let status = wait_exit(&mut child).expect("varve never exited");
    assert_eq!(status.code(), Some(0));
    assert_eq!(
        wait_for(&seen),
        "done\n",
        "the child saw a signal sent to varve alone"
    );
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_dead_shim_directory_on_path_is_not_an_outer_run() {
    // A leaked directory still on PATH is not a live outer --with: a fresh
    // --with runs, and a plain run gets the pin.
    let w = world();
    let dir = leak_a_shim_dir(&w);
    let path = format!("{}:/usr/bin:/bin", dir.display());
    let a = varve(&w)
        .env("PATH", &path)
        .args(["run", "--with", "synth@0.57.0", "--", "synth"])
        .assert()
        .success();
    assert!(stdout(&a).starts_with("synth-0.57 "), "{}", stderr(&a));
    let a = varve(&w)
        .env("PATH", &path)
        .args(["run", "--", "synth"])
        .assert()
        .success();
    assert!(
        stdout(&a).contains("synth-0.65 layer=2026.11.0 overrides= with="),
        "{}",
        stdout(&a)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_relative_path_entry_is_never_searched_for_the_command() {
    // `.` on PATH would run a file from the repository under a bare name.
    let w = world();
    executable(&w.project.join("zzmake"), "#!/bin/sh\necho REPO-FILE-RAN\n");
    let a = varve(&w)
        .env("PATH", ".:/usr/bin:/bin")
        .args(["run", "--with", "synth@0.57.0", "--", "zzmake"])
        .assert()
        .code(1);
    assert!(!stdout(&a).contains("REPO-FILE-RAN"), "{}", stdout(&a));
    assert!(w.tmp_is_empty());
}

// ---- third review (2026-11-14) ----

// rivet: verifies REQ-RUNWITH-001
#[test]
fn no_shell_stands_between_varve_and_the_command_or_its_shims() {
    // Under bash-as-sh, BASH_FUNC_read%% replaced `read` and SHELLOPTS=noexec
    // made a shell read without running. Neither may reach the gate or a
    // private shim: the right tool runs, through the wrapper. (These variables
    // bite where /bin/sh is bash — macOS, Fedora. Where it is dash, as on
    // Ubuntu, they could not have, so there this shows only that the run is
    // unaffected; the macOS run is the one that would go red.)
    let w = world();
    let evil = w.tmp().join("evil");
    executable(&evil.join("synth"), "#!/bin/sh\necho EVIL-SYNTH\n");
    let func = format!("() {{ d={}; }}", evil.display());
    for (key, value) in [
        ("BASH_FUNC_read%%", func.as_str()),
        ("BASH_FUNC_exec%%", func.as_str()),
        ("BASH_ENV", "/dev/null"),
    ] {
        w.clear_marks();
        let a = varve(&w)
            .env(key, value)
            .args([
                "run",
                "--with",
                "synth@0.57.0",
                "--",
                "/usr/bin/env",
                "synth",
            ])
            .assert()
            .success();
        let out = stdout(&a);
        assert!(
            out.starts_with("synth-0.57 "),
            "{key}: {out} {}",
            stderr(&a)
        );
        assert!(!out.contains("EVIL"), "{key}: {out}");
        assert!(w.ran("synth-0.57"), "{key}");
    }
    // SHELLOPTS=noexec made the old shell gate read the command and run
    // nothing. (The fixture's tools are themselves sh scripts, which it would
    // silence too, so a program that is not a script shows it.)
    let touched = w.dir.join("touched");
    varve(&w)
        .env("SHELLOPTS", "noexec")
        .args(["run", "--with", "synth@0.57.0", "--", "/usr/bin/touch"])
        .arg(&touched)
        .assert()
        .success();
    assert!(touched.exists(), "SHELLOPTS=noexec: the command never ran");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn high_numbered_inherited_descriptors_do_not_break_the_run() {
    // A gate that handed over a pipe on a high fd broke under dash (it rejects
    // fds >= 10). Start varve with fds 3-15 open and prove they reached the
    // command: it lists its own /dev/fd. The fds are opened by bash, named
    // absolutely — /bin/sh is dash on Ubuntu, which cannot open them at all.
    let Some(bash) = ["/bin/bash", "/usr/bin/bash"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.is_file())
    else {
        eprintln!("NOT RUN: no bash at /bin/bash or /usr/bin/bash to open fds 10-15");
        return;
    };
    use std::os::unix::process::CommandExt;
    let w = world();
    let opener = (3..=15)
        .map(|fd| format!("exec {fd}</dev/null; "))
        .collect::<String>();
    let fds = w.dir.join("fds");
    let out = w.dir.join("out");
    let none = w.dir.join("no-user-config");
    let mut child = std::process::Command::new(bash)
        .arg("-c")
        .arg(format!(
            "{opener}exec \"$VARVE\" run --with synth@0.57.0 -- sh -c 'ls /dev/fd > \"{}\"; synth > \"{}\"'",
            fds.display(),
            out.display()
        ))
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE", assert_cmd::cargo::cargo_bin("varve"))
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_WITH")
        .env_remove("VARVE_OVERRIDES")
        .current_dir(&w.project)
        .process_group(0)
        .spawn()
        .unwrap();
    let status = wait_exit(&mut child).expect("varve never exited");
    assert_eq!(status.code(), Some(0));
    let open: Vec<String> = std::fs::read_to_string(&fds)
        .expect("the command never ran")
        .lines()
        .map(str::to_string)
        .collect();
    for fd in 10..=15 {
        assert!(
            open.contains(&fd.to_string()),
            "fd {fd} did not reach the command: {open:?}"
        );
    }
    let out = std::fs::read_to_string(&out).unwrap();
    assert!(out.starts_with("synth-0.57 "), "{out}");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tmpdir_with_a_path_separator_or_newline_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    // `…/a:b` as TMPDIR would put `…/a` (world-writable, never checked)
    // first on PATH.
    let planted = w.tmp().join("a");
    executable(&planted.join("synth"), "#!/bin/sh\necho PLANTED-SYNTH\n");
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o777)).unwrap();
    for name in ["a:b", "c\nd"] {
        let t = w.tmp().join(name);
        std::fs::create_dir(&t).unwrap();
        std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o700)).unwrap();
        w.clear_marks();
        let a = varve(&w)
            .env("TMPDIR", &t)
            .args([
                "run",
                "--with",
                "synth@0.57.0",
                "--",
                "/usr/bin/env",
                "synth",
            ])
            .assert()
            .code(1);
        assert!(!stdout(&a).contains("PLANTED"), "{name:?}: {}", stdout(&a));
        assert!(
            stderr(&a).contains("split PATH"),
            "{name:?}: {}",
            stderr(&a)
        );
        assert!(std::fs::read_dir(&t).unwrap().next().is_none());
    }
}

/// A directory that LOOKS like a live --with tree of this project: the
/// record of a real run, and a lock held by this test process. No varve run
/// is alive.
fn forge_live_tree(w: &World) -> (tempfile::TempDir, std::fs::File) {
    let a = varve(w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "cat \"${PATH%%:*}/.v/with.json\"",
        ])
        .assert()
        .success();
    let forged = tempfile::Builder::new()
        .prefix("varve-with-forged-")
        .tempdir_in(w.tmp())
        .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(forged.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::create_dir(forged.path().join(".v")).unwrap();
    std::fs::write(forged.path().join(".v").join("with.json"), stdout(&a)).unwrap();
    let lock = std::fs::File::create(forged.path().join(".v").join("owner.lock")).unwrap();
    lock.lock().unwrap();
    (forged, lock)
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn ambient_state_never_selects_a_tool_for_a_plain_run() {
    // A forged "live tree" on PATH can only make a plain run REFUSE the tool
    // it names; it never makes it run another version.
    let w = world();
    let (forged, lock) = forge_live_tree(&w);
    let path = format!("{}:/usr/bin:/bin", forged.path().display());
    w.clear_marks();
    let a = varve(&w)
        .env("PATH", &path)
        .args(["run", "--", "synth"])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("already resolves"), "{}", stderr(&a));
    assert!(!w.ran("synth-0.57") && !w.ran("synth-0.65"));
    // Another tool runs from the pin, the inherited VARVE_* passed through.
    let a = varve(&w)
        .env("PATH", &path)
        .env("VARVE_WITH", "inherited-with")
        .env("VARVE_OVERRIDES", "inherited-overrides")
        .args(["run", "--", "loom"])
        .assert()
        .success();
    assert_eq!(
        stdout(&a).trim(),
        format!("loom-1.0 layer={PINNED} overrides=inherited-overrides with=inherited-with")
    );
    // Once the lock is released, nothing about it remains. (Bounded retry: a
    // child another test thread forked holds a duplicate of the lock's fd
    // until it execs, so the release can take a moment to be seen.)
    drop(lock);
    let mut last = String::new();
    for _ in 0..50 {
        let out = varve(&w)
            .env("PATH", &path)
            .args(["run", "--", "synth"])
            .output()
            .unwrap();
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.status.success() && last.starts_with("synth-0.65 ") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    assert!(last.starts_with("synth-0.65 "), "{last}");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn inside_a_with_tree_plain_runs_refuse_the_overridden_tool_and_pass_the_rest_through() {
    let w = world();
    let path = with_regular_shims(&w);
    let v = assert_cmd::cargo::cargo_bin("varve");
    let shim = w.root.join("shims").join("synth");
    w.clear_marks();
    let a = varve(&w)
        .env("PATH", &path)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            &format!(
                "'{v}' run -- loom; '{v}' run -- synth; '{shim}'; '{v}' which synth; echo end",
                v = v.display(),
                shim = shim.display()
            ),
        ])
        .assert()
        .success();
    let d = &w.older_digest;
    let out = stdout(&a);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        format!("loom-1.0 layer={PINNED} overrides=synth={OLDER}@{d} with=synth@0.57.0"),
        "{out}"
    );
    assert_eq!(*lines.last().unwrap(), "end");
    let err = stderr(&a);
    assert_eq!(
        err.matches("already resolves").count(),
        2,
        "plain run and regular shim: {err}"
    );
    assert!(
        err.contains("note:") && err.contains("synth@0.57.0"),
        "which notes it: {err}"
    );
    assert!(!w.ran("synth-0.65") && !w.ran("synth-0.57"));
    // `--varve` inside the tree is refused.
    let a = varve(&w)
        .env("PATH", &path)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            &format!("'{}' run --varve {OLDER} -- loom", v.display()),
        ])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("--varve"), "{}", stderr(&a));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_live_with_of_another_project_does_not_refuse_a_with_here() {
    // Only same-project nesting is refused.
    let w = world();
    let other = w.dir.join("other-project");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("varve-realms.toml"), &w.realms).unwrap();
    std::fs::write(
        other.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
             layer = \"{OLDER}\"\n"
        ),
    )
    .unwrap();
    let v = assert_cmd::cargo::cargo_bin("varve");
    let a = varve(&w)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            &format!(
                "cd '{}' && '{}' run --with loom@1.0.0 -- loom",
                other.display(),
                v.display()
            ),
        ])
        .assert()
        .success();
    assert!(
        stdout(&a).starts_with("loom-1.0 layer=2026.08.0 ")
            && stdout(&a).contains("with=loom@1.0.0"),
        "{} {}",
        stdout(&a),
        stderr(&a)
    );
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_fifo_planted_as_the_lock_neither_hangs_nor_fails_a_plain_run() {
    let w = world();
    let trap = w.tmp().join("varve-with-trap");
    std::fs::create_dir(&trap).unwrap();
    std::fs::create_dir(trap.join(".v")).unwrap();
    std::fs::write(trap.join(".v").join("with.json"), "{}").unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(trap.join(".v").join("owner.lock"))
            .status()
            .unwrap()
            .success()
    );
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("varve"))
        .args(["run", "--", "synth"])
        .env("PATH", format!("{}:/usr/bin:/bin", trap.display()))
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", w.dir.join("no-user-config"))
        .env("HOME", w.dir.join("no-user-config"))
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&w.project)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_exit(&mut child);
    if status.is_none() {
        let _ = child.kill();
        panic!("a FIFO named owner.lock hung a plain run");
    }
    assert_eq!(status.unwrap().code(), Some(0));
    assert!(w.ran("synth-0.65"));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_child_killed_by_a_core_dumping_signal_does_not_crash_varve() {
    use std::os::unix::process::ExitStatusExt;
    let w = world();
    for (sig, n) in [("SEGV", 11), ("ABRT", 6), ("QUIT", 3)] {
        let status = varve(&w)
            .args([
                "run",
                "--with",
                "synth@0.57.0",
                "--",
                "sh",
                "-c",
                &format!("kill -{sig} $$"),
            ])
            .output()
            .unwrap()
            .status;
        assert_eq!(
            status.signal(),
            None,
            "{sig}: varve must not die of it: {status:?}"
        );
        assert_eq!(status.code(), Some(128 + n), "{sig}");
    }
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn an_inherited_sigchld_ignore_keeps_the_exit_status() {
    // An ignored SIGCHLD makes the kernel reap children unasked; varve must
    // still learn its command's status.
    let w = world();
    let out = std::process::Command::new("/usr/bin/perl")
        .args(["-e", "$SIG{CHLD}='IGNORE'; exec @ARGV or die"])
        .arg(assert_cmd::cargo::cargo_bin("varve"))
        .args(["run", "--with", "synth@0.57.0", "--", "sh", "-c", "exit 7"])
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", w.dir.join("no-user-config"))
        .env("HOME", w.dir.join("no-user-config"))
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&w.project)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(w.tmp_is_empty());
}

/// Start `varve run --with synth@0.57.0 -- sh -c <script>` paused in setup
/// (the debug-only hook): it waits, handlers installed and the directory
/// made, until `release` is removed.
fn spawn_paused(w: &World, outer_prefix: &str, script: &str) -> (std::process::Child, PathBuf) {
    let release = w.dir.join("release");
    std::fs::write(&release, "").unwrap();
    let outer =
        format!("{outer_prefix} exec \"$VARVE\" run --with synth@0.57.0 -- sh -c '{script}'");
    let mut cmd_env = spawn_sh_cmd(w, &outer);
    cmd_env.env("VARVE_TEST_PAUSE_SETUP", &release);
    (cmd_env.spawn().unwrap(), release)
}

fn spawn_sh_cmd(w: &World, outer: &str) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let none = w.dir.join("no-user-config");
    let mut c = std::process::Command::new("/bin/sh");
    c.args(["-c", outer])
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE", assert_cmd::cargo::cargo_bin("varve"))
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_WITH")
        .env_remove("VARVE_OVERRIDES")
        .current_dir(&w.project)
        .process_group(0);
    c
}

/// Wait (bounded) until varve has reached its setup pause.
fn wait_for_setup(w: &World) {
    for _ in 0..1200 {
        if w.dir.join("release.paused").exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("varve never reached its setup pause");
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_signal_during_setup_abandons_the_run_unless_it_was_ignored() {
    use std::os::unix::process::ExitStatusExt;
    let ran = |w: &World| w.dir.join("ran");
    let script = |w: &World| format!("echo yes > {}; synth", ran(w).display());
    // A terminal Ctrl-C (the group) during setup: the command never starts,
    // the directory goes, varve dies of SIGINT.
    {
        let w = world();
        let (mut child, release) = spawn_paused(&w, "", &script(&w));
        wait_for_setup(&w);
        send_group("-INT", child.id());
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::remove_file(&release).unwrap();
        let status = wait_exit(&mut child).expect("varve never exited");
        assert_eq!(status.signal(), Some(2), "{status:?}");
        assert!(
            !ran(&w).exists(),
            "the command started after a Ctrl-C during setup"
        );
        assert!(w.tmp_is_empty());
    }
    // SIGTERM to varve alone during setup: forwarded, the run abandoned.
    {
        let w = world();
        let (mut child, release) = spawn_paused(&w, "", &script(&w));
        wait_for_setup(&w);
        send("-TERM", child.id());
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::remove_file(&release).unwrap();
        let status = wait_exit(&mut child).expect("varve never exited");
        assert_eq!(status.signal(), Some(15), "{status:?}");
        assert!(!ran(&w).exists());
        assert!(w.tmp_is_empty());
    }
    // An INT ignored when varve started (`trap '' INT`, `cmd &`) does not
    // abandon setup: the command runs.
    {
        let w = world();
        let (mut child, release) = spawn_paused(&w, "trap '' INT HUP;", &script(&w));
        wait_for_setup(&w);
        send_group("-INT", child.id());
        send_group("-HUP", child.id());
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::remove_file(&release).unwrap();
        let status = wait_exit(&mut child).expect("varve never exited");
        assert_eq!(status.code(), Some(0), "{status:?}");
        assert!(ran(&w).exists(), "an ignored signal abandoned the run");
        assert!(w.tmp_is_empty());
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_terminal_sigquit_removes_the_directory_and_exits_131() {
    // Ctrl-\ reaches the child through the group; varve survives it, cleans
    // up, and — SIGQUIT dumps core — exits 128 + 3 instead of crashing itself.
    let w = world();
    let ready = w.dir.join("ready");
    let script = format!(
        "echo \"${{PATH%%:*}}\" > '{}'; exec sleep 30",
        ready.display()
    );
    let mut child = spawn_varve(&w, &script);
    let dir = PathBuf::from(wait_for(&ready).trim());
    send_group("-QUIT", child.id());
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        (status.code(), status.signal()),
        (Some(131), None),
        "{status:?}"
    );
    assert!(!dir.exists());
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tmpdir_where_programs_cannot_run_is_refused() {
    // On a noexec TMPDIR every wrapper fails to start, and a bare call would
    // silently reach the next program on PATH while VARVE_WITH claimed the
    // override. Making such a mount needs the host's help, so this runs where
    // VARVE_TEST_NOEXEC_DIR names a directory on one (e.g. a RAM disk mounted
    // with -o noexec); elsewhere it reports that it did not run.
    let Some(mount) = std::env::var_os("VARVE_TEST_NOEXEC_DIR") else {
        eprintln!("not run: VARVE_TEST_NOEXEC_DIR is not set");
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    let t = tempfile::Builder::new()
        .prefix("varve-test-")
        .tempdir_in(&mount)
        .unwrap();
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let amb = w.dir.join("amb");
    executable(&amb.join("synth"), "#!/bin/sh\necho AMBIENT-SYNTH\n");
    w.clear_marks();
    let a = varve(&w)
        .env("TMPDIR", t.path())
        .env("PATH", format!("/usr/bin:/bin:{}", amb.display()))
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "/usr/bin/env",
            "synth",
        ])
        .assert()
        .code(1);
    assert!(!stdout(&a).contains("AMBIENT"), "{}", stdout(&a));
    assert!(stderr(&a).contains("cannot be run"), "{}", stderr(&a));
    assert!(std::fs::read_dir(t.path()).unwrap().next().is_none());
}

// ---- fourth review (2026-11-14) ----

/// A copy of varve at a path this test controls.
fn varve_copy(w: &World, name: &str) -> PathBuf {
    let bin = w.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let p = bin.join(name);
    std::fs::copy(assert_cmd::cargo::cargo_bin("varve"), &p).unwrap();
    p
}

/// `varve(w)`, but running the binary at `exe`.
fn varve_at(w: &World, exe: &Path) -> Command {
    let mut cmd = Command::new(exe);
    let none = w.dir.join("no-user-config");
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("RUNWITH_TEST_MARKS", w.marks())
        .env("TMPDIR", w.tmp())
        .env_remove("VARVE_TRUST_ROOT")
        .env_remove("VARVE_LAYER")
        .env_remove("VARVE_OVERRIDES")
        .env_remove("VARVE_WITH")
        .current_dir(&w.project);
    cmd
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_varve_binary_removed_mid_run_does_not_let_a_bare_call_fall_through() {
    // An upgrade or cleanup removes the installed varve while the command
    // runs. Wrappers naming it would fail with ENOENT, and execvp would try
    // the next PATH entry: an ambient synth, under VARVE_WITH=synth@0.57.0.
    let w = world();
    let copy = varve_copy(&w, "varve");
    let amb = w.dir.join("amb");
    executable(&amb.join("synth"), "#!/bin/sh\necho \"AMBIENT-SYNTH\"\n");
    w.clear_marks();
    let a = varve_at(&w, &copy)
        .env("PATH", format!("/usr/bin:/bin:{}", amb.display()))
        .env("VCOPY", &copy)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "/usr/bin/env synth; rm \"$VCOPY\"; /usr/bin/env synth",
        ])
        .assert()
        .success();
    let out = stdout(&a);
    assert!(!out.contains("AMBIENT"), "{out}");
    assert_eq!(
        out.matches("synth-0.57 ").count(),
        2,
        "{out} {}",
        stderr(&a)
    );
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_missing_explicit_program_is_refused_and_nothing_is_made() {
    let w = world();
    let a = varve(&w)
        .args(["run", "--with", "synth@0.57.0", "--", "./no-such-program"])
        .assert()
        .code(1);
    assert!(stderr(&a).contains("no-such-program"), "{}", stderr(&a));
    assert!(
        w.tmp_is_empty(),
        "a directory was made for a command that does not exist"
    );
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn the_gate_takes_pid_1_as_a_parent() {
    // varve as a container's entrypoint is pid 1, and tells its gate so. Run
    // here, our parent is not pid 1, so the gate gives up as orphaned — but it
    // must not refuse the request itself.
    let w = world();
    let a = varve(&w)
        .args(["--varve-with-gate", "1"])
        .arg(varve_core::runwith::build_identity())
        .arg(w.tmp().join("varve-with-x"))
        .args(["--", "/usr/bin/true"])
        .assert()
        .code(125);
    assert!(!stderr(&a).contains("pid"), "{}", stderr(&a));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_varve_binary_under_another_name_still_runs_its_gate() {
    // On Linux current_exe() resolves `varve -> varve-0.48.0`; the gate and
    // wrappers then ran under the real name, which argv[0] took for a shim.
    let w = world();
    let real = varve_copy(&w, "varve-0.48.0");
    let a = varve_at(&w, &real)
        .args(["--varve-with-gate", "4242"])
        .arg(varve_core::runwith::build_identity())
        .arg(w.tmp().join("varve-with-x"))
        .args(["--", "/usr/bin/true"])
        .assert()
        .code(125);
    assert!(!stderr(&a).contains("invoked as"), "{}", stderr(&a));
    // …and a run through a symlink named varve works end to end.
    let link = w.dir.join("bin").join("varve");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let a = varve_at(&w, &link)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "/usr/bin/env",
            "synth",
        ])
        .assert()
        .success();
    assert!(stdout(&a).starts_with("synth-0.57 "), "{}", stderr(&a));
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn the_gate_gives_up_when_varve_is_killed_during_setup() {
    // SIGKILL cannot be caught: varve dies mid-setup. Its gate must notice,
    // run nothing, and exit — no process of the run may outlive it.
    use std::os::unix::process::CommandExt;
    let w = world();
    let release = w.dir.join("release");
    std::fs::write(&release, "").unwrap();
    let ran = w.dir.join("ran");
    let none = w.dir.join("no-user-config");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("varve"))
        .args(["run", "--with", "synth@0.57.0", "--", "/usr/bin/touch"])
        .arg(&ran)
        .env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &w.root)
        .env("XDG_CONFIG_HOME", &none)
        .env("HOME", &none)
        .env("TMPDIR", w.tmp())
        .env("VARVE_TEST_PAUSE_SETUP", &release)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&w.project)
        .process_group(0)
        .spawn()
        .unwrap();
    let pg = child.id();
    wait_for_file(&w.dir.join("release.paused"));
    let members = || {
        let o = std::process::Command::new("ps")
            .args(["-A", "-o", "pid=,pgid="])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| l.split_whitespace().nth(1) == Some(pg.to_string().as_str()))
            .count()
    };
    assert!(members() >= 2, "varve and its gate");
    send("-KILL", pg);
    child.wait().unwrap();
    let mut left = members();
    for _ in 0..600 {
        if left == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        left = members();
    }
    std::fs::remove_file(&release).ok();
    assert_eq!(left, 0, "the gate outlived varve");
    assert!(!ran.exists(), "the command ran after varve was killed");
}

/// Wait (bounded, 60 s) for a file to exist.
fn wait_for_file(file: &Path) {
    for _ in 0..1200 {
        if file.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("{} never appeared", file.display());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_hard_linked_varve_keeps_the_installed_binarys_mode() {
    // A hard link shares the inode: changing the link's mode changes the
    // installed varve's, and other users could no longer run it.
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    // The installed varve on the same filesystem as TMPDIR, so the link is made.
    let installed = w.tmp().join("installed");
    std::fs::create_dir(&installed).unwrap();
    let varve_bin = installed.join("varve");
    std::fs::copy(assert_cmd::cargo::cargo_bin("varve"), &varve_bin).unwrap();
    std::fs::set_permissions(&varve_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let a = varve_at(&w, &varve_bin)
        .env("VINSTALLED", &varve_bin)
        .args([
            "run",
            "--with",
            "synth@0.57.0",
            "--",
            "sh",
            "-c",
            "ls -i \"${PATH%%:*}/.v/varve\" \"$VINSTALLED\"",
        ])
        .assert()
        .success();
    let inodes: Vec<String> = stdout(&a)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect();
    assert_eq!(inodes.len(), 2, "{}", stdout(&a));
    assert_eq!(
        inodes[0],
        inodes[1],
        "the link was not made: {}",
        stdout(&a)
    );
    let mode = std::fs::metadata(&varve_bin).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o755,
        "the installed varve's mode was changed to {mode:o}"
    );
}

// ---- fifth review (2026-11-14) ----

/// `world()`, except both layers also carry a tool named `name` (1.0.0 in
/// the pin, 0.9.0 in the older layer).
fn world_with_tool(name: &str) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let root = dir.join("varve-root");
    let project = dir.join("project");
    let registry = dir.join("acme-registry");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(dir.join("marks")).unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    put_layer(
        &registry,
        &sk,
        PINNED,
        "qualified",
        &[
            ("synth", "0.65.0", script("synth-0.65")),
            (name, "1.0.0", script("named-1.0")),
        ],
    );
    let older_digest = put_layer(
        &registry,
        &sk,
        OLDER,
        "qualified",
        &[
            ("synth", "0.57.0", script("synth-0.57")),
            (name, "0.9.0", script("named-0.9")),
        ],
    );
    let realms = format!(
        "[realm.acme]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
        registry.display(),
        hex::encode(&pk)
    );
    std::fs::write(project.join("varve-realms.toml"), &realms).unwrap();
    let vtmp = tempfile::Builder::new()
        .prefix("varve-test-tmp-")
        .tempdir_in("/tmp")
        .unwrap();
    let w = World {
        _tmp: tmp,
        vtmp,
        dir,
        root,
        project,
        registry,
        realms,
        sk,
        older_digest,
    };
    w.install_also(OLDER, &w.older_digest.clone());
    w
}

fn file_digest(path: &Path) -> String {
    varve_core::manifest_digest(&std::fs::read(path).unwrap())
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tool_named_varve_never_overwrites_the_installed_binary() {
    // The interpreter `<dir>/varve` and a wrapper for a tool named `varve`
    // (or `Varve`, on a case-insensitive filesystem) shared one name: the
    // wrapper was written through the hard link onto the INSTALLED varve.
    use std::os::unix::fs::PermissionsExt;
    for name in ["varve", "Varve"] {
        let w = world_with_tool(name);
        // Installed on the same filesystem as TMPDIR, so the link is made.
        let installed = w.tmp().join("installed");
        std::fs::create_dir(&installed).unwrap();
        let varve_bin = installed.join("varve");
        std::fs::copy(assert_cmd::cargo::cargo_bin("varve"), &varve_bin).unwrap();
        std::fs::set_permissions(&varve_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = file_digest(&varve_bin);
        let out = varve_at(&w, &varve_bin)
            .args([
                "run",
                "--with",
                &format!("{name}@0.9.0"),
                "--",
                "/usr/bin/env",
                name,
            ])
            .output()
            .unwrap();
        assert_eq!(
            file_digest(&varve_bin),
            before,
            "{name}: the installed varve changed"
        );
        let mode = std::fs::metadata(&varve_bin).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "{name}: mode {mode:o}");
        // …and the run did what was asked: the override of that tool ran.
        assert!(
            String::from_utf8_lossy(&out.stdout).starts_with("named-0.9 "),
            "{name}: {:?} {} {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tool_named_like_a_control_file_cannot_release_the_gate() {
    // A wrapper named `.go` was the gate's release marker: written with the
    // wrappers, it let the command start before setup had finished.
    let w = world_with_tool(".go");
    let a = varve(&w)
        .args([
            "run",
            "--with",
            ".go@0.9.0",
            "--",
            "sh",
            "-c",
            "echo ran; .go",
        ])
        .assert()
        .success();
    let out = stdout(&a);
    assert!(out.starts_with("ran\nnamed-0.9 "), "{out} {}", stderr(&a));
    assert!(w.tmp_is_empty());
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_tool_named_like_the_control_directory_is_refused() {
    let w = world();
    for name in [".v", ".V"] {
        let err = assert_refused(
            &w,
            &["run", "--with", &format!("{name}@1.0.0"), "--", "synth"],
            "reserved",
        );
        assert!(err.contains(name), "{err}");
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_signal_during_setup_never_leaks_a_copy_of_varve() {
    // Before the handlers are installed only an empty directory exists; the
    // interpreter is placed after them. Signal varve at varying points just
    // after its directory appears: anything left behind must be empty.
    use std::os::unix::process::CommandExt;
    let w = world();
    let none = w.dir.join("no-user-config");
    for i in 0..40u64 {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("varve"))
            .args(["run", "--with", "synth@0.57.0", "--", "/usr/bin/true"])
            .env("PATH", "/usr/bin:/bin")
            .env("VARVE_ROOT", &w.root)
            .env("XDG_CONFIG_HOME", &none)
            .env("HOME", &none)
            .env("TMPDIR", w.tmp())
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&w.project)
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while std::fs::read_dir(w.tmp()).unwrap().next().is_none()
            && start.elapsed() < std::time::Duration::from_secs(10)
        {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        std::thread::sleep(std::time::Duration::from_micros(500 * (i % 20)));
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        child.wait().unwrap();
        // A gate orphaned by an early signal gives up on its own.
        std::thread::sleep(std::time::Duration::from_millis(150));
        for e in std::fs::read_dir(w.tmp()).unwrap() {
            let leak = e.unwrap().path();
            let inside: Vec<_> = walk(&leak);
            assert!(
                inside.is_empty(),
                "iteration {i}: {} leaked with {inside:?}",
                leak.display()
            );
            std::fs::remove_dir_all(&leak).unwrap();
        }
    }
}

/// Every file under `dir` (not directories).
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if std::fs::symlink_metadata(&p).unwrap().is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_regular_shim_whose_first_argument_is_a_marker_runs_its_tool() {
    // The markers are honoured only from a private interpreter (the shim
    // marker) or as varve's own binary run by itself (the gate marker); a
    // regular shim hands such an argument to its tool like any other.
    let w = world();
    with_regular_shims(&w);
    let shim = w.root.join("shims").join("synth");
    for marker in ["--varve-with-shim", "--varve-with-gate"] {
        let none = w.dir.join("no-user-config");
        let a = Command::new(&shim)
            .args([marker, "/x", "--", "/usr/bin/true"])
            .env("PATH", "/usr/bin:/bin")
            .env("VARVE_ROOT", &w.root)
            .env("XDG_CONFIG_HOME", &none)
            .env("HOME", &none)
            .env("RUNWITH_TEST_MARKS", w.marks())
            .env_remove("VARVE_TRUST_ROOT")
            .current_dir(&w.project)
            .assert()
            .success();
        assert!(
            stdout(&a).starts_with("synth-0.65 "),
            "{marker}: {}",
            stderr(&a)
        );
    }
}

// rivet: verifies REQ-RUNWITH-001
#[test]
fn a_gate_refuses_a_varve_of_another_build() {
    // varve replaced by an upgrade between starting and spawning its gate:
    // the gate (the new build) is told the old build's identity and refuses,
    // with a reason, instead of waiting forever for a release it cannot read.
    let w = world();
    let a = varve(&w)
        .args(["--varve-with-gate", &std::process::id().to_string()])
        .arg("0.0.0+gate0")
        .arg(w.tmp().join("varve-with-x"))
        .args(["--", "/usr/bin/true"])
        .assert()
        .code(125);
    assert!(
        stderr(&a).contains("replaced") && stderr(&a).contains("0.0.0+gate0"),
        "{}",
        stderr(&a)
    );
}
