//! The deposit of a `zephyr-module` payload (REQ-ZMODEXPORT-001 clauses 1, 5).
//!
//! Clause 1: the payload carries the module tree with its `zephyr/module.yml`,
//! and a tree without one is refused. Clause 5: a module whose `module.yml`
//! declares `package-managers: pip` adds a Python dependency to every build, so
//! it is refused unless the layer records an opt-in naming EXACTLY the declared
//! requirement files. Both are decided at deposit, where the manifest can still
//! be fixed: the annotation lives inside the signature.

use std::io::Write;
use std::path::Path;

use varve_core::{DepositError, DepositSpec, DepositTool, LayerManifest, PayloadKind};

fn tar_gz(files: &[(&str, &str)]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, path, body.as_bytes()).unwrap();
    }
    let raw = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

fn zmod(name: &str, bytes: Vec<u8>, allow_pip: Option<Vec<String>>) -> DepositTool {
    DepositTool {
        name: name.into(),
        version: "0.1.0".into(),
        platform: None,
        target: None,
        bytes,
        source: None,
        runner: None,
        kind: Some(PayloadKind::ZephyrModule),
        sdk_prefix: None,
        docs_format: None,
        docs_entry: None,
        docs_title: None,
        docs_documents: None,
        libc: None,
        zephyr_allow_pip: allow_pip,
    }
}

fn deposit(tools: Vec<DepositTool>, dest: &Path) -> Result<LayerManifest, DepositError> {
    let (sk, _pk) = varve_core::generate_root_keypair();
    varve_core::deposit(
        &DepositSpec {
            includes: Vec::new(),
            layer: "2026.11.0".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-11-03T00:00:00Z".into(),
            tools,
        },
        &sk,
        "root-1",
        dest,
    )?;
    Ok(signed_manifest(dest))
}

fn signed_manifest(layout: &Path) -> LayerManifest {
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        if let Ok(m) = LayerManifest::parse(&bytes) {
            return m;
        }
    }
    panic!("no signed layer manifest in {}", layout.display());
}

fn good() -> Vec<u8> {
    tar_gz(&[
        ("zephyr/module.yml", "name: gale\nbuild:\n  cmake: .\n"),
        ("CMakeLists.txt", "# gale\n"),
    ])
}

fn pip(files: &[&str]) -> Vec<u8> {
    let mut y = String::from("name: py\npackage-managers:\n  pip:\n    requirement-files:\n");
    for f in files {
        y.push_str(&format!("      - {f}\n"));
    }
    tar_gz(&[("zephyr/module.yml", &y)])
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn a_tree_with_a_module_yml_deposits() {
    let tmp = tempfile::tempdir().unwrap();
    let m = deposit(vec![zmod("gale", good(), None)], &tmp.path().join("l"))
        .expect("a module with a module.yml deposits");
    let e = &m.entries[0];
    assert_eq!(
        e.annotations
            .get(varve_core::kind::ANN_KIND)
            .map(String::as_str),
        Some("zephyr-module")
    );
    assert!(
        !e.annotations
            .contains_key(varve_core::zephyrmodule::ANN_ALLOW_PIP),
        "no opt-in was given, so none is signed"
    );
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn a_tree_without_a_module_yml_is_refused_at_deposit() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = tar_gz(&[("CMakeLists.txt", "x"), ("src/a.c", "y")]);
    let err = deposit(vec![zmod("nomod", bytes, None)], &tmp.path().join("l"))
        .expect_err("no module.yml must be refused");
    let msg = err.to_string();
    assert!(matches!(err, DepositError::ZephyrModule(_)), "{msg}");
    assert!(
        msg.contains("zephyr/module.yml") && msg.contains("nomod"),
        "{msg}"
    );
    assert!(
        !tmp.path().join("l").exists(),
        "a refused deposit writes nothing"
    );
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn a_malformed_module_yml_is_refused_at_deposit() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = tar_gz(&[("zephyr/module.yml", "name: [unclosed\n")]);
    let err = deposit(vec![zmod("bad", bytes, None)], &tmp.path().join("l"))
        .expect_err("malformed module.yml must be refused");
    assert!(err.to_string().contains("does not parse"), "{err}");
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn something_that_is_not_an_archive_is_refused_at_deposit() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![zmod("html", b"<html>404</html>".to_vec(), None)],
        &tmp.path().join("l"),
    )
    .expect_err("an error page is not a module");
    assert!(matches!(err, DepositError::ZephyrModule(_)), "{err}");
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn pip_without_an_opt_in_is_refused_at_deposit() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![zmod("py", pip(&["scripts/requirements.txt"]), None)],
        &tmp.path().join("l"),
    )
    .expect_err("pip without opt-in must be refused");
    let msg = err.to_string();
    assert!(msg.contains("scripts/requirements.txt"), "{msg}");
    assert!(msg.contains("allow-pip"), "{msg}");
    assert!(msg.contains("Python"), "{msg}");
    assert!(!tmp.path().join("l").exists());
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn pip_with_the_matching_opt_in_deposits_and_signs_the_opt_in() {
    let tmp = tempfile::tempdir().unwrap();
    let m = deposit(
        vec![zmod(
            "py",
            pip(&["scripts/requirements.txt"]),
            Some(s(&["scripts/requirements.txt"])),
        )],
        &tmp.path().join("l"),
    )
    .expect("the opt-in names exactly the declared file");
    assert_eq!(
        m.entries[0]
            .annotations
            .get(varve_core::zephyrmodule::ANN_ALLOW_PIP)
            .map(String::as_str),
        Some("scripts/requirements.txt"),
        "the opt-in is inside the signature, so `varve inspect` can show it"
    );
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn pip_with_a_mismatched_opt_in_is_refused_at_deposit() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![zmod(
            "py",
            pip(&["scripts/requirements.txt"]),
            Some(s(&["scripts/other.txt"])),
        )],
        &tmp.path().join("l"),
    )
    .expect_err("a different list is a different dependency");
    let msg = err.to_string();
    assert!(
        msg.contains("scripts/requirements.txt") && msg.contains("scripts/other.txt"),
        "{msg}"
    );
    assert!(msg.contains("EXACTLY"), "{msg}");
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn an_opt_in_on_a_payload_that_is_not_a_zephyr_module_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut t = zmod("notmod", b"bytes".to_vec(), Some(s(&["a.txt"])));
    t.kind = Some(PayloadKind::Crate);
    let err = deposit(vec![t], &tmp.path().join("l")).expect_err("inert annotation");
    let msg = err.to_string();
    assert!(
        matches!(err, DepositError::ZephyrAllowPipOnNonModule { .. }),
        "{msg}"
    );
    assert!(msg.contains("notmod") && msg.contains("allow-pip"), "{msg}");
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn an_opt_in_that_cannot_survive_the_signed_encoding_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![zmod("py", pip(&["a,b.txt"]), Some(s(&["a,b.txt"])))],
        &tmp.path().join("l"),
    )
    .expect_err("a comma cannot round-trip");
    assert!(err.to_string().contains("comma"), "{err}");
}

// rivet: verifies REQ-ZMODEXPORT-001
#[test]
fn the_spec_file_carries_allow_pip_through_to_the_deposit_tool() {
    let spec = varve_core::parse_deposit_spec(
        r#"
layer = "2026.11.0"
channel = "rolling"
counter = 1

[[tool]]
name = "py"
version = "0.1.0"
path = "py.tar.gz"
kind = "zephyr-module"
allow-pip = ["scripts/requirements.txt"]
"#,
    )
    .expect("allow-pip is a known spec field");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("py.tar.gz"),
        pip(&["scripts/requirements.txt"]),
    )
    .unwrap();
    let tool = spec
        .tools
        .into_iter()
        .next()
        .unwrap()
        .into_deposit_tool(dir.path())
        .unwrap();
    assert_eq!(
        tool.zephyr_allow_pip,
        Some(s(&["scripts/requirements.txt"]))
    );
    assert_eq!(tool.kind, Some(PayloadKind::ZephyrModule));
}
