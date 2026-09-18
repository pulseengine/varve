//! A layer that carries only a composition is not an empty layer.
//!
//! `deposit` refused any spec with no tools — "an empty layer is not a
//! toolchain" — which is right about emptiness and wrong about composition. The
//! `covalent` realm varve's own roadmap describes (REQ-COVALENT-001 clause 1)
//! carries NO payloads of its own and only includes: a pin names exactly one
//! layer, so composing is the only way one pin reaches two toolchains, and a
//! composition that also shipped binaries would be a fourth place tools are
//! defined.
//!
//! Found by building that realm rather than by reading the code: the manifest
//! parsed, `plan` reported "0 payload(s)", and the deposit was refused.

use std::path::Path;

use varve_core::{DepositError, DepositSpec, DepositTool, LayerManifest, PayloadKind};

fn include(digest: &str, realm: &str) -> varve_core::deposit::DepositInclude {
    varve_core::deposit::DepositInclude {
        digest: digest.into(),
        realm: Some(realm.into()),
        layer: Some("2026.09.5".into()),
    }
}

fn spec(
    tools: Vec<DepositTool>,
    includes: Vec<varve_core::deposit::DepositInclude>,
) -> DepositSpec {
    DepositSpec {
        includes,
        layer: "2026.09.0".parse().unwrap(),
        channel: "rolling".into(),
        counter: 1,
        issued_at: "2026-09-18T00:00:00Z".into(),
        tools,
    }
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

const PULSEENGINE: &str = "sha256:98dbe9189b19f52917138b98eaf4191b20919b693d8d67424368303516299bc9";
const WASM: &str = "sha256:001480e799f7274248863a89a76deeb333ee475701bc2702f86fe326b527ae6e";

// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_layer_of_only_includes_deposits_and_signs_them() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = tmp.path().join("layout");
    let (sk, _pk) = varve_core::generate_root_keypair();
    varve_core::deposit(
        &spec(
            Vec::new(),
            vec![
                include(PULSEENGINE, "pulseengine"),
                include(WASM, "pulseengine-wasm"),
            ],
        ),
        &sk,
        "covalent-1",
        &layout,
    )
    .expect("a composition is not an empty layer");

    let m = signed_manifest(&layout);
    let composed: Vec<&varve_core::manifest::ManifestEntry> = m
        .entries
        .iter()
        .filter(|e| e.kind() == Ok(PayloadKind::Layer))
        .collect();
    assert_eq!(
        composed.len(),
        2,
        "both includes must be in the signed payload"
    );
    let realms: Vec<&str> = composed
        .iter()
        .filter_map(|e| {
            e.annotations
                .get(varve_core::compose::ANN_INCLUDE_REALM)
                .map(String::as_str)
        })
        .collect();
    assert!(realms.contains(&"pulseengine"), "{realms:?}");
    assert!(realms.contains(&"pulseengine-wasm"), "{realms:?}");
    assert!(
        m.entries.iter().all(|e| e.kind() == Ok(PayloadKind::Layer)),
        "a composition realm must carry no payloads of its own"
    );
}

/// The guard still has a job: nothing at all is still nothing.
// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_layer_with_neither_payloads_nor_includes_is_still_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let err = varve_core::deposit(
        &spec(Vec::new(), Vec::new()),
        &sk,
        "covalent-1",
        &tmp.path().join("layout"),
    )
    .expect_err("an empty layer is still not a toolchain");
    assert!(matches!(err, DepositError::NoTools), "{err:?}");
    assert!(
        !tmp.path().join("layout").exists(),
        "nothing is written for a refused deposit"
    );
}
