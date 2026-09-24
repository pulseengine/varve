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

/// A layer that carries ONLY a composition installs.
///
/// Found building the `covalent` realm — the worked multi-realm example: one
/// pin over the PulseEngine toolchain and the bytecodealliance component
/// tools. It deposited, it signed, and `varve install` refused it:
///
///   layer 2026.09.0 carries no entry for platform x86_64-unknown-linux-gnu —
///   refusing to install a wrong-architecture toolchain
///
/// The fail-closed platform rule is right and stays: a fully-stamped layer
/// with nothing for this host must never install looking complete. But it
/// asked the wrong question. A composition edge is not a payload — it names
/// another layer's manifest and is deliberately skipped by the fetch loop —
/// so a pure composition has ZERO entries that could ever match a platform,
/// and "none matched" is not evidence of a wrong architecture.
///
/// The deposit-side defect, one stage further down the pipeline: `deposit`
/// learned that a composition-only layer is not an empty layer, and `install`
/// had not. Same rule, a different command applying it.
// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_layer_that_is_only_a_composition_installs_on_any_platform() {
    let tmp = tempfile::tempdir().unwrap();
    let (sk, pk) = varve_core::generate_root_keypair();
    let layout = tmp.path().join("layout");

    // Two includes, no payloads of its own — the covalent realm's shape.
    let inc = |d: &str, realm: &str, layer: &str| varve_core::deposit::DepositInclude {
        digest: d.to_string(),
        realm: Some(realm.to_string()),
        layer: Some(layer.to_string()),
    };
    varve_core::deposit(
        &varve_core::DepositSpec {
            includes: vec![
                inc(
                    &format!("sha256:{}", "a".repeat(64)),
                    "pulseengine",
                    "2026.09.12",
                ),
                inc(
                    &format!("sha256:{}", "b".repeat(64)),
                    "pulseengine-wasm",
                    "2026.09.0",
                ),
            ],
            layer: "2026.09.0".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-09-24T00:00:00Z".into(),
            tools: Vec::new(),
        },
        &sk,
        "covalent-1",
        &layout,
    )
    .expect("a composition-only layer deposits");

    let envelope = std::fs::read_dir(layout.join("blobs/sha256"))
        .unwrap()
        .filter_map(|e| {
            let b = std::fs::read(e.unwrap().path()).ok()?;
            serde_json::from_slice::<serde_json::Value>(&b)
                .ok()?
                .get("payload")
                .is_some()
                .then_some(b)
        })
        .next()
        .expect("the signed envelope");
    let mut source = varve_core::source::MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        let d = varve_core::store::manifest_digest(&b);
        source = source.with_blob(&d, &b);
    }

    let root = tmp.path().join("root");
    let store = varve_core::store::Store::at(&root);
    let pin = varve_core::Pin::parse(
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.09.0\"\n",
        "varve.toml",
    )
    .unwrap();
    let mut marks = varve_core::rollback::HighWaterMarks::load(&root).unwrap();
    let verifier = varve_core::verify::PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();

    // The platform is deliberately one no payload could ever be stamped for:
    // a pure composition is platform-independent because it carries no bytes.
    let outcome = varve_core::install::install(
        &pin,
        &source,
        &verifier,
        &store,
        &mut marks,
        &varve_core::install::InstallPolicy {
            index: None,
            now: "2026-09-24T00:00:00Z",
            staleness_threshold_days: 3650,
            platform: "x86_64-unknown-linux-gnu",
        },
    )
    .expect("a layer that is only a composition must install — it carries no bytes to mismatch");
    assert_eq!(outcome.layer.to_string(), "2026.09.0");
}
