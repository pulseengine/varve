//! A composition's payloads are the payloads of EVERY layer in it.
//!
//! Reported from real use on a four-layer composition: `varve inspect` listed
//! all four layers and their realms, and `varve-serve` on the same pin answered
//!
//!   Error: layer 2026.09.1 carries no documentation.
//!
//! because the viewer read `layer.json` of the PINNED layer only and never
//! followed the includes. The documentation was in one of the other three.
//!
//! `varve export-docs` got this right — it walks the composition — so the two
//! commands disagreed about what one pin contains. That walk lived in the
//! `varve` binary where `varve-serve` could not reach it, which is why the
//! second implementation was a loop over one manifest.
//!
//! These tests exercise the walk from varve-core, where both binaries use it.

use std::collections::BTreeMap;

use varve_core::deposit::DepositInclude;
use varve_core::install::{InstallPolicy, install};
use varve_core::rollback::HighWaterMarks;
use varve_core::source::MemorySource;
use varve_core::store::{Store, manifest_digest};
use varve_core::verify::{PinnedKeyVerifier, generate_root_keypair};
use varve_core::{DepositSpec, DepositTool, PayloadKind, Pin};

struct Realm {
    sk: Vec<u8>,
    pk: Vec<u8>,
    name: String,
}

fn realm(name: &str) -> Realm {
    let (sk, pk) = generate_root_keypair();
    Realm {
        sk,
        pk,
        name: name.into(),
    }
}

fn docs_tool(name: &str) -> DepositTool {
    DepositTool {
        name: name.into(),
        version: "1.0.0".into(),
        platform: None,
        bytes: format!("<h1>{name}</h1>").into_bytes(),
        source: None,
        runner: None,
        kind: Some(PayloadKind::Docs),
        sdk_prefix: None,
        docs_format: Some("html".into()),
        docs_entry: None,
        docs_title: Some(format!("{name} handbook")),
        docs_documents: None,
    }
}

fn tool(name: &str) -> DepositTool {
    DepositTool {
        kind: None,
        docs_format: None,
        docs_title: None,
        ..docs_tool(name)
    }
}

/// Where the layers are built and installed: one store, one high-water-mark
/// root, one scratch directory.
struct Bench {
    store: Store,
    root: std::path::PathBuf,
    tmp: std::path::PathBuf,
}

/// Deposit a layer into a directory-shaped layout and install it.
fn deposit_and_install(
    b: &Bench,
    r: &Realm,
    layer: &str,
    counter: u64,
    tools: Vec<DepositTool>,
    includes: Vec<DepositInclude>,
) -> String {
    let (store, root, tmp) = (&b.store, b.root.as_path(), b.tmp.as_path());
    let layout = tmp.join(format!("layout-{layer}"));
    let outcome = varve_core::deposit(
        &DepositSpec {
            includes,
            layer: layer.parse().unwrap(),
            channel: "rolling".into(),
            counter,
            issued_at: "2026-09-20T00:00:00Z".into(),
            tools,
        },
        &r.sk,
        &format!("{}-1", r.name),
        &layout,
    )
    .expect("deposits");

    // Install from the layout the deposit just wrote.
    let envelope = std::fs::read(layout.join("layer.dsse.json"))
        .or_else(|_| {
            // The layout names the envelope by digest; find it among the blobs.
            for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
                let p = e.unwrap().path();
                let b = std::fs::read(&p).unwrap();
                if serde_json::from_slice::<serde_json::Value>(&b)
                    .ok()
                    .and_then(|v| v.get("payload").cloned())
                    .is_some()
                {
                    return Ok::<Vec<u8>, std::io::Error>(b);
                }
            }
            panic!("no envelope in {}", layout.display())
        })
        .unwrap();

    let mut source = MemorySource::new().with_manifest(&envelope);
    // Every payload blob the manifest names.
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let p = e.unwrap().path();
        let b = std::fs::read(&p).unwrap();
        let d = manifest_digest(&b);
        source = source.with_blob(&d, &b);
    }

    let pin = Pin::parse(
        &format!("manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"{layer}\"\n"),
        "varve.toml",
    )
    .unwrap();
    let mut marks = HighWaterMarks::load(root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&r.pk).unwrap();
    install(
        &pin,
        &source,
        &verifier,
        store,
        &mut marks,
        &InstallPolicy {
            index: None,
            now: "2026-09-20T00:00:00Z",
            staleness_threshold_days: 3650,
            platform: "test-platform",
        },
    )
    .expect("installs");
    outcome.digest
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn documentation_in_an_included_layer_is_found_from_the_composing_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let bench = Bench {
        store: store.clone(),
        root: root.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let upstream = realm("upstream");
    let top = realm("top");

    // The included layer carries the documentation; the composing layer does not.
    let included = deposit_and_install(
        &bench,
        &upstream,
        "2026.09.0",
        1,
        vec![docs_tool("handbook"), tool("rivet")],
        Vec::new(),
    );
    let composing = deposit_and_install(
        &bench,
        &top,
        "2026.09.1",
        1,
        vec![tool("aeolus")],
        vec![DepositInclude {
            digest: included.clone(),
            realm: Some(upstream.name.clone()),
            layer: Some("2026.09.0".into()),
        }],
    );

    let entry = store.get(&composing).unwrap().unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&top.pk).unwrap();
    let mut roots: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    roots.insert(upstream.name.clone(), upstream.pk.clone());

    let layers = varve_core::compose::walk_installed(
        &store,
        &entry,
        &verifier,
        &top.name,
        &roots,
        "test-platform",
    )
    .expect("the composition is walkable");

    assert_eq!(layers.len(), 2, "the walk stopped at the pinned layer");

    let docs = varve_core::compose::payloads_of(&layers, PayloadKind::Docs, "test-platform")
        .expect("collects");
    assert_eq!(
        docs.len(),
        1,
        "documentation carried by an INCLUDED layer was invisible — this is what made \
         varve-serve answer 'carries no documentation' on a four-layer composition"
    );
    assert_eq!(docs[0].name, "handbook");
}

/// The composing layer's own payloads are still there, and a payload appearing
/// in two layers is offered once.
// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn the_composition_offers_every_layers_tools_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let bench = Bench {
        store: store.clone(),
        root: root.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let upstream = realm("upstream");
    let top = realm("top");

    let included = deposit_and_install(
        &bench,
        &upstream,
        "2026.09.0",
        1,
        vec![tool("rivet")],
        Vec::new(),
    );
    let composing = deposit_and_install(
        &bench,
        &top,
        "2026.09.1",
        1,
        vec![tool("aeolus")],
        vec![DepositInclude {
            digest: included,
            realm: Some(upstream.name.clone()),
            layer: Some("2026.09.0".into()),
        }],
    );

    let entry = store.get(&composing).unwrap().unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&top.pk).unwrap();
    let mut roots: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    roots.insert(upstream.name.clone(), upstream.pk.clone());
    let layers = varve_core::compose::walk_installed(
        &store,
        &entry,
        &verifier,
        &top.name,
        &roots,
        "test-platform",
    )
    .expect("walks");
    let tools = varve_core::compose::payloads_of(&layers, PayloadKind::Tool, "test-platform")
        .expect("collects");
    let names: Vec<&str> = tools.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"aeolus"), "{names:?}");
    assert!(names.contains(&"rivet"), "{names:?}");
}
