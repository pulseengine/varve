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
/// A source serving one deposited layout: its signed envelope and every blob
/// the manifest names. Shared so that a fetch BY DIGEST is served exactly what
/// a fetch by pin is — otherwise the two paths could differ in the test and
/// agree in production, or the reverse.
/// The signed envelope a deposit wrote: named directly, or found among the
/// blobs when the layout names it by digest.
fn read_envelope(layout: &std::path::Path) -> Vec<u8> {
    std::fs::read(layout.join("layer.dsse.json"))
        .or_else(|_| {
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
        .unwrap()
}

fn source_at(layout: &std::path::Path) -> MemorySource {
    let envelope = read_envelope(layout);
    let mut source = MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let p = e.unwrap().path();
        let b = std::fs::read(&p).unwrap();
        let d = manifest_digest(&b);
        source = source.with_blob(&d, &b);
    }
    source
}

/// The layout a `deposit_and_install` wrote for one layer.
fn source_for(b: &Bench, layer: &str) -> MemorySource {
    source_at(&b.tmp.join(format!("layout-{layer}")))
}

fn policy<'a>() -> InstallPolicy<'a> {
    InstallPolicy {
        index: None,
        now: "2026-09-20T00:00:00Z",
        staleness_threshold_days: 3650,
        platform: "test-platform",
    }
}

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
    let source = source_at(&layout);

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

/// A composition of a composition: root -> mid -> leaf. The walk is over a DAG,
/// so a longer path is just a longer path — but the leaf must be reached, or a
/// chain passes because the root's DIRECT includes were all present.
// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_composition_of_a_composition_is_walked_to_the_leaf() {
    let tmp = tempfile::tempdir().unwrap();
    let root_dir = tmp.path().join("root");
    let store = Store::at(&root_dir);
    let bench = Bench {
        store: store.clone(),
        root: root_dir.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let leafr = realm("leaf-realm");
    let midr = realm("mid-realm");
    let topr = realm("top-realm");

    let leaf = deposit_and_install(
        &bench,
        &leafr,
        "2026.09.0",
        1,
        vec![docs_tool("deep")],
        Vec::new(),
    );
    let mid = deposit_and_install(
        &bench,
        &midr,
        "2026.09.1",
        1,
        vec![tool("middle")],
        vec![DepositInclude {
            digest: leaf,
            realm: Some(leafr.name.clone()),
            layer: Some("2026.09.0".into()),
        }],
    );
    let top = deposit_and_install(
        &bench,
        &topr,
        "2026.09.2",
        1,
        vec![tool("apex")],
        vec![DepositInclude {
            digest: mid,
            realm: Some(midr.name.clone()),
            layer: Some("2026.09.1".into()),
        }],
    );

    let entry = store.get(&top).unwrap().unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&topr.pk).unwrap();
    let mut roots: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    roots.insert(midr.name.clone(), midr.pk.clone());
    roots.insert(leafr.name.clone(), leafr.pk.clone());

    let layers = varve_core::compose::walk_installed(
        &store,
        &entry,
        &verifier,
        &topr.name,
        &roots,
        "test-platform",
    )
    .expect("walks the chain");
    assert_eq!(layers.len(), 3, "the walk stopped before the leaf");

    // The documentation is two levels down, which is where a viewer reading
    // only the pinned layer — or only its direct includes — would miss it.
    let docs = varve_core::compose::payloads_of(&layers, PayloadKind::Docs, "test-platform")
        .expect("collects");
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].name, "deep");
}

/// A DIAMOND: two layers of one composition sharing a base. The shared layer is
/// visited ONCE and is not mistaken for a cycle — conflating "reachable by two
/// paths" with "on its own path" is the bug this shape exists to catch.
// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_diamond_visits_the_shared_base_once_and_is_not_a_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    let root_dir = tmp.path().join("root");
    let store = Store::at(&root_dir);
    let bench = Bench {
        store: store.clone(),
        root: root_dir.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let baser = realm("base-realm");
    let leftr = realm("left-realm");
    let rightr = realm("right-realm");
    let topr = realm("top-realm");

    let base = deposit_and_install(
        &bench,
        &baser,
        "2026.09.0",
        1,
        vec![tool("shared")],
        Vec::new(),
    );
    let inc_base = |d: &str| DepositInclude {
        digest: d.to_string(),
        realm: Some(baser.name.clone()),
        layer: Some("2026.09.0".into()),
    };
    let left = deposit_and_install(
        &bench,
        &leftr,
        "2026.09.1",
        1,
        vec![tool("left")],
        vec![inc_base(&base)],
    );
    let right = deposit_and_install(
        &bench,
        &rightr,
        "2026.09.2",
        1,
        vec![tool("right")],
        vec![inc_base(&base)],
    );
    let top = deposit_and_install(
        &bench,
        &topr,
        "2026.09.3",
        1,
        vec![tool("apex")],
        vec![
            DepositInclude {
                digest: left,
                realm: Some(leftr.name.clone()),
                layer: Some("2026.09.1".into()),
            },
            DepositInclude {
                digest: right,
                realm: Some(rightr.name.clone()),
                layer: Some("2026.09.2".into()),
            },
        ],
    );

    let entry = store.get(&top).unwrap().unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&topr.pk).unwrap();
    let mut roots: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for r in [&baser, &leftr, &rightr] {
        roots.insert(r.name.clone(), r.pk.clone());
    }
    let layers = varve_core::compose::walk_installed(
        &store,
        &entry,
        &verifier,
        &topr.name,
        &roots,
        "test-platform",
    )
    .expect("a diamond is not a cycle");
    assert_eq!(
        layers.len(),
        4,
        "top, left, right, base — the base exactly once"
    );

    let tools = varve_core::compose::payloads_of(&layers, PayloadKind::Tool, "test-platform")
        .expect("collects");
    let shared: Vec<_> = tools.iter().filter(|p| p.name == "shared").collect();
    assert_eq!(shared.len(), 1, "the shared base was offered twice");
}

/// The depth bound, at its edge — both sides of the one comparison.
///
/// `cargo mutants` survived two mutations of `ancestors.len() > MAX_DEPTH` in
/// `walk_one` (`==` and `>=`): the cycle and diamond tests exercise the walk,
/// and nothing exercised the bound, so a walk that refused a composition one
/// layer shallower than documented would have passed every test. The pure
/// `walk` over views has this test; the store-backed walk that install and
/// varve-serve actually call did not.
///
/// One realm, one line, a chain built leaf-first so the counters ascend the
/// way a real deposit's do.
// rivet: verifies REQ-COMPOSE-001
#[test]
fn a_composition_exactly_max_depth_deep_walks_and_one_deeper_is_refused() {
    use varve_core::compose::MAX_DEPTH;

    let tmp = tempfile::tempdir().unwrap();
    let root_dir = tmp.path().join("root");
    let store = Store::at(&root_dir);
    let bench = Bench {
        store: store.clone(),
        root: root_dir.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let r = realm("deep-realm");

    // `chain[0]` is the leaf; `chain[n]` includes `chain[n - 1]`, so walking
    // from `chain[n]` visits n + 1 layers. The entry counts toward the bound —
    // `MAX_DEPTH` is how many layers a composition may have in total, not how
    // many it may sit above — so `chain[MAX_DEPTH - 1]` is the deepest legal
    // entry and `chain[MAX_DEPTH]` is one too far.
    let mut chain: Vec<(String, String)> = Vec::new();
    for i in 0..=MAX_DEPTH {
        let id = format!("2026.09.{i}");
        let includes = match chain.last() {
            None => Vec::new(),
            Some((digest, layer)) => vec![DepositInclude {
                digest: digest.clone(),
                realm: Some(r.name.clone()),
                layer: Some(layer.clone()),
            }],
        };
        let digest = deposit_and_install(
            &bench,
            &r,
            &id,
            i as u64 + 1,
            vec![tool(&format!("t{i}"))],
            includes,
        );
        chain.push((digest, id));
    }

    let verifier = PinnedKeyVerifier::from_public_key_bytes(&r.pk).unwrap();
    let roots: BTreeMap<String, Vec<u8>> = [(r.name.clone(), r.pk.clone())].into_iter().collect();
    let walk_from = |digest: &str| {
        let entry = store.get(digest).unwrap().unwrap();
        varve_core::compose::walk_installed(
            &store,
            &entry,
            &verifier,
            &r.name,
            &roots,
            "test-platform",
        )
    };

    // Exactly at the bound: a composition of MAX_DEPTH layers.
    let deepest_ok = &chain[MAX_DEPTH - 1].0;
    let layers = walk_from(deepest_ok)
        .unwrap_or_else(|e| panic!("a composition of exactly {MAX_DEPTH} layers must walk: {e}"));
    assert_eq!(
        layers.len(),
        MAX_DEPTH,
        "every layer of the chain, entry included"
    );

    // One layer deeper, and it is refused rather than walked.
    let too_deep = &chain[MAX_DEPTH].0;
    let err = walk_from(too_deep).expect_err("one deeper than the bound must be refused");
    assert!(
        matches!(err, varve_core::compose::ComposeError::TooDeep),
        "got: {err}"
    );
}

/// Fetching a layer known ONLY by the digest of its signed manifest.
///
/// This is what `varve install` does for every `[[include]]` it walks, and it
/// shipped without a test: the requirement said "install fetches what a
/// composition names" while nothing exercised the fetch, so the evidence for
/// it was a CLI path nobody re-ran. Found while preparing v0.38.0, by asking
/// rivet which markers pointed at the requirement and getting "No test markers
/// found".
///
/// The point of `install_by_digest` is that it DELEGATES: an included layer
/// must pass every check a pinned one does rather than a shorter list, because
/// it arrives without a pin to state expectations. So the test also proves the
/// checks are still there — a wrong root is refused, and a digest the source
/// does not hold is refused rather than silently skipped.
// rivet: verifies REQ-COMPOSEINSTALL-001
#[test]
fn a_layer_named_only_by_digest_is_fetched_verified_and_laid_down() {
    let tmp = tempfile::tempdir().unwrap();
    let root_dir = tmp.path().join("root");
    let store = Store::at(&root_dir);
    let bench = Bench {
        store: store.clone(),
        root: root_dir.clone(),
        tmp: tmp.path().to_path_buf(),
    };
    let r = realm("upstream-realm");

    // Deposited and installed once so the layout and a source for it exist;
    // then installed AGAIN, by digest alone, into a fresh store — the way a
    // composing project first meets it.
    let digest = deposit_and_install(&bench, &r, "2026.09.0", 1, vec![tool("wac")], Vec::new());

    let fresh_dir = tmp.path().join("fresh");
    let fresh = Store::at(&fresh_dir);
    let source = source_for(&bench, "2026.09.0");
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&r.pk).unwrap();
    let mut marks = HighWaterMarks::load(&fresh_dir).unwrap();
    let outcome = varve_core::install::install_by_digest(
        &digest,
        &source,
        &verifier,
        &fresh,
        &mut marks,
        &policy(),
    )
    .expect("a layer named by digest installs");

    assert_eq!(outcome.digest, digest, "installed something else");
    assert_eq!(outcome.layer.to_string(), "2026.09.0");
    assert!(
        fresh.get(&digest).unwrap().is_some(),
        "the fetch reported success and laid nothing down"
    );

    // The realm's own root is what vouches for it. Another realm's root must
    // not do — this is the trust boundary an include exists to draw, and
    // `install_by_digest` has no pin to carry it, so it can only come from the
    // verifier the caller resolved.
    let other = realm("someone-else");
    let wrong = PinnedKeyVerifier::from_public_key_bytes(&other.pk).unwrap();
    let other_dir = tmp.path().join("wrong-root");
    let other_store = Store::at(&other_dir);
    let mut other_marks = HighWaterMarks::load(&other_dir).unwrap();
    varve_core::install::install_by_digest(
        &digest,
        &source,
        &wrong,
        &other_store,
        &mut other_marks,
        &policy(),
    )
    .expect_err("a layer signed by one realm must not verify under another's root");

    // And a digest nobody serves is an error, not an empty success: a
    // composition that names bytes the registry does not hold must fail where
    // the operator can see it.
    let missing_dir = tmp.path().join("missing");
    let missing_store = Store::at(&missing_dir);
    let mut missing_marks = HighWaterMarks::load(&missing_dir).unwrap();
    varve_core::install::install_by_digest(
        &format!("sha256:{}", "0".repeat(64)),
        &source,
        &verifier,
        &missing_store,
        &mut missing_marks,
        &policy(),
    )
    .expect_err("a digest the source does not hold must be refused");
}
