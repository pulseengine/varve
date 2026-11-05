//! REQ-KEYROLES-001, PR 3b: the layer-manifest verification path judges a layer
//! manifest under the realm's LAYER keys in a roles realm, and under the root
//! in a realm that declares no roles.
//!
//! Layers are built through the real `deposit`, signed with the key under test,
//! and installed through the real `install` (which takes any `ManifestVerifier`,
//! so a layer whose signer is out of role is installed here with a permissive
//! verifier purely to have something in the store to re-verify and compose).

use std::collections::BTreeMap;

use varve_core::deposit::DepositInclude;
use varve_core::install::{InstallPolicy, ManifestVerifier, install};
use varve_core::keyroles::{DELEGATION_PAYLOAD_TYPE, Delegation, RealmTrust};
use varve_core::rollback::HighWaterMarks;
use varve_core::source::MemorySource;
use varve_core::store::{InstalledLayer, Store, manifest_digest};
use varve_core::verify::{PinnedKeyVerifier, dsse_sign_typed, generate_root_keypair};
use varve_core::{DepositSpec, DepositTool, Pin};

struct Key {
    sk: Vec<u8>,
    pk: Vec<u8>,
}

fn key() -> Key {
    let (sk, pk) = generate_root_keypair();
    Key { sk, pk }
}

/// A realm with a root, a LAYER key and a STATUS key.
struct RolesRealm {
    root: Key,
    layer: Key,
    status: Key,
}

fn roles_realm() -> RolesRealm {
    RolesRealm {
        root: key(),
        layer: key(),
        status: key(),
    }
}

impl RolesRealm {
    fn delegation(&self) -> Delegation {
        let doc = serde_json::json!({
            "realm-root": hex::encode(&self.root.pk),
            "counter": 1,
            "issued-at": "2026-11-05T00:00:00Z",
            "roles": {
                "layer": {"threshold": 1, "keys": [{"key": hex::encode(&self.layer.pk)}]},
                "status": {"threshold": 1, "keys": [{"key": hex::encode(&self.status.pk)}]},
            }
        });
        let env = dsse_sign_typed(
            doc.to_string().as_bytes(),
            DELEGATION_PAYLOAD_TYPE,
            &self.root.sk,
            "root",
        )
        .unwrap();
        Delegation::from_envelope(env.as_bytes(), &self.root.pk).unwrap()
    }

    fn trust(&self) -> RealmTrust {
        RealmTrust::with_roles(&self.root.pk, self.delegation()).unwrap()
    }

    /// The same realm as a consumer that declares NO roles sees it.
    fn flat_trust(&self) -> RealmTrust {
        RealmTrust::root_only(&self.root.pk).unwrap()
    }
}

fn tool(name: &str) -> DepositTool {
    DepositTool {
        name: name.into(),
        version: "1.0.0".into(),
        platform: None,
        target: None,
        bytes: format!("#!/bin/sh\necho {name}\n").into_bytes(),
        source: None,
        runner: None,
        kind: None,
        sdk_prefix: None,
        docs_format: None,
        docs_entry: None,
        docs_title: None,
        docs_documents: None,
        zephyr_allow_pip: None,
        libc: None,
    }
}

/// A layout deposited under `signer`'s key, returned as an envelope and a source.
struct Built {
    envelope: Vec<u8>,
    source: MemorySource,
    layer: String,
}

fn build(
    tmp: &std::path::Path,
    signer: &Key,
    layer: &str,
    includes: Vec<DepositInclude>,
    tools: Vec<DepositTool>,
) -> Built {
    let layout = tmp.join(format!("layout-{layer}-{}", hex::encode(&signer.pk[..4])));
    varve_core::deposit(
        &DepositSpec {
            includes,
            layer: layer.parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-11-05T00:00:00Z".into(),
            tools,
        },
        &signer.sk,
        "k-1",
        &layout,
    )
    .expect("deposits");
    let envelope = std::fs::read(layout.join("layer.dsse.json")).unwrap_or_else(|_| {
        for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            if serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| v.get("payload").cloned())
                .is_some()
            {
                return b;
            }
        }
        panic!("no envelope")
    });
    let mut source = MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        source = source.with_blob(&manifest_digest(&b), &b);
    }
    Built {
        envelope,
        source,
        layer: layer.to_string(),
    }
}

fn pin(layer: &str) -> Pin {
    Pin::parse(
        &format!("manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"{layer}\"\n"),
        "varve.toml",
    )
    .unwrap()
}

fn policy() -> InstallPolicy<'static> {
    InstallPolicy {
        index: None,
        now: "2026-11-05T00:00:00Z",
        staleness_threshold_days: 3650,
        platform: "test-platform",
    }
}

/// Install `b` through `verifier`; Err is the refusal.
fn try_install(
    store: &Store,
    root: &std::path::Path,
    b: &Built,
    verifier: &dyn ManifestVerifier,
) -> Result<InstalledLayer, String> {
    let mut marks = HighWaterMarks::load(root).unwrap();
    let out = install(
        &pin(&b.layer),
        &b.source,
        verifier,
        store,
        &mut marks,
        &policy(),
    )
    .map_err(|e| e.to_string())?;
    Ok(store.get(&out.digest).unwrap().unwrap())
}

/// A permissive verifier for `signer`, used only to put an out-of-role layer in
/// the store so the roles verifier has something to refuse offline.
fn trusting(signer: &Key) -> PinnedKeyVerifier {
    PinnedKeyVerifier::from_public_key_bytes(&signer.pk).unwrap()
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_layer_signed_manifest_verifies_under_a_roles_realm() {
    let r = roles_realm();
    let tmp = tempfile::tempdir().unwrap();
    let b = build(tmp.path(), &r.layer, "2026.11.0", vec![], vec![tool("a")]);
    let v = PinnedKeyVerifier::from_trust(r.trust());
    v.verify(&b.envelope)
        .expect("a LAYER-signed layer manifest verifies in a roles realm");
    // The root the verifier names is the realm ROOT: the store partitions on it.
    assert_eq!(v.trust().map(|t| t.root()), Some(r.root.pk.as_slice()));
    assert_eq!(v.public_key(), r.root.pk.as_slice());
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_status_or_root_signed_layer_manifest_is_refused_in_a_roles_realm() {
    let r = roles_realm();
    let tmp = tempfile::tempdir().unwrap();
    let v = PinnedKeyVerifier::from_trust(r.trust());
    let by_status = build(tmp.path(), &r.status, "2026.11.0", vec![], vec![tool("a")]);
    let e = v.verify(&by_status.envelope).unwrap_err().to_string();
    assert!(e.contains("STATUS") && e.contains("LAYER"), "{e}");
    let by_root = build(tmp.path(), &r.root, "2026.11.1", vec![], vec![tool("a")]);
    let e = v.verify(&by_root.envelope).unwrap_err().to_string();
    assert!(e.contains("ROOT"), "{e}");
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn the_same_layer_signed_bytes_are_refused_under_a_realm_declaring_no_roles() {
    let r = roles_realm();
    let tmp = tempfile::tempdir().unwrap();
    let b = build(tmp.path(), &r.layer, "2026.11.0", vec![], vec![tool("a")]);
    let flat = PinnedKeyVerifier::from_trust(r.flat_trust());
    flat.verify(&b.envelope)
        .expect_err("a no-roles realm trusts only its root; the LAYER key is nobody");
    // And a root-signed layer still verifies there, exactly as before.
    let by_root = build(tmp.path(), &r.root, "2026.11.1", vec![], vec![tool("a")]);
    flat.verify(&by_root.envelope)
        .expect("root-only is today's behaviour");
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_layer_signed_layer_installs_and_re_verifies_offline_in_a_roles_realm() {
    let r = roles_realm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let b = build(tmp.path(), &r.layer, "2026.11.0", vec![], vec![tool("a")]);
    let v = PinnedKeyVerifier::from_trust(r.trust());
    let entry = try_install(&store, &root, &b, &v).expect("installs under the LAYER key");
    varve_core::reverify::verify_installed(&store, &entry, &v, "test-platform")
        .expect("re-verifies offline");
    varve_core::reverify::verify_retained_envelope(&entry, &v).expect("retained envelope");
    // The same store under a no-roles view of the realm: refused.
    let flat = PinnedKeyVerifier::from_trust(r.flat_trust());
    varve_core::reverify::verify_retained_envelope(&entry, &flat)
        .expect_err("root-only does not accept the LAYER key");
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_status_or_root_signed_installed_layer_is_refused_by_reverify() {
    let r = roles_realm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let v = PinnedKeyVerifier::from_trust(r.trust());
    for (signer, layer) in [(&r.status, "2026.11.0"), (&r.root, "2026.11.1")] {
        let b = build(tmp.path(), signer, layer, vec![], vec![tool("a")]);
        let entry = try_install(&store, &root, &b, &trusting(signer)).unwrap();
        varve_core::reverify::verify_installed(&store, &entry, &v, "test-platform")
            .expect_err("out of role");
        varve_core::reverify::verify_retained_envelope(&entry, &v).expect_err("out of role");
    }
}

/// `top` (a plain realm) includes a layer of `up`, signed by `signer`.
struct Composed {
    _tmp: tempfile::TempDir,
    store: Store,
    entry: InstalledLayer,
    top: PinnedKeyVerifier,
}

fn composition(signer: &Key) -> Composed {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let top = key();
    let included = build(tmp.path(), signer, "2026.11.0", vec![], vec![tool("base")]);
    let inc = try_install(&store, &root, &included, &trusting(signer)).unwrap();
    let composing = build(
        tmp.path(),
        &top,
        "2026.11.1",
        vec![DepositInclude {
            digest: inc.digest.clone(),
            realm: Some("up".into()),
            layer: Some("2026.11.0".into()),
        }],
        vec![tool("aeolus")],
    );
    let top_v = trusting(&top);
    let entry = try_install(&store, &root, &composing, &top_v).unwrap();
    Composed {
        _tmp: tmp,
        store,
        entry,
        top: top_v,
    }
}

fn walk(
    c: &Composed,
    trust: RealmTrust,
) -> Result<Vec<varve_core::compose::ComposedLayer>, varve_core::compose::ComposeError> {
    let mut trusts = BTreeMap::new();
    trusts.insert("up".to_string(), trust);
    varve_core::compose::walk_installed(&c.store, &c.entry, &c.top, "top", &trusts, "test-platform")
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_layer_signed_included_layer_composes_under_its_roles_realm() {
    let up = roles_realm();
    let c = composition(&up.layer);
    let layers = walk(&c, up.trust()).expect("composes");
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[1].realm, "up");
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_status_or_root_signed_included_layer_is_refused_by_compose() {
    let up = roles_realm();
    for signer in [&up.status, &up.root] {
        let c = composition(signer);
        let e = walk(&c, up.trust()).expect_err("out of role").to_string();
        assert!(e.contains("LAYER"), "{e}");
    }
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn layer_signed_bytes_are_refused_by_compose_under_a_no_roles_realm() {
    let up = roles_realm();
    let c = composition(&up.layer);
    walk(&c, up.flat_trust()).expect_err("root-only does not accept the LAYER key");
    // And a root-signed included layer composes there, as it always did.
    let c = composition(&up.root);
    walk(&c, up.flat_trust()).expect("no-roles behaviour unchanged");
}
