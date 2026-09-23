//! A cross-toolchain is identified by the PAIR (host, target) — end to end.
//!
//! REQ-SDKTARGET-001 exists because varve's platform model is host-only: a
//! payload is filed under the triple of the machine that RUNS it. For a
//! compiler you invoke that is the whole story. For a cross-toolchain it is
//! half of it — `zephyrproject-rtos/sdk-ng` ships 140 assets named
//! `toolchain_gnu_<host>_<target>.tar.xz`, and every target for one host has
//! the SAME platform. A realm wanting arm and riscv for its developers was
//! therefore depositing one identity twice.
//!
//! Each layer of the change has its own unit test. This one runs the chain the
//! way a realm does, because the two halves could each be right and still not
//! meet: deposit could record a target the store ignores, or the store could
//! key by a target deposit never writes, and every unit test would pass.

use varve_core::install::{InstallPolicy, install};
use varve_core::rollback::HighWaterMarks;
use varve_core::source::MemorySource;
use varve_core::store::{Store, manifest_digest};
use varve_core::verify::{PinnedKeyVerifier, generate_root_keypair};
use varve_core::{DepositSpec, DepositTool, PayloadKind, Pin};

const HOST: &str = "x86_64-unknown-linux-gnu";

fn sdk(target: &str) -> DepositTool {
    DepositTool {
        name: "zephyr-sdk".into(),
        version: "1.0.1".into(),
        platform: Some(HOST.into()),
        target: Some(target.into()),
        bytes: format!("bytes for {target}").into_bytes(),
        source: None,
        runner: None,
        kind: Some(PayloadKind::Sdk),
        sdk_prefix: Some("/opt/zephyr-sdk-1.0.1".into()),
        docs_format: None,
        docs_entry: None,
        docs_title: None,
        docs_documents: None,
    }
}

// rivet: verifies REQ-SDKTARGET-001
#[test]
fn two_targets_of_one_sdk_are_deposited_installed_and_kept_apart() {
    let tmp = tempfile::tempdir().unwrap();
    let (sk, pk) = generate_root_keypair();
    let layout = tmp.path().join("layout");

    let targets = ["arm-zephyr-eabi", "riscv64-zephyr-elf"];
    varve_core::deposit(
        &DepositSpec {
            includes: Vec::new(),
            layer: "2026.09.0".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-09-23T00:00:00Z".into(),
            tools: targets.iter().map(|t| sdk(t)).collect(),
        },
        &sk,
        "zephyr-root-1",
        &layout,
    )
    .expect("two targets of one SDK deposit");

    // Serve what the deposit wrote, then install as a consumer on that host.
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
    let mut source = MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        let d = manifest_digest(&b);
        source = source.with_blob(&d, &b);
    }

    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let pin = Pin::parse(
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.09.0\"\n",
        "varve.toml",
    )
    .unwrap();
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
    let outcome = install(
        &pin,
        &source,
        &verifier,
        &store,
        &mut marks,
        &InstallPolicy {
            index: None,
            now: "2026-09-23T00:00:00Z",
            staleness_threshold_days: 3650,
            platform: HOST,
        },
    )
    .expect("both toolchains install for this host");

    // Both are on disk, under their own target, with their own bytes. Before
    // this they were one path written twice and the second won.
    let entry = store.get(&outcome.digest).unwrap().unwrap();
    for target in targets {
        let p = entry
            .root
            .join(varve_core::store::PAYLOAD_DIR)
            .join("zephyr-sdk")
            .join("1.0.1")
            .join(target);
        assert_eq!(
            std::fs::read(&p).unwrap(),
            format!("bytes for {target}").into_bytes(),
            "{} holds the wrong toolchain",
            p.display()
        );
    }

    // And the store resolves each entry to its own file, which is what a
    // consumer asking for "the arm toolchain" actually calls.
    let manifest =
        varve_core::LayerManifest::parse(&std::fs::read(entry.root.join("layer.json")).unwrap())
            .unwrap();
    let mut resolved: Vec<String> = Vec::new();
    for e in &manifest.entries {
        if let Some(p) = store.entry_path(&entry, e) {
            resolved.push(p.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    resolved.sort();
    assert_eq!(resolved, vec!["arm-zephyr-eabi", "riscv64-zephyr-elf"]);
}
