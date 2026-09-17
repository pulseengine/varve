//! What a realm DECLARES must be what its signed layer SAYS.
//!
//! Every link of this chain had tests, and the chain as a whole did not work.
//! `layer.toml` accepted `[[docs]]` with a format, an entry and a title;
//! `varve deposit` refused a docs payload without a format and signed the
//! format into the manifest; `varve export-docs` read it back. The system test
//! proved deposit → install → export end to end — from a HAND-WRITTEN spec.
//! Nothing ever fed a spec the producer wrote into the deposit, and the
//! producer wrote `kind = None` and no format for every document: a docs
//! payload deposited by `varve-producer` was signed as a plain tool, and
//! `export-docs` found nothing in the layer. Found 2026-09-17 while adding
//! crates, whose kind would have fallen through the same wildcard.
//!
//! So this test does not stop at any seam. It starts from `layer.toml` text,
//! runs the producer's own plan and staging, renders the spec, converts it with
//! the SAME function `varve deposit --spec` uses, signs a real layer, and reads
//! the signed manifest back.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use varve_producer::carryforward::{Decision, FetchReason};
use varve_producer::deposit::{Names, stage_one};
use varve_producer::gh::{CommandRunner, RunOutput};
use varve_producer::ingest::{Accepted, Mechanism};
use varve_producer::orchestrate::Resolved;
use varve_producer::spec::SpecOut;

const MANIFEST: &str = r#"
[varve]
version = "v0.36.0"

[realm]
name     = "pulseengine"
channel  = "rolling"
registry = "oci://ghcr.io/pulseengine/layers"

[[docs]]
name    = "handbook"
version = "1.2.0"
format  = "pdf"
title   = "The handbook"
asset   = "handbook-%V.pdf"

[[docs]]
name    = "trace"
repo    = "pulseengine/varve"
version = "0.36.0"
release = "v0.36.0"
format  = "html"
entry   = "index.html"
asset   = "trace-%V.tar.gz"

[[crate]]
name    = "varve-core"
repo    = "pulseengine/varve"
version = "0.36.0"
release = "v0.36.0"
"#;

/// Documents and crates never shell out; a runner that is called is a bug.
struct NoCommands;
impl CommandRunner for NoCommands {
    fn run(&self, program: &str, _a: &[String], _e: &[(String, String)]) -> RunOutput {
        panic!("staging a held payload ran {program}");
    }
}

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut b = tar::Builder::new(enc);
    for (path, bytes) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, path, *bytes).unwrap();
    }
    let mut enc = b.into_inner().unwrap();
    enc.flush().unwrap();
    enc.finish().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The signed layer manifest inside an OCI layout, found by trying every blob
/// — raw, or as the payload of a DSSE envelope.
fn signed_manifest(layout: &Path) -> varve_core::LayerManifest {
    use base64::Engine;
    let blobs = layout.join("blobs/sha256");
    for e in std::fs::read_dir(&blobs).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        if let Ok(m) = varve_core::LayerManifest::parse(&bytes) {
            return m;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(p) = v.get("payload").and_then(|p| p.as_str())
            && let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(p)
            && let Ok(m) = varve_core::LayerManifest::parse(&raw)
        {
            return m;
        }
    }
    panic!("no signed layer manifest in {}", layout.display());
}

// rivet: verifies REQ-LAYERDOCS-001
// rivet: partially-verifies REQ-CRATEPAYLOAD-001
#[test]
fn what_layer_toml_declares_is_what_the_signed_layer_says() {
    let tmp = tempfile::tempdir().unwrap();
    let (dl, stage, scratch, layout) = (
        tmp.path().join("dl"),
        tmp.path().join("stage"),
        tmp.path().join("scratch"),
        tmp.path().join("layout"),
    );
    for d in [&dl, &stage, &scratch] {
        std::fs::create_dir_all(d).unwrap();
    }

    let pdf = b"%PDF-1.7 the handbook".to_vec();
    let site = tar_gz(&[("index.html", b"<h1>trace</h1>"), ("a/b.html", b"<p/>")]);
    // Stands in for `cargo package` output: what matters is that the bytes
    // deposited are these bytes, unmodified, because their sha256 is the
    // `cksum` crates.io serves and that `export-cargo` writes into the index.
    let krate = tar_gz(&[("varve-core-0.36.0/Cargo.toml", b"[package]\n")]);

    let m = varve_core::layerspec::parse_layer_manifest(MANIFEST).expect("layer.toml");
    let plan = varve_producer::plan::plan(&m, &["x86_64-unknown-linux-gnu"]).expect("plan");

    let mut spec = SpecOut::new("2026.09.4", "rolling", 5);
    for item in &plan {
        let bytes = match item.name.as_str() {
            "handbook" => &pdf,
            "trace" => &site,
            "varve-core" => &krate,
            other => panic!("unplanned payload {other}"),
        };
        std::fs::write(dl.join(&item.asset), bytes).unwrap();
        let r = Resolved {
            plan: item.clone(),
            digest: sha256(bytes),
            accepted: Accepted {
                mechanism: Mechanism::CosignSums,
                signer: "https://github.com/pulseengine/varve/.github/workflows/release.yml@refs/tags/v0.36.0".into(),
                asserts: "SHA256SUMS.txt".into(),
            },
            bytes: None,
            decision: Decision::Fetch {
                why: FetchReason::NoPrevious,
            },
        };
        let out = stage_one(
            &NoCommands,
            &r,
            &item.version,
            &stage,
            &dl,
            &scratch,
            Names {
                deposited: &item.name,
                binary: &item.name,
            },
        )
        .unwrap_or_else(|e| panic!("staging {}: {e:#}", item.name));
        spec.tools.push(out);
    }

    let spec_path = stage.join("deposit.toml");
    std::fs::write(&spec_path, spec.render().unwrap()).unwrap();
    let file_spec =
        varve_core::parse_deposit_spec(&std::fs::read_to_string(&spec_path).unwrap()).unwrap();
    let tools = file_spec
        .tools
        .into_iter()
        .map(|t| t.into_deposit_tool(&stage))
        .collect::<Result<Vec<_>, _>>()
        .expect("the spec the producer wrote converts the way `varve deposit` converts it");
    let (sk, _pk) = varve_core::generate_root_keypair();
    varve_core::deposit(
        &varve_core::DepositSpec {
            includes: Vec::new(),
            layer: file_spec.layer.parse().unwrap(),
            channel: file_spec.channel,
            counter: file_spec.counter,
            issued_at: "2026-09-17T00:00:00Z".into(),
            tools,
        },
        &sk,
        "root-1",
        &layout,
    )
    .expect("the producer's spec deposits");

    let signed = signed_manifest(&layout);
    let by_name: BTreeMap<&str, &varve_core::manifest::ManifestEntry> = signed
        .entries
        .iter()
        .filter_map(|e| {
            e.annotations
                .get("eu.pulseengine.tool")
                .map(|n| (n.as_str(), e))
        })
        .collect();
    let ann = |name: &str, key: &str| {
        by_name
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not in the signed layer: {:?}", by_name.keys()))
            .annotations
            .get(key)
            .cloned()
    };
    let kind = |name: &str| by_name[name].kind().unwrap();

    assert_eq!(
        kind("handbook"),
        varve_core::PayloadKind::Docs,
        "a declared document was signed as something else"
    );
    assert_eq!(
        ann("handbook", varve_core::deposit::ANN_DOCS_FORMAT).as_deref(),
        Some("pdf")
    );
    assert_eq!(
        ann("handbook", varve_core::deposit::ANN_DOCS_TITLE).as_deref(),
        Some("The handbook")
    );

    assert_eq!(kind("trace"), varve_core::PayloadKind::Docs);
    assert_eq!(
        ann("trace", varve_core::deposit::ANN_DOCS_FORMAT).as_deref(),
        Some("html")
    );
    assert_eq!(
        ann("trace", varve_core::deposit::ANN_DOCS_ENTRY).as_deref(),
        Some("index.html")
    );

    assert_eq!(
        kind("varve-core"),
        varve_core::PayloadKind::Crate,
        "a declared crate was signed as something else"
    );
    assert_eq!(
        by_name["varve-core"].digest,
        format!("sha256:{}", sha256(&krate)),
        "the crate's bytes changed between the release and the layer — its digest is the crates.io cksum"
    );
}
