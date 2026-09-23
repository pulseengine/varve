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

[[docs]]
name      = "varve-core-api"
repo      = "pulseengine/varve"
version   = "0.36.0"
release   = "v0.36.0"
format    = "rustdoc"
entry     = "varve_core/index.html"
documents = "varve-core"
asset     = "varve-core-%V-rustdoc.tar.gz"

# The composition: this layer carries its own payloads AND references another
# realm's layer by the digest of its signed manifest.
[[include]]
digest = "sha256:001480e799f7274248863a89a76deeb333ee475701bc2702f86fe326b527ae6e"
realm  = "pulseengine"
layer  = "2026.09.4"

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
    tar_gz_mode(files, 0o644)
}

/// A tool archive: the binary must be executable, or staging refuses it.
fn tar_gz_exec(files: &[(&str, &[u8])]) -> Vec<u8> {
    tar_gz_mode(files, 0o755)
}

fn tar_gz_mode(files: &[(&str, &[u8])], mode: u32) -> Vec<u8> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut b = tar::Builder::new(enc);
    for (path, bytes) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(mode);
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
    // Rustdoc's real top level — the crate directory beside `static.files` and
    // `crates.js`, as in the archive release.yml builds. A lone `varve_core/`
    // would read as a wrapper directory and have its root stripped, which is
    // a shape rustdoc never produces.
    let api = tar_gz(&[
        ("crates.js", b"window.ALL_CRATES = [\"varve_core\"];"),
        ("static.files/rustdoc.css", b"body{}"),
        ("varve_core/index.html", b"<h1>varve_core</h1>"),
    ]);

    let m = varve_core::layerspec::parse_layer_manifest(MANIFEST).expect("layer.toml");
    let plan = varve_producer::plan::plan(&m, &["x86_64-unknown-linux-gnu"]).expect("plan");

    let mut staged = Vec::new();
    for item in &plan {
        let bytes = match item.name.as_str() {
            "handbook" => &pdf,
            "trace" => &site,
            "varve-core" => &krate,
            "varve-core-api" => &api,
            other => panic!("unplanned payload {other}"),
        };
        std::fs::write(dl.join(&item.asset), bytes).unwrap();
        let r = Resolved {
            plan: item.clone(),
            digest: sha256(bytes),
            accepted: Accepted {
                mechanism: Mechanism::CosignSums,
                signer: Some("https://github.com/pulseengine/varve/.github/workflows/release.yml@refs/tags/v0.36.0".into()),
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
        staged.push(out);
    }
    // Through the producer's own fold, not a hand-built spec: `describe` is
    // what `varve-producer deposit` calls, and the includes ride with it.
    let spec = varve_producer::deposit::describe("2026.09.4", "rolling", 5, staged, &m.includes);

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
            includes: file_spec
                .includes
                .into_iter()
                .map(varve_core::deposit::SpecInclude::into_deposit_include)
                .collect(),
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
    // The composition must be INSIDE the signature, or it can drift after
    // signing — which is the one thing an include exists to prevent.
    let included: Vec<&varve_core::manifest::ManifestEntry> = signed
        .entries
        .iter()
        .filter(|e| e.kind() == Ok(varve_core::PayloadKind::Layer))
        .collect();
    assert_eq!(
        included.len(),
        1,
        "a [[include]] in layer.toml did not reach the signed layer — a realm cannot \
         compose at all, which is why composition has no worked example"
    );
    assert_eq!(
        included[0].digest,
        "sha256:001480e799f7274248863a89a76deeb333ee475701bc2702f86fe326b527ae6e"
    );
    assert_eq!(
        included[0]
            .annotations
            .get(varve_core::compose::ANN_INCLUDE_REALM)
            .map(String::as_str),
        Some("pulseengine"),
        "without the realm, verify falls back to the PINNING project's root — trust widening"
    );
    assert_eq!(
        included[0]
            .annotations
            .get(varve_core::compose::ANN_INCLUDE_LAYER)
            .map(String::as_str),
        Some("2026.09.4")
    );
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

    // The rustdoc names the crate it documents, and only it does.
    assert_eq!(kind("varve-core-api"), varve_core::PayloadKind::Docs);
    assert_eq!(
        ann("varve-core-api", varve_core::deposit::ANN_DOCS_FORMAT).as_deref(),
        Some("rustdoc")
    );
    assert_eq!(
        ann("varve-core-api", varve_core::deposit::ANN_DOCS_DOCUMENTS).as_deref(),
        Some("varve-core"),
        "a declared `documents` did not reach the signed layer"
    );
    assert_eq!(
        ann("handbook", varve_core::deposit::ANN_DOCS_DOCUMENTS),
        None
    );
}

/// A realm that ingests an unproven upstream on a recorded opt-in must be able
/// to DEPOSIT it.
///
/// `pulseengine-wasm` layer 2026.09.0 failed on exactly this, after the opt-in
/// itself was fixed:
///
///   error: payload 'wac' from bytecodealliance/wac declares proof =
///   "unverified" and also names proof-signer "" — nothing vouched for these
///   bytes, so naming an identity that did would be signed, attributable and
///   false.
///
/// The refusal is right. The producer was wrong: the ingest ladder's unverified
/// rung reports "no signer" as an EMPTY STRING, and staging wrapped that in
/// `Some(..)` unconditionally, so "nobody vouched" was signed as "somebody
/// vouched and declined to say who". Both halves had tests — the ladder's, that
/// the signer is empty; the spec's, that a `None` signer is not rendered — and
/// neither one ever ran the empty string through the thing that decides.
///
/// So this drives the REAL ladder (`choose`, with a probe that offers nothing)
/// into the unverified rung and carries its answer the whole way to a signed
/// layer, the way the realm's own deposit does.
// rivet: verifies REQ-INGEST-001
#[test]
fn an_unproven_upstream_ingested_on_an_opt_in_reaches_a_signed_layer() {
    const OPTIN_MANIFEST: &str = r#"
[varve]
version = "v0.37.0"

[realm]
name     = "pulseengine-wasm"
channel  = "rolling"
registry = "oci://ghcr.io/pulseengine/wasm-layers"

[[tool]]
name    = "wac"
repo    = "bytecodealliance/wac"
version = "v0.11.0"
asset   = "wac-%V.tar.gz"
unverified-reason = "publishes neither cosign-signed sums nor build provenance (measured 2026-09-18)"
"#;

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

    let m = varve_core::layerspec::parse_layer_manifest(OPTIN_MANIFEST).expect("layer.toml");
    let plan = varve_producer::plan::plan(&m, &["x86_64-unknown-linux-gnu"]).expect("plan");
    // The opt-ins the deposit command would be running with: the manifest's own
    // reasons, no environment.
    let optins = varve_producer::ingest::optins_in_force(
        plan.iter().filter_map(|p| {
            p.unverified_reason
                .as_ref()
                .map(|why| (p.repo.clone(), why.clone()))
        }),
        "",
    );

    let mut staged = Vec::new();
    for item in &plan {
        let bytes = tar_gz_exec(&[("wac", b"#!/bin/sh\nexec true\n")]);
        std::fs::write(dl.join(&item.asset), &bytes).unwrap();
        // Not a hand-written verdict: the ladder itself, with a release that
        // offers no cosign sums, no attestation and no upstream sums.
        let accepted = varve_producer::ingest::choose(
            &varve_producer::forge::Forge::github_com(),
            &item.repo,
            &item.version,
            &varve_producer::ingest::ReleaseProbe::default(),
            &optins,
            None,
        )
        .expect("the recorded opt-in admits it");
        assert_eq!(accepted.mechanism, Mechanism::Unverified);

        let r = Resolved {
            plan: item.clone(),
            digest: sha256(&bytes),
            accepted,
            bytes: None,
            decision: Decision::Fetch {
                why: FetchReason::NoPrevious,
            },
        };
        staged.push(
            // A tool payload is unpacked for real: `Spawn` is the runner the
            // producer itself uses.
            stage_one(
                &varve_producer::source::Spawn,
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
            .unwrap_or_else(|e| panic!("staging {}: {e:#}", item.name)),
        );
    }

    let spec = varve_producer::deposit::describe("2026.09.0", "rolling", 1, staged, &m.includes);
    let text = spec.render().unwrap();
    assert!(
        !text.contains("proof-signer"),
        "the producer names a signer for bytes nobody vouched for:\n{text}"
    );
    let file_spec = varve_core::parse_deposit_spec(&text).unwrap();
    let tools = file_spec
        .tools
        .into_iter()
        .map(|t| t.into_deposit_tool(&stage))
        .collect::<Result<Vec<_>, _>>()
        .expect("converts");
    let (sk, _pk) = varve_core::generate_root_keypair();
    varve_core::deposit(
        &varve_core::DepositSpec {
            includes: Vec::new(),
            layer: file_spec.layer.parse().unwrap(),
            channel: file_spec.channel,
            counter: file_spec.counter,
            issued_at: "2026-09-19T00:00:00Z".into(),
            tools,
        },
        &sk,
        "root-1",
        &layout,
    )
    .expect("an opt-in payload the producer staged deposits");

    let signed = signed_manifest(&layout);
    let wac = signed
        .entries
        .iter()
        .find(|e| e.annotations.get("eu.pulseengine.tool").map(String::as_str) == Some("wac"))
        .expect("wac is in the signed layer");
    assert_eq!(
        wac.annotations
            .get("eu.pulseengine.source.proof")
            .map(String::as_str),
        Some("unverified")
    );
    assert!(
        !wac.annotations
            .contains_key("eu.pulseengine.source.proof-signer"),
        "the layer names a signer for unverified bytes: {:?}",
        wac.annotations
    );
    assert!(
        wac.annotations
            .get("eu.pulseengine.source.proof-asserts")
            .is_some_and(|a| a.contains("NOTHING vouched")),
        "the reason the operator gave did not travel with the bytes: {:?}",
        wac.annotations
    );
}
