//! A document names the payload it documents (REQ-LAYERDOCS-001 clause 2).
//!
//! The field exists so a reader can ask for "the rustdoc of varve-core" rather
//! than guess which of several documents that is. That only works if the name
//! is RIGHT, and a wrong name signs as cleanly as a right one: the deposit is
//! the one place that can see every payload of the layer at once, so it is the
//! place that refuses a name matching nothing.

use std::path::Path;

use varve_core::{DepositError, DepositSpec, DepositTool, LayerManifest, PayloadKind};

fn tool(name: &str, kind: Option<PayloadKind>) -> DepositTool {
    DepositTool {
        name: name.into(),
        version: "0.36.0".into(),
        platform: None,
        bytes: format!("{name}-bytes").into_bytes(),
        source: None,
        runner: None,
        kind,
        sdk_prefix: None,
        docs_format: None,
        docs_entry: None,
        docs_title: None,
        docs_documents: None,
    }
}

fn rustdoc(documents: &str) -> DepositTool {
    DepositTool {
        docs_format: Some("rustdoc".into()),
        docs_entry: Some("varve_core/index.html".into()),
        docs_documents: Some(documents.into()),
        ..tool("varve-core-api", Some(PayloadKind::Docs))
    }
}

fn deposit(tools: Vec<DepositTool>, dest: &Path) -> Result<LayerManifest, DepositError> {
    let (sk, _pk) = varve_core::generate_root_keypair();
    varve_core::deposit(
        &DepositSpec {
            includes: Vec::new(),
            layer: "2026.09.4".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-09-17T00:00:00Z".into(),
            tools,
        },
        &sk,
        "root-1",
        dest,
    )?;
    Ok(signed_manifest(dest))
}

/// The signed layer manifest, read back out of the layout.
fn signed_manifest(layout: &Path) -> LayerManifest {
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        if let Ok(m) = LayerManifest::parse(&bytes) {
            return m;
        }
    }
    panic!("no signed layer manifest in {}", layout.display());
}

// rivet: verifies REQ-LAYERDOCS-001
#[test]
fn the_payload_a_document_documents_is_signed_into_the_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let m = deposit(
        vec![
            tool("varve-core", Some(PayloadKind::Crate)),
            rustdoc("varve-core"),
        ],
        &tmp.path().join("layout"),
    )
    .expect("a document naming a payload of its own layer deposits");
    let doc = m
        .entries
        .iter()
        .find(|e| {
            e.annotations.get("eu.pulseengine.tool").map(String::as_str) == Some("varve-core-api")
        })
        .expect("the document is in the layer");
    assert_eq!(
        doc.annotations
            .get(varve_core::deposit::ANN_DOCS_DOCUMENTS)
            .map(String::as_str),
        Some("varve-core")
    );
    let krate = m
        .entries
        .iter()
        .find(|e| {
            e.annotations.get("eu.pulseengine.tool").map(String::as_str) == Some("varve-core")
        })
        .expect("the crate is in the layer");
    assert!(
        !krate
            .annotations
            .contains_key(varve_core::deposit::ANN_DOCS_DOCUMENTS),
        "only the document carries the field"
    );
}

/// A typo signs as cleanly as the right name, and would then answer every
/// `export-docs --for varve-core` with "nothing documents that".
// rivet: verifies REQ-LAYERDOCS-001
#[test]
fn a_document_naming_a_payload_the_layer_does_not_carry_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![
            tool("varve-core", Some(PayloadKind::Crate)),
            rustdoc("varve_core"),
        ],
        &tmp.path().join("layout"),
    )
    .expect_err("a dangling name must not be signed");
    let msg = err.to_string();
    assert!(
        matches!(err, DepositError::DocsDocumentsDangling { .. }),
        "{err:?}"
    );
    assert!(msg.contains("varve_core"), "names what was asked: {msg}");
    assert!(msg.contains("varve-core"), "names what IS carried: {msg}");
    assert!(
        !tmp.path().join("layout").exists(),
        "nothing is written for a refused deposit"
    );
}

/// Documentation of documentation is not a thing a reader asks for; allowing
/// it would let a document satisfy the check by naming itself.
// rivet: verifies REQ-LAYERDOCS-001
#[test]
fn a_document_cannot_document_a_document_or_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let err = deposit(
        vec![
            tool("varve-core", Some(PayloadKind::Crate)),
            rustdoc("varve-core-api"),
        ],
        &tmp.path().join("layout"),
    )
    .expect_err("a document naming a document must be refused");
    assert!(
        matches!(err, DepositError::DocsDocumentsDangling { .. }),
        "{err:?}"
    );
}

/// The field on anything but a document is an annotation nothing reads.
// rivet: verifies REQ-LAYERDOCS-001
#[test]
fn documents_on_a_payload_that_is_not_documentation_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut krate = tool("varve-core", Some(PayloadKind::Crate));
    krate.docs_documents = Some("varve-core".into());
    let err = deposit(vec![krate], &tmp.path().join("layout"))
        .expect_err("documents on a crate must be refused");
    assert!(
        matches!(err, DepositError::DocsDocumentsOnNonDocs { .. }),
        "{err:?}"
    );
}
