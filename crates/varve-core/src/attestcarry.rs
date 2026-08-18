//! Carrying attestations with the layer (REQ-ATTEST-002).
//!
//! v0.22.0 shipped BINDING — `sign-attestation` / `check-attestation` — and a
//! review found REQ-ATTEST-001 marked verified with this half unimplemented.
//! Binding says "this attestation belongs to that layer". Carriage is what
//! makes the claim reach anyone: attestations attached to a deposit layout as
//! referrer artifacts, surviving `archive` and an offline install, and
//! reported by `varve verify`.
//!
//! Why it matters more than it sounds: registries DO publish this evidence and
//! mirroring tools DROP it. bandersnatch and Verdaccio carry no attestations,
//! and every Bazel Central Registry attestation URL points at github.com — so
//! the moment a consumer crosses an air gap they receive the bytes without the
//! evidence about them, and no error says so. A layer that travels without its
//! attestations is not less trustworthy; it is less ACCOUNTABLE, and the
//! consumer cannot tell the difference from the inside.
//!
//! Two blobs travel per attestation: the signed STATEMENT (varve's assertion
//! about the attestation) and the attestation BYTES themselves, verbatim. varve
//! never re-signs another party's judgement — re-signing would launder it under
//! this root and an assessor could no longer tell who asserted what (DD-021).
//!
//! The referrer machinery is line-status's (REQ-STATUS-DIST-001) rather than a
//! second shape, with one deliberate difference: a line has exactly one status,
//! so attaching REPLACES; a layer has many attestations, so attaching ADDS and
//! is keyed by the statement's own digest.

use std::path::Path;

use crate::attest::{AttestError, AttestationStatement};

/// Artifact type for a carried attestation statement.
pub const STATEMENT_ARTIFACT_TYPE: &str = crate::attest::PAYLOAD_TYPE;

/// Artifact type for the attested bytes travelling verbatim beside it.
pub const ATTESTATION_ARTIFACT_TYPE: &str =
    "application/vnd.pulseengine.varve.attestation-bytes.v1";

/// Annotation linking carried bytes back to the statement about them.
pub const ANN_STATEMENT: &str = "eu.pulseengine.varve.attests";

#[derive(Debug, thiserror::Error)]
pub enum CarryError {
    #[error(transparent)]
    Attest(#[from] AttestError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {reason}")]
    Layout { path: String, reason: String },
    #[error(
        "layer {layer} carries an attestation statement whose attested bytes are not present in \
         the layout (statement {statement}, expected blob {digest}). The statement travelled and \
         the evidence did not — which is exactly the mirror-boundary failure carriage exists to \
         prevent."
    )]
    OrphanStatement {
        layer: String,
        statement: String,
        digest: String,
    },
}

/// One attestation as it sits in a layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedAttestation {
    /// Digest of the signed statement envelope.
    pub statement_digest: String,
    /// The statement envelope bytes.
    pub statement: Vec<u8>,
    /// The attested bytes, verbatim as the producer emitted them.
    pub bytes: Vec<u8>,
}

/// What `verify` reports about one carried attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationReport {
    pub kind: String,
    pub producer: String,
    /// Whether the statement verifies against the trust root AND still binds
    /// to this layer and these bytes.
    pub binds: bool,
    /// Why not, when it does not.
    pub reason: Option<String>,
}

fn io(path: &Path, source: std::io::Error) -> CarryError {
    CarryError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn blob_path(layout: &Path, digest: &str) -> std::path::PathBuf {
    layout
        .join("blobs")
        .join("sha256")
        .join(digest.strip_prefix("sha256:").unwrap_or(digest))
}

/// Attach an attestation to a deposit layout: both blobs, plus two referrer
/// entries. Idempotent — re-attaching the same statement replaces its entries
/// rather than duplicating them, so a re-run CI step stays clean.
pub fn attach(
    layout: &Path,
    statement_envelope: &[u8],
    attested_bytes: &[u8],
) -> Result<String, CarryError> {
    let st_digest = crate::store::manifest_digest(statement_envelope);
    let bytes_digest = crate::store::manifest_digest(attested_bytes);

    let dir = layout.join("blobs").join("sha256");
    std::fs::create_dir_all(&dir).map_err(|e| io(&dir, e))?;
    for (digest, content) in [
        (&st_digest, statement_envelope),
        (&bytes_digest, attested_bytes),
    ] {
        let p = blob_path(layout, digest);
        std::fs::write(&p, content).map_err(|e| io(&p, e))?;
    }

    let index_path = layout.join("index.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).map_err(|e| io(&index_path, e))?)
            .map_err(|e| CarryError::Layout {
                path: index_path.display().to_string(),
                reason: format!("index.json: {e}"),
            })?;
    let entries = index["manifests"]
        .as_array_mut()
        .ok_or_else(|| CarryError::Layout {
            path: index_path.display().to_string(),
            reason: "index.json has no manifests array".into(),
        })?;
    // Replace THIS statement's entries only. A layer has many attestations, so
    // unlike line-status this must not clear the others.
    entries.retain(|e| {
        !(e["digest"] == *st_digest
            || (e["artifactType"] == ATTESTATION_ARTIFACT_TYPE
                && e["annotations"][ANN_STATEMENT] == *st_digest))
    });
    entries.push(serde_json::json!({
        "mediaType": "application/json",
        "artifactType": STATEMENT_ARTIFACT_TYPE,
        "digest": st_digest,
        "size": statement_envelope.len(),
    }));
    entries.push(serde_json::json!({
        "mediaType": "application/octet-stream",
        "artifactType": ATTESTATION_ARTIFACT_TYPE,
        "digest": bytes_digest,
        "size": attested_bytes.len(),
        "annotations": { ANN_STATEMENT: st_digest }
    }));
    std::fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).expect("index serializes"),
    )
    .map_err(|e| io(&index_path, e))?;
    Ok(st_digest)
}

/// Every attestation a layout carries. A statement whose attested bytes are
/// absent is an ERROR, not a skipped entry: that is precisely the
/// mirror-boundary failure this requirement exists to catch, and dropping it
/// silently would reproduce the bug in the code meant to detect it.
pub fn read_all(layout: &Path, layer: &str) -> Result<Vec<CarriedAttestation>, CarryError> {
    let index_path = layout.join("index.json");
    let bytes = match std::fs::read(&index_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io(&index_path, source)),
    };
    let index: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| CarryError::Layout {
            path: index_path.display().to_string(),
            reason: format!("index.json: {e}"),
        })?;
    let Some(entries) = index["manifests"].as_array() else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for entry in entries {
        if entry["artifactType"] != STATEMENT_ARTIFACT_TYPE {
            continue;
        }
        let Some(st_digest) = entry["digest"].as_str() else {
            continue;
        };
        let st_path = blob_path(layout, st_digest);
        let statement = std::fs::read(&st_path).map_err(|e| io(&st_path, e))?;

        // Find the bytes this statement is about.
        let bytes_digest = entries
            .iter()
            .find(|e| {
                e["artifactType"] == ATTESTATION_ARTIFACT_TYPE
                    && e["annotations"][ANN_STATEMENT] == *st_digest
            })
            .and_then(|e| e["digest"].as_str());
        let Some(bytes_digest) = bytes_digest else {
            return Err(CarryError::OrphanStatement {
                layer: layer.to_string(),
                statement: st_digest.to_string(),
                digest: "<no referrer entry>".into(),
            });
        };
        let b_path = blob_path(layout, bytes_digest);
        let attested = std::fs::read(&b_path).map_err(|_| CarryError::OrphanStatement {
            layer: layer.to_string(),
            statement: st_digest.to_string(),
            digest: bytes_digest.to_string(),
        })?;
        out.push(CarriedAttestation {
            statement_digest: st_digest.to_string(),
            statement,
            bytes: attested,
        });
    }
    // Same deterministic order as `read_persisted`. These two readers agreed
    // by luck until a full-suite run disagreed: index order here, `read_dir`
    // order there, and `read_dir` order is filesystem-dependent. Evidence that
    // reshuffles between runs is a diff generator for anyone recording verify
    // output, and an order-dependent test is a flake waiting to be explained
    // away.
    out.sort_by(|a, b| a.statement_digest.cmp(&b.statement_digest));
    Ok(out)
}

/// Report on every carried attestation: does it verify against the root, and
/// does it still bind to THIS layer and THESE bytes?
///
/// Reporting, not refusing. An attestation that no longer binds is evidence
/// about the evidence — a consumer must see it, but a layer whose own
/// signature and digests are good is still a good layer. Failing the install
/// on a third party's stale audit would make varve's verdict depend on someone
/// else's release cadence.
pub fn report(
    carried: &[CarriedAttestation],
    layer_manifest_digest: &str,
    layer_name: &str,
    root_pk: &[u8],
) -> Vec<AttestationReport> {
    carried
        .iter()
        .map(|c| {
            let st: AttestationStatement =
                match crate::attest::verify_statement(&c.statement, root_pk) {
                    Ok(st) => st,
                    Err(e) => {
                        return AttestationReport {
                            kind: "<unverified>".into(),
                            producer: "<unverified>".into(),
                            binds: false,
                            reason: Some(e.to_string()),
                        };
                    }
                };
            let reason = crate::attest::check(&st, &c.bytes, layer_manifest_digest, layer_name)
                .err()
                .map(|e| e.to_string());
            AttestationReport {
                kind: st.kind.to_string(),
                producer: st.producer.clone(),
                binds: reason.is_none(),
                reason,
            }
        })
        .collect()
}

/// Where an installed layer keeps the attestations that travelled with it.
pub const STORE_DIR: &str = "attestations";

/// Persist carried attestations into an installed layer's root, so they
/// survive into `archive` and an offline re-export. Without this the evidence
/// reaches the machine and then dies there — the same mirror-boundary loss,
/// one hop later.
pub fn persist(layer_root: &Path, carried: &[CarriedAttestation]) -> Result<(), CarryError> {
    if carried.is_empty() {
        return Ok(());
    }
    let dir = layer_root.join(STORE_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| io(&dir, e))?;
    for c in carried {
        let stem = c
            .statement_digest
            .strip_prefix("sha256:")
            .unwrap_or(&c.statement_digest);
        let st = dir.join(format!("{stem}.statement.json"));
        std::fs::write(&st, &c.statement).map_err(|e| io(&st, e))?;
        let by = dir.join(format!("{stem}.bytes"));
        std::fs::write(&by, &c.bytes).map_err(|e| io(&by, e))?;
    }
    Ok(())
}

/// Read back what `persist` wrote. A statement without its bytes is an error
/// here too — the loss is the thing being detected, wherever it happens.
pub fn read_persisted(
    layer_root: &Path,
    layer: &str,
) -> Result<Vec<CarriedAttestation>, CarryError> {
    let dir = layer_root.join(STORE_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(io(&dir, source)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| io(&dir, e))?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".statement.json") else {
            continue;
        };
        let statement = std::fs::read(&path).map_err(|e| io(&path, e))?;
        let bytes_path = dir.join(format!("{stem}.bytes"));
        let bytes = std::fs::read(&bytes_path).map_err(|_| CarryError::OrphanStatement {
            layer: layer.to_string(),
            statement: format!("sha256:{stem}"),
            digest: bytes_path.display().to_string(),
        })?;
        out.push(CarriedAttestation {
            statement_digest: format!("sha256:{stem}"),
            statement,
            bytes,
        });
    }
    // Deterministic order — see the note in `read_all`.
    out.sort_by(|a, b| a.statement_digest.cmp(&b.statement_digest));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{AttestationKind, sign, statement};
    use crate::verify::generate_root_keypair;

    /// A minimal layout with an index.json, as `deposit` writes.
    fn layout() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("index.json"),
            br#"{"schemaVersion":2,"manifests":[]}"#,
        )
        .unwrap();
        tmp
    }

    const LAYER: &str = "2026.08.0";
    const LAYER_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn an_attestation_travels_with_the_layer_and_still_binds() {
        // The whole point: the statement AND the bytes cross the boundary, and
        // the claim is still checkable on the far side with no network.
        let (sk, pk) = generate_root_keypair();
        let tmp = layout();
        let bytes = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[]}"#;
        let st = statement(
            LAYER,
            LAYER_DIGEST,
            AttestationKind::Provenance,
            bytes,
            "acme-ci",
        );
        let envelope = sign(&st, &sk, "root-1").unwrap();

        attach(tmp.path(), envelope.as_bytes(), bytes).unwrap();

        let carried = read_all(tmp.path(), LAYER).unwrap();
        assert_eq!(carried.len(), 1, "one attestation carried");
        assert_eq!(
            carried[0].bytes, bytes,
            "the attested bytes travel VERBATIM — varve carries another party's \
             judgement, it does not restate it"
        );

        let reports = report(&carried, LAYER_DIGEST, LAYER, &pk);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].binds, "reason: {:?}", reports[0].reason);
        assert_eq!(reports[0].producer, "acme-ci");
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn a_statement_whose_evidence_did_not_travel_is_an_error_not_a_skip() {
        // THE mirror-boundary failure. bandersnatch and Verdaccio drop
        // attestations; a consumer must not receive a layout that looks
        // attested while the evidence is gone. Silently skipping the entry
        // would reproduce, inside the detector, the exact bug it exists to
        // detect.
        let (sk, _pk) = generate_root_keypair();
        let tmp = layout();
        let bytes = b"the-evidence";
        let st = statement(LAYER, LAYER_DIGEST, AttestationKind::Sbom, bytes, "acme-ci");
        let envelope = sign(&st, &sk, "root-1").unwrap();
        attach(tmp.path(), envelope.as_bytes(), bytes).unwrap();

        // A mirror drops the evidence blob but keeps the index entry.
        std::fs::remove_file(blob_path(tmp.path(), &crate::store::manifest_digest(bytes))).unwrap();

        let err = read_all(tmp.path(), LAYER).expect_err("an orphaned statement must be an error");
        let msg = err.to_string();
        assert!(msg.contains(LAYER), "names the layer: {msg}");
        assert!(
            msg.contains("did not"),
            "says the evidence failed to travel, not merely that a file is absent: {msg}"
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn an_attestation_for_another_layer_is_reported_as_not_binding() {
        // Carriage must not launder a mis-issued statement into looking
        // attached just because it physically travelled beside the layer.
        let (sk, pk) = generate_root_keypair();
        let tmp = layout();
        let bytes = b"evidence-for-someone-else";
        let other = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let st = statement(
            "2026.01.0",
            other,
            AttestationKind::Provenance,
            bytes,
            "acme-ci",
        );
        attach(
            tmp.path(),
            sign(&st, &sk, "root-1").unwrap().as_bytes(),
            bytes,
        )
        .unwrap();

        let carried = read_all(tmp.path(), LAYER).unwrap();
        let reports = report(&carried, LAYER_DIGEST, LAYER, &pk);
        assert!(
            !reports[0].binds,
            "a statement for another layer must not bind"
        );
        assert!(
            reports[0].reason.as_ref().unwrap().contains("refusing"),
            "the reason must say what was refused: {:?}",
            reports[0].reason
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn an_attestation_signed_by_someone_else_does_not_bind() {
        // The carried statement is varve's own assertion, so it must verify
        // under the realm's root. Physical proximity in a layout is not
        // evidence of anything.
        let (impostor_sk, _) = generate_root_keypair();
        let (_realm_sk, realm_pk) = generate_root_keypair();
        let tmp = layout();
        let bytes = b"evidence";
        let st = statement(
            LAYER,
            LAYER_DIGEST,
            AttestationKind::Provenance,
            bytes,
            "acme-ci",
        );
        attach(
            tmp.path(),
            sign(&st, &impostor_sk, "not-the-realm").unwrap().as_bytes(),
            bytes,
        )
        .unwrap();

        let carried = read_all(tmp.path(), LAYER).unwrap();
        let reports = report(&carried, LAYER_DIGEST, LAYER, &realm_pk);
        assert!(!reports[0].binds);
        assert_eq!(
            reports[0].kind, "<unverified>",
            "an unverified statement's own claims must not be echoed as fact"
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn many_attestations_travel_together_and_reattaching_is_idempotent() {
        // A line-status is one per line and attaching REPLACES. A layer has an
        // SBOM and a provenance and an audit; attaching must ADD. Getting this
        // wrong would silently keep only the last one attached.
        let (sk, pk) = generate_root_keypair();
        let tmp = layout();
        let sbom = b"sbom-bytes";
        let slsa = b"slsa-bytes";
        for (kind, bytes) in [
            (AttestationKind::Sbom, sbom.as_slice()),
            (AttestationKind::Provenance, slsa.as_slice()),
        ] {
            let st = statement(LAYER, LAYER_DIGEST, kind, bytes, "acme-ci");
            attach(
                tmp.path(),
                sign(&st, &sk, "root-1").unwrap().as_bytes(),
                bytes,
            )
            .unwrap();
        }
        assert_eq!(
            read_all(tmp.path(), LAYER).unwrap().len(),
            2,
            "both carried"
        );

        // Re-attaching one (a CI re-run) must not duplicate it.
        let st = statement(LAYER, LAYER_DIGEST, AttestationKind::Sbom, sbom, "acme-ci");
        attach(
            tmp.path(),
            sign(&st, &sk, "root-1").unwrap().as_bytes(),
            sbom,
        )
        .unwrap();
        let carried = read_all(tmp.path(), LAYER).unwrap();
        assert_eq!(carried.len(), 2, "re-attaching replaces, never duplicates");
        assert!(
            report(&carried, LAYER_DIGEST, LAYER, &pk)
                .iter()
                .all(|r| r.binds)
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn evidence_survives_the_store_and_can_be_re_emitted() {
        // The requirement's actual subject: the evidence must cross the air
        // gap, not merely reach the machine. bandersnatch and Verdaccio drop
        // attestations and every BCR attestation URL points at github.com, so
        // a consumer downstream of a mirror gets bytes with no accountability
        // and no error saying so. Persisting into the installed layer is what
        // lets `archive` put it back on the wire.
        let (sk, pk) = generate_root_keypair();
        let src = layout();
        let sbom = b"sbom-bytes";
        let prov = b"provenance-bytes";
        for (kind, bytes) in [
            (AttestationKind::Sbom, sbom.as_slice()),
            (AttestationKind::Provenance, prov.as_slice()),
        ] {
            let st = statement(LAYER, LAYER_DIGEST, kind, bytes, "acme-ci");
            attach(
                src.path(),
                sign(&st, &sk, "root-1").unwrap().as_bytes(),
                bytes,
            )
            .unwrap();
        }
        let carried = read_all(src.path(), LAYER).unwrap();

        // Install persists it into the layer root…
        let installed = tempfile::tempdir().unwrap();
        persist(installed.path(), &carried).unwrap();
        let back = read_persisted(installed.path(), LAYER).unwrap();
        assert_eq!(back.len(), 2, "both attestations survive the store");

        // …and it re-emits into a fresh layout, byte-identical, still binding
        // with NO network and NO trust in the transport.
        let dest = layout();
        for c in &back {
            attach(dest.path(), &c.statement, &c.bytes).unwrap();
        }
        let round_tripped = read_all(dest.path(), LAYER).unwrap();
        assert_eq!(
            round_tripped, carried,
            "the evidence that crossed the gap is the evidence that was signed"
        );
        assert!(
            report(&round_tripped, LAYER_DIGEST, LAYER, &pk)
                .iter()
                .all(|r| r.binds),
            "every attestation still binds on the far side"
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn a_store_that_lost_the_evidence_is_an_error_on_read_back_too() {
        // The loss is the thing being detected, wherever it happens — a
        // half-copied store must not read back as "this layer has fewer
        // attestations than it does".
        let (sk, _pk) = generate_root_keypair();
        let installed = tempfile::tempdir().unwrap();
        let bytes = b"evidence";
        let st = statement(LAYER, LAYER_DIGEST, AttestationKind::Audit, bytes, "acme");
        persist(
            installed.path(),
            &[CarriedAttestation {
                statement_digest: crate::store::manifest_digest(
                    sign(&st, &sk, "k").unwrap().as_bytes(),
                ),
                statement: sign(&st, &sk, "k").unwrap().into_bytes(),
                bytes: bytes.to_vec(),
            }],
        )
        .unwrap();

        // Something copies the statements and not the payloads.
        for e in std::fs::read_dir(installed.path().join(STORE_DIR)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "bytes") {
                std::fs::remove_file(p).unwrap();
            }
        }
        assert!(
            matches!(
                read_persisted(installed.path(), LAYER),
                Err(CarryError::OrphanStatement { .. })
            ),
            "a statement whose evidence is gone must not read back as absent"
        );
    }
}
