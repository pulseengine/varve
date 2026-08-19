//! Line-status documents (REQ-KP-001, DD-008) — signed, updatable evidence
//! beside immutable layers.
//!
//! One document per release line carries what changes *after* deposit:
//! known problems (the Ferrocene schema: workaround, detection, mitigation,
//! affected layers), the support window, and yank markers. It is DSSE-signed
//! with the same root as layers but under its own payload type, carries its
//! own monotonic counter, and is cached per line so `varve status` answers
//! offline. A yanked layer warns loudly but remains installable — the
//! consumer owns the freeze decision.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::install::VerifyError;
use crate::layer::{LayerId, Line};
use crate::verify::{dsse_sign_typed, dsse_verify_typed};

/// The authenticated payload type — a signed something-else cannot be
/// replayed as a status document.
pub const LINE_STATUS_PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.line-status.v1+json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownProblem {
    pub id: String,
    pub title: String,
    pub severity: String,
    /// Layers affected, e.g. ["2026.07.0", "2026.07.1"].
    pub affected: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub workaround: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineStatus {
    /// The release line, e.g. "2026.07".
    pub line: String,
    /// Monotonic per-line document counter — a stale advisory must not
    /// silently replace a newer one.
    pub counter: u64,
    /// RFC 3339 issue time of this document.
    #[serde(rename = "issued-at")]
    pub issued_at: String,
    /// Stated support window end, RFC 3339 date, if committed.
    #[serde(
        rename = "support-until",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub support_until: Option<String>,
    /// Yanked layers of this line, layer → reason.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub yanked: BTreeMap<String, String>,
    #[serde(
        rename = "known-problems",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub known_problems: Vec<KnownProblem>,
}

#[derive(Debug, thiserror::Error)]
pub enum LineStatusError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("line-status payload is not valid: {0}")]
    Payload(String),
    #[error("line-status covers line {got} but line {expected} was requested")]
    LineMismatch { expected: String, got: String },
    #[error(
        "refusing stale line-status document for {line}: presented counter {presented}, cached {cached}"
    )]
    Stale {
        line: String,
        presented: u64,
        cached: u64,
    },
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl LineStatus {
    /// Verify an envelope against the trust root and parse the payload.
    pub fn verify_and_parse(
        envelope: &[u8],
        root_public_key: &[u8],
    ) -> Result<Self, LineStatusError> {
        let payload = dsse_verify_typed(envelope, LINE_STATUS_PAYLOAD_TYPE, root_public_key)?;
        serde_json::from_slice(&payload).map_err(|e| LineStatusError::Payload(e.to_string()))
    }

    /// Sign a status document (the producing side — CI, next to deposit).
    pub fn sign(&self, secret_key: &[u8], key_id: &str) -> Result<String, LineStatusError> {
        let payload = serde_json::to_vec_pretty(self).expect("status serializes");
        Ok(dsse_sign_typed(
            &payload,
            LINE_STATUS_PAYLOAD_TYPE,
            secret_key,
            key_id,
        )?)
    }

    /// What this document says about one layer.
    pub fn report_for(&self, layer: &LayerId) -> LayerStatusReport {
        let name = layer.to_string();
        let problems: Vec<&KnownProblem> = self
            .known_problems
            .iter()
            .filter(|kp| kp.affected.iter().any(|a| a == &name))
            .collect();
        LayerStatusReport {
            yanked_reason: self.yanked.get(&name).cloned(),
            support_until: self.support_until.clone(),
            problems_total: problems.len(),
            problems_with_workaround: problems.iter().filter(|kp| kp.workaround.is_some()).count(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerStatusReport {
    pub yanked_reason: Option<String>,
    pub support_until: Option<String>,
    pub problems_total: usize,
    pub problems_with_workaround: usize,
}

/// Per-line cache of the newest verified document, under the varve root.
#[derive(Debug)]
pub struct StatusCache {
    dir: PathBuf,
}

impl StatusCache {
    pub fn at_root(root: &Path) -> Self {
        StatusCache {
            dir: root.join("state").join("line-status"),
        }
    }

    /// Store a VERIFIED envelope for its line, refusing counter regressions.
    pub fn update(
        &self,
        line: &Line,
        envelope: &[u8],
        parsed: &LineStatus,
    ) -> Result<(), LineStatusError> {
        if let Some(cached) = self.load_parsed(line)?
            && parsed.counter < cached.counter
        {
            return Err(LineStatusError::Stale {
                line: line.to_string(),
                presented: parsed.counter,
                cached: cached.counter,
            });
        }
        let io = |path: &Path, source: std::io::Error| LineStatusError::Io {
            path: path.display().to_string(),
            source,
        };
        std::fs::create_dir_all(&self.dir).map_err(|e| io(&self.dir, e))?;
        let path = self.envelope_path(line);
        std::fs::write(&path, envelope).map_err(|e| io(&path, e))?;
        Ok(())
    }

    /// The cached envelope bytes for a line, unparsed, if any.
    ///
    /// Used by `archive` to carry the baseline across an air gap (varve#77).
    /// Deliberately opaque: the caller re-attaches the bytes verbatim, and the
    /// far side re-verifies against its own trust root — archiving must not
    /// become a place where a document is re-signed or re-shaped.
    pub fn envelope_bytes(&self, line: &Line) -> Result<Option<Vec<u8>>, LineStatusError> {
        let path = self.envelope_path(line);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(LineStatusError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Load and re-verify the cached envelope for a line.
    pub fn load(
        &self,
        line: &Line,
        root_public_key: &[u8],
    ) -> Result<Option<LineStatus>, LineStatusError> {
        let path = self.envelope_path(line);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(LineStatus::verify_and_parse(&bytes, root_public_key)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(LineStatusError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    fn load_parsed(&self, line: &Line) -> Result<Option<LineStatus>, LineStatusError> {
        let path = self.envelope_path(line);
        match std::fs::read(&path) {
            Ok(bytes) => {
                // Cached envelopes were verified at update time; parse the
                // payload without re-verifying just to read the counter.
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| LineStatusError::Payload("cache is not UTF-8".into()))?;
                let env = wsc::dsse::DsseEnvelope::from_json(text)
                    .map_err(|e| LineStatusError::Payload(e.to_string()))?;
                let payload = env
                    .payload_bytes()
                    .map_err(|e| LineStatusError::Payload(e.to_string()))?;
                Ok(Some(
                    serde_json::from_slice(&payload)
                        .map_err(|e| LineStatusError::Payload(e.to_string()))?,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(LineStatusError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    fn envelope_path(&self, line: &Line) -> PathBuf {
        self.dir.join(format!("{line}.dsse.json"))
    }
}

/// artifactType for a line-status envelope carried in an OCI image layout.
pub const LINE_STATUS_ARTIFACT_TYPE: &str = LINE_STATUS_PAYLOAD_TYPE;
/// Annotation naming the line a carried status document covers.
pub const ANN_LINE: &str = "eu.pulseengine.varve.status-line";

/// Attach a (verified-by-the-caller) status envelope to an existing OCI
/// image layout — evidence added AFTER deposit, without touching any layer
/// blob or digest. Replaces a previous document for the same line.
pub fn attach_to_layout(
    layout: &Path,
    line: &Line,
    envelope: &[u8],
) -> Result<(), LineStatusError> {
    let io = |path: &Path, source: std::io::Error| LineStatusError::Io {
        path: path.display().to_string(),
        source,
    };
    let digest = crate::store::manifest_digest(envelope);
    let hex = digest.strip_prefix("sha256:").expect("digest shape");
    let blob_dir = layout.join("blobs").join("sha256");
    std::fs::create_dir_all(&blob_dir).map_err(|e| io(&blob_dir, e))?;
    let blob_path = blob_dir.join(hex);
    std::fs::write(&blob_path, envelope).map_err(|e| io(&blob_path, e))?;

    let index_path = layout.join("index.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).map_err(|e| io(&index_path, e))?)
            .map_err(|e| LineStatusError::Payload(format!("index.json: {e}")))?;
    let entries = index["manifests"]
        .as_array_mut()
        .ok_or_else(|| LineStatusError::Payload("index.json has no manifests array".into()))?;
    let line_name = line.to_string();
    entries.retain(|e| {
        !(e["artifactType"] == LINE_STATUS_ARTIFACT_TYPE
            && e["annotations"][ANN_LINE] == *line_name)
    });
    entries.push(serde_json::json!({
        "mediaType": "application/json",
        "artifactType": LINE_STATUS_ARTIFACT_TYPE,
        "digest": digest,
        "size": envelope.len(),
        "annotations": { ANN_LINE: line_name }
    }));
    std::fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).expect("index serializes"),
    )
    .map_err(|e| io(&index_path, e))?;
    Ok(())
}

/// Fetch the baseline line-status a source carries beside a layer, verify it
/// against the trust root, and cache it monotonically (REQ-STATUS-DIST-001).
/// Returns `Ok(Some(counter))` when a baseline was cached, `Ok(None)` when the
/// source carries none. Verification, cache, or transport failures are `Err`
/// — the caller decides severity (the CLI downgrades them to a note, since a
/// bad baseline never blocks an otherwise-verified install, but it is never
/// silently cached). The untrusted bytes are re-verified here; the source is
/// not trusted to have checked them.
pub fn cache_baseline_from_source(
    source: &dyn crate::source::LayerSource,
    layer: &crate::source::LayerRef,
    line: &Line,
    root_pk: &[u8],
    store_root: &Path,
) -> Result<Option<u64>, LineStatusError> {
    let envelope = match source
        .fetch_line_status(layer)
        .map_err(|e| LineStatusError::Payload(format!("fetching baseline line-status: {e}")))?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };
    let doc = LineStatus::verify_and_parse(&envelope, root_pk)?;
    // A validly-signed status for a DIFFERENT line must not be cached under
    // this one — mirror the `--from-file` guard so all cache paths agree.
    if doc.line != line.to_string() {
        return Err(LineStatusError::LineMismatch {
            expected: line.to_string(),
            got: doc.line,
        });
    }
    let counter = doc.counter;
    StatusCache::at_root(store_root).update(line, &envelope, &doc)?;
    Ok(Some(counter))
}

/// Attach a signed line-status envelope to a deposit layout, deriving the
/// line from the document itself (REQ-STATUS-DIST-001). Returns the line and
/// counter attached. The payload is read to learn the line but not verified
/// here — install re-verifies the bytes against the trust root, and the
/// deposit pipeline produced this envelope moments earlier with its own key.
pub fn attach_envelope_to_layout(
    layout: &Path,
    envelope: &[u8],
) -> Result<(Line, u64), LineStatusError> {
    let text = std::str::from_utf8(envelope)
        .map_err(|e| LineStatusError::Payload(format!("envelope is not utf-8: {e}")))?;
    let env = wsc::dsse::DsseEnvelope::from_json(text)
        .map_err(|e| LineStatusError::Payload(format!("not a DSSE envelope: {e}")))?;
    let payload = env
        .payload_bytes()
        .map_err(|e| LineStatusError::Payload(format!("envelope payload: {e}")))?;
    let doc: LineStatus = serde_json::from_slice(&payload)
        .map_err(|e| LineStatusError::Payload(format!("status document: {e}")))?;
    let line: Line = doc
        .line
        .parse()
        .map_err(|e| LineStatusError::Payload(format!("status line '{}': {e}", doc.line)))?;
    // Monotonicity holds here too. `status --from-file` and `install` both
    // refuse a counter regression; attaching did not, so a re-run CI step could
    // silently downgrade a layout's baseline — shipping a pre-yank document
    // that fresh consumers cache and are told "not yanked" about a YANKED
    // layer. The one place the rule was missing was the one that produces the
    // artifact.
    if let Some(existing) = read_any_from_layout(layout)?
        && let Ok(prev) = parse_unverified(&existing)
        && prev.line == doc.line
        && doc.counter < prev.counter
    {
        return Err(LineStatusError::Stale {
            line: doc.line.clone(),
            presented: doc.counter,
            cached: prev.counter,
        });
    }
    // The status must belong to THIS layout's line. Attaching a 2099.01 status
    // to a 2026.08 layout used to succeed, leaving the consumer to discover it
    // (REQ-PRODUCER-001).
    if let Some(layout_line) = layout_line(layout)
        && layout_line != line.to_string()
    {
        return Err(LineStatusError::LineMismatch {
            expected: layout_line,
            got: line.to_string(),
        });
    }
    attach_to_layout(layout, &line, envelope)?;
    Ok((line, doc.counter))
}

/// Parse a status document out of an envelope WITHOUT verifying it. Used only
/// to read back what a layout already carries, so a regression can be refused;
/// the signature is checked wherever the document is actually trusted.
fn parse_unverified(envelope: &[u8]) -> Result<LineStatus, LineStatusError> {
    let text = std::str::from_utf8(envelope)
        .map_err(|e| LineStatusError::Payload(format!("envelope is not utf-8: {e}")))?;
    let env = wsc::dsse::DsseEnvelope::from_json(text)
        .map_err(|e| LineStatusError::Payload(format!("not a DSSE envelope: {e}")))?;
    let payload = env
        .payload_bytes()
        .map_err(|e| LineStatusError::Payload(format!("envelope payload: {e}")))?;
    serde_json::from_slice(&payload)
        .map_err(|e| LineStatusError::Payload(format!("status document: {e}")))
}

/// The line a deposit layout's own manifest declares, if it can be read. Best
/// effort: a layout we cannot introspect is not blocked from being annotated,
/// but one that plainly disagrees is.
pub(crate) fn layout_line(layout: &Path) -> Option<String> {
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.join("index.json")).ok()?).ok()?;
    for m in index["manifests"].as_array()? {
        let digest = m["digest"].as_str()?.replace(':', "-");
        let blob = layout
            .join("blobs")
            .join("sha256")
            .join(digest.trim_start_matches("sha256-"));
        let Ok(bytes) = std::fs::read(&blob) else {
            continue;
        };
        // The layer envelope's payload carries the line annotation. Reuse the
        // DSSE reader already used in this module rather than hand-rolling.
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text) else {
            continue;
        };
        let Ok(payload) = env.payload_bytes() else {
            continue;
        };
        let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&payload) else {
            continue;
        };
        if let Some(line) = doc["annotations"]["eu.pulseengine.varve.line"].as_str() {
            return Some(line.to_string());
        }
    }
    None
}

/// Read the single baseline status envelope a deposit layout carries,
/// without needing to name its line (REQ-STATUS-DIST-001). A deposit layout
/// holds exactly one line-status; a consumer installing by digest may not
/// know the line up front. Returns the first line-status referrer found.
pub fn read_any_from_layout(layout: &Path) -> Result<Option<Vec<u8>>, LineStatusError> {
    let index_path = layout.join("index.json");
    let bytes = match std::fs::read(&index_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(LineStatusError::Io {
                path: index_path.display().to_string(),
                source,
            });
        }
    };
    let index: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| LineStatusError::Payload(format!("index.json: {e}")))?;
    let Some(entry) = index["manifests"].as_array().and_then(|entries| {
        entries
            .iter()
            .find(|e| e["artifactType"] == LINE_STATUS_ARTIFACT_TYPE)
    }) else {
        return Ok(None);
    };
    let digest = entry["digest"]
        .as_str()
        .ok_or_else(|| LineStatusError::Payload("status entry has no digest".into()))?;
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let blob_path = layout.join("blobs").join("sha256").join(hex);
    std::fs::read(&blob_path)
        .map(Some)
        .map_err(|source| LineStatusError::Io {
            path: blob_path.display().to_string(),
            source,
        })
}

/// Read the status envelope for a line from an OCI image layout, if carried.
pub fn read_from_layout(layout: &Path, line: &Line) -> Result<Option<Vec<u8>>, LineStatusError> {
    let index_path = layout.join("index.json");
    let bytes = match std::fs::read(&index_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(LineStatusError::Io {
                path: index_path.display().to_string(),
                source,
            });
        }
    };
    let index: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| LineStatusError::Payload(format!("index.json: {e}")))?;
    let line_name = line.to_string();
    let Some(entry) = index["manifests"].as_array().and_then(|entries| {
        entries.iter().find(|e| {
            e["artifactType"] == LINE_STATUS_ARTIFACT_TYPE
                && e["annotations"][ANN_LINE] == *line_name
        })
    }) else {
        return Ok(None);
    };
    let digest = entry["digest"]
        .as_str()
        .ok_or_else(|| LineStatusError::Payload("status entry has no digest".into()))?;
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let blob_path = layout.join("blobs").join("sha256").join(hex);
    std::fs::read(&blob_path)
        .map(Some)
        .map_err(|source| LineStatusError::Io {
            path: blob_path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::generate_root_keypair;

    fn status(counter: u64) -> LineStatus {
        LineStatus {
            line: "2026.07".into(),
            counter,
            issued_at: "2026-08-07T00:00:00Z".into(),
            support_until: Some("2028-07-31".into()),
            yanked: BTreeMap::from([(
                "2026.07.0".to_string(),
                "CVE-2026-0001 in synth".to_string(),
            )]),
            known_problems: vec![
                KnownProblem {
                    id: "KP-1".into(),
                    title: "synth mla fusion regresses flat_flight".into(),
                    severity: "medium".into(),
                    affected: vec!["2026.07.0".into()],
                    workaround: Some("disable mla fusion".into()),
                    detection: None,
                    mitigation: None,
                },
                KnownProblem {
                    id: "KP-2".into(),
                    title: "witness truth-table gap on nested variants".into(),
                    severity: "high".into(),
                    affected: vec!["2026.07.0".into(), "2026.07.1".into()],
                    workaround: None,
                    detection: Some("witness gap rows non-empty".into()),
                    mitigation: None,
                },
            ],
        }
    }

    // rivet: verifies REQ-KP-001
    #[test]
    fn a_signed_status_document_round_trips() {
        let (sk, pk) = generate_root_keypair();
        let envelope = status(1).sign(&sk, "varve-root-1").unwrap();
        let parsed = LineStatus::verify_and_parse(envelope.as_bytes(), &pk).unwrap();
        assert_eq!(parsed, status(1));
    }

    // rivet: verifies REQ-KP-001
    #[test]
    fn a_layer_manifest_envelope_cannot_pose_as_a_status_document() {
        let (sk, pk) = generate_root_keypair();
        // Signed with the right key but the wrong payload type.
        let manifest = crate::manifest::fixtures::manifest(
            "2026.07.0",
            "qualified",
            1,
            "2026-08-07T00:00:00Z",
        );
        let envelope = crate::verify::sign_layer_manifest(&manifest, &sk, "varve-root-1").unwrap();
        let err = LineStatus::verify_and_parse(envelope.as_bytes(), &pk).unwrap_err();
        assert!(err.to_string().contains("payload type"), "got: {err}");
    }

    // rivet: verifies REQ-KP-001
    #[test]
    fn the_report_names_yank_support_window_and_problem_counts() {
        let doc = status(1);
        let report = doc.report_for(&"2026.07.0".parse().unwrap());
        assert_eq!(
            report.yanked_reason.as_deref(),
            Some("CVE-2026-0001 in synth")
        );
        assert_eq!(report.support_until.as_deref(), Some("2028-07-31"));
        assert_eq!(report.problems_total, 2);
        assert_eq!(report.problems_with_workaround, 1);
        let clean = doc.report_for(&"2026.07.2".parse().unwrap());
        assert_eq!(clean.yanked_reason, None);
        assert_eq!(clean.problems_total, 0);
    }

    // rivet: verifies REQ-KP-001
    #[test]
    fn attaching_status_to_a_layout_leaves_every_layer_blob_untouched() {
        use crate::deposit::{DepositSpec, DepositTool, deposit};
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        let spec = DepositSpec {
            includes: Vec::new(),
            layer: "2026.07.0".parse().unwrap(),
            channel: "qualified".into(),
            counter: 1,
            issued_at: "2026-08-07T00:00:00Z".into(),
            tools: vec![DepositTool {
                name: "synth".into(),
                version: "1".into(),
                platform: None,
                bytes: b"t".to_vec(),
                source: None,
                runner: None,
                kind: None,
            }],
        };
        let outcome = deposit(&spec, &sk, "k", &dest).unwrap();

        // Snapshot the layer-relevant blobs before attaching evidence.
        let blob_dir = dest.join("blobs/sha256");
        let before: std::collections::BTreeMap<String, Vec<u8>> = std::fs::read_dir(&blob_dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
            .collect();

        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let envelope = status(1).sign(&sk, "k").unwrap();
        attach_to_layout(&dest, &line, envelope.as_bytes()).unwrap();

        // Every pre-existing blob is byte-identical; the manifest digest is
        // unchanged — evidence was added, identity was not.
        for (name, bytes) in &before {
            assert_eq!(&std::fs::read(blob_dir.join(name)).unwrap(), bytes);
        }
        let carried = read_from_layout(&dest, &line).unwrap().unwrap();
        let parsed = LineStatus::verify_and_parse(&carried, &pk).unwrap();
        assert_eq!(parsed.counter, 1);
        let hex = outcome.digest.strip_prefix("sha256:").unwrap();
        assert!(
            blob_dir.join(hex).is_file(),
            "layer manifest blob still present"
        );

        // Replacing the document for the same line keeps exactly one entry.
        let envelope2 = status(2).sign(&sk, "k").unwrap();
        attach_to_layout(&dest, &line, envelope2.as_bytes()).unwrap();
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dest.join("index.json")).unwrap()).unwrap();
        let count = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["artifactType"] == LINE_STATUS_ARTIFACT_TYPE)
            .count();
        assert_eq!(count, 1);
    }

    // rivet: verifies REQ-KP-001
    #[test]
    fn the_cache_refuses_a_counter_regression() {
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let cache = StatusCache::at_root(tmp.path());
        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();

        let newer = status(2);
        let env2 = newer.sign(&sk, "k").unwrap();
        cache.update(&line, env2.as_bytes(), &newer).unwrap();

        let older = status(1);
        let env1 = older.sign(&sk, "k").unwrap();
        let err = cache.update(&line, env1.as_bytes(), &older).unwrap_err();
        assert!(matches!(
            err,
            LineStatusError::Stale {
                presented: 1,
                cached: 2,
                ..
            }
        ));

        // The cached newer document survives and re-verifies.
        let loaded = cache.load(&line, &pk).unwrap().unwrap();
        assert_eq!(loaded.counter, 2);
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_source_baseline_is_verified_and_cached_so_status_works_offline() {
        use crate::source::{LayerRef, MemorySource};
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let store_root = tmp.path();
        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let doc = status(5);
        let envelope = doc.sign(&sk, "k").unwrap();
        let source = MemorySource::new().with_line_status(envelope.as_bytes());
        let layer = LayerRef::Name("2026.07.0".parse().unwrap());

        let cached = cache_baseline_from_source(&source, &layer, &line, &pk, store_root).unwrap();
        assert_eq!(
            cached,
            Some(5),
            "a carried baseline is cached at its counter"
        );

        // Now `status` works offline: the cache has it, verified.
        let loaded = StatusCache::at_root(store_root)
            .load(&line, &pk)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.counter, 5);
    }

    // rivet: verifies REQ-STATUS-DIST-001, REQ-VERIFY-001
    #[test]
    fn a_baseline_for_the_wrong_line_is_refused_not_miscached() {
        // A root-signed status document for a DIFFERENT line must not be
        // cached under the requested line — even validly signed. (Clean-room
        // review finding: the --from-file path asserted this; the baseline
        // path did not.)
        use crate::source::{LayerRef, MemorySource};
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let requested: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let mut doc = status(5);
        doc.line = "2026.08".into(); // signed, but for the WRONG line
        let envelope = doc.sign(&sk, "k").unwrap();
        let source = MemorySource::new().with_line_status(envelope.as_bytes());
        let err = cache_baseline_from_source(
            &source,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &requested,
            &pk,
            tmp.path(),
        )
        .unwrap_err();
        assert!(
            matches!(err, LineStatusError::LineMismatch { .. }),
            "a baseline for the wrong line must be refused: {err}"
        );
        assert!(
            StatusCache::at_root(tmp.path())
                .load(&requested, &pk)
                .unwrap()
                .is_none(),
            "nothing is cached under the requested line"
        );
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_source_with_no_baseline_caches_nothing_and_does_not_error() {
        use crate::source::{LayerRef, MemorySource};
        let (_sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let source = MemorySource::new();
        let cached = cache_baseline_from_source(
            &source,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &line,
            &pk,
            tmp.path(),
        )
        .unwrap();
        assert_eq!(cached, None);
    }

    // rivet: verifies REQ-STATUS-DIST-001, REQ-VERIFY-001
    #[test]
    fn a_baseline_signed_by_an_impostor_is_refused_not_cached() {
        use crate::source::{LayerRef, MemorySource};
        let (attacker_sk, _) = generate_root_keypair();
        let (_real_sk, real_pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let envelope = status(5).sign(&attacker_sk, "k").unwrap();
        let source = MemorySource::new().with_line_status(envelope.as_bytes());
        let err = cache_baseline_from_source(
            &source,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &line,
            &real_pk,
            tmp.path(),
        )
        .unwrap_err();
        // The impostor's baseline never reaches the cache.
        assert!(
            StatusCache::at_root(tmp.path())
                .load(&line, &real_pk)
                .unwrap()
                .is_none(),
            "a baseline that fails verification must not be cached: {err}"
        );
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn attaching_by_envelope_derives_the_line_from_the_document() {
        use crate::deposit::{DepositSpec, DepositTool, deposit};
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        deposit(
            &DepositSpec {
                includes: Vec::new(),
                layer: "2026.07.0".parse().unwrap(),
                channel: "qualified".into(),
                counter: 1,
                issued_at: "2026-08-07T00:00:00Z".into(),
                tools: vec![DepositTool {
                    name: "synth".into(),
                    version: "1".into(),
                    platform: None,
                    bytes: b"t".to_vec(),
                    source: None,
                    runner: None,
                    kind: None,
                }],
            },
            &sk,
            "k",
            &dest,
        )
        .unwrap();

        let envelope = status(4).sign(&sk, "k").unwrap();
        let (line, counter) = attach_envelope_to_layout(&dest, envelope.as_bytes()).unwrap();
        assert_eq!(line.to_string(), "2026.07");
        assert_eq!(counter, 4);
        // The layout now carries it and it re-verifies.
        let carried = read_any_from_layout(&dest).unwrap().unwrap();
        assert_eq!(
            LineStatus::verify_and_parse(&carried, &pk).unwrap().counter,
            4
        );
    }

    // rivet: verifies REQ-PRODUCE-002
    #[test]
    fn attaching_a_stale_document_over_a_newer_one_is_refused() {
        // An independent review deleted the Stale block from
        // attach_envelope_to_layout and the whole workspace stayed green: the
        // test cited as this clause's evidence exercises StatusCache::update, a
        // DIFFERENT function, and the attach test above attaches exactly once.
        // Unguarded, a re-run CI step downgrades a layout's baseline — shipping
        // a pre-yank document that fresh consumers cache and are told "not
        // yanked" about a YANKED layer.
        use crate::deposit::{DepositSpec, DepositTool, deposit};
        let (sk, _pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        deposit(
            &DepositSpec {
                includes: Vec::new(),
                layer: "2026.07.0".parse().unwrap(),
                channel: "qualified".into(),
                counter: 1,
                issued_at: "2026-08-07T00:00:00Z".into(),
                tools: vec![DepositTool {
                    name: "synth".into(),
                    version: "1".into(),
                    platform: None,
                    bytes: b"t".to_vec(),
                    source: None,
                    runner: None,
                    kind: None,
                }],
            },
            &sk,
            "k",
            &dest,
        )
        .unwrap();

        // The newer document lands…
        attach_envelope_to_layout(&dest, status(7).sign(&sk, "k").unwrap().as_bytes()).unwrap();
        // …and the older one is refused, naming both counters.
        let err = attach_envelope_to_layout(&dest, status(3).sign(&sk, "k").unwrap().as_bytes())
            .unwrap_err();
        assert!(
            matches!(
                err,
                LineStatusError::Stale {
                    presented: 3,
                    cached: 7,
                    ..
                }
            ),
            "a lower counter must be refused, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains('3') && msg.contains('7'), "names both: {msg}");
        // The layout still carries the NEWER document, not the stale one.
        let carried = parse_unverified(&read_any_from_layout(&dest).unwrap().unwrap()).unwrap();
        assert_eq!(
            carried.counter, 7,
            "the newer baseline survives the attempt"
        );
        // Re-attaching the SAME counter is not a regression and is allowed —
        // CI re-runs must stay idempotent.
        attach_envelope_to_layout(&dest, status(7).sign(&sk, "k").unwrap().as_bytes()).unwrap();
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_deposit_layouts_baseline_is_readable_without_naming_the_line() {
        // A registry/layout consumer that installs by digest may not know the
        // line up front — the baseline must be recoverable from the layout
        // alone. A deposit layout carries exactly one line-status.
        use crate::deposit::{DepositSpec, DepositTool, deposit};
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        let spec = DepositSpec {
            includes: Vec::new(),
            layer: "2026.07.0".parse().unwrap(),
            channel: "qualified".into(),
            counter: 1,
            issued_at: "2026-08-07T00:00:00Z".into(),
            tools: vec![DepositTool {
                name: "synth".into(),
                version: "1".into(),
                platform: None,
                bytes: b"t".to_vec(),
                source: None,
                runner: None,
                kind: None,
            }],
        };
        deposit(&spec, &sk, "k", &dest).unwrap();

        // No baseline yet -> None, not an error.
        assert!(read_any_from_layout(&dest).unwrap().is_none());

        let line: Line = "2026.07.0".parse::<LayerId>().unwrap().line().clone();
        let envelope = status(3).sign(&sk, "k").unwrap();
        attach_to_layout(&dest, &line, envelope.as_bytes()).unwrap();

        let carried = read_any_from_layout(&dest).unwrap().unwrap();
        let parsed = LineStatus::verify_and_parse(&carried, &pk).unwrap();
        assert_eq!(parsed.counter, 3);
    }
}
