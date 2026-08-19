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
    /// The DSSE envelope failed verification or was malformed. Carries the
    /// verifier's reason verbatim — but under a line-status heading, because
    /// the old `#[error(transparent)]` route surfaced these as "manifest
    /// signature verification failed", sending the reader to the wrong
    /// document entirely (varve#60).
    #[error("line-status envelope rejected: {0}")]
    Envelope(String),
    #[error("cannot sign the line-status document: {0}")]
    Sign(String),
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
    /// An advisory entry that can never fire (varve#61): `varve status`
    /// matches `affected` ids and yank keys against installed layer ids
    /// EXACTLY, so a typo'd id signs fine and then warns nobody. Refused on
    /// the producing side, where the fix (re-sign) is still cheap.
    #[error(
        "{what} names layer '{id}', which is not a layer of line {line} ({reason}) — `varve \
         status` matches layer ids exactly, so this entry would never fire for any installed \
         layer; fix the id and re-sign the document"
    )]
    DeadReference {
        what: String,
        id: String,
        line: String,
        reason: String,
    },
    #[error(
        "{layout} is not an OCI image layout (it has no index.json) — point --layout at the \
         directory `varve deposit --out` produced"
    )]
    NotALayout { layout: String },
    // The io source is NOT repeated in the message: anyhow's `{err:#}` chain
    // already appends every source, and including it here printed the cause
    // twice ("… No such file or directory: No such file or directory").
    #[error("io error at {path}")]
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
        // Diagnose the not-an-envelope case BEFORE the verifier does: its
        // wrapped parser error prints the cause twice and never names the
        // commonest mistake — handing over the raw status JSON instead of the
        // signed envelope (varve#60).
        if let Ok(text) = std::str::from_utf8(envelope)
            && wsc::dsse::DsseEnvelope::from_json(text).is_err()
        {
            return Err(not_an_envelope(text));
        }
        let payload = dsse_verify_typed(envelope, LINE_STATUS_PAYLOAD_TYPE, root_public_key)
            .map_err(|VerifyError(msg)| {
                // A wrong-realm signature is indistinguishable from tampering
                // at this layer; say so, because "No valid signatures" alone
                // sends the reader hunting for corruption.
                let hint = if msg.contains("does not verify") {
                    " (is the document signed by THIS realm's root? `varve pubkey <key>` \
                     prints the public half a signature verifies against)"
                } else {
                    ""
                };
                LineStatusError::Envelope(format!("{msg}{hint}"))
            })?;
        serde_json::from_slice(&payload).map_err(|e| LineStatusError::Payload(e.to_string()))
    }

    /// Sign a status document (the producing side — CI, next to deposit).
    /// Refuses a document whose yank or `affected` entries could never fire
    /// (varve#61) — a typo'd layer id is cheapest to fix before the signature
    /// exists.
    pub fn sign(&self, secret_key: &[u8], key_id: &str) -> Result<String, LineStatusError> {
        self.check_layer_refs()?;
        let payload = serde_json::to_vec_pretty(self).expect("status serializes");
        dsse_sign_typed(&payload, LINE_STATUS_PAYLOAD_TYPE, secret_key, key_id)
            .map_err(|VerifyError(msg)| LineStatusError::Sign(msg))
    }

    /// Every yank key and every known problem's `affected` id must be a layer
    /// of THIS document's line (varve#61). `report_for` matches ids exactly,
    /// and the cache is keyed per line, so an id outside the line — or one
    /// that is not a layer id at all — is an advisory that signs fine and
    /// then fires for nobody. Enforced wherever a producer commits the
    /// document: `sign` and `attach_envelope_to_layout`.
    pub fn check_layer_refs(&self) -> Result<(), LineStatusError> {
        let line: Line = self.line.parse().map_err(|e| {
            LineStatusError::Payload(format!("'{}' is not a YYYY.MM line: {e}", self.line))
        })?;
        let check = |what: String, id: &str| -> Result<(), LineStatusError> {
            let dead = |reason: String| LineStatusError::DeadReference {
                what: what.clone(),
                id: id.to_string(),
                line: self.line.clone(),
                reason,
            };
            match id.parse::<LayerId>() {
                Ok(layer) if layer.line() == &line => Ok(()),
                Ok(layer) => Err(dead(format!("it belongs to line {}", layer.line()))),
                Err(e) => Err(dead(e.to_string())),
            }
        };
        for id in self.yanked.keys() {
            check("the yank entry".to_string(), id)?;
        }
        for kp in &self.known_problems {
            for id in &kp.affected {
                check(format!("known problem '{}'", kp.id), id)?;
            }
        }
        Ok(())
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
    // Refuse a directory that is not a layout BEFORE writing anything into
    // it: the old path created blobs/ inside an arbitrary directory and then
    // failed on the missing index.json with a bare io error (varve#60).
    if !layout.join("index.json").is_file() {
        return Err(LineStatusError::NotALayout {
            layout: layout.display().to_string(),
        });
    }
    let text = std::str::from_utf8(envelope)
        .map_err(|e| LineStatusError::Payload(format!("envelope is not utf-8: {e}")))?;
    let env = wsc::dsse::DsseEnvelope::from_json(text).map_err(|_| not_an_envelope(text))?;
    let payload = env
        .payload_bytes()
        .map_err(|e| LineStatusError::Payload(format!("envelope payload: {e}")))?;
    let doc: LineStatus = serde_json::from_slice(&payload)
        .map_err(|e| LineStatusError::Payload(format!("status document: {e}")))?;
    let line: Line = doc
        .line
        .parse()
        .map_err(|e| LineStatusError::Payload(format!("status line '{}': {e}", doc.line)))?;
    // A yank or affected id outside the layout's line would attach fine and
    // fire for nobody (varve#61) — this command knows the line, so it is the
    // last producer-side place the typo is cheap to fix.
    doc.check_layer_refs()?;
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

/// The bytes are not a DSSE envelope — with the commonest cause named: the
/// raw status document handed over where the SIGNED envelope belongs. The
/// verifier's own wrapping ("not a DSSE envelope: Internal error: [Failed to
/// parse DSSE envelope: …]") said the same thing twice and the fix zero
/// times (varve#60).
fn not_an_envelope(text: &str) -> LineStatusError {
    if serde_json::from_str::<LineStatus>(text).is_ok() {
        LineStatusError::Payload(
            "this is the UNSIGNED status document, not a signed envelope — sign it first \
             (`varve sign-status --file <doc> --key <key> --out <envelope>`) and pass the \
             envelope"
                .into(),
        )
    } else {
        LineStatusError::Payload(
            "not a DSSE envelope — expected the signed output of `varve sign-status`".into(),
        )
    }
}

/// Parse a status document out of an envelope WITHOUT verifying it. Used only
/// to read back what a layout already carries, so a regression can be refused;
/// the signature is checked wherever the document is actually trusted.
fn parse_unverified(envelope: &[u8]) -> Result<LineStatus, LineStatusError> {
    let text = std::str::from_utf8(envelope)
        .map_err(|e| LineStatusError::Payload(format!("envelope is not utf-8: {e}")))?;
    let env = wsc::dsse::DsseEnvelope::from_json(text).map_err(|_| not_an_envelope(text))?;
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
                sdk_prefix: None,
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
        // A self-consistent document for the WRONG line — internally valid,
        // validly signed, and still not the line this consumer asked about.
        let doc = LineStatus {
            line: "2026.08".into(),
            counter: 5,
            issued_at: "2026-08-07T00:00:00Z".into(),
            support_until: None,
            yanked: BTreeMap::new(),
            known_problems: Vec::new(),
        };
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
                    sdk_prefix: None,
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
                    sdk_prefix: None,
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

    // rivet: verifies REQ-PRODUCE-002
    #[test]
    fn an_advisory_that_could_never_fire_is_refused_at_sign_time() {
        // varve#61: `report_for` matches ids EXACTLY and the cache is keyed
        // per line, so a typo'd affected id — "2026.9.0" for "2026.09.0" —
        // signed fine and the advisory then fired for nobody. The signature
        // is the cheapest place to stop it.
        let (sk, _pk) = generate_root_keypair();
        let cases: &[(&str, &str)] = &[
            ("2026.7.0", "not a valid YYYY.MM.P id"), // typo'd month width
            ("2026.07", "missing its patch component"), // a line, not a layer
            ("2026.08.0", "belongs to another line"), // wrong line entirely
            ("2026.07.O", "letter O for zero"),
        ];
        for (bad, why) in cases {
            let mut doc = status(1);
            doc.known_problems[0].affected = vec![bad.to_string()];
            let err = doc.sign(&sk, "k").unwrap_err();
            assert!(
                matches!(err, LineStatusError::DeadReference { .. }),
                "{why}: affected id {bad:?} must be refused, got: {err}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains(bad) && msg.contains("2026.07") && msg.contains("re-sign"),
                "the error must name the id, the line, and the fix: {msg}"
            );
        }
        // A typo'd YANK key is the same dead advisory.
        let mut doc = status(1);
        doc.yanked = BTreeMap::from([("2026.8.0".to_string(), "CVE".to_string())]);
        assert!(matches!(
            doc.sign(&sk, "k").unwrap_err(),
            LineStatusError::DeadReference { .. }
        ));
        // …and the untouched fixture still signs: the gate can pass, not
        // merely fail.
        status(1).sign(&sk, "k").unwrap();
    }

    // rivet: verifies REQ-PRODUCE-002
    #[test]
    fn attach_refuses_a_pre_signed_advisory_that_could_never_fire() {
        // The envelope may come from an older varve whose sign-status did not
        // validate — attach is the last producer-side gate before the layout
        // ships. Built with the raw signer to bypass `sign`'s own check,
        // exactly as an old binary would have.
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
                    sdk_prefix: None,
                }],
            },
            &sk,
            "k",
            &dest,
        )
        .unwrap();
        let mut doc = status(1);
        doc.known_problems[0].affected = vec!["2026.7.0".to_string()];
        let payload = serde_json::to_vec_pretty(&doc).unwrap();
        let envelope = dsse_sign_typed(&payload, LINE_STATUS_PAYLOAD_TYPE, &sk, "k").unwrap();
        let err = attach_envelope_to_layout(&dest, envelope.as_bytes()).unwrap_err();
        assert!(
            matches!(err, LineStatusError::DeadReference { .. }),
            "got: {err}"
        );
        assert!(
            read_any_from_layout(&dest).unwrap().is_none(),
            "the dead advisory must not land in the layout"
        );
    }

    // rivet: verifies REQ-PRODUCE-002
    #[test]
    fn attaching_to_a_directory_that_is_not_a_layout_is_refused_before_writing() {
        // The old path created blobs/sha256/ inside the directory and then
        // failed on index.json with "io error at …: No such file or directory
        // (os error 2): No such file or directory (os error 2)" — the cause
        // twice, the fix never (varve#60).
        let (sk, _pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let not_a_layout = tmp.path().join("somedir");
        std::fs::create_dir_all(&not_a_layout).unwrap();
        let envelope = status(1).sign(&sk, "k").unwrap();
        let err = attach_envelope_to_layout(&not_a_layout, envelope.as_bytes()).unwrap_err();
        assert!(
            matches!(err, LineStatusError::NotALayout { .. }),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("varve deposit"),
            "the error must carry its fix: {err}"
        );
        assert!(
            !not_a_layout.join("blobs").exists(),
            "nothing may be written into a directory that is not a layout"
        );
    }

    // rivet: verifies REQ-PRODUCE-002
    #[test]
    fn the_unsigned_document_mistake_is_named_not_wrapped() {
        // Handing the raw status JSON where the signed envelope belongs is
        // the commonest producer mistake; the old error was a doubled parser
        // wrap that never said "sign it" (varve#60).
        let raw = serde_json::to_string_pretty(&status(1)).unwrap();
        let err = not_an_envelope(&raw);
        let msg = err.to_string();
        assert!(
            msg.contains("UNSIGNED") && msg.contains("varve sign-status"),
            "raw document must be diagnosed with its fix: {msg}"
        );
        // Garbage is still garbage, said once, with the expected shape named.
        let msg = not_an_envelope("garbage").to_string();
        assert!(
            msg.contains("not a DSSE envelope") && msg.contains("varve sign-status"),
            "got: {msg}"
        );
        // And verify_and_parse routes through the same diagnosis.
        let (_sk, pk) = generate_root_keypair();
        let err = LineStatus::verify_and_parse(raw.as_bytes(), &pk).unwrap_err();
        assert!(err.to_string().contains("UNSIGNED"), "got: {err}");
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
                sdk_prefix: None,
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
