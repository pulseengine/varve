//! The layer manifest as seen at acceptance time (DD-005).
//!
//! At install, the manifest is not just "annotations with a name" (the store's
//! lenient view of what is already on disk) — it is the signed statement being
//! *accepted*. Acceptance is strict: the layer identity, the per-line release
//! counter, and the issued-at timestamp must all be present and well-formed,
//! because they are what the anti-rollback and staleness verdicts stand on.
//! A manifest missing its counter is not "an older format" — it is unacceptable.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::layer::LayerId;

pub const ANN_LAYER: &str = "eu.pulseengine.varve.layer";
pub const ANN_LINE: &str = "eu.pulseengine.varve.line";
pub const ANN_CHANNEL: &str = "eu.pulseengine.varve.channel";
pub const ANN_COUNTER: &str = "eu.pulseengine.varve.counter";
pub const ANN_ISSUED_AT: &str = "org.opencontainers.image.created";

/// One artifact (tool × platform) referenced by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ManifestEntry {
    pub digest: String,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

impl ManifestEntry {
    /// The payload kind this entry declares (REQ-KIND-001). Absent → `Tool`
    /// (back-compat); an unrecognised kind is refused, never guessed.
    pub fn kind(&self) -> Result<crate::kind::PayloadKind, crate::kind::UnknownKind> {
        match self.annotations.get(crate::kind::ANN_KIND) {
            Some(s) => s.parse(),
            None => Ok(crate::kind::PayloadKind::default()),
        }
    }
}

/// A layer manifest accepted for installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerManifest {
    pub layer: LayerId,
    pub channel: String,
    /// Monotonic per-line release counter — the anti-rollback anchor.
    /// Lives inside the signed payload, never in mutable tag state.
    pub counter: u64,
    /// RFC 3339 issued-at — drives the staleness verdict.
    pub issued_at: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("layer manifest is not valid JSON: {0}")]
    Json(String),
    #[error("layer manifest is missing required annotation '{0}'")]
    MissingAnnotation(&'static str),
    #[error("layer manifest annotation '{ann}' is invalid: {reason}")]
    BadAnnotation { ann: &'static str, reason: String },
}

impl LayerManifest {
    /// Parse manifest bytes for acceptance. Strict on the fields the
    /// anti-rollback and staleness verdicts depend on.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            annotations: BTreeMap<String, String>,
            #[serde(default)]
            manifests: Vec<ManifestEntry>,
        }
        let raw: Raw =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
        let ann = |key: &'static str| -> Result<&String, ManifestError> {
            raw.annotations
                .get(key)
                .ok_or(ManifestError::MissingAnnotation(key))
        };
        let layer: LayerId = ann(ANN_LAYER)?
            .parse()
            .map_err(
                |e: crate::layer::LayerIdError| ManifestError::BadAnnotation {
                    ann: ANN_LAYER,
                    reason: e.to_string(),
                },
            )?;
        let channel = ann(ANN_CHANNEL)?.clone();
        let counter: u64 = ann(ANN_COUNTER)?
            .parse()
            .map_err(|_| ManifestError::BadAnnotation {
                ann: ANN_COUNTER,
                reason: format!(
                    "'{}' is not a non-negative integer",
                    raw.annotations[ANN_COUNTER]
                ),
            })?;
        let issued_at = ann(ANN_ISSUED_AT)?.clone();
        // Reject a malformed issued-at at parse (F2): the staleness verdict
        // must never silently fail open on a signed-but-undated manifest.
        if crate::rollback::epoch_days(&issued_at).is_none() {
            return Err(ManifestError::BadAnnotation {
                ann: ANN_ISSUED_AT,
                reason: format!("'{issued_at}' is not an RFC 3339 date"),
            });
        }
        Ok(LayerManifest {
            layer,
            channel,
            counter,
            issued_at,
            entries: raw.manifests,
        })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// Entries with an optional per-entry platform annotation
    /// (REQ-PLATFORM-001 fixtures).
    pub fn manifest_with_platform_tools(
        layer: &str,
        channel: &str,
        counter: u64,
        issued_at: &str,
        tools: &[(&str, &str, Option<&str>)],
    ) -> Vec<u8> {
        let entries = tools
            .iter()
            .map(|(name, digest, platform)| {
                let platform_ann = platform
                    .map(|p| format!(",\n        \"eu.pulseengine.platform\": \"{p}\""))
                    .unwrap_or_default();
                format!(
                    r#"    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{digest}",
      "size": 0,
      "annotations": {{
        "eu.pulseengine.tool": "{name}"{platform_ann}
      }}
    }}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.line": "{line}",
    "eu.pulseengine.varve.channel": "{channel}",
    "eu.pulseengine.varve.counter": "{counter}",
    "org.opencontainers.image.created": "{issued_at}"
  }},
  "manifests": [
{entries}
  ]
}}"#,
            line = &layer[..layer.rfind('.').unwrap()],
        )
        .into_bytes()
    }

    /// Entries carrying a payload KIND and a version — the REQ-STORE-002
    /// shape, in which one name may legitimately appear at several versions.
    /// Each tuple is (name, version, kind, blob digest); an empty kind stamps
    /// no kind annotation, which is how a pre-kind layer reads.
    pub fn manifest_with_payloads(
        layer: &str,
        channel: &str,
        counter: u64,
        issued_at: &str,
        payloads: &[(&str, &str, &str, &str)],
    ) -> Vec<u8> {
        let entries = payloads
            .iter()
            .map(|(name, version, kind, digest)| {
                let kind_ann = if kind.is_empty() {
                    String::new()
                } else {
                    format!(",\n        \"eu.pulseengine.varve.kind\": \"{kind}\"")
                };
                format!(
                    r#"    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{digest}",
      "size": 0,
      "annotations": {{
        "eu.pulseengine.tool": "{name}",
        "eu.pulseengine.tool.version": "{version}"{kind_ann}
      }}
    }}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.line": "{line}",
    "eu.pulseengine.varve.channel": "{channel}",
    "eu.pulseengine.varve.counter": "{counter}",
    "org.opencontainers.image.created": "{issued_at}"
  }},
  "manifests": [
{entries}
  ]
}}"#,
            line = &layer[..layer.rfind('.').unwrap()],
        )
        .into_bytes()
    }

    /// An acceptance-grade manifest whose entries reference tools by blob
    /// digest — the shape `install` consumes.
    pub fn manifest_with_tools(
        layer: &str,
        channel: &str,
        counter: u64,
        issued_at: &str,
        tools: &[(&str, &str)],
    ) -> Vec<u8> {
        let entries = tools
            .iter()
            .map(|(name, digest)| {
                format!(
                    r#"    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{digest}",
      "size": 0,
      "annotations": {{ "eu.pulseengine.tool": "{name}" }}
    }}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.line": "{line}",
    "eu.pulseengine.varve.channel": "{channel}",
    "eu.pulseengine.varve.counter": "{counter}",
    "org.opencontainers.image.created": "{issued_at}"
  }},
  "manifests": [
{entries}
  ]
}}"#,
            line = &layer[..layer.rfind('.').unwrap()],
        )
        .into_bytes()
    }

    /// A complete, acceptance-grade layer manifest.
    pub fn manifest(layer: &str, channel: &str, counter: u64, issued_at: &str) -> Vec<u8> {
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.line": "{line}",
    "eu.pulseengine.varve.channel": "{channel}",
    "eu.pulseengine.varve.counter": "{counter}",
    "org.opencontainers.image.created": "{issued_at}"
  }},
  "manifests": []
}}"#,
            line = &layer[..layer.rfind('.').unwrap()],
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-KIND-001
    #[test]
    fn an_entry_kind_defaults_to_tool_and_refuses_unknowns() {
        use crate::kind::{ANN_KIND, PayloadKind};
        let mut e = ManifestEntry {
            digest: "sha256:abc".into(),
            annotations: BTreeMap::new(),
        };
        // Absent kind -> tool (back-compat with pre-kind layers).
        assert_eq!(e.kind().unwrap(), PayloadKind::Tool);
        // Stamped kind -> that kind.
        e.annotations.insert(ANN_KIND.into(), "crate".into());
        assert_eq!(e.kind().unwrap(), PayloadKind::Crate);
        // Unknown kind -> refused, not guessed.
        e.annotations.insert(ANN_KIND.into(), "quantum-blob".into());
        assert!(e.kind().is_err());
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn parses_counter_and_issued_at_from_the_signed_annotations() {
        let bytes = fixtures::manifest("2026.07.0", "qualified", 3, "2026-07-31T09:14:00Z");
        let m = LayerManifest::parse(&bytes).unwrap();
        assert_eq!(m.layer.to_string(), "2026.07.0");
        assert_eq!(m.channel, "qualified");
        assert_eq!(m.counter, 3);
        assert_eq!(m.issued_at, "2026-07-31T09:14:00Z");
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_manifest_without_a_counter_is_unacceptable() {
        let bytes = fixtures::manifest("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z");
        let stripped = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.contains("counter"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = LayerManifest::parse(stripped.as_bytes()).unwrap_err();
        assert!(
            matches!(err, ManifestError::MissingAnnotation(ANN_COUNTER)),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_non_numeric_counter_is_unacceptable() {
        let bytes = fixtures::manifest("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z");
        let bad = String::from_utf8(bytes).unwrap().replace(
            "\"eu.pulseengine.varve.counter\": \"1\"",
            "\"eu.pulseengine.varve.counter\": \"one\"",
        );
        let err = LayerManifest::parse(bad.as_bytes()).unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::BadAnnotation {
                    ann: ANN_COUNTER,
                    ..
                }
            ),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_manifest_without_issued_at_is_unacceptable() {
        let bytes = fixtures::manifest("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z");
        let bad = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.contains("image.created"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(
                "\"eu.pulseengine.varve.counter\": \"1\",",
                "\"eu.pulseengine.varve.counter\": \"1\"",
            );
        let err = LayerManifest::parse(bad.as_bytes()).unwrap_err();
        assert!(
            matches!(err, ManifestError::MissingAnnotation(ANN_ISSUED_AT)),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_non_date_issued_at_is_refused_not_silently_undated() {
        // F2 (2026-08-08 audit): a signed manifest with a malformed
        // issued-at must be REJECTED at parse — otherwise the staleness
        // verdict silently fails open (epoch_days returns None → no
        // warning), voiding SH-002's bound.
        for bad in [
            "unknown",
            "2026-08",
            "2026-13-01T00:00:00Z",
            "2026-02-31T00:00:00Z",
            "",
        ] {
            let bytes = fixtures::manifest("2026.07.0", "qualified", 1, bad);
            let err = LayerManifest::parse(&bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    ManifestError::BadAnnotation {
                        ann: ANN_ISSUED_AT,
                        ..
                    }
                ),
                "issued-at {bad:?} must be refused, got: {err:?}"
            );
        }
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn garbage_bytes_are_rejected_not_defaulted() {
        assert!(matches!(
            LayerManifest::parse(b"not json").unwrap_err(),
            ManifestError::Json(_)
        ));
    }
}
