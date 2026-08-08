//! The pin — `varve.toml`, the human-written half of the two manifests.
//!
//! Checked into the consuming repo, discovered by walking up from the working
//! directory, reviewed like code. It names the layer a project is frozen on;
//! it is a *preference*, where the layer manifest is *evidence*. Conflating
//! the two is how toolchains drift (see `docs/manifest-format.md`).
//!
//! Parsing is strict: unknown keys, a missing patch component, or a malformed
//! digest are hard errors carrying corrective guidance — a qualified pin that
//! half-parses is worse than one that fails loudly.

use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;

use crate::layer::{LayerId, LayerIdError};

/// The release channel a pin selects.
///
/// `qualified` names a line with a stated support window and qualification
/// evidence attached; `rolling` has neither and may move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Qualified,
    Rolling,
}

/// A parsed, validated pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Optional trust universe (REQ-REALM-001). When named, the realm's
    /// registry and trust root are AUTHORITATIVE for this project.
    pub realm: Option<String>,
    pub channel: Channel,
    pub layer: LayerId,
    /// Optional exact manifest digest. When present it wins over the name:
    /// a name resolving to a different digest is a hard failure (DD-005's
    /// lever available at the pin level).
    pub digest: Option<String>,
    /// Optional restriction to a subset of the layer's tools. `None` means
    /// every tool in the layer.
    pub tools: Option<Vec<String>>,
}

/// Why a pin failed to parse or validate.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: not valid varve.toml: {source}")]
    Toml {
        path: String,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("{path}: manifest-version {found} is not supported (this varve understands version 1)")]
    UnsupportedManifestVersion { path: String, found: i64 },
    // Display carries only the location; the cause prints once via the
    // #[source] chain (varve#7 — the anyhow alternate formatter was
    // printing it twice).
    #[error("{path}: invalid layer identifier")]
    Layer {
        path: String,
        #[source]
        source: LayerIdError,
    },
    #[error(
        "{path}: digest '{found}' is not a valid digest: expected 'sha256:' followed by 64 hex characters"
    )]
    MalformedDigest { path: String, found: String },
    #[error("{path}: tools list is present but empty — omit it to select every tool in the layer")]
    EmptyTools { path: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPin {
    #[serde(rename = "manifest-version")]
    manifest_version: i64,
    toolchain: RawToolchain,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolchain {
    #[serde(default)]
    realm: Option<String>,
    channel: Channel,
    layer: String,
    digest: Option<String>,
    tools: Option<Vec<String>>,
}

impl Pin {
    /// Parse and validate pin content. `origin` names the source (a path, in
    /// diagnostics) — errors must tell the reader *which* file is wrong.
    pub fn parse(content: &str, origin: &str) -> Result<Self, PinError> {
        let raw: RawPin = toml::from_str(content).map_err(|source| PinError::Toml {
            path: origin.to_string(),
            source: Box::new(source),
        })?;
        if raw.manifest_version != 1 {
            return Err(PinError::UnsupportedManifestVersion {
                path: origin.to_string(),
                found: raw.manifest_version,
            });
        }
        let layer = LayerId::from_str(&raw.toolchain.layer).map_err(|source| PinError::Layer {
            path: origin.to_string(),
            source,
        })?;
        if let Some(digest) = &raw.toolchain.digest {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or_else(|| PinError::MalformedDigest {
                    path: origin.to_string(),
                    found: digest.clone(),
                })?;
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(PinError::MalformedDigest {
                    path: origin.to_string(),
                    found: digest.clone(),
                });
            }
        }
        if let Some(tools) = &raw.toolchain.tools
            && tools.is_empty()
        {
            return Err(PinError::EmptyTools {
                path: origin.to_string(),
            });
        }
        Ok(Pin {
            realm: raw.toolchain.realm,
            channel: raw.toolchain.channel,
            layer,
            digest: raw.toolchain.digest,
            tools: raw.toolchain.tools,
        })
    }

    /// Read and parse a pin file from disk.
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let content = std::fs::read_to_string(path).map_err(|source| PinError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&content, &path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.07.0"
digest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
tools   = ["rivet", "synth"]
"#;

    // rivet: verifies REQ-PIN-001
    #[test]
    fn parses_a_complete_pin() {
        let pin = Pin::parse(FULL, "varve.toml").unwrap();
        assert_eq!(pin.channel, Channel::Qualified);
        assert_eq!(pin.layer, LayerId::from_str("2026.07.0").unwrap());
        assert_eq!(
            pin.digest.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            pin.tools.as_deref(),
            Some(&["rivet".to_string(), "synth".to_string()][..])
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn digest_and_tools_are_optional() {
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n",
            "varve.toml",
        )
        .unwrap();
        assert_eq!(pin.channel, Channel::Rolling);
        assert_eq!(pin.digest, None);
        assert_eq!(pin.tools, None);
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unsupported_manifest_version() {
        let err = Pin::parse(
            "manifest-version = 2\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::UnsupportedManifestVersion { found: 2, .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn rejects_two_part_layer_with_the_grammar_guidance() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07\"\n",
            "varve.toml",
        )
        .unwrap_err();
        let PinError::Layer { source, .. } = &err else {
            panic!("got: {err}");
        };
        assert!(matches!(source, LayerIdError::MissingPatch(_)));
        // The guidance lives in the SOURCE (printed once via the chain).
        assert!(
            source.to_string().contains("three-part"),
            "the chain must teach the grammar: {source}"
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unknown_keys_instead_of_ignoring_them() {
        let err = Pin::parse(
            "manifest-version = 1\nsurprise = true\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::Toml { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unknown_channel() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"latest\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::Toml { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_malformed_digest() {
        // Includes a wrong-length PURE-HEX digest: length and charset are
        // independent checks and each must reject alone.
        for bad in [
            "sha256:short",
            "md5:aaaa",
            "aaaaaaaa",
            "sha256:GGGG",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let toml = format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ndigest = \"{bad}\"\n"
            );
            let err = Pin::parse(&toml, "varve.toml").unwrap_err();
            assert!(
                matches!(err, PinError::MalformedDigest { .. }),
                "input {bad:?} got: {err}"
            );
        }
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_empty_tools_list() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = []\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::EmptyTools { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn errors_name_the_offending_file() {
        let err = Pin::parse("nonsense", "proj/sub/varve.toml").unwrap_err();
        assert!(
            err.to_string().contains("proj/sub/varve.toml"),
            "diagnostic must carry the path: {err}"
        );
    }
}
