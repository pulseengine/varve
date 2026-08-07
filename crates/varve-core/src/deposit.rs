//! Deposit — how a layer comes into being (REQ-DEPOSIT-001).
//!
//! One auditable step, run by CI: assemble the layer manifest (an OCI image
//! index) from the pinned per-tool artifacts, embed the release counter and
//! issued-at inside the payload, sign it into a DSSE envelope with the
//! PulseEngine root key, and write the same directory-shaped OCI image
//! layout that `varve archive` produces — so a fresh deposit and an archived
//! core are byte-compatible, and both install through the one pipeline.
//! Hand-edited layer manifests do not exist: this module is the only writer.

use std::path::Path;

use crate::install::VerifyError;
use crate::layer::LayerId;
use crate::store::manifest_digest;
use crate::verify::sign_layer_manifest;

/// What to deposit: the layer identity and the tools that make it up.
#[derive(Debug, Clone)]
pub struct DepositSpec {
    pub layer: LayerId,
    /// `qualified` | `rolling` — recorded verbatim in the annotations.
    pub channel: String,
    /// Monotonic per-line release counter (DD-005). The depositor owns
    /// monotonicity; clients enforce it.
    pub counter: u64,
    /// RFC 3339 issued-at, supplied by the caller (CI knows the time; this
    /// library does not sample clocks).
    pub issued_at: String,
    /// (tool name, tool version, binary bytes) triples.
    pub tools: Vec<DepositTool>,
}

#[derive(Debug, Clone)]
pub struct DepositTool {
    pub name: String,
    pub version: String,
    /// Target triple this binary is built for; `None` claims
    /// platform-independence (scripts, data). New deposits should stamp it.
    pub platform: Option<String>,
    pub bytes: Vec<u8>,
    /// Where the bytes came from — recorded INSIDE the signed payload so
    /// downstream lockfiles (Bazel registries) inherit the signature anchor
    /// (REQ-BAZEL-001).
    pub source: Option<ToolSource>,
}

/// Upstream provenance of a deposited tool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSource {
    /// e.g. "pulseengine/rivet"
    pub repo: String,
    /// e.g. "v0.32.0"
    pub release: String,
    /// The release asset AS DOWNLOADED, e.g. "rivet-v0.32.0-<triple>.tar.gz"
    pub asset: String,
    /// sha256 of that asset (the bytes Bazel will hash), bare hex or
    /// sha256:-prefixed.
    pub sha256: String,
}

/// A completed deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositOutcome {
    /// Digest of the manifest payload — what pins reference.
    pub digest: String,
    pub layer: LayerId,
    pub counter: u64,
}

/// A deposit described as a file (CI-authored TOML) rather than flags —
/// the shape the deposit workflow and the Bazel extension both read.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositFileSpec {
    pub layer: String,
    pub channel: String,
    pub counter: u64,
    #[serde(default, rename = "tool")]
    pub tools: Vec<SpecTool>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecTool {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub platform: Option<String>,
    /// Binary path, absolute or relative to the spec file's directory.
    pub path: String,
    #[serde(default)]
    pub source: Option<ToolSource>,
}

pub fn parse_deposit_spec(toml_text: &str) -> Result<DepositFileSpec, DepositError> {
    toml::from_str(toml_text).map_err(|e| DepositError::Spec(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    #[error("deposit spec is not valid: {0}")]
    Spec(String),
    #[error("deposit has no tools — an empty layer is not a toolchain")]
    NoTools,
    #[error("duplicate tool name '{0}' in deposit")]
    DuplicateTool(String),
    #[error(transparent)]
    Sign(#[from] VerifyError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Assemble, sign, and write a layer as an OCI image layout at `dest`.
pub fn deposit(
    spec: &DepositSpec,
    signing_key: &[u8],
    key_id: &str,
    dest: &Path,
) -> Result<DepositOutcome, DepositError> {
    if spec.tools.is_empty() {
        return Err(DepositError::NoTools);
    }
    let mut tools: Vec<&DepositTool> = spec.tools.iter().collect();
    tools.sort_by(|a, b| (&a.name, &a.platform).cmp(&(&b.name, &b.platform)));
    for pair in tools.windows(2) {
        if pair[0].name == pair[1].name && pair[0].platform == pair[1].platform {
            return Err(DepositError::DuplicateTool(pair[0].name.clone()));
        }
    }

    // Assemble the payload deterministically: sorted tools, fixed key order
    // (serde_json sorts map keys), no timestamps beyond the caller-supplied
    // issued-at. Identical specs must produce identical digests — the digest
    // is the identity a pin freezes against.
    let entries: Vec<serde_json::Value> = tools
        .iter()
        .map(|tool| {
            let mut annotations = serde_json::Map::new();
            annotations.insert("eu.pulseengine.tool".into(), tool.name.clone().into());
            annotations.insert(
                "eu.pulseengine.tool.version".into(),
                tool.version.clone().into(),
            );
            if let Some(platform) = &tool.platform {
                annotations.insert(
                    crate::platform::ANN_PLATFORM.into(),
                    platform.clone().into(),
                );
            }
            if let Some(source) = &tool.source {
                annotations.insert(
                    crate::bazel::ANN_SRC_REPO.into(),
                    source.repo.clone().into(),
                );
                annotations.insert(
                    crate::bazel::ANN_SRC_RELEASE.into(),
                    source.release.clone().into(),
                );
                annotations.insert(
                    crate::bazel::ANN_SRC_ASSET.into(),
                    source.asset.clone().into(),
                );
                annotations.insert(
                    crate::bazel::ANN_SRC_SHA256.into(),
                    source.sha256.clone().into(),
                );
            }
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest(&tool.bytes),
                "size": tool.bytes.len(),
                "annotations": annotations,
            })
        })
        .collect();
    let payload_json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
        "annotations": {
            "eu.pulseengine.varve.layer": spec.layer.to_string(),
            "eu.pulseengine.varve.line": spec.layer.line().to_string(),
            "eu.pulseengine.varve.channel": spec.channel,
            "eu.pulseengine.varve.counter": spec.counter.to_string(),
            "org.opencontainers.image.created": spec.issued_at,
        },
        "manifests": entries,
    });
    let payload = serde_json::to_vec_pretty(&payload_json).expect("payload serializes");
    let envelope = sign_layer_manifest(&payload, signing_key, key_id)?;

    let blobs: Vec<(String, Vec<u8>)> = tools
        .iter()
        .map(|tool| (manifest_digest(&tool.bytes), tool.bytes.clone()))
        .collect();
    crate::archive::write_oci_layout(
        &payload,
        envelope.as_bytes(),
        &blobs,
        &spec.layer.to_string(),
        &spec.channel,
        dest,
    )
    .map_err(|(path, source)| DepositError::Io { path, source })?;

    Ok(DepositOutcome {
        digest: manifest_digest(&payload),
        layer: spec.layer.clone(),
        counter: spec.counter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::OciLayoutSource;
    use crate::install::{InstallPolicy, install};
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::store::Store;
    use crate::verify::{PinnedKeyVerifier, generate_root_keypair};

    fn spec() -> DepositSpec {
        DepositSpec {
            layer: "2026.08.0".parse().unwrap(),
            channel: "qualified".into(),
            counter: 1,
            issued_at: "2026-08-07T00:00:00Z".into(),
            tools: vec![
                DepositTool {
                    name: "synth".into(),
                    version: "0.45.0".into(),
                    platform: None,
                    bytes: b"synth-bytes".to_vec(),
                    source: None,
                },
                DepositTool {
                    name: "rivet".into(),
                    version: "0.32.0".into(),
                    platform: None,
                    bytes: b"rivet-bytes".to_vec(),
                    source: None,
                },
            ],
        }
    }

    // rivet: verifies REQ-DEPOSIT-001
    #[test]
    fn a_deposit_round_trips_through_the_standard_install_pipeline() {
        let (sk, pk) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("deposit");
        let outcome = deposit(&spec(), &sk, "varve-root-1", &dest).unwrap();
        assert_eq!(outcome.layer.to_string(), "2026.08.0");

        // Standard layout markers present.
        assert!(dest.join("oci-layout").is_file());
        assert!(dest.join("index.json").is_file());

        // Install from the deposit exactly as from an archive.
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.08.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let root = tmp.path().join("fresh");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let installed = install(
            &pin,
            &OciLayoutSource::at(&dest),
            &verifier,
            &store,
            &mut marks,
            &policy,
        )
        .unwrap();
        assert_eq!(installed.digest, outcome.digest);
        assert_eq!(installed.counter, 1);
        let entry = store.get(&installed.digest).unwrap().unwrap();
        let checked =
            crate::reverify::verify_installed(&store, &entry, &verifier, "test-platform").unwrap();
        assert_eq!(checked, 2);
    }

    // rivet: verifies REQ-DEPOSIT-001
    #[test]
    fn the_payload_records_layer_line_channel_counter_and_tool_versions() {
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("deposit");
        let outcome = deposit(&spec(), &sk, "varve-root-1", &dest).unwrap();
        let hex = outcome.digest.strip_prefix("sha256:").unwrap();
        let payload = std::fs::read(dest.join("blobs/sha256").join(hex)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let ann = &json["annotations"];
        assert_eq!(ann["eu.pulseengine.varve.layer"], "2026.08.0");
        assert_eq!(ann["eu.pulseengine.varve.line"], "2026.08");
        assert_eq!(ann["eu.pulseengine.varve.channel"], "qualified");
        assert_eq!(ann["eu.pulseengine.varve.counter"], "1");
        assert_eq!(
            ann["org.opencontainers.image.created"],
            "2026-08-07T00:00:00Z"
        );
        let entries = json["manifests"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| {
            e["annotations"]["eu.pulseengine.tool"] == "synth"
                && e["annotations"]["eu.pulseengine.tool.version"] == "0.45.0"
        }));
    }

    // rivet: verifies REQ-DEPOSIT-001
    #[test]
    fn identical_specs_deposit_identical_digests() {
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let a = deposit(&spec(), &sk, "varve-root-1", &tmp.path().join("a")).unwrap();
        let b = deposit(&spec(), &sk, "varve-root-1", &tmp.path().join("b")).unwrap();
        assert_eq!(
            a.digest, b.digest,
            "the payload is deterministic — the digest IS the identity"
        );
    }

    // rivet: verifies REQ-DEPOSIT-001
    #[test]
    fn empty_and_duplicate_tool_lists_are_refused() {
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut empty = spec();
        empty.tools.clear();
        assert!(matches!(
            deposit(&empty, &sk, "k", &tmp.path().join("x")).unwrap_err(),
            DepositError::NoTools
        ));
        let mut dup = spec();
        dup.tools[1].name = "synth".into();
        assert!(matches!(
            deposit(&dup, &sk, "k", &tmp.path().join("y")).unwrap_err(),
            DepositError::DuplicateTool(name) if name == "synth"
        ));
    }
}
