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

/// An RFC 3339 timestamp, not merely a date. `epoch_days` accepts a bare
/// `YYYY-MM-DD` because it only needs day resolution; a manifest's issued-at
/// must carry a time, since it lands verbatim in the SBOM's `metadata.timestamp`
/// where a bare date is invalid (REQ-PRODUCER-001).
fn is_rfc3339(s: &str) -> bool {
    let Some((date, time)) = s.split_once('T') else {
        return false;
    };
    if crate::rollback::epoch_days(date).is_none() {
        return false;
    }
    // hh:mm:ss, then an optional fraction, then Z or a numeric offset.
    let b = time.as_bytes();
    if b.len() < 9 || b[2] != b':' || b[5] != b':' {
        return false;
    }
    if !b[..8].iter().enumerate().all(|(i, c)| {
        if i == 2 || i == 5 {
            *c == b':'
        } else {
            c.is_ascii_digit()
        }
    }) {
        return false;
    }
    let rest = &time[8..];
    rest == "Z" || rest.ends_with('Z') || rest.contains('+') || rest.matches('-').count() == 1
}

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
    /// Layers composed into this one (REQ-COMPOSE-001).
    pub includes: Vec<DepositInclude>,
}

/// One composed layer, as the depositor names it.
#[derive(Debug, Clone, Default)]
pub struct DepositInclude {
    pub digest: String,
    pub realm: Option<String>,
    pub layer: Option<String>,
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
    /// Runner contract for portable wasm entries (REQ-RUNNER-001): the tool
    /// (from the SAME layer) that executes this entry, prefix args, and an
    /// optional per-user-argument flag (kilnd's --wasi-arg shape).
    pub runner: Option<RunnerSpec>,
    /// Payload kind (REQ-KIND-001). `None` or `Tool` deposits no kind
    /// annotation — pre-kind and tool layers keep byte-identical payloads.
    pub kind: Option<crate::kind::PayloadKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSpec {
    pub tool: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(rename = "arg-prefix", default)]
    pub arg_prefix: Option<String>,
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
    /// Layers this one composes (REQ-COMPOSE-001). Without this a composed
    /// layer could not be PRODUCED at all — only hand-authored.
    #[serde(default, rename = "include")]
    pub includes: Vec<SpecInclude>,
}

/// A layer composed into this one: named by the digest of its signed manifest,
/// plus the realm whose trust root is authoritative for it.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecInclude {
    /// `sha256:<hex>` of the included layer's signed manifest.
    pub digest: String,
    /// The realm that verifies it. Absent = this layer's own realm.
    #[serde(default)]
    pub realm: Option<String>,
    /// The included layer's identifier, so errors can name it before it is
    /// fetched.
    #[serde(default)]
    pub layer: Option<String>,
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
    #[serde(default)]
    pub runner: Option<RunnerSpec>,
    /// Payload kind (REQ-KIND-001): tool|crate|wit|zephyr-module|sdk|
    /// wasm-component|vsix. Absent = tool.
    #[serde(default)]
    pub kind: Option<String>,
}

pub fn parse_deposit_spec(toml_text: &str) -> Result<DepositFileSpec, DepositError> {
    toml::from_str(toml_text).map_err(|e| DepositError::Spec(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    #[error(
        "the envelope this deposit just signed does not verify against the key that signed \
         it — refusing to publish an artifact no consumer could accept"
    )]
    SelfVerifyFailed,
    #[error(
        "channel {channel:?} is not one a pin can name — use `qualified` or `rolling`. \
         Signing it would produce a layer no varve.toml could ever select."
    )]
    BadChannel { channel: String },
    #[error(
        "issued-at {issued_at:?} is not an RFC 3339 timestamp (e.g. 2026-08-01T00:00:00Z). \
         It is signed into the manifest and drives staleness and the SBOM timestamp, so it \
         cannot be corrected afterwards."
    )]
    BadIssuedAt { issued_at: String },
    #[error("deposit spec is not valid: {0}")]
    Spec(String),
    #[error("deposit has no tools — an empty layer is not a toolchain")]
    NoTools,
    #[error(
        "tool '{name}' is deposited twice for platform {platform} (versions {first} and \
         {second}) — a tool is DISPATCHED BY NAME (`varve run {name}`, `varve which {name}`, the \
         argv[0] shims), so one name must resolve to exactly one binary per platform. Deposit the \
         other version as a separate layer, or give it a distinct name."
    )]
    DuplicateTool {
        name: String,
        platform: String,
        first: String,
        second: String,
    },
    #[error(
        "payload '{name}' version {version} is deposited twice for platform {platform} — a layer \
         may hold several VERSIONS of one name, but not one version twice: the two would be the \
         same payload, and only one set of bytes could land."
    )]
    DuplicatePayload {
        name: String,
        version: String,
        platform: String,
    },
    #[error(transparent)]
    Sign(#[from] VerifyError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// How a platform reads in an error when the entry claims none.
fn platform_label(platform: Option<&String>) -> String {
    platform
        .cloned()
        .unwrap_or_else(|| "any (unstamped)".to_string())
}

/// Refuse only TRUE duplicates, under the identity of REQ-STORE-002 clause 1
/// (clause 3).
///
/// A `tool` is dispatched by name, so its identity is (name, platform) and two
/// versions of one tool in one layer is a genuine error — `varve run synth`
/// would have no answer. Every other kind is held, not dispatched: its identity
/// is (name, version, platform), so `serde@1.0.200` beside `serde@1.0.210` is
/// the ORDINARY shape of a dependency graph and must be accepted. varve's own
/// Cargo.lock has 14 names at more than one version; refusing them meant varve
/// could not express its own dependency graph as a layer.
fn check_identities(tools: &[&DepositTool]) -> Result<(), DepositError> {
    // (name, platform) -> the version already seen, for dispatchable payloads.
    let mut dispatched: std::collections::BTreeMap<(&str, Option<&String>), &str> =
        std::collections::BTreeMap::new();
    // (name, version, platform) -> seen, for everything else.
    let mut held: std::collections::BTreeSet<(&str, &str, Option<&String>)> =
        std::collections::BTreeSet::new();
    for tool in tools {
        let dispatchable = tool.kind.unwrap_or_default().is_dispatchable();
        let platform = tool.platform.as_ref();
        if dispatchable {
            if let Some(first) = dispatched.insert((&tool.name, platform), &tool.version) {
                return Err(DepositError::DuplicateTool {
                    name: tool.name.clone(),
                    platform: platform_label(platform),
                    first: first.to_string(),
                    second: tool.version.clone(),
                });
            }
        } else if !held.insert((&tool.name, &tool.version, platform)) {
            return Err(DepositError::DuplicatePayload {
                name: tool.name.clone(),
                version: tool.version.clone(),
                platform: platform_label(platform),
            });
        }
    }
    Ok(())
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
    // Sorted by the FULL identity, so the payload order is deterministic even
    // when one name appears at several versions — the digest is the identity a
    // pin freezes against, and it must not depend on spec order.
    tools.sort_by(|a, b| {
        (&a.name, &a.version, &a.platform).cmp(&(&b.name, &b.version, &b.platform))
    });
    check_identities(&tools)?;

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
            // Stamp the payload kind only when it is non-default: a `tool`
            // (or unspecified) entry carries no kind annotation, so pre-kind
            // tool layers keep byte-identical signed payloads (REQ-KIND-001).
            if let Some(kind) = tool.kind
                && kind != crate::kind::PayloadKind::Tool
            {
                annotations.insert(crate::kind::ANN_KIND.into(), kind.as_str().into());
            }
            if let Some(runner) = &tool.runner {
                annotations.insert(crate::bazel::ANN_RUNNER.into(), runner.tool.clone().into());
                if !runner.args.is_empty() {
                    annotations.insert(
                        crate::bazel::ANN_RUNNER_ARGS.into(),
                        runner.args.join(" ").into(),
                    );
                }
                if let Some(prefix) = &runner.arg_prefix {
                    annotations.insert(
                        crate::bazel::ANN_RUNNER_ARG_PREFIX.into(),
                        prefix.clone().into(),
                    );
                }
            }
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest(&tool.bytes),
                "size": tool.bytes.len(),
                "annotations": annotations,
            })
        })
        .collect();
    // Composed layers are entries too: a `layer`-kind reference whose digest is
    // the included layer's SIGNED MANIFEST digest. Emitting them here is what
    // makes the composition part of the signed payload — and what lets a
    // composed layer be produced at all rather than hand-authored.
    let mut entries = entries;
    for inc in &spec.includes {
        let mut annotations = serde_json::Map::new();
        annotations.insert(
            crate::kind::ANN_KIND.into(),
            crate::kind::PayloadKind::Layer.as_str().into(),
        );
        if let Some(realm) = &inc.realm {
            annotations.insert(
                crate::compose::ANN_INCLUDE_REALM.into(),
                realm.clone().into(),
            );
        }
        if let Some(layer) = &inc.layer {
            annotations.insert(
                crate::compose::ANN_INCLUDE_LAYER.into(),
                layer.clone().into(),
            );
        }
        entries.push(serde_json::json!({
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": inc.digest,
            "size": 0,
            "annotations": annotations,
        }));
    }
    // Validate BEFORE signing. Everything below becomes immutable the moment it
    // is signed, so a bad value here is not a mistake you can correct — it is a
    // released artifact nobody can use (REQ-PRODUCER-001).
    if spec.channel.parse::<crate::pin::Channel>().is_err() {
        return Err(DepositError::BadChannel {
            channel: spec.channel.clone(),
        });
    }
    if !is_rfc3339(&spec.issued_at) {
        return Err(DepositError::BadIssuedAt {
            issued_at: spec.issued_at.clone(),
        });
    }
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
    // Read our own work back before publishing it. The cheapest possible guard
    // against emitting a release artifact nobody can verify — and the last
    // point at which it is still correctable (REQ-PRODUCER-001).
    let public = &signing_key[32..];
    match crate::verify::dsse_verify_typed(
        envelope.as_bytes(),
        crate::verify::LAYER_PAYLOAD_TYPE,
        public,
    ) {
        Ok(back) if back == payload => {}
        _ => return Err(DepositError::SelfVerifyFailed),
    }

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
        // A deposit carries every platform the producer built, so it makes no
        // single-platform claim — unlike an archive (varve#80).
        None,
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
mod producer_tests {
    use super::*;

    // rivet: verifies REQ-PRODUCER-001
    #[test]
    fn a_channel_no_pin_could_name_is_refused_before_signing() {
        // `--channel stable` signed happily and produced a layer no varve.toml
        // could ever select, exit 0. The enum is shared with the pin parser so
        // the two cannot drift.
        assert!("qualified".parse::<crate::pin::Channel>().is_ok());
        assert!("rolling".parse::<crate::pin::Channel>().is_ok());
        for bad in ["stable", "Qualified", "", "beta"] {
            assert!(
                bad.parse::<crate::pin::Channel>().is_err(),
                "{bad} must be refused"
            );
        }
    }

    // rivet: verifies REQ-PRODUCER-001
    #[test]
    fn issued_at_must_be_a_timestamp_not_merely_a_date() {
        // A bare date passed `epoch_days` (which needs only day resolution) but
        // lands verbatim in the SBOM's metadata.timestamp, where it is invalid
        // and uncorrectable after signing.
        assert!(is_rfc3339("2026-08-01T00:00:00Z"));
        assert!(is_rfc3339("2026-08-01T12:34:56.789Z"));
        assert!(is_rfc3339("2026-08-01T12:34:56+02:00"));
        for bad in [
            "2026-10-01",
            "not-a-date",
            "",
            "2026-08-01T",
            "2026-13-01T00:00:00Z",
        ] {
            assert!(!is_rfc3339(bad), "{bad} must be refused");
        }
    }
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
            includes: Vec::new(),
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
                    runner: None,
                    kind: None,
                },
                DepositTool {
                    name: "rivet".into(),
                    version: "0.32.0".into(),
                    platform: None,
                    bytes: b"rivet-bytes".to_vec(),
                    source: None,
                    runner: None,
                    kind: None,
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
            index: None,
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
        let err = deposit(&dup, &sk, "k", &tmp.path().join("y")).unwrap_err();
        assert!(
            matches!(&err, DepositError::DuplicateTool { name, .. } if name == "synth"),
            "got: {err}"
        );
    }

    /// One entry of a given kind, at a given version and platform.
    fn payload(
        name: &str,
        version: &str,
        kind: Option<crate::kind::PayloadKind>,
        platform: Option<&str>,
    ) -> DepositTool {
        DepositTool {
            name: name.into(),
            version: version.into(),
            platform: platform.map(str::to_string),
            bytes: format!("{name}-{version}-bytes").into_bytes(),
            source: None,
            runner: None,
            kind,
        }
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn two_versions_of_one_crate_are_a_layer_not_a_duplicate() {
        // THE reported defect (varve#69), at the function that raised it.
        // `deposit` keyed on (name, platform) and ignored version and kind, so
        // serde 1.0.200 beside serde 1.0.210 was refused as "duplicate tool
        // name 'serde'" — and varve could not express its own dependency graph
        // (252 packages, 14 names at more than one version) as a layer.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            payload("serde", "1.0.200", Some(PayloadKind::Crate), None),
            payload("serde", "1.0.210", Some(PayloadKind::Crate), None),
        ];
        let outcome = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap();

        // Both versions are in the SIGNED payload, each under its own digest.
        let hex = outcome.digest.strip_prefix("sha256:").unwrap();
        let payload_bytes = std::fs::read(tmp.path().join("d/blobs/sha256").join(hex)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let entries = json["manifests"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let versions: Vec<&str> = entries
            .iter()
            .map(|e| {
                e["annotations"]["eu.pulseengine.tool.version"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(versions, vec!["1.0.200", "1.0.210"]);
        assert_ne!(
            entries[0]["digest"], entries[1]["digest"],
            "two versions are two artifacts"
        );
    }

    // rivet: verifies REQ-VSIX-001
    #[test]
    fn extensions_deposit_as_vsix_entries_at_several_versions() {
        // Clause 1: the kind reaches the SIGNED payload as `vsix`, spelled that
        // way — the annotation is what a consumer's `export-vsix` keys on, and
        // it is inside the DSSE payload, so it cannot be corrected afterwards.
        // Clause 4: an extension is not dispatched by name, so its identity is
        // (name, version) and two versions of one extension is a layer, not a
        // duplicate — the same rule REQ-STORE-002 established for crates,
        // reached here through `is_dispatchable` rather than a second list.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            payload(
                "rust-lang.rust-analyzer",
                "0.3.2260",
                Some(PayloadKind::Vsix),
                None,
            ),
            payload(
                "rust-lang.rust-analyzer",
                "0.3.2300",
                Some(PayloadKind::Vsix),
                None,
            ),
            payload(
                "vadimcn.vscode-lldb",
                "1.11.4",
                Some(PayloadKind::Vsix),
                None,
            ),
        ];
        let outcome = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap();

        let hex = outcome.digest.strip_prefix("sha256:").unwrap();
        let payload_bytes = std::fs::read(tmp.path().join("d/blobs/sha256").join(hex)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let entries = json["manifests"].as_array().unwrap();
        assert_eq!(entries.len(), 3, "all three extensions must be signed in");
        for e in entries {
            assert_eq!(
                e["annotations"][crate::kind::ANN_KIND],
                "vsix",
                "every entry must carry the vsix kind in the SIGNED payload"
            );
        }
        let ids: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e["annotations"]["eu.pulseengine.tool"].as_str().unwrap(),
                    e["annotations"]["eu.pulseengine.tool.version"]
                        .as_str()
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(
            ids,
            vec![
                ("rust-lang.rust-analyzer", "0.3.2260"),
                ("rust-lang.rust-analyzer", "0.3.2300"),
                ("vadimcn.vscode-lldb", "1.11.4"),
            ]
        );
        assert_ne!(
            entries[0]["digest"], entries[1]["digest"],
            "two versions of one extension are two artifacts"
        );

        // …and one version deposited twice is still a true duplicate.
        let mut dup = spec;
        dup.tools = vec![
            payload("pub.ext", "1.0.0", Some(PayloadKind::Vsix), None),
            payload("pub.ext", "1.0.0", Some(PayloadKind::Vsix), None),
        ];
        let err = deposit(&dup, &sk, "k", &tmp.path().join("e")).unwrap_err();
        assert!(
            matches!(&err, DepositError::DuplicatePayload { name, version, .. }
                     if name == "pub.ext" && version == "1.0.0"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_tool_may_not_appear_twice_under_one_name_however_its_versions_differ() {
        // Clause 1's other half, and the reason the rule is not simply
        // "(name, version)": dispatch is BY NAME. `varve run synth` must have
        // exactly one answer, so two versions of one TOOL in one layer is a
        // real error — and the error must name both versions, or the depositor
        // cannot tell which two entries collided.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            payload("synth", "0.45.0", Some(PayloadKind::Tool), None),
            payload("synth", "0.46.0", None, None), // absent kind == tool
        ];
        let err = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(&err, DepositError::DuplicateTool { name, .. } if name == "synth"),
            "got: {err}"
        );
        assert!(msg.contains("0.45.0") && msg.contains("0.46.0"), "{msg}");
        // The identity includes the platform, so the verdict must name it —
        // otherwise a depositor of a cross-platform layer is told two entries
        // collide without being told on WHICH platform they do.
        assert!(
            msg.contains("any"),
            "an unstamped entry is any-platform: {msg}"
        );
        let mut stamped = spec;
        for tool in &mut stamped.tools {
            tool.platform = Some("x86_64-unknown-linux-gnu".into());
        }
        let msg = deposit(&stamped, &sk, "k", &tmp.path().join("e"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("x86_64-unknown-linux-gnu"), "{msg}");
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn one_version_deposited_twice_is_still_refused_and_the_error_names_it() {
        // Clause 3: relaxing the check must refuse only TRUE duplicates. Two
        // entries with ONE identity are the same payload twice — only one set
        // of bytes could land, so this stays an error, and the message carries
        // the version the old one lacked.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            payload("serde", "1.0.200", Some(PayloadKind::Crate), None),
            payload("serde", "1.0.200", Some(PayloadKind::Crate), None),
        ];
        let err = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(&err, DepositError::DuplicatePayload { name, version, .. }
                if name == "serde" && version == "1.0.200"),
            "got: {err}"
        );
        assert!(msg.contains("serde") && msg.contains("1.0.200"), "{msg}");
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn platform_still_separates_identities_for_both_rules() {
        // Clause 1 keeps `platform` in BOTH keys. The same tool for two
        // platforms is the ordinary cross-platform layer (install filters to
        // one), and the same crate for two platforms must likewise be allowed —
        // dropping platform from the key would refuse layers that install fine.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            payload("synth", "0.45.0", None, Some("aarch64-apple-darwin")),
            payload("synth", "0.45.0", None, Some("x86_64-unknown-linux-gnu")),
            payload(
                "serde",
                "1.0.200",
                Some(PayloadKind::Crate),
                Some("aarch64-apple-darwin"),
            ),
            payload(
                "serde",
                "1.0.200",
                Some(PayloadKind::Crate),
                Some("x86_64-unknown-linux-gnu"),
            ),
        ];
        deposit(&spec, &sk, "k", &tmp.path().join("d")).expect(
            "distinct platforms, distinct
             identities",
        );
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn the_signed_digest_does_not_depend_on_the_order_versions_are_listed_in() {
        // The payload is sorted by the FULL identity now that one name can
        // appear more than once. Sorting by (name, platform) alone left two
        // versions of one name in spec order, so the same layer deposited from
        // a reordered spec would have produced a DIFFERENT digest — and the
        // digest is the identity a pin freezes against.
        use crate::kind::PayloadKind;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let a_first = vec![
            payload("serde", "1.0.200", Some(PayloadKind::Crate), None),
            payload("serde", "1.0.210", Some(PayloadKind::Crate), None),
        ];
        let b_first: Vec<DepositTool> = a_first.iter().rev().cloned().collect();
        let mut s1 = spec();
        s1.tools = a_first;
        let mut s2 = spec();
        s2.tools = b_first;
        assert_eq!(
            deposit(&s1, &sk, "k", &tmp.path().join("a"))
                .unwrap()
                .digest,
            deposit(&s2, &sk, "k", &tmp.path().join("b"))
                .unwrap()
                .digest,
        );
    }
}
