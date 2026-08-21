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
    /// The absolute path a tree-shaped payload was BUILT for, signed into the
    /// manifest as `eu.pulseengine.varve.sdk.prefix` (REQ-SDK-001 clause 4).
    ///
    /// It is the relocation BUDGET, so it has to be attributable rather than
    /// guessed: `export-sdk` refuses a destination longer than this, and a
    /// consumer must not be able to talk varve into trying. Only a tree payload
    /// has one — see `check_identities` for why depositing it on anything else
    /// is refused rather than ignored.
    pub sdk_prefix: Option<String>,
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
    /// WHICH mechanism vouched for these bytes (REQ-INGEST-001 clause 2).
    /// `None` on a spec written before the requirement; a layer deposited that
    /// way reads as `unrecorded`, never as verified.
    #[serde(default)]
    pub proof: Option<crate::ingest::IngestProof>,
    /// The identity that vouched — the cosign certificate identity, or the
    /// attestation's `buildSignerURI`.
    #[serde(rename = "proof-signer", default)]
    pub proof_signer: Option<String>,
    /// What that mechanism ASSERTED, in one line. For `unverified` this is the
    /// operator's recorded reason, and it is mandatory: see
    /// `DepositError::UnverifiedWithoutReason`.
    #[serde(rename = "proof-asserts", default)]
    pub proof_asserts: Option<String>,
}

/// How a deposit treats a destination that is not empty (REQ-NODESTROY-001).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DepositOptions {
    /// Overwrite a layout that already carries referrers, destroying them.
    /// Deliberate and stated — the point of the guard is that the destructive
    /// case must be ASKED for, not stumbled into.
    pub force: bool,
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
    /// `sdk-prefix` — the absolute path this tree was built for (REQ-SDK-001
    /// clause 4). Required to make an `sdk` exportable at all: without it there
    /// is no relocation budget, so `varve export-sdk` has nothing to patch.
    #[serde(rename = "sdk-prefix", default)]
    pub sdk_prefix: Option<String>,
}

pub fn parse_deposit_spec(toml_text: &str) -> Result<DepositFileSpec, DepositError> {
    toml::from_str(toml_text).map_err(|e| DepositError::Spec(e.to_string()))
}

impl From<crate::archive::LayoutWriteError> for DepositError {
    fn from(e: crate::archive::LayoutWriteError) -> Self {
        match e {
            crate::archive::LayoutWriteError::Io { path, source } => {
                DepositError::Io { path, source }
            }
            crate::archive::LayoutWriteError::WouldDestroy(d) => {
                DepositError::WouldDestroySignedWork(d)
            }
        }
    }
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
    /// REQ-NODESTROY-001. `deposit` writes the WHOLE layout, `index.json`
    /// included, so a second deposit into a directory that has had evidence
    /// attached dropped all of it and reported success. Documentation warned
    /// about this in three topics and guarded nothing.
    #[error(transparent)]
    WouldDestroySignedWork(#[from] crate::referrers::WouldDestroy),
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
    #[error(
        "payload '{name}' is kind {kind} and carries `sdk-prefix` — only a tree payload (sdk) is \
         relocated, so the prefix would be signed into the manifest, ignored by every adapter, \
         and believed. Drop it, or deposit this payload as kind = \"sdk\"."
    )]
    SdkPrefixOnNonTree { name: String, kind: String },
    #[error(
        "sdk '{name}' version {version} declares no `sdk-prefix` — the absolute path it was \
         BUILT for. Without it `varve export-sdk` has no relocation budget and no path to \
         patch, so the layer would install and verify and could never be exported. Add \
         `sdk-prefix = \"/opt/poky/4.0\"` (the path the SDK was built for) to the [[tool]] table."
    )]
    SdkPrefixMissing { name: String, version: String },
    #[error(
        "sdk '{name}' declares sdk-prefix {prefix:?}, which is not absolute — the prefix is the \
         path PATCHED INTO the SDK's binaries, and a relative one there would resolve against \
         whatever directory a compiler happens to run in"
    )]
    SdkPrefixNotAbsolute { name: String, prefix: String },
    #[error(
        "payload '{name}' from {repo} declares proof = \"unverified\" and records no reason — \
         \"we could not verify this\" must never be the silent path. Nothing vouched for these \
         bytes, so the only thing that can travel with them is WHY you shipped them anyway: set \
         `proof-asserts` on [tool.source] to the operator's justification, which is signed into \
         the layer where `varve inspect` and every consumer will see it."
    )]
    UnverifiedWithoutReason { name: String, repo: String },
    #[error(
        "payload '{name}' from {repo} declares proof = \"unverified\" and also names \
         proof-signer {signer:?} — nothing vouched for these bytes, so naming an identity that \
         did would be signed, attributable and false. Drop the signer, or declare the mechanism \
         that actually established it."
    )]
    UnverifiedNamesASigner {
        name: String,
        repo: String,
        signer: String,
    },
    #[error(
        "payload '{name}' from {repo} carries ingestion-proof detail ({detail}) but declares no \
         `proof` mechanism — the detail would be signed into the layer with nothing saying HOW \
         it was established, which makes it attributable and believed rather than checkable. \
         Declare `proof = \"cosign-sums\" | \"build-provenance\" | \"unverified\"`, or drop the \
         detail."
    )]
    ProofDetailWithoutMechanism {
        name: String,
        repo: String,
        detail: &'static str,
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

/// The relocation budget must be present exactly where it can be acted on, and
/// absent everywhere else (REQ-SDK-001 clause 4).
///
/// Both directions are refusals rather than warnings, at the PRODUCING end. An
/// `sdk-prefix` on a payload nobody relocates is signed, ignored and believed;
/// an `sdk` without one installs and verifies and can never be exported, which
/// the consumer discovers on the far side of an air gap. Neither is repairable
/// without re-depositing, because the annotation lives inside the signature.
fn check_sdk_prefixes(tools: &[&DepositTool]) -> Result<(), DepositError> {
    for tool in tools {
        let is_tree = tool.kind == Some(crate::kind::PayloadKind::Sdk);
        match (&tool.sdk_prefix, is_tree) {
            (Some(_), false) => {
                return Err(DepositError::SdkPrefixOnNonTree {
                    name: tool.name.clone(),
                    kind: tool.kind.unwrap_or_default().as_str().to_string(),
                });
            }
            (None, true) => {
                return Err(DepositError::SdkPrefixMissing {
                    name: tool.name.clone(),
                    version: tool.version.clone(),
                });
            }
            (Some(prefix), true) if !prefix.starts_with('/') => {
                return Err(DepositError::SdkPrefixNotAbsolute {
                    name: tool.name.clone(),
                    prefix: prefix.clone(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// The ingestion proof must be sayable, or not said at all (REQ-INGEST-001
/// clause 3), checked at the PRODUCING end for the same reason
/// `check_sdk_prefixes` is: everything below is immutable the moment it is
/// signed.
///
/// This function does NOT require a proof to be present. A crate ingested from
/// crates.io and a layer deposited before this requirement both legitimately
/// carry none, and they read as `unrecorded` rather than as verified. What it
/// refuses are the three shapes that would be signed and BELIEVED:
///
/// * `unverified` with no recorded reason — the silent path the requirement
///   exists to close;
/// * `unverified` naming a signer — an identity credited with vouching for
///   bytes nothing vouched for;
/// * proof detail with no mechanism — a claim with no account of how it was
///   established.
///
/// Refusing a MISSING proof is the assembler's job, not this one's: only the
/// assembler knows it went looking for a mechanism and found none.
fn check_ingest_proofs(tools: &[&DepositTool]) -> Result<(), DepositError> {
    for tool in tools {
        let Some(source) = &tool.source else { continue };
        match source.proof {
            Some(crate::ingest::IngestProof::Unverified) => {
                if source
                    .proof_asserts
                    .as_ref()
                    .is_none_or(|r| r.trim().is_empty())
                {
                    return Err(DepositError::UnverifiedWithoutReason {
                        name: tool.name.clone(),
                        repo: source.repo.clone(),
                    });
                }
                if let Some(signer) = &source.proof_signer {
                    return Err(DepositError::UnverifiedNamesASigner {
                        name: tool.name.clone(),
                        repo: source.repo.clone(),
                        signer: signer.clone(),
                    });
                }
            }
            Some(_) => {}
            None => {
                let detail = match (&source.proof_signer, &source.proof_asserts) {
                    (Some(_), Some(_)) => Some("proof-signer and proof-asserts"),
                    (Some(_), None) => Some("proof-signer"),
                    (None, Some(_)) => Some("proof-asserts"),
                    (None, None) => None,
                };
                if let Some(detail) = detail {
                    return Err(DepositError::ProofDetailWithoutMechanism {
                        name: tool.name.clone(),
                        repo: source.repo.clone(),
                        detail,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Assemble, sign, and write a layer as an OCI image layout at `dest`,
/// refusing a destination that already carries signed work (REQ-NODESTROY-001).
pub fn deposit(
    spec: &DepositSpec,
    signing_key: &[u8],
    key_id: &str,
    dest: &Path,
) -> Result<DepositOutcome, DepositError> {
    deposit_with_options(spec, signing_key, key_id, dest, &DepositOptions::default())
}

/// `deposit`, with the destructive case available to callers that ask for it.
pub fn deposit_with_options(
    spec: &DepositSpec,
    signing_key: &[u8],
    key_id: &str,
    dest: &Path,
    options: &DepositOptions,
) -> Result<DepositOutcome, DepositError> {
    // FIRST, before anything is validated or signed. `write_oci_layout` runs
    // the same guard — it is the single writer, and clause 4 lives there — but
    // asking here too means a deposit that would destroy signed work is
    // refused before a key is even read, rather than after a signature exists
    // for an artifact that will not be written (REQ-NODESTROY-001).
    crate::referrers::guard(dest, options.force)?;
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
    check_sdk_prefixes(&tools)?;
    check_ingest_proofs(&tools)?;

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
                // WHICH mechanism vouched for these bytes, and what it
                // asserted (REQ-INGEST-001 clause 2) — inside the signed
                // payload, so a consumer can tell a cosign-signed tool from an
                // attested one without leaving the layer.
                //
                // Stamped only when the spec declares it. An absent annotation
                // is the pre-requirement layer and reads as `unrecorded`;
                // synthesising a default here would silently upgrade every
                // payload deposited by an older spec to a claim nobody made,
                // and would change the signed bytes of layers that carry no
                // proof at all (the crate deposits, whose ingestion is
                // crates.io and not a release page).
                if let Some(proof) = source.proof {
                    annotations.insert(crate::ingest::ANN_PROOF.into(), proof.as_str().into());
                }
                if let Some(signer) = &source.proof_signer {
                    annotations.insert(
                        crate::ingest::ANN_PROOF_SIGNER.into(),
                        signer.clone().into(),
                    );
                }
                if let Some(asserts) = &source.proof_asserts {
                    annotations.insert(
                        crate::ingest::ANN_PROOF_ASSERTS.into(),
                        asserts.clone().into(),
                    );
                }
            }
            // Stamp the payload kind only when it is non-default: a `tool`
            // (or unspecified) entry carries no kind annotation, so pre-kind
            // tool layers keep byte-identical signed payloads (REQ-KIND-001).
            if let Some(kind) = tool.kind
                && kind != crate::kind::PayloadKind::Tool
            {
                annotations.insert(crate::kind::ANN_KIND.into(), kind.as_str().into());
            }
            // The relocation budget, inside the signature (REQ-SDK-001
            // clause 4). `check_identities` has already refused it on a kind
            // that is not a tree, so an entry carrying it is one `export-sdk`
            // can act on.
            if let Some(prefix) = &tool.sdk_prefix {
                annotations.insert(
                    crate::sdkexport::ANN_SDK_PREFIX.into(),
                    prefix.clone().into(),
                );
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
        options.force,
    )
    .map_err(DepositError::from)?;

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

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn a_deposit_that_would_drop_a_referrer_is_refused_before_a_byte_is_written() {
        use crate::verify::generate_root_keypair;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        let spec = super::tests::spec();
        deposit(&spec, &sk, "k", &dest).unwrap();
        // Evidence attached after the deposit — the append-only half of the
        // producer pipeline.
        let status = crate::linestatus::LineStatus {
            line: "2026.08".into(),
            counter: 1,
            issued_at: "2026-08-07T00:00:00Z".into(),
            support_until: None,
            yanked: Default::default(),
            known_problems: Vec::new(),
        };
        crate::linestatus::attach_to_layout(
            &dest,
            &"2026.08".parse().unwrap(),
            status.sign(&sk, "k").unwrap().as_bytes(),
        )
        .unwrap();

        let index_before = std::fs::read(dest.join("index.json")).unwrap();
        let err = deposit(&spec, &sk, "k", &dest).expect_err("must refuse");
        assert!(
            matches!(&err, DepositError::WouldDestroySignedWork { .. }),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("line-status") && msg.contains("2026.08"),
            "{msg}"
        );
        assert!(msg.contains("varve attach-status"), "{msg}");
        assert_eq!(
            index_before,
            std::fs::read(dest.join("index.json")).unwrap(),
            "a refused deposit must not have touched the layout"
        );

        // …and --force is the deliberate way through, because sometimes the
        // operator really does mean to start the directory over.
        deposit_with_options(&spec, &sk, "k", &dest, &DepositOptions { force: true })
            .expect("--force overrides the guard");
        assert!(
            crate::linestatus::read_any_from_layout(&dest)
                .unwrap()
                .is_none(),
            "--force is destructive on purpose — the referrer is gone"
        );
    }

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn depositing_into_a_fresh_or_previously_clean_directory_still_works() {
        // The guard must fire on ATTACHED work only. A guard that also refused
        // a directory holding nothing but a previous clean deposit would break
        // every idempotent CI re-run, and a guard that gets switched off
        // protects nobody.
        use crate::verify::generate_root_keypair;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("layout");
        let spec = super::tests::spec();
        let first = deposit(&spec, &sk, "k", &dest).unwrap();
        let second = deposit(&spec, &sk, "k", &dest).expect("a clean layout may be re-deposited");
        assert_eq!(first.digest, second.digest);
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

    pub(super) fn spec() -> DepositSpec {
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
                    sdk_prefix: None,
                },
                DepositTool {
                    name: "rivet".into(),
                    version: "0.32.0".into(),
                    platform: None,
                    bytes: b"rivet-bytes".to_vec(),
                    source: None,
                    runner: None,
                    kind: None,
                    sdk_prefix: None,
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

    /// A tool whose bytes arrived through a NAMED ingestion mechanism
    /// (REQ-INGEST-001).
    fn ingested(name: &str, repo: &str, proof: crate::ingest::IngestProof) -> DepositTool {
        let mut tool = payload(name, "1.0.0", None, Some("x86_64-unknown-linux-gnu"));
        tool.source = Some(ToolSource {
            repo: repo.into(),
            release: "v1.0.0".into(),
            asset: format!("{name}-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"),
            sha256: "a".repeat(64),
            proof: Some(proof),
            proof_signer: match proof {
                crate::ingest::IngestProof::Unverified => None,
                _ => Some(format!(
                    "https://github.com/{repo}/.github/workflows/release.yml@refs/tags/v1.0.0"
                )),
            },
            proof_asserts: Some(match proof {
                crate::ingest::IngestProof::CosignSums => {
                    "SHA256SUMS.txt signed for this repo".to_string()
                }
                crate::ingest::IngestProof::BuildProvenance => {
                    "built from source commit deadbeef".to_string()
                }
                crate::ingest::IngestProof::Unverified => {
                    "NOTHING — operator opt-in: needed for the 2026.09 bring-up".to_string()
                }
            }),
        });
        tool
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_mechanism_that_vouched_for_each_payload_is_inside_the_signed_layer() {
        // Clause 2. A consumer must be able to tell a cosign-signed tool from
        // an attested one WITHOUT leaving the layer, so the mechanism and what
        // it asserted are annotations on the payload entry — inside the DSSE
        // payload, uncorrectable after signing, exactly like the kind and the
        // source digests beside them.
        use crate::ingest::{ANN_PROOF, ANN_PROOF_ASSERTS, ANN_PROOF_SIGNER, IngestProof};
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.tools = vec![
            ingested("rivet", "pulseengine/rivet", IngestProof::CosignSums),
            ingested(
                "wasm-tools",
                "bytecodealliance/wasm-tools",
                IngestProof::BuildProvenance,
            ),
            ingested(
                "wit-bindgen",
                "bytecodealliance/wit-bindgen",
                IngestProof::Unverified,
            ),
        ];
        let outcome = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap();
        let hex = outcome.digest.strip_prefix("sha256:").unwrap();
        let bytes = std::fs::read(tmp.path().join("d/blobs/sha256").join(hex)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entries = json["manifests"].as_array().unwrap();
        let by_name = |n: &str| {
            entries
                .iter()
                .find(|e| e["annotations"]["eu.pulseengine.tool"] == n)
                .unwrap_or_else(|| panic!("{n} is not in the payload"))
                .clone()
        };

        let rivet = by_name("rivet");
        assert_eq!(rivet["annotations"][ANN_PROOF], "cosign-sums");
        assert_eq!(
            rivet["annotations"][ANN_PROOF_SIGNER],
            "https://github.com/pulseengine/rivet/.github/workflows/release.yml@refs/tags/v1.0.0"
        );

        let wasm_tools = by_name("wasm-tools");
        assert_eq!(
            wasm_tools["annotations"][ANN_PROOF], "build-provenance",
            "an attested tool must not read as a cosign-signed one"
        );
        assert_eq!(
            wasm_tools["annotations"][ANN_PROOF_ASSERTS],
            "built from source commit deadbeef"
        );

        let wit_bindgen = by_name("wit-bindgen");
        assert_eq!(wit_bindgen["annotations"][ANN_PROOF], "unverified");
        assert!(
            wit_bindgen["annotations"][ANN_PROOF_SIGNER].is_null(),
            "nothing vouched for it, so no signer may be named"
        );
        assert!(
            wit_bindgen["annotations"][ANN_PROOF_ASSERTS]
                .as_str()
                .unwrap()
                .contains("2026.09 bring-up"),
            "the recorded opt-in reason travels with the payload"
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unproven_payload_may_not_be_signed_in_silently() {
        // Clause 3, at the signing end. `unverified` is a real, sayable state —
        // but only WITH the recorded reason. A bare `proof = "unverified"` and
        // no `proof-asserts` is the silent path the requirement forbids, and it
        // is refused before a key is read rather than published and believed.
        use crate::ingest::IngestProof;
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        let mut tool = ingested(
            "wit-bindgen",
            "bytecodealliance/wit-bindgen",
            IngestProof::Unverified,
        );
        tool.source.as_mut().unwrap().proof_asserts = None;
        spec.tools = vec![tool];
        let err = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap_err();
        assert!(
            matches!(&err, DepositError::UnverifiedWithoutReason { name, .. } if name == "wit-bindgen"),
            "got: {err}"
        );

        // …and a signer named for a mechanism that vouched for nothing is a
        // claim of provenance where there is none.
        let mut spec = super::tests::spec();
        let mut tool = ingested(
            "wit-bindgen",
            "bytecodealliance/wit-bindgen",
            IngestProof::Unverified,
        );
        tool.source.as_mut().unwrap().proof_signer = Some("https://github.com/someone/".into());
        spec.tools = vec![tool];
        let err = deposit(&spec, &sk, "k", &tmp.path().join("e")).unwrap_err();
        assert!(
            matches!(&err, DepositError::UnverifiedNamesASigner { name, .. } if name == "wit-bindgen"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn proof_detail_without_a_mechanism_is_refused_rather_than_signed() {
        // The other direction: `proof-signer` / `proof-asserts` with no
        // `proof` would land a signer and a claim in the signed payload with
        // nothing saying HOW it was established — attributable, believed, and
        // meaningless. Same shape of refusal as an sdk-prefix on a non-tree.
        let (sk, _) = generate_root_keypair();
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = spec();
        let mut tool = ingested(
            "wasm-tools",
            "bytecodealliance/wasm-tools",
            crate::ingest::IngestProof::BuildProvenance,
        );
        tool.source.as_mut().unwrap().proof = None;
        spec.tools = vec![tool];
        let err = deposit(&spec, &sk, "k", &tmp.path().join("d")).unwrap_err();
        assert!(
            matches!(&err, DepositError::ProofDetailWithoutMechanism { name, .. } if name == "wasm-tools"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_layer_deposited_before_this_requirement_reads_as_unrecorded_not_as_verified() {
        // The compatibility promise. Every layer already published carries no
        // proof annotation, and the absent case must NOT read as "verified" —
        // that would silently upgrade every pre-REQ-INGEST-001 payload to a
        // claim nobody made. Absent is its own state: `unrecorded`.
        use crate::ingest::IngestProof;
        use crate::manifest::ManifestEntry;
        let entry = ManifestEntry {
            digest: "sha256:abc".into(),
            annotations: Default::default(),
        };
        assert_eq!(entry.ingest_proof(), Ok(None));
        assert_eq!(IngestProof::label(None), "unrecorded");

        let mut entry = entry;
        entry
            .annotations
            .insert(crate::ingest::ANN_PROOF.into(), "build-provenance".into());
        assert_eq!(entry.ingest_proof(), Ok(Some(IngestProof::BuildProvenance)));
        // An unknown mechanism is reported verbatim, never guessed into a
        // known one — a newer varve may mint mechanisms this build has not
        // heard of, and quietly reading one as `cosign-sums` would be a lie.
        entry
            .annotations
            .insert(crate::ingest::ANN_PROOF.into(), "notary-v2".into());
        assert_eq!(
            entry.ingest_proof(),
            Err(crate::ingest::UnknownProof("notary-v2".into()))
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
            sdk_prefix: None,
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
