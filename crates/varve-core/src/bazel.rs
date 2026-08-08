//! Bazel checksum-registry compilation (REQ-BAZEL-001).
//!
//! rules_wasm_component pins tools with per-tool JSON checksum registries
//! and a pure sha256 download path. This module compiles those registries
//! FROM a verified layer manifest: the hashes Bazel enforces become
//! transcriptions from a signed, counter-protected document instead of
//! trust-on-first-use hashes of whatever a release page served. Bazel's
//! fetch path does not change; its trust anchor does.
//!
//! The digests exported are the SOURCE-ASSET digests (the bytes Bazel
//! downloads), recorded inside the signed payload at deposit time — the
//! layer's own entry digests cover the extracted binaries, which Bazel
//! never sees.

use std::collections::BTreeMap;

use crate::manifest::LayerManifest;

pub const ANN_SRC_REPO: &str = "eu.pulseengine.source.repo";
pub const ANN_SRC_RELEASE: &str = "eu.pulseengine.source.release";
pub const ANN_SRC_ASSET: &str = "eu.pulseengine.source.asset";
pub const ANN_SRC_SHA256: &str = "eu.pulseengine.source.sha256";

pub const ANN_RUNNER: &str = "eu.pulseengine.runner";
pub const ANN_RUNNER_ARGS: &str = "eu.pulseengine.runner-args";
pub const ANN_RUNNER_ARG_PREFIX: &str = "eu.pulseengine.runner-arg-prefix";

/// Map a target triple to rules_wasm_component's platform-key vocabulary.
pub fn bazel_platform_key(triple: &str) -> Option<&'static str> {
    match triple {
        "aarch64-apple-darwin" => Some("darwin_arm64"),
        "x86_64-apple-darwin" => Some("darwin_amd64"),
        "aarch64-unknown-linux-gnu" => Some("linux_arm64"),
        "x86_64-unknown-linux-gnu" => Some("linux_amd64"),
        "x86_64-pc-windows-msvc" => Some("windows_amd64"),
        _ => None,
    }
}

/// One compiled registry per tool, plus what could not be compiled and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BazelExport {
    /// tool name → registry JSON (rules_wasm_component schema).
    pub registries: BTreeMap<String, serde_json::Value>,
    /// (tool, platform, reason) skipped — loud, never silent.
    pub skipped: Vec<(String, String, String)>,
}

/// Compile the registries from a (verified-by-the-caller) layer manifest.
pub fn export(manifest: &LayerManifest) -> BazelExport {
    let mut skipped = Vec::new();
    // tool → version → bazel platform key → {sha256, url_suffix}
    let mut tools: BTreeMap<String, (String, String, BTreeMap<String, serde_json::Value>)> =
        BTreeMap::new();

    for entry in &manifest.entries {
        let ann = &entry.annotations;
        let Some(tool) = ann.get("eu.pulseengine.tool") else {
            continue;
        };
        let version = ann
            .get("eu.pulseengine.tool.version")
            .cloned()
            .unwrap_or_default();
        let platform = ann
            .get(crate::platform::ANN_PLATFORM)
            .cloned()
            .unwrap_or_default();
        let Some(key) = bazel_platform_key(&platform) else {
            skipped.push((
                tool.clone(),
                platform.clone(),
                "platform has no Bazel key".into(),
            ));
            continue;
        };
        let (Some(repo), Some(asset), Some(src_sha)) = (
            ann.get(ANN_SRC_REPO),
            ann.get(ANN_SRC_ASSET),
            ann.get(ANN_SRC_SHA256),
        ) else {
            skipped.push((
                tool.clone(),
                platform.clone(),
                "no source provenance recorded at deposit".into(),
            ));
            continue;
        };
        let hex = src_sha
            .strip_prefix("sha256:")
            .unwrap_or(src_sha)
            .to_string();
        let slot = tools
            .entry(tool.clone())
            .or_insert_with(|| (repo.clone(), version.clone(), BTreeMap::new()));
        slot.2.insert(
            key.to_string(),
            serde_json::json!({ "sha256": hex, "url_suffix": asset }),
        );
    }

    let registries = tools
        .into_iter()
        .map(|(tool, (repo, version, platforms))| {
            let json = serde_json::json!({
                "_generated_by": format!(
                    "varve export-bazel — layer {} (counter {}); digests transcribed from the \
                     signed layer manifest. Do not hand-edit.",
                    manifest.layer, manifest.counter
                ),
                "tool_name": tool,
                "github_repo": repo,
                "latest_version": version,
                "versions": {
                    version.clone(): { "platforms": platforms }
                }
            });
            (tool, json)
        })
        .collect();
    BazelExport {
        registries,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_sources() -> LayerManifest {
        let payload = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "annotations": {
    "eu.pulseengine.varve.layer": "2026.08.1",
    "eu.pulseengine.varve.channel": "rolling",
    "eu.pulseengine.varve.counter": "2",
    "org.opencontainers.image.created": "2026-08-07T00:00:00Z"
  },
  "manifests": [
    {
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "annotations": {
        "eu.pulseengine.tool": "rivet",
        "eu.pulseengine.tool.version": "0.32.0",
        "eu.pulseengine.platform": "aarch64-apple-darwin",
        "eu.pulseengine.source.repo": "pulseengine/rivet",
        "eu.pulseengine.source.release": "v0.32.0",
        "eu.pulseengine.source.asset": "rivet-v0.32.0-aarch64-apple-darwin.tar.gz",
        "eu.pulseengine.source.sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    },
    {
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "annotations": {
        "eu.pulseengine.tool": "rivet",
        "eu.pulseengine.tool.version": "0.32.0",
        "eu.pulseengine.platform": "x86_64-unknown-linux-gnu",
        "eu.pulseengine.source.repo": "pulseengine/rivet",
        "eu.pulseengine.source.release": "v0.32.0",
        "eu.pulseengine.source.asset": "rivet-v0.32.0-x86_64-unknown-linux-gnu.tar.gz",
        "eu.pulseengine.source.sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      }
    },
    {
      "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "annotations": {
        "eu.pulseengine.tool": "wsc",
        "eu.pulseengine.tool.version": "0.10.0",
        "eu.pulseengine.platform": "aarch64-apple-darwin"
      }
    }
  ]
}"#;
        LayerManifest::parse(payload.as_bytes()).unwrap()
    }

    // rivet: verifies REQ-BAZEL-001
    #[test]
    fn registries_compile_in_the_rules_schema_with_source_digests() {
        let export = export(&manifest_with_sources());
        let rivet = &export.registries["rivet"];
        assert_eq!(rivet["tool_name"], "rivet");
        assert_eq!(rivet["github_repo"], "pulseengine/rivet");
        assert_eq!(rivet["latest_version"], "0.32.0");
        let platforms = &rivet["versions"]["0.32.0"]["platforms"];
        assert_eq!(
            platforms["darwin_arm64"]["sha256"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            platforms["darwin_arm64"]["url_suffix"],
            "rivet-v0.32.0-aarch64-apple-darwin.tar.gz"
        );
        // sha256: prefix normalized to bare hex, per the rules schema.
        assert_eq!(
            platforms["linux_amd64"]["sha256"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        // Provenance header names the layer and forbids hand-editing.
        let header = rivet["_generated_by"].as_str().unwrap();
        assert!(header.contains("2026.08.1") && header.contains("Do not hand-edit"));
    }

    // rivet: verifies REQ-BAZEL-001
    #[test]
    fn a_tool_without_source_provenance_is_skipped_loudly() {
        let export = export(&manifest_with_sources());
        assert!(!export.registries.contains_key("wsc"));
        assert!(
            export
                .skipped
                .iter()
                .any(|(tool, _, reason)| tool == "wsc" && reason.contains("no source provenance")),
            "skips must be reported: {:?}",
            export.skipped
        );
    }

    // rivet: verifies REQ-BAZEL-001
    #[test]
    fn platform_keys_map_the_rules_vocabulary() {
        assert_eq!(
            bazel_platform_key("aarch64-apple-darwin"),
            Some("darwin_arm64")
        );
        assert_eq!(
            bazel_platform_key("x86_64-apple-darwin"),
            Some("darwin_amd64")
        );
        assert_eq!(
            bazel_platform_key("aarch64-unknown-linux-gnu"),
            Some("linux_arm64")
        );
        assert_eq!(
            bazel_platform_key("x86_64-unknown-linux-gnu"),
            Some("linux_amd64")
        );
        assert_eq!(
            bazel_platform_key("x86_64-pc-windows-msvc"),
            Some("windows_amd64")
        );
        assert_eq!(bazel_platform_key("wasm32-wasip2"), None);
    }
}
