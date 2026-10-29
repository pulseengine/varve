//! What a verified composition holds, as plain data.
//!
//! The ONE place `varve-core`'s composed layers are turned into what
//! `context` and `ask` talk about. It reads nothing but the signed manifests
//! and the store paths they name, after `main` has verified every layer, so
//! nothing here decides trust — it decides which entries are tools, which are
//! held, and where the cache goes.

use std::collections::{BTreeMap, BTreeSet};

use varve_core::compose::ComposedLayer;
use varve_core::docsexport::DocsPayload;
use varve_core::{LayerManifest, PayloadKind};

use crate::harvest::ToolSource;

/// The header of an orientation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub realm: String,
    pub layer: String,
    pub channel: String,
    /// The pinned layer's manifest digest: what `varve which` reports.
    pub manifest_digest: String,
}

/// A payload the store holds and PATH does not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub platforms: Vec<String>,
}

/// A docs payload with what the manifest signed about it.
#[derive(Debug, Clone)]
pub struct DocsSource {
    pub payload: DocsPayload,
    /// The payload digest from the signed manifest.
    pub digest: String,
    pub layer: String,
    pub realm: String,
}

#[derive(Debug, Clone)]
pub struct Pinned {
    pub facts: Facts,
    pub tools: Vec<ToolSource>,
    pub held: Vec<Held>,
    pub docs: Vec<DocsSource>,
}

/// Add a tool unless the same name with the same signed digest is already
/// there: one binary offered by two layers of a composition is one tool, while
/// the same name with different bytes is two, and `context` shows both.
fn add_tool(tools: &mut Vec<ToolSource>, new: ToolSource) {
    if !tools
        .iter()
        .any(|t| t.name == new.name && t.digest == new.digest)
    {
        tools.push(new);
    }
}

fn cache_file(l: &ComposedLayer) -> std::path::PathBuf {
    l.store
        .root()
        .join("cache")
        .join("agent-context")
        .join(format!("{}.json", l.entry.digest.replace(':', "-")))
}

fn manifest_of(l: &ComposedLayer) -> anyhow::Result<LayerManifest> {
    let bytes = std::fs::read(l.entry.root.join("layer.json"))?;
    Ok(LayerManifest::parse(&bytes)?)
}

/// Every docs payload of the composition, verified against its signed digest.
pub fn docs_sources(layers: &[ComposedLayer], platform: &str) -> anyhow::Result<Vec<DocsSource>> {
    let mut out = Vec::new();
    for p in varve_core::compose::payloads_of(layers, PayloadKind::Docs, platform)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
    {
        out.push(DocsSource {
            digest: p.digest.clone(),
            layer: p.layer.clone(),
            realm: p.realm.clone(),
            payload: DocsPayload::from_signed(&p.annotations, p.bytes)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        });
    }
    Ok(out)
}

/// Read the composition. `layers` must already be verified, pinned layer
/// first (`walk_installed` returns them so).
pub fn pinned(layers: &[ComposedLayer], platform: &str) -> anyhow::Result<Pinned> {
    let head = layers
        .first()
        .ok_or_else(|| anyhow::anyhow!("the composition has no layers"))?;
    let facts = Facts {
        realm: head.realm.clone(),
        layer: head.entry.layer.to_string(),
        channel: head.entry.channel.clone(),
        manifest_digest: head.entry.digest.clone(),
    };
    let mut tools: Vec<ToolSource> = Vec::new();
    let mut held: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for l in layers {
        for e in &manifest_of(l)?.entries {
            let name = e
                .annotations
                .get("eu.pulseengine.tool")
                .cloned()
                .unwrap_or_else(|| "(unnamed entry)".into());
            let version = varve_core::store::entry_version(e)
                .unwrap_or("-")
                .to_string();
            let platform_ann = e
                .annotations
                .get(varve_core::platform::ANN_PLATFORM)
                .map(String::as_str);
            let kind = match e.kind() {
                Ok(PayloadKind::Layer) => continue,
                Ok(PayloadKind::Tool) => {
                    if varve_core::platform::entry_matches(platform_ann, platform) {
                        add_tool(
                            &mut tools,
                            ToolSource {
                                name,
                                version,
                                realm: l.realm.clone(),
                                layer: l.entry.layer.to_string(),
                                layer_digest: l.entry.digest.clone(),
                                digest: e.digest.clone(),
                                path: l.store.entry_path(&l.entry, e),
                                cache_file: Some(cache_file(l)),
                            },
                        );
                    }
                    continue;
                }
                Ok(k) => k.as_str().to_string(),
                Err(varve_core::UnknownKind(raw)) => raw,
            };
            held.entry((kind, name, version))
                .or_default()
                .insert(platform_ann.unwrap_or("any").to_string());
        }
    }
    tools.sort_by(|a, b| (&a.name, &a.layer, &a.digest).cmp(&(&b.name, &b.layer, &b.digest)));
    Ok(Pinned {
        facts,
        tools,
        held: held
            .into_iter()
            .map(|((kind, name, version), platforms)| Held {
                kind,
                name,
                version,
                platforms: platforms.into_iter().collect(),
            })
            .collect(),
        docs: docs_sources(layers, platform)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_core::PayloadKind;

    use crate::fixture;
    use fixture::*;

    /// Tools, held payloads and docs are told apart, the header is the pinned
    /// layer's, and the cache sits under the store keyed by the layer digest.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_composition_is_read_as_tools_held_payloads_and_docs() {
        let fx = install_layer(vec![
            script_tool("zeta", "1.0.0", "true"),
            script_tool("alpha", "2.0.0", "true"),
            held_tool("varve-core", "0.43.0", PayloadKind::Crate),
            held_tool("rivet-sdlc", "0.41.1", PayloadKind::Vsix),
            docs_tool(
                "varve-core-api",
                Some("varve-core"),
                &[("a/index.html", "x")],
            ),
        ]);
        let p = pinned(&fx.composed(), &varve_core::host_platform()).unwrap();
        assert_eq!(p.facts.layer, "2026.10.1");
        assert_eq!(p.facts.channel, "rolling");
        assert_eq!(p.facts.realm, "(this project)");
        assert_eq!(p.facts.manifest_digest, fx.digest);
        let names: Vec<&str> = p.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["alpha", "zeta"], "tools, sorted, and only tools");
        assert_eq!(p.tools[0].version, "2.0.0");
        assert!(p.tools[0].path.as_ref().unwrap().is_file());
        assert!(p.tools[0].digest.starts_with("sha256:"));
        assert_eq!(
            p.tools[0].cache_file.as_ref().unwrap(),
            &fx.root
                .join("cache/agent-context")
                .join(format!("{}.json", fx.digest.replace(':', "-")))
        );
        let held: Vec<(&str, &str)> = p
            .held
            .iter()
            .map(|h| (h.kind.as_str(), h.name.as_str()))
            .collect();
        assert_eq!(
            held,
            [
                ("crate", "varve-core"),
                ("docs", "varve-core-api"),
                ("vsix", "rivet-sdlc")
            ]
        );
        assert_eq!(p.held[0].platforms, ["any"]);
        assert_eq!(p.docs.len(), 1);
        assert_eq!(p.docs[0].payload.name, "varve-core-api");
        assert_eq!(p.docs[0].layer, "2026.10.1");
        assert!(p.docs[0].digest.starts_with("sha256:"));
        assert_eq!(
            p.docs[0].digest,
            varve_core::store::manifest_digest(&p.docs[0].payload.bytes)
        );
    }

    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_tool_offered_twice_is_one_tool_and_different_bytes_are_two() {
        let t = |name: &str, digest: &str| ToolSource {
            name: name.into(),
            version: "1".into(),
            realm: "r".into(),
            layer: "l".into(),
            layer_digest: "sha256:l".into(),
            digest: digest.into(),
            path: None,
            cache_file: None,
        };
        let mut tools = Vec::new();
        add_tool(&mut tools, t("a", "sha256:1"));
        add_tool(&mut tools, t("a", "sha256:1"));
        assert_eq!(tools.len(), 1);
        add_tool(&mut tools, t("a", "sha256:2"));
        add_tool(&mut tools, t("b", "sha256:1"));
        assert_eq!(tools.len(), 3);
    }

    /// A tool for another platform is not on this host's PATH, and an empty
    /// composition is refused rather than invented.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn another_platforms_tool_is_not_listed_and_nothing_is_refused() {
        let mut other = script_tool("elsewhere", "1.0.0", "true");
        other.platform = Some("riscv64-unknown-linux-gnu".into());
        let fx = install_layer(vec![script_tool("here", "1.0.0", "true"), other]);
        let p = pinned(&fx.composed(), &varve_core::host_platform()).unwrap();
        assert_eq!(p.tools.len(), 1, "{:?}", p.tools);
        assert!(pinned(&[], "x").is_err());
    }
}
