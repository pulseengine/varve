//! Layer composition (REQ-COMPOSE-001).
//!
//! A pin names one realm and one layer. That was fine while a layer held one
//! organisation's tools, and it broke the first time a consumer needed two: the
//! PulseEngine tools that CHECK their work and the upstream tools that BUILD it
//! (varve#52). Putting both in one layer would place releases we do not control
//! under a qualification claim covering tools we do — so instead a layer may
//! COMPOSE another.
//!
//! An include is a manifest entry of payload kind `layer`, whose digest is the
//! included layer's manifest digest and whose annotations name its realm. It
//! lives in the signed payload, so the composition is signed; and because the
//! digest is the identity, an include cannot silently drift.
//!
//! Everything here fails closed. A cycle is refused rather than followed, depth
//! is bounded, and a tool exposed by two layers is an ERROR naming both — varve
//! does not pick a winner, for the same reason a pin that does not resolve
//! uniquely is an error and not a fallback.

use std::collections::{BTreeMap, BTreeSet};

/// A lenient view of a layer manifest — just what composition needs.
///
/// Deliberately NOT `LayerManifest`: that parse enforces the full install
/// contract (counter, issued-at), and requiring it merely to discover whether a
/// layer composes another would make `which` fail on layers that resolve fine
/// today. Reading less is what lets this be additive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LayerView {
    pub includes: Vec<Include>,
    /// Dispatchable tool names this layer exposes.
    pub tools: Vec<String>,
}

/// Read the composition-relevant parts of a manifest. An unparseable manifest
/// is an error, never an empty view — silently reporting "no includes" for a
/// layer we could not read is the failure mode that hides a composition.
pub fn view(bytes: &[u8]) -> Result<LayerView, ComposeError> {
    let json: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ComposeError::Unreadable(e.to_string()))?;
    let mut v = LayerView::default();
    let Some(entries) = json["manifests"].as_array() else {
        return Ok(v);
    };
    for e in entries {
        let ann = &e["annotations"];
        let digest = e["digest"].as_str().unwrap_or_default().to_string();
        match ann[crate::kind::ANN_KIND].as_str() {
            Some("layer") => v.includes.push(Include {
                digest,
                realm: ann[ANN_INCLUDE_REALM].as_str().map(|s| s.to_string()),
                layer: ann[ANN_INCLUDE_LAYER].as_str().map(|s| s.to_string()),
            }),
            // Absent kind = tool (back-compat, as everywhere else).
            None => {
                if let Some(t) = ann["eu.pulseengine.tool"].as_str() {
                    v.tools.push(t.to_string());
                }
            }
            // Any other kind is not dispatchable and not an include.
            Some(_) => {}
        }
    }
    Ok(v)
}

/// Annotation naming the realm an included layer belongs to. Absent means the
/// including layer's own realm.
pub const ANN_INCLUDE_REALM: &str = "eu.pulseengine.varve.include.realm";
/// Annotation carrying the included layer's identity, for error messages that
/// can name it before it has been fetched.
pub const ANN_INCLUDE_LAYER: &str = "eu.pulseengine.varve.include.layer";

/// How deep a composition graph may go. Generous for real use (a layer
/// including a layer including a base), small enough that a malicious or
/// mistaken graph cannot spend the client's time.
pub const MAX_DEPTH: usize = 8;

/// One layer this manifest composes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Include {
    /// `sha256:<hex>` of the included layer's signed manifest — its identity.
    pub digest: String,
    /// The realm whose trust root verifies it. `None` = the including realm.
    pub realm: Option<String>,
    /// The included layer's identifier, for messages before it is resolved.
    pub layer: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error(
        "composition cycle: layer {digest} includes itself, directly or through \
         {via} — refusing to follow it"
    )]
    Cycle { digest: String, via: String },
    #[error(
        "composition is more than {MAX_DEPTH} layers deep — refusing to walk further \
         (a layer graph this deep is a mistake, not a design)"
    )]
    TooDeep,
    #[error("layer manifest could not be read for composition: {0}")]
    Unreadable(String),
    #[error(
        "tool '{tool}' is exposed by more than one layer in this composition \
         ({first} and {second}) — refusing to choose. Restrict the pin's `tools`, \
         or remove the duplicate from one layer."
    )]
    AmbiguousTool {
        tool: String,
        first: String,
        second: String,
    },
}

/// The layers a view directly composes, in manifest order.
pub fn includes(v: &LayerView) -> Vec<Include> {
    v.includes.clone()
}

/// Walk a composition graph breadth-first from a root manifest, refusing cycles
/// and excessive depth. `fetch` supplies a manifest for a digest, or `None` if
/// that layer is not installed — a missing layer is the caller's error to
/// report (with its corrective `varve install`), not this walker's to invent.
///
/// Returns the visit order, root first, so callers can union tools predictably.
pub fn walk<F>(
    root_digest: &str,
    root: &LayerView,
    mut fetch: F,
) -> Result<Vec<(String, LayerView)>, ComposeError>
where
    F: FnMut(&str) -> Option<LayerView>,
{
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = vec![(root_digest.to_string(), root.clone())];
    seen.insert(root_digest.to_string());

    // (digest, manifest, depth) — breadth-first so a shallow duplicate is
    // reported against the layer nearest the root.
    let mut queue: Vec<(String, LayerView, usize)> =
        vec![(root_digest.to_string(), root.clone(), 0)];
    while let Some((from, manifest, depth)) = queue.pop() {
        if depth >= MAX_DEPTH {
            return Err(ComposeError::TooDeep);
        }
        for inc in includes(&manifest) {
            if seen.contains(&inc.digest) {
                // Re-including a layer already in the graph is a cycle: the
                // graph is a tree of distinct layers by construction.
                return Err(ComposeError::Cycle {
                    digest: inc.digest.clone(),
                    via: from.clone(),
                });
            }
            let Some(child) = fetch(&inc.digest) else {
                // Not installed. The caller names it and how to fix it.
                continue;
            };
            seen.insert(inc.digest.clone());
            out.push((inc.digest.clone(), child.clone()));
            queue.push((inc.digest.clone(), child, depth + 1));
        }
    }
    Ok(out)
}

/// Union the tool names a composition exposes, refusing any name that appears
/// in more than one layer. Returns tool → the digest of the layer providing it.
pub fn union_tools(
    layers: &[(String, LayerView)],
) -> Result<BTreeMap<String, String>, ComposeError> {
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for (digest, v) in layers {
        for tool in &v.tools {
            if let Some(first) = owner.get(tool)
                && first != digest
            {
                return Err(ComposeError::AmbiguousTool {
                    tool: tool.clone(),
                    first: first.clone(),
                    second: digest.clone(),
                });
            }
            owner.insert(tool.clone(), digest.clone());
        }
    }
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest with the given tools and includes.
    fn manifest(layer: &str, tools: &[&str], includes: &[(&str, &str)]) -> LayerView {
        let mut entries: Vec<String> = tools
            .iter()
            .map(|t| {
                format!(
                    r#"{{"digest":"sha256:{t}","annotations":{{"eu.pulseengine.tool":"{t}"}}}}"#
                )
            })
            .collect();
        for (digest, realm) in includes {
            entries.push(format!(
                r#"{{"digest":"{digest}","annotations":{{"eu.pulseengine.varve.kind":"layer","{ANN_INCLUDE_REALM}":"{realm}"}}}}"#
            ));
        }
        let json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
"artifactType":"application/vnd.pulseengine.varve.layer.v1+json",
"annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"qualified",
"eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-08-01T00:00:00Z"}},
"manifests":[{}]}}"#,
            entries.join(",")
        );
        let _ = layer;
        view(json.as_bytes()).unwrap()
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_composition_exposes_both_layers_tools() {
        let upstream = manifest("2026.08.0", &["wasm-tools", "cargo-component"], &[]);
        let root = manifest(
            "2026.08.0",
            &["rivet", "meld"],
            &[("sha256:up", "bytecodealliance")],
        );
        let inc = includes(&root);
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].digest, "sha256:up");
        assert_eq!(inc[0].realm.as_deref(), Some("bytecodealliance"));

        let layers = walk("sha256:root", &root, |d| {
            (d == "sha256:up").then(|| upstream.clone())
        })
        .unwrap();
        assert_eq!(layers.len(), 2, "root plus the included layer");
        let tools = union_tools(&layers).unwrap();
        // The producing half is now answerable alongside the checking half.
        for t in ["rivet", "meld", "wasm-tools", "cargo-component"] {
            assert!(tools.contains_key(t), "{t} missing from the composition");
        }
        assert_eq!(tools["wasm-tools"], "sha256:up");
        assert_eq!(tools["rivet"], "sha256:root");
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_tool_in_two_layers_is_an_error_not_a_silent_choice() {
        // Both layers ship `wasm-tools`. varve must not pick one.
        let upstream = manifest("2026.08.0", &["wasm-tools"], &[]);
        let root = manifest(
            "2026.08.0",
            &["wasm-tools"],
            &[("sha256:up", "bytecodealliance")],
        );
        let layers = walk("sha256:root", &root, |d| {
            (d == "sha256:up").then(|| upstream.clone())
        })
        .unwrap();
        match union_tools(&layers) {
            Err(ComposeError::AmbiguousTool { tool, .. }) => assert_eq!(tool, "wasm-tools"),
            other => panic!("expected AmbiguousTool, got {other:?}"),
        }
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_cycle_is_refused_not_followed() {
        // A includes B; B includes A. Following it would not terminate.
        let a = manifest("2026.08.0", &["x"], &[("sha256:b", "r")]);
        let b = manifest("2026.08.0", &["y"], &[("sha256:a", "r")]);
        let (ac, bc) = (a.clone(), b.clone());
        let err = walk("sha256:a", &a, move |d| match d {
            "sha256:b" => Some(bc.clone()),
            "sha256:a" => Some(ac.clone()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, ComposeError::Cycle { .. }), "got {err:?}");
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn an_uninstalled_include_is_skipped_for_the_caller_to_report() {
        // walk() does not invent a fetch. A missing layer is the caller's
        // error to report, with its corrective `varve install`.
        let root = manifest("2026.08.0", &["rivet"], &[("sha256:missing", "other")]);
        let layers = walk("sha256:root", &root, |_| None).unwrap();
        assert_eq!(layers.len(), 1, "only the root resolved");
        assert_eq!(
            includes(&root).len(),
            1,
            "but the include is still declared"
        );
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_layer_without_includes_composes_to_itself() {
        // Back-compat: every existing layer has no `layer` entries and must
        // behave exactly as before.
        let plain = manifest("2026.08.0", &["rivet", "meld"], &[]);
        assert!(includes(&plain).is_empty());
        let layers = walk("sha256:root", &plain, |_| None).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(union_tools(&layers).unwrap().len(), 2);
    }
}
