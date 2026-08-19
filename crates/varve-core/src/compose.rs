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
    /// Boxed: six strings inline would make every `ComposeError` — and so
    /// every `ResolveError` — large enough to move on the happy path.
    #[error(transparent)]
    ConflictingPayload(#[from] Box<PayloadConflict>),
}

/// Two layers of one composition offering the same (name, version) as
/// different bytes (REQ-COMPOSEEXPORT-001 clause 2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "{name} {version} is offered by two layers in this composition with DIFFERENT bytes: \
     {first} has {first_digest}, {second} has {second_digest} — refusing to choose. \
     Two realms disagreeing about what one name-and-version IS cannot both be exported; \
     a name at different VERSIONS is legal and both export, but one (name, version) must \
     be one artifact. Re-deposit one of the layers against the other's bytes, or drop the \
     duplicate from the composition."
)]
pub struct PayloadConflict {
    pub name: String,
    pub version: String,
    pub first: String,
    pub first_digest: String,
    pub second: String,
    pub second_digest: String,
}

/// Where one payload of a composition came from and what it claims to be. The
/// identity the collision rule is stated over (REQ-COMPOSEEXPORT-001 clause 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadOrigin {
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` of the bytes, as the signed manifest records it.
    pub digest: String,
    /// The realm whose trust root vouched for the layer offering it, and the
    /// layer itself — both, because the error must name the realms that
    /// disagree, not merely the layers.
    pub realm: String,
    pub layer: String,
}

impl PayloadOrigin {
    /// How this payload is named in an error: realm first, since the realms
    /// are what disagree.
    fn describe(&self) -> String {
        format!("realm '{}' layer {}", self.realm, self.layer)
    }
}

/// Union the payloads every layer of a composition offers, applying the rule
/// that is NOT the tool rule (REQ-COMPOSEEXPORT-001 clause 2).
///
/// A tool name in two layers is ambiguous because dispatch must pick ONE
/// binary for a bare name — so `union_tools` refuses it. A payload is not
/// dispatched: it is placed in a registry keyed by (name, version), and two
/// versions of one crate are the ordinary case a lockfile requires. So:
///
/// * the same name at DIFFERENT versions — both export;
/// * the same name AND version with the SAME digest — one copy (a diamond
///   offers a shared base twice; that is agreement, not conflict);
/// * the same name AND version with DIFFERENT digests — an ERROR naming both
///   realms, because two realms then disagree about what those bytes are and
///   varve does not pick a winner.
///
/// Order is preserved (root layer first), so the export is a function of the
/// composition rather than of a map's iteration order.
pub fn union_payloads<T>(
    items: Vec<(PayloadOrigin, T)>,
) -> Result<Vec<(PayloadOrigin, T)>, ComposeError> {
    let mut first_seen: BTreeMap<(String, String), PayloadOrigin> = BTreeMap::new();
    let mut out = Vec::new();
    for (origin, payload) in items {
        let key = (origin.name.clone(), origin.version.clone());
        match first_seen.get(&key) {
            Some(first) if first.digest != origin.digest => {
                return Err(ComposeError::ConflictingPayload(Box::new(
                    PayloadConflict {
                        name: origin.name.clone(),
                        version: origin.version.clone(),
                        first: first.describe(),
                        first_digest: first.digest.clone(),
                        second: origin.describe(),
                        second_digest: origin.digest,
                    },
                )));
            }
            // Same bytes, offered twice: export one copy, not an error.
            Some(_) => continue,
            None => {
                first_seen.insert(key, origin.clone());
                out.push((origin, payload));
            }
        }
    }
    Ok(out)
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
    let mut out = vec![(root_digest.to_string(), root.clone())];
    let mut emitted: BTreeSet<String> = BTreeSet::new();
    emitted.insert(root_digest.to_string());
    // (digest, view, ancestors-on-this-path). A CYCLE is a digest reappearing
    // on its OWN path — not merely one seen before. An earlier version used a
    // global `seen`, which reported a DIAMOND (two layers sharing a base) as a
    // cycle, with a message falsely claiming the layer included itself. A
    // shared base is the most ordinary composition there is.
    let mut stack: Vec<(String, LayerView, BTreeSet<String>)> = vec![(
        root_digest.to_string(),
        root.clone(),
        BTreeSet::from([root_digest.to_string()]),
    )];
    while let Some((from, view, path)) = stack.pop() {
        if path.len() > MAX_DEPTH {
            return Err(ComposeError::TooDeep);
        }
        for inc in includes(&view) {
            if path.contains(&inc.digest) {
                return Err(ComposeError::Cycle {
                    digest: inc.digest.clone(),
                    via: from.clone(),
                });
            }
            let Some(child) = fetch(&inc.digest) else {
                // Not installed. The caller names it and how to fix it.
                continue;
            };
            // A layer reachable by two paths is walked once, not refused.
            if emitted.insert(inc.digest.clone()) {
                out.push((inc.digest.clone(), child.clone()));
            }
            let mut child_path = path.clone();
            child_path.insert(inc.digest.clone());
            stack.push((inc.digest.clone(), child, child_path));
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
    fn depth_is_bounded_so_a_long_chain_cannot_exhaust_the_walker() {
        // The bound is what keeps "refused" from meaning "followed until the
        // process aborts". Re-verification found `verify` recursing without it
        // and stack-overflowing on a self-referencing store entry; both walkers
        // are now bounded.
        let leaf = manifest("2026.08.0", &["leaf"], &[]);
        // A chain longer than MAX_DEPTH, each link including the next.
        let chain: Vec<LayerView> = (0..=MAX_DEPTH + 2)
            .map(|i| manifest("2026.08.0", &["t"], &[(&format!("sha256:{}", i + 1), "r")]))
            .collect();
        let err = walk("sha256:0", &chain[0], |d| {
            let n: usize = d.trim_start_matches("sha256:").parse().ok()?;
            chain.get(n).cloned().or_else(|| Some(leaf.clone()))
        })
        .unwrap_err();
        assert!(matches!(err, ComposeError::TooDeep), "got {err:?}");
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_diamond_is_walked_once_not_refused_as_a_cycle() {
        // A includes B and C; both include D. This terminates and is the most
        // ordinary composition shape there is — two layers sharing a base.
        // The first version reported it as a cycle, with a message claiming D
        // "includes itself". Found by clean-room review.
        let d = manifest("2026.08.0", &["base"], &[]);
        let b = manifest("2026.08.0", &["b"], &[("sha256:d", "r")]);
        let c = manifest("2026.08.0", &["c"], &[("sha256:d", "r")]);
        let a = manifest("2026.08.0", &["a"], &[("sha256:b", "r"), ("sha256:c", "r")]);
        let walked = walk("sha256:a", &a, |q| match q {
            "sha256:b" => Some(b.clone()),
            "sha256:c" => Some(c.clone()),
            "sha256:d" => Some(d.clone()),
            _ => None,
        })
        .unwrap();
        assert_eq!(walked.len(), 4, "A, B, C and D each once: {walked:?}");
        // …and the shared base's tool resolves exactly once, not ambiguously.
        let tools = union_tools(&walked).unwrap();
        assert_eq!(tools["base"], "sha256:d");
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

    /// One payload offered by a named realm.
    fn offered(realm: &str, name: &str, version: &str, digest: &str) -> (PayloadOrigin, ()) {
        (
            PayloadOrigin {
                name: name.into(),
                version: version.into(),
                digest: format!("sha256:{digest}"),
                realm: realm.into(),
                layer: "2026.08.0".into(),
            },
            (),
        )
    }

    // rivet: verifies REQ-COMPOSEEXPORT-001
    #[test]
    fn two_versions_of_one_crate_both_export() {
        // Clause 2: the collision rule is NOT the tool rule. `serde 1.0.200`
        // and `serde 1.0.210` are not ambiguous — a lockfile that names two
        // majors of one crate NEEDS both present to build offline, and varve's
        // own lockfile has 14 such names.
        let kept = union_payloads(vec![
            offered("pulseengine", "serde", "1.0.200", "aa"),
            offered("bytecodealliance", "serde", "1.0.210", "bb"),
        ])
        .unwrap();
        assert_eq!(kept.len(), 2);
        let mut vers: Vec<&str> = kept.iter().map(|(o, _)| o.version.as_str()).collect();
        vers.sort();
        assert_eq!(vers, ["1.0.200", "1.0.210"]);
    }

    // rivet: verifies REQ-COMPOSEEXPORT-001
    #[test]
    fn the_same_name_and_version_with_the_same_bytes_exports_once() {
        // A diamond: two layers each including the same base. Both offer the
        // same crate at the same digest — that is two realms AGREEING, and
        // exporting the bytes twice or refusing them both would be wrong.
        let kept = union_payloads(vec![
            offered("pulseengine", "cfg-if", "1.0.0", "aa"),
            offered("bytecodealliance", "cfg-if", "1.0.0", "aa"),
        ])
        .unwrap();
        assert_eq!(kept.len(), 1, "one copy of agreed bytes: {kept:?}");
        assert_eq!(kept[0].0.realm, "pulseengine", "the first offer wins");
    }

    // rivet: verifies REQ-COMPOSEEXPORT-001
    #[test]
    fn the_same_name_and_version_with_different_bytes_names_both_realms() {
        // Clause 2's error case. Two realms disagree about what `cfg-if 1.0.0`
        // IS; picking either would put bytes one realm never vouched for into
        // an export the consumer believes is verified. The message must name
        // BOTH realms, or the reader cannot tell which side to fix.
        let err = union_payloads(vec![
            offered("pulseengine", "cfg-if", "1.0.0", "aa"),
            offered("bytecodealliance", "cfg-if", "1.0.0", "bb"),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ComposeError::ConflictingPayload(_)), "{msg}");
        assert!(msg.contains("cfg-if") && msg.contains("1.0.0"), "{msg}");
        assert!(
            msg.contains("pulseengine") && msg.contains("bytecodealliance"),
            "both realms must be named: {msg}"
        );
        assert!(
            msg.contains("sha256:aa") && msg.contains("sha256:bb"),
            "both digests must be named: {msg}"
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
