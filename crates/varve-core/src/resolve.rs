//! Resolution — pin + core → exactly one layer, or a loud failure.
//!
//! The load-bearing rule (REQ-PIN-001): a pinned layer resolves *exactly*, or
//! the command fails with the corrective install command. There is no fallback
//! layer, no PATH fall-through, no "close enough" — the error type has no
//! variant for any of those, so the fallback cannot be written.
//!
//! And the constraint behind it (REQ-NOUPDATE-001): resolution is a pure
//! function of (pin, store). Nothing here consults "latest", the network, or
//! the environment; laying a newer layer down cannot change what an existing
//! pin resolves to.

use std::path::PathBuf;

use crate::pin::Pin;
use crate::store::{InstalledLayer, Store, StoreError};

/// A successful resolution: the one layer this pin selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub layer: InstalledLayer,
    /// The tools this pin exposes (the pin's `tools` subset, or every tool in
    /// the layer), each with its resolved binary path. Exactly one entry per
    /// NAME — that is what keeps one shim per name (REQ-REALM2-001 clause 4c).
    pub tools: Vec<(String, PathBuf)>,
    /// Every provider of every exposed name, including the ones a bare name
    /// does NOT dispatch to (REQ-REALM2-001 clause 4b). Addressable as
    /// `realm/tool`, so "compare our fork against upstream" keeps working
    /// instead of the unselected binary disappearing.
    pub qualified: Vec<(crate::compose::ToolProvider, PathBuf)>,
    /// Runner contracts (REQ-RUNNER-001): tool → (runner tool, prefix args,
    /// optional per-user-arg flag), from the signed manifest annotations.
    pub runners: std::collections::BTreeMap<String, RunnerContract>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerContract {
    pub tool: String,
    pub args: Vec<String>,
    pub arg_prefix: Option<String>,
}

/// Resolution failures. Every variant carries what the user must do next.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("layer {layer} is not installed — run `varve install` in this project to lay it down")]
    NotInstalled { layer: String },
    #[error(
        "pin digest {pinned} is not installed — run `varve install` in this project to lay it down"
    )]
    DigestNotInstalled { pinned: String },
    #[error(
        "pin names layer {named} but pins digest {pinned}, which is layer {found} — the name is a label, the digest is the artifact; refusing to guess. Fix the pin."
    )]
    NameDigestMismatch {
        named: String,
        pinned: String,
        found: String,
    },
    #[error(
        "layer {layer} is installed more than once under different digests ({count} entries) and the pin carries no digest to disambiguate — add `digest = \"sha256:…\"` to the pin"
    )]
    Ambiguous { layer: String, count: usize },
    #[error(
        "layer {layer} is installed but incomplete: missing {missing:?} — run `varve install` to repair it; refusing to fall back to PATH"
    )]
    PartialLayer { layer: String, missing: Vec<String> },
    #[error(
        "this project's pin restricts `tools` to {missing:?}, which layer {layer} does not \
         contain. It exposes: {available}. Re-installing cannot help — the layer is complete, \
         the pin asks for something that was never in it. Fix the `tools` list in varve.toml, \
         or drop it to expose everything the layer carries."
    )]
    PinNamesUnknownTool {
        layer: String,
        missing: Vec<String>,
        available: String,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(
        "layer {layer} is installed on channel '{installed}', but this project's pin selects \
         '{pinned}' — refusing. A qualified line carries a support window and qualification \
         evidence; a rolling one carries neither. Install the {pinned} layer, or change the \
         pin deliberately."
    )]
    ChannelMismatch {
        layer: String,
        installed: String,
        pinned: String,
    },
    #[error(transparent)]
    Compose(#[from] crate::compose::ComposeError),
    #[error(
        "layer {layer} composes layer {missing}{realm}, which is not installed — \
         `varve install` it, then retry"
    )]
    IncludeNotInstalled {
        layer: String,
        missing: String,
        realm: String,
    },
}

/// Resolve a pin against the local core. Pure: consults nothing but its
/// arguments.
pub fn resolve(pin: &Pin, store: &Store) -> Result<Resolved, ResolveError> {
    let layer = match &pin.digest {
        Some(digest) => {
            let entry = store
                .get(digest)?
                .ok_or_else(|| ResolveError::DigestNotInstalled {
                    pinned: digest.clone(),
                })?;
            if entry.layer != pin.layer {
                return Err(ResolveError::NameDigestMismatch {
                    named: pin.layer.to_string(),
                    pinned: digest.clone(),
                    found: entry.layer.to_string(),
                });
            }
            entry
        }
        None => {
            let matching: Vec<InstalledLayer> = store
                .list()?
                .into_iter()
                .filter(|entry| entry.layer == pin.layer)
                .collect();
            match matching.len() {
                0 => {
                    return Err(ResolveError::NotInstalled {
                        layer: pin.layer.to_string(),
                    });
                }
                1 => matching.into_iter().next().expect("len checked"),
                count => {
                    return Err(ResolveError::Ambiguous {
                        layer: pin.layer.to_string(),
                        count,
                    });
                }
            }
        }
    };

    // The pin's channel is part of the pin. `install` refuses a mismatched
    // fetch, but nothing re-checked an ALREADY-INSTALLED layer, so editing a
    // pin from `rolling` to `qualified` left `which`, `verify` and `run`
    // happily resolving the rolling layer — a silent fallback in the one
    // distinction varve exists to make, and the opposite of what the docs
    // promise ("a pin resolves exactly or the command fails").
    if !layer.channel.is_empty() && layer.channel != pin.channel.as_str() {
        return Err(ResolveError::ChannelMismatch {
            layer: layer.layer.to_string(),
            installed: layer.channel.clone(),
            pinned: pin.channel.as_str().to_string(),
        });
    }

    // Composition first (REQ-COMPOSE-001): a pin restricting `tools` may name a
    // tool that lives in an INCLUDED layer, so the composed set has to be known
    // before deciding what is missing. Resolving the root first reported
    // `PartialLayer` for a perfectly resolvable composed tool.
    let offers: Vec<Offer> = composition_offers(pin, &layer, store)?;

    // What the pin exposes, and where it has CHOSEN a realm for a name
    // (REQ-REALM2-001 clause 4a).
    let (tool_names, chosen) = exposed_and_chosen(pin, &offers);

    // The one decision: which provider a BARE name dispatches to. It is made
    // over every provider the composition has, then narrowed to what the pin
    // exposes — so a collision the pin never asked about cannot refuse a
    // command that does not touch it.
    let exposed: Vec<crate::compose::ToolProvider> = offers
        .iter()
        .filter(|o| tool_names.contains(&o.provider.tool))
        .map(|o| o.provider.clone())
        .collect();
    let dispatch = crate::compose::select_tools(&exposed, &chosen)?;

    let mut tools = Vec::new();
    let mut missing = Vec::new();
    for name in &tool_names {
        match dispatch
            .get(name)
            .and_then(|p| offers.iter().find(|o| o.provider == *p))
            .and_then(|o| o.path.clone())
        {
            Some(path) => tools.push((name.clone(), path)),
            None => missing.push(name.clone()),
        }
    }
    if !missing.is_empty() {
        // A pin restricting `tools` to a name the layer never carried is NOT an
        // incomplete install, and telling the user to re-install is a fix that
        // cannot work: install succeeds, changes nothing, and the same error
        // returns. A ten-persona audit graded this the one true dead end in the
        // tool — the only error whose stated remedy provably fails.
        if pin.tools.is_some() {
            let mut available: Vec<String> = store
                .manifest_tool_names(&layer)
                .unwrap_or_default()
                .into_iter()
                .chain(offers.iter().map(|o| o.provider.tool.clone()))
                .collect();
            available.sort();
            available.dedup();
            let unknown: Vec<String> = missing
                .iter()
                .filter(|m| !available.contains(m))
                .cloned()
                .collect();
            if !unknown.is_empty() {
                return Err(ResolveError::PinNamesUnknownTool {
                    layer: layer.layer.to_string(),
                    missing: unknown,
                    available: if available.is_empty() {
                        "(nothing)".into()
                    } else {
                        available.join(", ")
                    },
                });
            }
        }
        return Err(ResolveError::PartialLayer {
            layer: layer.layer.to_string(),
            missing,
        });
    }

    // Clause 4b: every provider of an exposed name stays addressable, chosen
    // or not. Losing the binary the pin did not pick would be a worse answer
    // than the refusal this feature replaces.
    let qualified: Vec<(crate::compose::ToolProvider, PathBuf)> = offers
        .iter()
        .filter(|o| tool_names.contains(&o.provider.tool))
        .filter_map(|o| o.path.clone().map(|p| (o.provider.clone(), p)))
        .collect();

    // Runner contracts from the stored manifest's entry annotations —
    // lenient read: legacy layers without them simply have none.
    let mut runners = std::collections::BTreeMap::new();
    if let Ok(bytes) = std::fs::read(layer.root.join("layer.json"))
        && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(entries) = json["manifests"].as_array()
    {
        for entry in entries {
            let ann = &entry["annotations"];
            if let (Some(tool), Some(runner)) = (
                ann["eu.pulseengine.tool"].as_str(),
                ann[crate::bazel::ANN_RUNNER].as_str(),
            ) {
                runners.insert(
                    tool.to_string(),
                    RunnerContract {
                        tool: runner.to_string(),
                        args: ann[crate::bazel::ANN_RUNNER_ARGS]
                            .as_str()
                            .map(|a| a.split_whitespace().map(str::to_string).collect())
                            .unwrap_or_default(),
                        arg_prefix: ann[crate::bazel::ANN_RUNNER_ARG_PREFIX]
                            .as_str()
                            .map(str::to_string),
                    },
                );
            }
        }
    }
    Ok(Resolved {
        layer,
        tools,
        qualified,
        runners,
    })
}

/// The names a pin exposes, and the realm it CHOSE for each name it qualified
/// (REQ-REALM2-001 clause 4a).
///
/// A pin with no `tools` exposes the whole composition and chooses nothing —
/// which is why an unchosen collision still refuses. A pin with `tools`
/// exposes exactly those names, in the order written, and every qualified
/// entry records its realm.
fn exposed_and_chosen(
    pin: &Pin,
    offers: &[Offer],
) -> (Vec<String>, std::collections::BTreeMap<String, String>) {
    let Some(subset) = &pin.tools else {
        let mut names: Vec<String> = offers.iter().map(|o| o.provider.tool.clone()).collect();
        names.sort();
        names.dedup();
        return (names, std::collections::BTreeMap::new());
    };
    let mut names = Vec::with_capacity(subset.len());
    let mut chosen = std::collections::BTreeMap::new();
    for selector in subset {
        names.push(selector.name.clone());
        if let Some(realm) = &selector.realm {
            chosen.insert(selector.name.clone(), realm.clone());
        }
    }
    (names, chosen)
}

/// One layer of a composition offering one dispatchable name, and where that
/// name's bytes are — `None` when the manifest declares a tool whose file is
/// not on disk, which is an incomplete install rather than a missing tool.
#[derive(Debug, Clone)]
struct Offer {
    provider: crate::compose::ToolProvider,
    path: Option<PathBuf>,
}

/// Every dispatchable name the pinned layer's COMPOSITION offers — the root's
/// own and every included layer's — each labelled with the realm whose root
/// vouches for it. Included layers must already be installed; fetching them
/// transitively is deliberately out of scope for v0.23.0 (REQ-COMPOSE-001), so
/// a missing one is an error naming it and its corrective install.
///
/// A name is offered if the SIGNED manifest declares it or a file of that name
/// sits in the layer's `bin/` — but only if SOME layer of the composition has
/// it on disk. All three parts earn their place:
///
/// * `bin/` alone would let a corrupt install decide dispatch: a root whose
///   declared `wasm-tools` failed to land would silently hand the bare name to
///   an included layer, which is exactly the install-state-dependent choice
///   clause 4c forbids. Reading the signed manifest keeps that a refusal.
/// * the manifest alone over-reports: a layer's manifest declares a tool for
///   EVERY platform it ships, and a tool absent for this host (loom ships no
///   aarch64-apple-darwin) would become an exposed name nothing can resolve.
/// * so a name no layer has on disk is dropped: on this host it is not a
///   collision and not a dispatchable name, it is simply not here.
fn composition_offers(
    pin: &Pin,
    layer: &InstalledLayer,
    store: &Store,
) -> Result<Vec<Offer>, ResolveError> {
    let root_realm = pin.realm.clone().unwrap_or_default();
    let path = layer.root.join("layer.json");
    let root_view = match std::fs::read(&path) {
        // A manifest we cannot read is an ERROR, not an empty composition —
        // an earlier version returned Ok(empty) here and silently resolved a
        // composed layer to none of its included tools.
        Ok(bytes) => crate::compose::view(&bytes)?,
        // No stored manifest at all: a pre-composition layer laid down by an
        // older varve. Nothing to compose, and nothing hidden.
        Err(_) => crate::compose::LayerView::default(),
    };
    // Every declared include must already be installed. Fetching transitively
    // is deliberately out of scope (REQ-COMPOSE-001), so name it and its fix.
    for inc in &root_view.includes {
        // Look across partitions: a cross-realm include lives under the
        // INCLUDED realm's fingerprint (REQ-STORE-001).
        if store.find_anywhere(&inc.digest)?.is_none() {
            return Err(ResolveError::IncludeNotInstalled {
                layer: layer.layer.to_string(),
                missing: inc.layer.clone().unwrap_or_else(|| inc.digest.clone()),
                realm: inc
                    .realm
                    .as_ref()
                    .map(|r| format!(" from realm '{r}'"))
                    .unwrap_or_default(),
            });
        }
    }
    let walked = crate::compose::walk(&layer.digest, &root_realm, &root_view, |digest| {
        let (_, entry) = store.find_anywhere(digest).ok().flatten()?;
        let bytes = std::fs::read(entry.root.join("layer.json")).ok()?;
        crate::compose::view(&bytes).ok()
    })?;

    let mut out = Vec::new();
    for step in &walked {
        // The root is already in hand; an included layer is looked up wherever
        // its realm partitioned it.
        let (owner, entry) = if step.digest == layer.digest {
            (store.clone(), layer.clone())
        } else {
            match store.find_anywhere(&step.digest)? {
                Some(found) => found,
                None => continue,
            }
        };
        let mut names: Vec<String> = step.view.tools.clone();
        if let Ok(rd) = std::fs::read_dir(entry.root.join("bin")) {
            names.extend(
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .map(|e| e.file_name().to_string_lossy().into_owned()),
            );
        }
        names.sort();
        names.dedup();
        for name in names {
            out.push(Offer {
                path: owner.tool_path(&entry, &name),
                provider: crate::compose::ToolProvider {
                    tool: name,
                    realm: step.realm.clone(),
                    layer: entry.layer.to_string(),
                    digest: step.digest.clone(),
                },
            });
        }
    }
    // Drop names no layer of this composition actually has on this host. A
    // manifest declares a tool for every platform the layer ships, so without
    // this an unrestricted pin would expose `loom` on a machine whose platform
    // that release skipped and then refuse to resolve it.
    let on_disk: std::collections::BTreeSet<String> = out
        .iter()
        .filter(|o| o.path.is_some())
        .map(|o| o.provider.tool.clone())
        .collect();
    out.retain(|o| on_disk.contains(&o.provider.tool));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::Pin;
    use crate::store::{Store, fixtures, manifest_digest};

    fn pin(toml: &str) -> Pin {
        Pin::parse(toml, "varve.toml").unwrap()
    }

    fn qualified_pin(layer: &str) -> Pin {
        pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
        ))
    }

    fn store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("varve-root"));
        (tmp, store)
    }

    /// A manifest that composes another layer by digest.
    fn manifest_composing(layer: &str, tools: &[&str], include: &str) -> Vec<u8> {
        let mut entries: Vec<String> = tools
            .iter()
            .map(|t| {
                format!(
                    r#"{{"digest":"sha256:{t}","annotations":{{"eu.pulseengine.tool":"{t}"}}}}"#
                )
            })
            .collect();
        entries.push(format!(
            r#"{{"digest":"{include}","annotations":{{"eu.pulseengine.varve.kind":"layer"}}}}"#
        ));
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"qualified"}},"manifests":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    // rivet: verifies REQ-CHANNEL-001
    #[test]
    fn a_pin_selecting_qualified_refuses_an_installed_rolling_layer() {
        // THE distinction varve exists to make. `install` refused a mismatched
        // FETCH, but nothing re-checked an already-installed layer — so editing
        // a pin from rolling to qualified left which/verify/run resolving the
        // rolling layer and reporting success. A safety-critical consumer would
        // have pinned `qualified` and silently received an unqualified
        // toolchain, with verify saying OK.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "rolling"),
                &[("synth", b"s")],
            )
            .unwrap();
        let err = resolve(&qualified_pin("2026.07.0"), &store).unwrap_err();
        match err {
            ResolveError::ChannelMismatch {
                installed, pinned, ..
            } => {
                assert_eq!(installed, "rolling");
                assert_eq!(pinned, "qualified");
            }
            other => panic!("expected ChannelMismatch, got {other}"),
        }
    }

    // rivet: verifies REQ-CHANNEL-001
    #[test]
    fn a_matching_channel_still_resolves() {
        // The guard must not break the ordinary case.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("synth", b"s")],
            )
            .unwrap();
        assert!(resolve(&qualified_pin("2026.07.0"), &store).is_ok());
    }

    // rivet: verifies REQ-CHANNEL-001
    #[test]
    fn the_channel_refusal_names_both_channels_and_what_they_cost() {
        // An independent review replaced the whole #[error(...)] with the text
        // "channel mismatch" and the entire workspace suite stayed GREEN: the
        // existing tests assert the struct's FIELDS and never render the
        // message a user actually reads. The clause is that the error names
        // both channels AND what each means, so the test renders it.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "rolling"),
                &[("synth", b"s")],
            )
            .unwrap();
        let msg = resolve(&qualified_pin("2026.07.0"), &store)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("rolling"), "names what is installed: {msg}");
        assert!(msg.contains("qualified"), "names what is pinned: {msg}");
        // …and why the difference is the point, not a label mismatch.
        assert!(
            msg.contains("support window"),
            "says what qualified carries: {msg}"
        );
        assert!(
            msg.contains("qualification evidence"),
            "says what rolling lacks: {msg}"
        );
    }

    // rivet: verifies REQ-CHANNEL-001
    #[test]
    fn a_layer_predating_channel_annotations_is_not_refused() {
        // Deleting `!layer.channel.is_empty() &&` from the guard left the whole
        // suite green, because every fixture in the workspace writes a channel.
        // Without the exemption, every layer deposited before channels existed
        // becomes unresolvable — a silent break of installed toolchains.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest_without_channel("2026.07.0"),
                &[("synth", b"s")],
            )
            .unwrap();
        let resolved = resolve(&qualified_pin("2026.07.0"), &store);
        assert!(
            resolved.is_ok(),
            "a layer that states no channel contradicts no pin: {:?}",
            resolved.err()
        );
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn resolve_returns_the_composed_layers_tools() {
        // The unit-level guard on composition. Mutation testing kills with
        // `--workspace --lib`, so the CLI integration tests cannot protect this
        // — `compose_tools -> Ok(vec![])` survived until this existed, meaning
        // nothing noticed a composition silently resolving to nothing.
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("wasm-tools", b"w")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.07.0", &["rivet"], &up),
                &[("rivet", b"r")],
            )
            .unwrap();
        let resolved = resolve(&qualified_pin("2026.07.0"), &store).unwrap();
        let names: Vec<&str> = resolved.tools.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"rivet"), "own tool missing: {names:?}");
        assert!(
            names.contains(&"wasm-tools"),
            "composed tool missing — the composition resolved to nothing: {names:?}"
        );
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn resolve_refuses_a_tool_exposed_by_both_layers() {
        // Kills the `n == &name` -> `!=` mutant: with the comparison inverted,
        // the duplicate would slip through instead of being refused.
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("wasm-tools", b"u")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.07.0", &["wasm-tools"], &up),
                &[("wasm-tools", b"r")],
            )
            .unwrap();
        let err = resolve(&qualified_pin("2026.07.0"), &store).unwrap_err();
        assert!(
            matches!(err, ResolveError::Compose(_)),
            "a tool in two layers must be refused, got {err}"
        );
    }

    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_pin_restricting_tools_also_restricts_the_composition() {
        // Kills the `!subset.contains(..)` -> `subset.contains(..)` mutant:
        // inverted, the pin would admit exactly the tools it excluded.
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("wasm-tools", b"w"), ("wkg", b"k")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.07.0", &["rivet"], &up),
                &[("rivet", b"r")],
            )
            .unwrap();
        let pinned = pin(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"rivet\", \"wasm-tools\"]\n",
        );
        let resolved = resolve(&pinned, &store).unwrap();
        let names: Vec<&str> = resolved.tools.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"wasm-tools"),
            "selected composed tool: {names:?}"
        );
        assert!(
            !names.contains(&"wkg"),
            "the pin did not select wkg, so the composition must not add it: {names:?}"
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn resolves_the_pinned_layer_by_name() {
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("synth", b"s"), ("rivet", b"r")],
            )
            .unwrap();
        let resolved = resolve(&qualified_pin("2026.07.0"), &store).unwrap();
        assert_eq!(resolved.layer.layer.to_string(), "2026.07.0");
        let names: Vec<&str> = resolved.tools.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["rivet", "synth"], "all tools, stable order");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn missing_layer_fails_with_the_corrective_command() {
        let (_tmp, store) = store();
        let err = resolve(&qualified_pin("2026.07.0"), &store).unwrap_err();
        assert!(matches!(&err, ResolveError::NotInstalled { layer } if layer == "2026.07.0"));
        assert!(
            err.to_string().contains("varve install"),
            "error must carry the fix: {err}"
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn partial_layer_is_an_error_not_a_fallback() {
        // The layer's MANIFEST declares both tools; only one was laid down.
        // That is a genuinely incomplete install, and re-installing is the
        // right advice. The fixture must declare them, or this case cannot be
        // told apart from the one below.
        let (_tmp, store) = store();
        store
            .lay_down(
                &crate::manifest::fixtures::manifest_with_tools(
                    "2026.07.0",
                    "qualified",
                    1,
                    "2026-07-01T00:00:00Z",
                    &[("rivet", "sha256:aa"), ("synth", "sha256:bb")],
                ),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = pin(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"rivet\", \"synth\"]\n",
        );
        match resolve(&p, &store).unwrap_err() {
            ResolveError::PartialLayer { missing, .. } => {
                assert_eq!(missing, vec!["synth".to_string()]);
            }
            other => panic!("expected PartialLayer, got: {other}"),
        }
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn a_pin_naming_a_tool_the_layer_never_had_is_not_told_to_reinstall() {
        // A ten-persona audit graded this the ONE true dead end in the tool:
        // `tools = ["notathing"]` produced "run `varve install` to repair it",
        // install succeeded and changed nothing, and the same error returned.
        // A fix that provably cannot work is worse than no advice, because the
        // user doubts their machine rather than their pin.
        let (_tmp, store) = store();
        store
            .lay_down(
                &crate::manifest::fixtures::manifest_with_tools(
                    "2026.07.0",
                    "qualified",
                    1,
                    "2026-07-01T00:00:00Z",
                    &[("rivet", "sha256:aa")],
                ),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = pin(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"notathing\"]\n",
        );
        match resolve(&p, &store).unwrap_err() {
            ResolveError::PinNamesUnknownTool {
                missing, available, ..
            } => {
                assert_eq!(missing, vec!["notathing".to_string()]);
                assert!(
                    available.contains("rivet"),
                    "names what IS there: {available}"
                );
            }
            other => panic!("expected PinNamesUnknownTool, got: {other}"),
        }
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn pinned_digest_wins_and_a_mismatching_name_is_a_hard_failure() {
        let (_tmp, store) = store();
        let july = fixtures::manifest("2026.07.0", "qualified");
        store.lay_down(&july, &[("synth", b"s")]).unwrap();
        let d_july = manifest_digest(&july);

        // Pin says layer 2026.08.0 but pins July's digest: refuse loudly.
        let hex = d_july.strip_prefix("sha256:").unwrap();
        let p = pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.08.0\"\ndigest = \"sha256:{hex}\"\n"
        ));
        let err = resolve(&p, &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::NameDigestMismatch { named, found, .. }
                if named == "2026.08.0" && found == "2026.07.0"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn matching_digest_pin_resolves() {
        let (_tmp, store) = store();
        let july = fixtures::manifest("2026.07.0", "qualified");
        store.lay_down(&july, &[("synth", b"s")]).unwrap();
        let hex = manifest_digest(&july)
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        let p = pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ndigest = \"sha256:{hex}\"\n"
        ));
        let resolved = resolve(&p, &store).unwrap();
        assert_eq!(resolved.layer.layer.to_string(), "2026.07.0");
    }

    // rivet: verifies REQ-NOUPDATE-001
    #[test]
    fn a_newer_layer_in_the_core_cannot_change_what_a_pin_resolves_to() {
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("synth", b"july")],
            )
            .unwrap();
        let p = qualified_pin("2026.07.0");
        let before = resolve(&p, &store).unwrap();

        // A newer layer arrives. The pin must not move.
        store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("synth", b"august")],
            )
            .unwrap();
        let after = resolve(&p, &store).unwrap();
        assert_eq!(
            before, after,
            "resolution is a pure function of (pin, store entry)"
        );
        assert_eq!(after.layer.layer.to_string(), "2026.07.0");
    }

    // rivet: verifies REQ-NOUPDATE-001
    #[test]
    fn ambiguous_name_fails_closed_instead_of_choosing() {
        let (_tmp, store) = store();
        // Same layer name, two different manifests (e.g. differing counters):
        // without a digest in the pin, refusing is the only honest answer.
        let a = fixtures::manifest("2026.07.0", "qualified");
        let mut b = a.clone();
        b.extend_from_slice(b"\n");
        store.lay_down(&a, &[]).unwrap();
        store.lay_down(&b, &[]).unwrap();
        let err = resolve(&qualified_pin("2026.07.0"), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::Ambiguous { count: 2, .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-SCOPE-001
    #[test]
    fn resolution_and_listing_never_write_to_the_core() {
        fn tree_snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
            let mut out = Vec::new();
            if !root.exists() {
                return out;
            }
            let mut stack = vec![root.to_path_buf()];
            while let Some(dir) = stack.pop() {
                let mut entries: Vec<_> = std::fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect();
                entries.sort();
                for path in entries {
                    if path.is_dir() {
                        stack.push(path);
                    } else {
                        out.push((path.display().to_string(), std::fs::read(&path).unwrap()));
                    }
                }
            }
            out.sort();
            out
        }

        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("synth", b"s")],
            )
            .unwrap();
        let before = tree_snapshot(store.root());
        let _ = resolve(&qualified_pin("2026.07.0"), &store).unwrap();
        let _ = store.list().unwrap();
        let _ = resolve(&qualified_pin("2026.09.0"), &store).unwrap_err();
        let after = tree_snapshot(store.root());
        assert_eq!(
            before, after,
            "select/verify/report must never mutate the core"
        );
    }

    // rivet: verifies REQ-REALM2-001
    #[test]
    fn a_tool_the_manifest_declares_for_other_platforms_is_not_exposed_here() {
        // A layer's manifest declares a tool for EVERY platform it ships. loom
        // ships no aarch64-apple-darwin, so on that host the name is declared
        // and no file lands. Exposing it would make an unrestricted pin refuse
        // to resolve at all — caught by the two-realm system gate, where
        // `varve verify` failed with `missing ["loom"]` on a layer that had
        // deliberately omitted it.
        let (_tmp, store) = store();
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"2026.07.0","eu.pulseengine.varve.channel":"qualified"}},"manifests":[
{{"digest":"sha256:aa","annotations":{{"eu.pulseengine.tool":"rivet","eu.pulseengine.platform":"{here}"}}}},
{{"digest":"sha256:bb","annotations":{{"eu.pulseengine.tool":"loom","eu.pulseengine.platform":"some-other-triple"}}}}]}}"#,
            here = crate::platform::host_platform()
        );
        // Only `rivet` lands, exactly as the installer would place it.
        store
            .lay_down(manifest.as_bytes(), &[("rivet", b"r")])
            .unwrap();
        let resolved = resolve(&qualified_pin("2026.07.0"), &store).unwrap();
        let names: Vec<&str> = resolved.tools.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["rivet"], "loom is declared, not laid down here");
    }

    // rivet: verifies REQ-REALM2-001
    #[test]
    fn a_declared_tool_whose_bytes_are_missing_still_collides_with_a_composed_one() {
        // The other half of the same rule, and the reason it reads the SIGNED
        // manifest at all. If the root's `wasm-tools` failed to land, deciding
        // from `bin/` alone would hand the bare name to the included layer
        // without a word — dispatch chosen by install state, which is exactly
        // what clause 4c forbids. The composed layer HAS the name on disk, so
        // the collision is real and must still be refused.
        let (_tmp, store) = store();
        let up = manifest_composing("2026.08.0", &["wasm-tools"], "sha256:none");
        // Strip the include from the upstream layer: it is a leaf.
        let up = String::from_utf8(up).unwrap().replace(
            r#",{"digest":"sha256:none","annotations":{"eu.pulseengine.varve.kind":"layer"}}"#,
            "",
        );
        let up_digest = store
            .lay_down(up.as_bytes(), &[("wasm-tools", b"upstream")])
            .unwrap();
        // The root DECLARES wasm-tools and lays down only rivet.
        let root = manifest_composing("2026.07.0", &["wasm-tools", "rivet"], &up_digest);
        store.lay_down(&root, &[("rivet", b"r")]).unwrap();

        let err = resolve(&qualified_pin("2026.07.0"), &store).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("provided by more than one layer"),
            "a half-installed root must not silently yield the name: {msg}"
        );
    }
}
