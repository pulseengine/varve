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
    /// Tools dispatched from ANOTHER verified layer of the realm
    /// (REQ-OVERRIDE-001, DD-043 (4)), sorted by tool. Each one's path is
    /// already what `tools` holds for that name. Non-empty means the
    /// toolchain is MIXED, and nothing may report it as `layer`.
    pub overrides: Vec<ResolvedOverride>,
}

/// One `[toolchain.override.<tool>]`, resolved: the source layer as installed
/// in the pin's own realm partition, and the binary dispatched for the tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOverride {
    pub tool: String,
    pub layer: InstalledLayer,
    pub path: PathBuf,
}

impl Resolved {
    /// Is any tool dispatched from a layer other than the pinned one's
    /// composition? (REQ-OVERRIDE-001 clause 3.)
    pub fn is_mixed(&self) -> bool {
        !self.overrides.is_empty()
    }

    /// The override an address names, bare (`synth`) or realm-qualified
    /// (`acme/synth`): every address of an overridden tool is that override.
    pub fn override_for(&self, address: &str) -> Option<&ResolvedOverride> {
        let bare = address.rsplit('/').next().unwrap_or(address);
        self.overrides.iter().find(|o| o.tool == bare)
    }

    /// The overrides as every report records them.
    pub fn recorded_overrides(&self) -> Vec<crate::overrides::RecordedOverride> {
        self.overrides
            .iter()
            .map(|o| crate::overrides::RecordedOverride {
                tool: o.tool.clone(),
                layer: o.layer.layer.to_string(),
                digest: o.layer.digest.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerContract {
    pub tool: String,
    pub args: Vec<String>,
    pub arg_prefix: Option<String>,
    /// The runner's binary, from the SAME verified layer as the tool it runs
    /// (REQ-RUNNER-001): the pinned composition's for a pinned tool, the
    /// override layer's for an overridden one. `None` where that layer set
    /// exposes no such runner — dispatch then refuses.
    pub path: Option<PathBuf>,
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
    #[error(
        "[toolchain.override.{tool}]: layer {layer} as pinned here does not provide '{tool}' \
         (it provides: {available}). An override REPLACES a tool the pin already has; it \
         cannot add one, or it would put on PATH a tool no reviewer pinned \
         (REQ-OVERRIDE-001 clause 4). For a tool no layer carries see `varve docs \
         passthrough`; to ship it, add it to a layer."
    )]
    OverrideNotInPin {
        tool: String,
        layer: String,
        available: String,
    },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} ({digest}) does not carry '{tool}' — it \
         carries: {available}. Name a layer that ships this tool."
    )]
    OverrideSourceLacksTool {
        tool: String,
        layer: String,
        digest: String,
        available: String,
    },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} ({digest}) is not installed — run `varve \
         install` in this project: it fetches the override layer from this pin's realm and \
         verifies it against the realm's trust root, exactly as it does the pinned layer"
    )]
    OverrideNotInstalled {
        tool: String,
        layer: String,
        digest: String,
    },
    #[error(
        "[toolchain.override.{tool}]: names layer {named} but its digest {digest} is layer \
         {found} — the name is a label, the digest is the artifact; refusing to guess. Fix \
         the override."
    )]
    OverrideNameDigestMismatch {
        tool: String,
        named: String,
        digest: String,
        found: String,
    },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} ({digest}) is installed only under another \
         realm's trust root, not this pin's. An override comes from the pin's own realm and is \
         verified against its root; another realm's word does not reach this toolchain."
    )]
    OverrideFromAnotherRealm {
        tool: String,
        layer: String,
        digest: String,
    },
    #[error(
        "cannot tell what the pinned layer carries ({why}), so no override can be checked \
         against it — refusing rather than guessing"
    )]
    CannotTellWhatThePinCarries { why: String },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} runs '{tool}' through the runner \
         '{runner}', which that layer does not carry — a runner comes from the same verified \
         layer as the tool it runs (REQ-RUNNER-001), never from the pin's. Name a layer that \
         carries both."
    )]
    OverrideRunnerMissing {
        tool: String,
        layer: String,
        runner: String,
    },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} is on channel '{installed}', but this \
         project's pin selects '{pinned}' — refusing. An override is held to the pin's channel \
         as the pinned layer is: a qualified line carries a support window and qualification \
         evidence, a rolling one neither."
    )]
    OverrideChannelMismatch {
        tool: String,
        layer: String,
        installed: String,
        pinned: String,
    },
    #[error(
        "[toolchain.override.{tool}]: layer {layer} ({digest}) was installed for {platform}, not \
         this machine ({host}) — its payloads were selected for that platform, so dispatching \
         them here would run another machine's binary. `varve install` it in this project on \
         this machine."
    )]
    OverrideForAnotherPlatform {
        tool: String,
        layer: String,
        digest: String,
        platform: String,
        host: String,
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
    let mut runners = runners_of(&layer);
    // A pinned tool's runner is the pinned composition's, decided BEFORE any
    // override replaces a path: overriding the runner itself must not change
    // what runs the pin's own tools.
    for contract in runners.values_mut() {
        contract.path = tools
            .iter()
            .find(|(name, _)| *name == contract.tool)
            .map(|(_, p)| p.clone());
    }
    let overrides = resolve_overrides(pin, &layer, store, &mut tools, &mut runners)?;
    // Every ADDRESS of an overridden tool reaches the override: its qualified
    // providers are replaced by one, the override layer in the pin's realm.
    // Leaving them would let `realm/tool` run the pinned binary under a pin
    // that overrides it (REQ-OVERRIDE-001).
    let mut qualified = qualified;
    for o in &overrides {
        qualified.retain(|(p, _)| p.tool != o.tool);
        qualified.push((
            crate::compose::ToolProvider {
                tool: o.tool.clone(),
                realm: pin.realm.clone().unwrap_or_default(),
                layer: o.layer.layer.to_string(),
                digest: o.layer.digest.clone(),
            },
            o.path.clone(),
        ));
    }
    Ok(Resolved {
        layer,
        tools,
        qualified,
        runners,
        overrides,
    })
}

/// The runner contracts (REQ-RUNNER-001) a layer's signed manifest declares,
/// per tool.
fn runners_of(layer: &InstalledLayer) -> std::collections::BTreeMap<String, RunnerContract> {
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
                        path: None,
                    },
                );
            }
        }
    }
    runners
}

/// The tool names a layer's signed manifest declares as DISPATCHABLE for
/// `platform`: dispatchable as the store decides it (`entry_is_dispatchable` —
/// no kind annotation is a tool, an unknown kind is not), and an entry whose
/// platform annotation `platform::entry_matches` the target. Read leniently,
/// like `compose::view`, so a manifest this varve stored is never re-judged.
fn dispatchable_names_of(entry: &InstalledLayer, platform: &str) -> Result<Vec<String>, String> {
    let path = entry.root.join("layer.json");
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    Ok(json["manifests"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|e| {
                    let ann = &e["annotations"];
                    let tool = match ann[crate::kind::ANN_KIND].as_str() {
                        None => true,
                        Some(kind) => kind
                            .parse::<crate::kind::PayloadKind>()
                            .is_ok_and(|k| k.is_dispatchable()),
                    };
                    tool && crate::platform::entry_matches(
                        ann[crate::platform::ANN_PLATFORM].as_str(),
                        platform,
                    )
                })
                .filter_map(|e| e["annotations"]["eu.pulseengine.tool"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

/// Every DISPATCHABLE tool name the pinned layer's composition declares in its
/// signed manifests for `platform` — the install's TARGET, which is what
/// `resolve` exposes on the machine that runs it.
///
/// An include that is not installed is SKIPPED here, as `compose::walk` skips
/// it (it cannot be read), not reported as "could not tell": the caller asks
/// this only after `install` has fetched the pinned layer's includes and
/// refused if any is missing. A layer that IS reached but whose manifest
/// cannot be read is an error, never "carries nothing".
fn dispatchable_tool_names(
    pin: &Pin,
    layer: &InstalledLayer,
    store: &Store,
    platform: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    let root_bytes = std::fs::read(layer.root.join("layer.json"))
        .map_err(|e| format!("cannot read the pinned layer's manifest: {e}"))?;
    let root_view = crate::compose::view(&root_bytes).map_err(|e| e.to_string())?;
    let walked = crate::compose::walk(
        &layer.digest,
        &pin.realm.clone().unwrap_or_default(),
        &root_view,
        |digest| {
            let (_, entry) = store.find_anywhere(digest).ok().flatten()?;
            let bytes = std::fs::read(entry.root.join("layer.json")).ok()?;
            crate::compose::view(&bytes).ok()
        },
    )
    .map_err(|e| e.to_string())?;
    let mut names = std::collections::BTreeSet::new();
    for step in &walked {
        let entry = if step.digest == layer.digest {
            layer.clone()
        } else {
            store
                .find_anywhere(&step.digest)
                .map_err(|e| e.to_string())?
                .map(|(_, entry)| entry)
                .ok_or_else(|| format!("included layer {} is not installed", step.digest))?
        };
        names.extend(dispatchable_names_of(&entry, platform)?);
    }
    Ok(names)
}

/// Clause 4 as `install` asks it BEFORE fetching any override layer, for the
/// install's TARGET `platform`: from the pin and what the pinned composition's
/// signed manifests declare as a dispatchable tool for that target — never
/// from what resolves on this host. `install --platform <other>` is not
/// refused for a pinned tool only this host lacks, and a tool the pinned layer
/// ships for some other platform only is not the pin's on this target. A
/// `tools` list narrows what the pin exposes. `resolve` repeats the exact,
/// host-side check (`overrides_in_pin`) before anything runs.
pub fn overrides_carried_by_pin(
    pin: &Pin,
    pinned: &InstalledLayer,
    store: &Store,
    platform: &str,
) -> Result<(), ResolveError> {
    // A tool the pin has: one the composition's signed manifests declare as
    // DISPATCHABLE, for some platform — a held payload's name (a crate) is not
    // a tool, and neither is a stray file — and, where the pin lists `tools`,
    // one it lists. A subset name the layer never carried is no tool either.
    let carried = dispatchable_tool_names(pin, pinned, store, platform)
        .map_err(|why| ResolveError::CannotTellWhatThePinCarries { why })?;
    let exposed: Vec<String> = match &pin.tools {
        Some(subset) => subset
            .iter()
            .map(|s| s.name.clone())
            .filter(|name| carried.contains(name))
            .collect(),
        None => carried.into_iter().collect(),
    };
    for o in &pin.overrides {
        if !exposed.contains(&o.tool) {
            return Err(ResolveError::OverrideNotInPin {
                tool: o.tool.clone(),
                layer: pinned.layer.to_string(),
                available: if exposed.is_empty() {
                    "nothing".into()
                } else {
                    exposed.join(", ")
                },
            });
        }
    }
    Ok(())
}

/// REQ-OVERRIDE-001 clause 4: every override names a tool the pinned layer,
/// as this pin exposes it, already provides — an override replaces, it never
/// adds. Decidable from the pin and the pinned layer alone, so `install` asks
/// it BEFORE fetching any override layer, and `resolve` before anything else.
/// `tools` is what the pin exposes (`Resolved::tools` of the pin without its
/// overrides).
pub fn overrides_in_pin(
    pin: &Pin,
    pinned: &InstalledLayer,
    tools: &[(String, PathBuf)],
) -> Result<(), ResolveError> {
    for o in &pin.overrides {
        if !tools.iter().any(|(name, _)| *name == o.tool) {
            let mut available: Vec<&str> = tools.iter().map(|(n, _)| n.as_str()).collect();
            available.sort();
            return Err(ResolveError::OverrideNotInPin {
                tool: o.tool.clone(),
                layer: pinned.layer.to_string(),
                available: if available.is_empty() {
                    "nothing".into()
                } else {
                    available.join(", ")
                },
            });
        }
    }
    Ok(())
}

/// Apply the pin's overrides (REQ-OVERRIDE-001, DD-043 (3) and (4)): each
/// replaces one EXPOSED tool's path with the binary of another layer installed
/// in this pin's own realm partition. Every refusal happens here, at resolve
/// time, so nothing is executed for a pin whose override cannot be honoured.
///
/// The source layer is looked up in `store` — this pin's partition — and
/// nowhere else: that is what "from the pin's realm, verified against its
/// root" means for an installed layer. One found only in another partition is
/// named as such rather than reported as missing.
fn resolve_overrides(
    pin: &Pin,
    pinned: &InstalledLayer,
    store: &Store,
    tools: &mut [(String, PathBuf)],
    runners: &mut std::collections::BTreeMap<String, RunnerContract>,
) -> Result<Vec<ResolvedOverride>, ResolveError> {
    // Clause 4 first, for every override: whether the pin has the tool does
    // not depend on whether any override layer is installed.
    overrides_in_pin(pin, pinned, tools)?;
    let mut out = Vec::with_capacity(pin.overrides.len());
    for o in &pin.overrides {
        let Some(slot) = tools.iter_mut().find(|(name, _)| *name == o.tool) else {
            continue;
        };
        let Some(source) = store.get(&o.digest)? else {
            if store.find_anywhere(&o.digest)?.is_some() {
                return Err(ResolveError::OverrideFromAnotherRealm {
                    tool: o.tool.clone(),
                    layer: o.layer.to_string(),
                    digest: o.digest.clone(),
                });
            }
            return Err(ResolveError::OverrideNotInstalled {
                tool: o.tool.clone(),
                layer: o.layer.to_string(),
                digest: o.digest.clone(),
            });
        };
        // Parity with the pinned entry where a consumer refuses one installed
        // for another platform (varve-serve): an override is refused here, at
        // resolve time, so EVERY consumer refuses it — dispatch, verify,
        // export, attestation and the viewer alike. A layer from before the
        // platform was recorded has none, and is taken as this host's, as
        // every layer is.
        let host = crate::platform::host_platform();
        if let Some(platform) = source.platform.as_deref()
            && platform != host
        {
            return Err(ResolveError::OverrideForAnotherPlatform {
                tool: o.tool.clone(),
                layer: source.layer.to_string(),
                digest: source.digest.clone(),
                platform: platform.to_string(),
                host,
            });
        }
        // The same channel rule the pinned layer obeys; a layer from before
        // channel annotations states none and contradicts no pin.
        if !source.channel.is_empty() && source.channel != pin.channel.as_str() {
            return Err(ResolveError::OverrideChannelMismatch {
                tool: o.tool.clone(),
                layer: source.layer.to_string(),
                installed: source.channel.clone(),
                pinned: pin.channel.as_str().to_string(),
            });
        }
        if source.layer != o.layer {
            return Err(ResolveError::OverrideNameDigestMismatch {
                tool: o.tool.clone(),
                named: o.layer.to_string(),
                digest: o.digest.clone(),
                found: source.layer.to_string(),
            });
        }
        // The tool must be one the override layer's SIGNED manifest declares
        // as dispatchable for this host — what `install` checked before laying
        // it down (`overrides::check_manifest`) — and its binary must be on
        // disk. A file in `bin/` alone is not a tool; a manifest this varve
        // cannot read declares nothing (fail closed).
        let declared = dispatchable_names_of(&source, &crate::platform::host_platform())
            .unwrap_or_default()
            .contains(&o.tool);
        let Some(path) = store.tool_path(&source, &o.tool).filter(|_| declared) else {
            let mut available = store.manifest_tool_names(&source).unwrap_or_default();
            available.sort();
            available.dedup();
            return Err(ResolveError::OverrideSourceLacksTool {
                tool: o.tool.clone(),
                layer: source.layer.to_string(),
                digest: source.digest.clone(),
                available: if available.is_empty() {
                    "nothing".into()
                } else {
                    available.join(", ")
                },
            });
        };
        slot.1 = path.clone();
        // A runner contract was signed with the bytes it runs: the pin's
        // contract for this tool goes, the source layer's (if any) applies.
        runners.remove(&o.tool);
        if let Some(mut contract) = runners_of(&source).remove(&o.tool) {
            // …and its runner is the override layer's own (REQ-RUNNER-001),
            // or the override is refused: pairing it with the pin's runner
            // would run bytes no single layer vouched for together.
            let Some(runner) = store.tool_path(&source, &contract.tool) else {
                return Err(ResolveError::OverrideRunnerMissing {
                    tool: o.tool.clone(),
                    layer: source.layer.to_string(),
                    runner: contract.tool,
                });
            };
            contract.path = Some(runner);
            runners.insert(o.tool.clone(), contract);
        }
        out.push(ResolvedOverride {
            tool: o.tool.clone(),
            layer: source,
            path,
        });
    }
    Ok(out)
}

/// Every tool name the pinned layer CARRIES: its signed manifest's tools, the
/// files in its `bin/`, and the same for every layer it includes or composes —
/// whether or not the pin's `tools` subset selects them (REQ-PASSTHROUGH-001
/// clause 2). `Resolved::qualified` holds only what the pin EXPOSES, so a guard
/// built on it lets a carried-but-unexposed tool through to an ambient binary.
///
/// Names are folded to ASCII lower case: on a case-insensitive filesystem the
/// shim `PROBE` IS `probe`, so the comparison must not depend on the spelling.
/// A carried name that is not ASCII is an `Err` too (no sound comparison
/// exists), as is an unreadable `bin/`.
///
/// FAILS CLOSED: a manifest in the composition that cannot be read, or an
/// included layer that cannot be found, is an `Err` — "we could not tell what
/// the layer carries" must never read as "it carries nothing".
pub fn carried_tool_names(
    pin: &Pin,
    layer: &InstalledLayer,
    store: &Store,
) -> Result<std::collections::BTreeSet<String>, String> {
    let read = |entry: &InstalledLayer| -> Result<Vec<u8>, String> {
        let path = entry.root.join("layer.json");
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    };
    let root_view = crate::compose::view(&read(layer)?).map_err(|e| e.to_string())?;
    let mut unreadable: Vec<String> = Vec::new();
    let walked = crate::compose::walk(
        &layer.digest,
        &pin.realm.clone().unwrap_or_default(),
        &root_view,
        |digest| {
            let view = store
                .find_anywhere(digest)
                .ok()
                .flatten()
                .and_then(|(_, entry)| std::fs::read(entry.root.join("layer.json")).ok())
                .and_then(|bytes| crate::compose::view(&bytes).ok());
            if view.is_none() {
                unreadable.push(digest.to_string());
            }
            view
        },
    )
    .map_err(|e| e.to_string())?;
    if let Some(digest) = unreadable.first() {
        return Err(format!(
            "an included layer ({digest}) is not installed or its manifest cannot be read"
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for step in &walked {
        let entry = if step.digest == layer.digest {
            layer.clone()
        } else {
            match store
                .find_anywhere(&step.digest)
                .map_err(|e| e.to_string())?
            {
                Some((_, entry)) => entry,
                None => return Err(format!("layer {} is not installed", step.digest)),
            }
        };
        // The signed manifest, re-read strictly even for the root.
        read(&entry)?;
        names.extend(step.view.tools.iter().map(|t| t.to_ascii_lowercase()));
        names.extend(
            store
                .manifest_tool_names(&entry)
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|t| t.to_ascii_lowercase()),
        );
        // A layer with no `bin/` carries nothing there; one that cannot be
        // listed (or an entry that cannot be read) is "we could not tell".
        let bin = entry.root.join("bin");
        match std::fs::read_dir(&bin) {
            Ok(rd) => {
                for e in rd {
                    let e = e.map_err(|e| format!("cannot list {}: {e}", bin.display()))?;
                    names.insert(e.file_name().to_string_lossy().to_ascii_lowercase());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot list {}: {e}", bin.display())),
        }
    }
    // Folding is ASCII only, and a filesystem may fold more (APFS: `ñ` is `Ñ`;
    // NFC is NFD; the Kelvin sign is `k`). A non-ASCII name cannot be compared
    // soundly, so it is "we could not tell", never "not carried".
    if let Some(odd) = names.iter().find(|n| !n.is_ascii()) {
        return Err(format!(
            "the layer carries a tool name that is not ASCII ({}), which cannot be \
             compared safely with the name requested",
            odd.escape_default()
        ));
    }
    Ok(names)
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
    const RISCV: &str = "riscv64-unknown-linux-gnu";
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

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn carried_names_cover_the_whole_composition_whatever_the_pin_selects() {
        // Clause 2. The pin exposes `rivet` only; the layer also carries `Loom`
        // (manifest only, no bytes on this host) and `ghost` (bin/ only), and
        // composes `Wasm-Tools`. All of them are CARRIED, folded to lower case.
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("Wasm-Tools", b"w")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.07.0", &["rivet", "Loom"], &up),
                &[("rivet", b"r"), ("ghost", b"g")],
            )
            .unwrap();
        let mut p = qualified_pin("2026.07.0");
        p.tools = Some(vec![crate::pin::ToolSelector {
            name: "rivet".into(),
            realm: None,
        }]);
        let layer = resolve(&p, &store).unwrap().layer;
        let names = carried_tool_names(&p, &layer, &store).unwrap();
        let got: Vec<&str> = names.iter().map(String::as_str).collect();
        assert_eq!(got, ["ghost", "loom", "rivet", "wasm-tools"]);
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn carried_names_fail_closed_when_a_manifest_cannot_be_read() {
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("w", b"w")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.07.0", &["rivet"], &up),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = qualified_pin("2026.07.0");
        let layer = resolve(&p, &store).unwrap().layer;
        assert!(carried_tool_names(&p, &layer, &store).is_ok());

        // The included layer's manifest vanishes: we cannot say what it carries.
        let inc = store.get(&up).unwrap().unwrap();
        std::fs::remove_file(inc.root.join("layer.json")).unwrap();
        assert!(carried_tool_names(&p, &layer, &store).is_err());

        // So does the root's own.
        std::fs::remove_file(layer.root.join("layer.json")).unwrap();
        assert!(carried_tool_names(&p, &layer, &store).is_err());
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn a_carried_name_that_is_not_ascii_is_an_error_not_a_name() {
        // ASCII folding cannot compare it with a filesystem's own folding.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("rivet", b"r"), ("\u{f1}", b"n")],
            )
            .unwrap();
        let p = qualified_pin("2026.07.0");
        let layer = resolve(&p, &store).unwrap().layer;
        let why = carried_tool_names(&p, &layer, &store).unwrap_err();
        assert!(why.contains("not ASCII"), "{why}");
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[cfg(unix)]
    #[test]
    fn carried_names_fail_closed_when_bin_cannot_be_listed() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = qualified_pin("2026.07.0");
        let layer = resolve(&p, &store).unwrap().layer;
        assert!(carried_tool_names(&p, &layer, &store).is_ok());
        let bin = layer.root.join("bin");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unlistable = std::fs::read_dir(&bin).is_err();
        let got = carried_tool_names(&p, &layer, &store);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Skip only where permission bits are not enforced (running as root).
        if !unlistable {
            return;
        }
        assert!(
            got.is_err(),
            "an unlistable bin/ read as 'carries nothing there'"
        );
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn a_layer_with_no_bin_directory_carries_just_its_manifest_names() {
        // NotFound is the one error that is not an error: nothing is there.
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = qualified_pin("2026.07.0");
        let layer = resolve(&p, &store).unwrap().layer;
        std::fs::remove_dir_all(layer.root.join("bin")).unwrap();
        assert!(carried_tool_names(&p, &layer, &store).is_ok());
    }

    /// A manifest declaring `tools`, with optional extra annotations per tool.
    fn manifest_declaring(layer: &str, tools: &[(&str, &str)]) -> Vec<u8> {
        let entries: Vec<String> = tools
            .iter()
            .map(|(t, extra)| {
                format!(
                    r#"{{"digest":"sha256:{t}","annotations":{{"eu.pulseengine.tool":"{t}"{extra}}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"qualified"}},"manifests":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    /// The pinned layer 2026.11.0 carries synth and loom; 2026.08.0 carries an
    /// older synth and a tool the pin does not have. Returns the older layer's
    /// digest.
    fn mixed_store(store: &Store) -> String {
        store
            .lay_down(
                &manifest_declaring("2026.11.0", &[("synth", ""), ("loom", "")]),
                &[("synth", b"synth-0.65"), ("loom", b"loom-pinned")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_declaring("2026.08.0", &[("synth", ""), ("extra", "")]),
                &[("synth", b"synth-0.57"), ("extra", b"extra")],
            )
            .unwrap()
    }

    fn pin_overriding(tool: &str, layer: &str, digest: &str) -> Pin {
        pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
             [toolchain.override.{tool}]\nlayer = \"{layer}\"\ndigest = \"{digest}\"\n"
        ))
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_dispatches_that_tool_from_its_layer_and_the_rest_from_the_pin() {
        // DD-043 (4): Resolved gains overrides, and the tool's path comes from
        // the override layer.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let resolved = resolve(&pin_overriding("synth", "2026.08.0", &older), &store).unwrap();
        assert_eq!(
            resolved.layer.layer.to_string(),
            "2026.11.0",
            "the pin is the pin"
        );
        let path_of = |name: &str| {
            resolved
                .tools
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, p)| std::fs::read(p).unwrap())
        };
        assert_eq!(path_of("synth").as_deref(), Some(&b"synth-0.57"[..]));
        assert_eq!(path_of("loom").as_deref(), Some(&b"loom-pinned"[..]));
        assert_eq!(path_of("extra"), None, "an override adds nothing else");
        assert_eq!(resolved.overrides.len(), 1);
        let o = &resolved.overrides[0];
        assert_eq!(o.tool, "synth");
        assert_eq!(o.layer.layer.to_string(), "2026.08.0");
        assert_eq!(o.layer.digest, older);
        assert_eq!(std::fs::read(&o.path).unwrap(), b"synth-0.57");
        assert!(resolved.is_mixed());
        assert_eq!(
            resolved.recorded_overrides(),
            vec![crate::overrides::RecordedOverride {
                tool: "synth".into(),
                layer: "2026.08.0".into(),
                digest: older.clone(),
            }]
        );
        // The pure pin is not mixed and records nothing.
        let pure = resolve(&qualified_pin("2026.11.0"), &store).unwrap();
        assert!(!pure.is_mixed());
        assert!(pure.overrides.is_empty() && pure.recorded_overrides().is_empty());
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_of_a_tool_the_pinned_layer_does_not_carry_is_refused() {
        // Clause 4: the override layer HAS `extra`; the pin does not. An
        // override replaces, it never adds, or it would smuggle a tool in.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let err = resolve(&pin_overriding("extra", "2026.08.0", &older), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNotInPin { tool, layer, .. }
                if tool == "extra" && layer == "2026.11.0"),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("passthrough"), "names the alternative: {msg}");
        assert!(msg.contains("loom, synth"), "names what the pin has: {msg}");
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_of_a_tool_the_pin_restricts_away_is_refused_too() {
        // `tools` exposes only loom; synth is carried but not exposed, so an
        // override of it would put on PATH a name the pin left off.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let p = pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
             tools = [\"loom\"]\n[toolchain.override.synth]\nlayer = \"2026.08.0\"\ndigest = \"{older}\"\n"
        ));
        let err = resolve(&p, &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNotInPin { tool, .. } if tool == "synth"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_layer_that_does_not_carry_the_tool_is_refused() {
        let (_tmp, store) = store();
        mixed_store(&store);
        let other = store
            .lay_down(
                &manifest_declaring("2026.09.0", &[("rivet", "")]),
                &[("rivet", b"r")],
            )
            .unwrap();
        let err = resolve(&pin_overriding("synth", "2026.09.0", &other), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideSourceLacksTool { tool, layer, .. }
                if tool == "synth" && layer == "2026.09.0"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("rivet"),
            "names what it has: {err}"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_digest_that_is_not_installed_is_refused_with_the_fix() {
        let (_tmp, store) = store();
        mixed_store(&store);
        let absent = format!("sha256:{}", "c".repeat(64));
        let err = resolve(&pin_overriding("synth", "2026.08.0", &absent), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNotInstalled { tool, digest, .. }
                if tool == "synth" && *digest == absent),
            "got: {err}"
        );
        assert!(err.to_string().contains("varve install"), "{err}");
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_whose_digest_is_another_layer_is_refused() {
        // The name is a label, the digest is the artifact: a disagreement is
        // refused, never resolved by either half.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let err = resolve(&pin_overriding("synth", "2026.09.0", &older), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNameDigestMismatch { named, found, .. }
                if named == "2026.09.0" && found == "2026.08.0"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_layer_installed_under_another_realm_is_refused() {
        // DD-043: the source layer is in the pin's OWN realm. A layer another
        // realm's root vouched for lives in that realm's partition, and is not
        // vouched for by this pin's root.
        let (_tmp, store) = store();
        mixed_store(&store);
        let elsewhere = Store::at(store.root().join("realms").join("0123abcd"));
        let foreign = elsewhere
            .lay_down(
                &manifest_declaring("2026.08.1", &[("synth", "")]),
                &[("synth", b"foreign")],
            )
            .unwrap();
        let err = resolve(&pin_overriding("synth", "2026.08.1", &foreign), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideFromAnotherRealm { tool, .. } if tool == "synth"),
            "got: {err}"
        );
        assert!(err.to_string().contains("realm"), "{err}");
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_overridden_tool_takes_its_runner_contract_from_the_override_layer() {
        // A runner contract belongs to the bytes it was signed with: the pin's
        // contract for synth must not wrap the override's synth, and the
        // override layer's own contract must apply.
        let (_tmp, store) = store();
        let runner = format!(r#","{}":"wasmtime""#, crate::bazel::ANN_RUNNER);
        store
            .lay_down(
                &manifest_declaring(
                    "2026.11.0",
                    &[
                        ("synth", runner.as_str()),
                        ("wasmtime", ""),
                        ("loom", runner.as_str()),
                    ],
                ),
                &[("synth", b"s"), ("wasmtime", b"w"), ("loom", b"l")],
            )
            .unwrap();
        let older = store
            .lay_down(
                &manifest_declaring("2026.08.0", &[("synth", "")]),
                &[("synth", b"native")],
            )
            .unwrap();
        let resolved = resolve(&pin_overriding("synth", "2026.08.0", &older), &store).unwrap();
        assert!(
            !resolved.runners.contains_key("synth"),
            "{:?}",
            resolved.runners
        );
        assert!(resolved.runners.contains_key("loom"), "others keep theirs");

        // The override layer carries the runner its contract names: a runner
        // comes from the same layer as the tool (REQ-RUNNER-001).
        let wrapped = store
            .lay_down(
                &manifest_declaring("2026.09.0", &[("synth", runner.as_str()), ("wasmtime", "")]),
                &[("synth", b"wasm"), ("wasmtime", b"w9")],
            )
            .unwrap();
        let resolved = resolve(&pin_overriding("synth", "2026.09.0", &wrapped), &store).unwrap();
        assert_eq!(
            resolved.runners.get("synth").map(|c| c.tool.as_str()),
            Some("wasmtime")
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_layer_installed_for_another_platform_is_refused() {
        // Its bytes were selected for that platform: dispatching them here
        // would run another machine's binary under this pin.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let entry = store.get(&older).unwrap().unwrap();
        crate::store::record_install_platform(&entry.root, "riscv64-unknown-linux-gnu").unwrap();
        let err = resolve(&pin_overriding("synth", "2026.08.0", &older), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideForAnotherPlatform { tool, platform, .. }
                if tool == "synth" && platform == "riscv64-unknown-linux-gnu"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("riscv64-unknown-linux-gnu"),
            "{err}"
        );
        // Installed for THIS host is the ordinary case and resolves.
        crate::store::record_install_platform(&entry.root, &crate::platform::host_platform())
            .unwrap();
        assert!(resolve(&pin_overriding("synth", "2026.08.0", &older), &store).is_ok());
    }

    fn realm_pin_overriding(tool: &str, layer: &str, digest: &str) -> Pin {
        pin(&format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"qualified\"\n\
             layer = \"2026.11.0\"\n[toolchain.override.{tool}]\nlayer = \"{layer}\"\n\
             digest = \"{digest}\"\n"
        ))
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_qualified_address_of_an_overridden_tool_reaches_the_override_layer() {
        // `acme/synth` is the same tool as `synth`: every address of an
        // overridden tool must reach the override's bytes, never the pin's.
        let (_tmp, store) = store();
        let older = mixed_store(&store);
        let resolved =
            resolve(&realm_pin_overriding("synth", "2026.08.0", &older), &store).unwrap();
        let synths: Vec<_> = resolved
            .qualified
            .iter()
            .filter(|(p, _)| p.tool == "synth")
            .collect();
        assert_eq!(synths.len(), 1, "one provider of synth: {synths:?}");
        let (provider, path) = synths[0];
        assert_eq!(provider.qualified().as_deref(), Some("acme/synth"));
        assert_eq!(provider.layer, "2026.08.0");
        assert_eq!(provider.digest, older);
        assert_eq!(std::fs::read(path).unwrap(), b"synth-0.57");
        // A tool that is not overridden keeps its provider.
        let loom = resolved
            .qualified
            .iter()
            .find(|(p, _)| p.tool == "loom")
            .unwrap();
        assert_eq!(loom.0.layer, "2026.11.0");
        assert_eq!(std::fs::read(&loom.1).unwrap(), b"loom-pinned");
        // Which override, if any, an address names — bare or qualified.
        assert_eq!(resolved.override_for("synth").unwrap().tool, "synth");
        assert_eq!(resolved.override_for("other/synth").unwrap().tool, "synth");
        assert!(resolved.override_for("loom").is_none());
        assert!(resolved.override_for("acme/loom").is_none());
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn an_override_layer_on_another_channel_is_refused_naming_both() {
        // The pin's channel is part of the pin, for an override as for the
        // pinned layer: a rolling synth must not enter a qualified toolchain.
        let (_tmp, store) = store();
        mixed_store(&store);
        let rolling = store
            .lay_down(
                &manifest_declaring("2026.09.0", &[("synth", "")])
                    .iter()
                    .map(|b| *b as char)
                    .collect::<String>()
                    .replace("\"qualified\"", "\"rolling\"")
                    .into_bytes(),
                &[("synth", b"rolling-synth")],
            )
            .unwrap();
        let err = resolve(&pin_overriding("synth", "2026.09.0", &rolling), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideChannelMismatch { tool, installed, pinned, .. }
                if tool == "synth" && installed == "rolling" && pinned == "qualified"),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("rolling") && msg.contains("qualified"),
            "{msg}"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001, REQ-RUNNER-001
    #[test]
    fn an_overridden_tools_runner_comes_from_the_override_layer_or_is_refused() {
        // REQ-RUNNER-001: the runner comes from the SAME verified layer as the
        // tool it runs. An override's contract is paired with the override
        // layer's runner, never the pin's.
        let (_tmp, store) = store();
        let runner = format!(r#","{}":"wasmtime""#, crate::bazel::ANN_RUNNER);
        store
            .lay_down(
                &manifest_declaring(
                    "2026.11.0",
                    &[("synth", ""), ("wasmtime", ""), ("loom", runner.as_str())],
                ),
                &[
                    ("synth", b"s"),
                    ("wasmtime", b"pin-wasmtime"),
                    ("loom", b"l"),
                ],
            )
            .unwrap();
        // The override layer carries its own runner.
        let carried = store
            .lay_down(
                &manifest_declaring("2026.09.0", &[("synth", runner.as_str()), ("wasmtime", "")]),
                &[("synth", b"wasm"), ("wasmtime", b"own-wasmtime")],
            )
            .unwrap();
        let resolved = resolve(&pin_overriding("synth", "2026.09.0", &carried), &store).unwrap();
        let path = resolved.runners["synth"]
            .path
            .clone()
            .expect("a runner path");
        assert_eq!(std::fs::read(path).unwrap(), b"own-wasmtime");
        // The pin's own contract keeps the pin's runner.
        let loom = resolved.runners["loom"].path.clone().unwrap();
        assert_eq!(std::fs::read(loom).unwrap(), b"pin-wasmtime");
        // An override layer whose contract names a runner it does not carry
        // is refused, naming the layer and the runner.
        let bare = store
            .lay_down(
                &manifest_declaring("2026.08.0", &[("synth", runner.as_str())]),
                &[("synth", b"wasm-alone")],
            )
            .unwrap();
        let err = resolve(&pin_overriding("synth", "2026.08.0", &bare), &store).unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideRunnerMissing { tool, layer, runner }
                if tool == "synth" && layer == "2026.08.0" && runner == "wasmtime"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001, REQ-RUNNER-001
    #[test]
    fn overriding_a_runner_does_not_change_what_runs_the_pins_tools() {
        let (_tmp, store) = store();
        let runner = format!(r#","{}":"wasmtime""#, crate::bazel::ANN_RUNNER);
        store
            .lay_down(
                &manifest_declaring("2026.11.0", &[("wasmtime", ""), ("loom", runner.as_str())]),
                &[("wasmtime", b"pin-wasmtime"), ("loom", b"l")],
            )
            .unwrap();
        let other = store
            .lay_down(
                &manifest_declaring("2026.09.0", &[("wasmtime", "")]),
                &[("wasmtime", b"other-wasmtime")],
            )
            .unwrap();
        let resolved = resolve(&pin_overriding("wasmtime", "2026.09.0", &other), &store).unwrap();
        let loom = resolved.runners["loom"].path.clone().unwrap();
        assert_eq!(std::fs::read(loom).unwrap(), b"pin-wasmtime");
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn clause_four_before_any_fetch_does_not_depend_on_the_host() {
        // `install --platform <other>` must decide clause 4 from the pin and
        // what the pinned layer CARRIES, not from what resolves on this host:
        // loom is declared for another platform only and laid down nowhere
        // here, yet the pin exposes it and an override of it is legitimate.
        let (_tmp, store) = store();
        store
            .lay_down(
                &manifest_declaring(
                    "2026.11.0",
                    &[
                        ("synth", ""),
                        (
                            "loom",
                            r#","eu.pulseengine.platform":"riscv64-unknown-linux-gnu""#,
                        ),
                    ],
                ),
                &[("synth", b"s")],
            )
            .unwrap();
        let p = |tools: &str, tool: &str| {
            pin(&format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
                 {tools}[toolchain.override.{tool}]\nlayer = \"2026.08.0\"\ndigest = \"sha256:{}\"\n",
                "a".repeat(64)
            ))
        };
        let layer = store.list().unwrap().remove(0);
        assert!(overrides_carried_by_pin(&p("", "loom"), &layer, &store, RISCV).is_ok());
        assert!(
            overrides_carried_by_pin(
                &p("", "synth"),
                &layer,
                &store,
                &crate::platform::host_platform()
            )
            .is_ok()
        );
        let err = overrides_carried_by_pin(
            &p("", "extra"),
            &layer,
            &store,
            &crate::platform::host_platform(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNotInPin { tool, .. } if tool == "extra"),
            "{err}"
        );
        // A `tools` subset decides what the pin exposes, carried or not.
        let subset = "tools = [\"loom\"]\n";
        assert!(overrides_carried_by_pin(&p(subset, "loom"), &layer, &store, RISCV).is_ok());
        assert!(matches!(
            overrides_carried_by_pin(
                &p(subset, "synth"),
                &layer,
                &store,
                &crate::platform::host_platform()
            ),
            Err(ResolveError::OverrideNotInPin { .. })
        ));
        // "Could not tell" is a refusal, never "carried".
        std::fs::remove_file(layer.root.join("layer.json")).unwrap();
        assert!(matches!(
            overrides_carried_by_pin(
                &p("", "synth"),
                &layer,
                &store,
                &crate::platform::host_platform()
            ),
            Err(ResolveError::CannotTellWhatThePinCarries { .. })
        ));
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn clause_four_counts_only_dispatchable_tools_the_composition_carries() {
        // A subset name the layer never carried, and a HELD payload's name,
        // are not tools the pin has: an override of either adds a tool.
        let (_tmp, store) = store();
        store
            .lay_down(
                &manifest_declaring(
                    "2026.11.0",
                    &[
                        ("synth", ""),
                        ("acme-core", r#","eu.pulseengine.varve.kind":"crate""#),
                    ],
                ),
                &[("synth", b"s")],
            )
            .unwrap();
        let layer = store.list().unwrap().remove(0);
        let p = |tools: &str, tool: &str| {
            pin(&format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
                 {tools}[toolchain.override.{tool}]\nlayer = \"2026.08.0\"\ndigest = \"sha256:{}\"\n",
                "a".repeat(64)
            ))
        };
        for (tools, tool) in [
            ("tools = [\"ghost\"]\n", "ghost"),
            ("", "acme-core"),
            ("tools = [\"acme-core\"]\n", "acme-core"),
        ] {
            let err = overrides_carried_by_pin(
                &p(tools, tool),
                &layer,
                &store,
                &crate::platform::host_platform(),
            )
            .unwrap_err();
            assert!(
                matches!(&err, ResolveError::OverrideNotInPin { tool: t, .. } if t == tool),
                "{tools}{tool}: {err}"
            );
        }
        assert!(
            overrides_carried_by_pin(
                &p("tools = [\"synth\"]\n", "synth"),
                &layer,
                &store,
                &crate::platform::host_platform()
            )
            .is_ok()
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn clause_four_before_any_fetch_counts_what_an_included_layer_carries() {
        // A tool the pin has through its COMPOSITION is the pin's: an
        // override of the included layer's wasm-tools is a replacement.
        let (_tmp, store) = store();
        let up = store
            .lay_down(
                &manifest_declaring("2026.08.0", &[("wasm-tools", "")]),
                &[("wasm-tools", b"w")],
            )
            .unwrap();
        store
            .lay_down(
                &manifest_composing("2026.11.0", &["rivet"], &up),
                &[("rivet", b"r")],
            )
            .unwrap();
        let layer = store
            .list()
            .unwrap()
            .into_iter()
            .find(|e| e.layer.to_string() == "2026.11.0")
            .unwrap();
        let p = |tool: &str| {
            pin(&format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
                 [toolchain.override.{tool}]\nlayer = \"2026.09.0\"\ndigest = \"sha256:{}\"\n",
                "a".repeat(64)
            ))
        };
        assert!(
            overrides_carried_by_pin(
                &p("wasm-tools"),
                &layer,
                &store,
                &crate::platform::host_platform()
            )
            .is_ok()
        );
        assert!(
            overrides_carried_by_pin(
                &p("rivet"),
                &layer,
                &store,
                &crate::platform::host_platform()
            )
            .is_ok()
        );
        assert!(
            overrides_carried_by_pin(
                &p("ghost"),
                &layer,
                &store,
                &crate::platform::host_platform()
            )
            .is_err()
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn clause_four_before_any_fetch_counts_tools_for_the_target_platform() {
        // A tool the pinned layer ships only for ANOTHER platform is not one
        // the pin has on THIS target: an override of it would add one here.
        let (_tmp, store) = store();
        store
            .lay_down(
                &manifest_declaring(
                    "2026.11.0",
                    &[
                        ("synth", ""),
                        (
                            "loom",
                            r#","eu.pulseengine.platform":"riscv64-unknown-linux-gnu""#,
                        ),
                    ],
                ),
                &[("synth", b"s")],
            )
            .unwrap();
        let layer = store.list().unwrap().remove(0);
        let p = pin(&format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.11.0\"\n\
             [toolchain.override.loom]\nlayer = \"2026.08.0\"\ndigest = \"sha256:{}\"\n",
            "a".repeat(64)
        ));
        let err = overrides_carried_by_pin(&p, &layer, &store, "aarch64-apple-darwin").unwrap_err();
        assert!(
            matches!(&err, ResolveError::OverrideNotInPin { tool, .. } if tool == "loom"),
            "{err}"
        );
        assert!(overrides_carried_by_pin(&p, &layer, &store, RISCV).is_ok());
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn resolve_refuses_an_installed_override_entry_that_is_not_a_tool_for_this_host() {
        // What resolve enforces on the INSTALLED override layer: its signed
        // manifest declares the tool as dispatchable for this host. A file in
        // bin/ is not enough.
        for extra in [
            r#","eu.pulseengine.varve.kind":"crate""#,
            r#","eu.pulseengine.platform":"riscv64-unknown-linux-gnu""#,
        ] {
            let (_tmp, store) = store();
            mixed_store(&store);
            let odd = store
                .lay_down(
                    &manifest_declaring("2026.09.0", &[("synth", extra)]),
                    &[("synth", b"not-a-host-tool")],
                )
                .unwrap();
            let err = resolve(&pin_overriding("synth", "2026.09.0", &odd), &store).unwrap_err();
            assert!(
                matches!(&err, ResolveError::OverrideSourceLacksTool { tool, .. } if tool == "synth"),
                "{extra}: {err}"
            );
        }
    }
}
