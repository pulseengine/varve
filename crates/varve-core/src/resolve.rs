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
    /// the layer), each with its resolved binary path.
    pub tools: Vec<(String, PathBuf)>,
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
    #[error(transparent)]
    Store(#[from] StoreError),
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

    let tool_names: Vec<String> = match &pin.tools {
        Some(subset) => subset.clone(),
        None => {
            let bin = layer.root.join("bin");
            let mut names: Vec<String> = match std::fs::read_dir(&bin) {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect(),
                Err(_) => Vec::new(),
            };
            names.sort();
            names
        }
    };

    let mut tools = Vec::new();
    let mut missing = Vec::new();
    for name in tool_names {
        match store.tool_path(&layer, &name) {
            Some(path) => tools.push((name, path)),
            None => missing.push(name),
        }
    }

    // Composition (REQ-COMPOSE-001): a layer may include others, so one pin can
    // span two trust universes. Tools from included layers join this layer's,
    // and a name exposed twice is an error rather than a silent choice.
    let composed = compose_tools(&layer, store)?;
    for (name, path) in composed {
        if tools.iter().any(|(n, _)| n == &name) {
            // Also caught by union_tools, but this covers a pin-restricted
            // subset where the duplicate is not in the walked set.
            return Err(ResolveError::Compose(
                crate::compose::ComposeError::AmbiguousTool {
                    tool: name,
                    first: layer.digest.clone(),
                    second: "an included layer".into(),
                },
            ));
        }
        // A pin restricting `tools` selects from the composition too.
        if let Some(subset) = &pin.tools
            && !subset.contains(&name)
        {
            continue;
        }
        tools.push((name, path));
    }
    if !missing.is_empty() {
        return Err(ResolveError::PartialLayer {
            layer: layer.layer.to_string(),
            missing,
        });
    }

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
        runners,
    })
}

/// Resolve the tools an installed layer's COMPOSITION exposes, excluding the
/// layer's own. Included layers must already be installed; fetching them
/// transitively is deliberately out of scope for v0.23.0 (REQ-COMPOSE-001), so
/// a missing one is an error naming it and its corrective install.
fn compose_tools(
    layer: &InstalledLayer,
    store: &Store,
) -> Result<Vec<(String, std::path::PathBuf)>, ResolveError> {
    let path = layer.root.join("layer.json");
    let Ok(bytes) = std::fs::read(&path) else {
        // No stored manifest at all: a pre-composition layer laid down by an
        // older varve. Nothing to compose, and nothing hidden.
        return Ok(Vec::new());
    };
    // A manifest we cannot read is an ERROR, not an empty composition — the
    // earlier version returned Ok(empty) here and silently resolved a composed
    // layer to none of its included tools.
    let root_view = crate::compose::view(&bytes)?;
    if root_view.includes.is_empty() {
        return Ok(Vec::new());
    }
    // Every declared include must already be installed. Fetching transitively
    // is deliberately out of scope (REQ-COMPOSE-001), so name it and its fix.
    for inc in &root_view.includes {
        if store.get(&inc.digest)?.is_none() {
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
    let walked = crate::compose::walk(&layer.digest, &root_view, |digest| {
        let entry = store.get(digest).ok().flatten()?;
        let bytes = std::fs::read(entry.root.join("layer.json")).ok()?;
        crate::compose::view(&bytes).ok()
    })?;
    // Refuse a name exposed by more than one layer, before resolving any path.
    crate::compose::union_tools(&walked)?;

    let mut out = Vec::new();
    for (digest, _) in walked.iter().skip(1) {
        let Some(entry) = store.get(digest)? else {
            continue;
        };
        let bin = entry.root.join("bin");
        let Ok(rd) = std::fs::read_dir(&bin) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            if let Some(path) = store.tool_path(&entry, &name) {
                out.push((name, path));
            }
        }
    }
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
        let (_tmp, store) = store();
        store
            .lay_down(
                &fixtures::manifest("2026.07.0", "qualified"),
                &[("rivet", b"r")],
            )
            .unwrap();
        let p = pin(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"rivet\", \"synth\"]\n",
        );
        let err = resolve(&p, &store).unwrap_err();
        match err {
            ResolveError::PartialLayer { missing, .. } => {
                assert_eq!(missing, vec!["synth".to_string()]);
            }
            other => panic!("expected PartialLayer, got: {other}"),
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
}
