//! `varve run --with <tool>@<version>` (REQ-RUNWITH-001, DD-043 (7)).
//!
//! One command runs with one tool at another version, and nothing persists.
//! The version is resolved to a layer id and digest ONLY among the layers
//! already installed in the pin's own realm partition — this never fetches —
//! and the result is an in-memory `[toolchain.override.<tool>]`: `resolve`
//! then applies every rule an override in varve.toml obeys (clause 4, the
//! source layer's channel and platform, the tool declared and on disk, the
//! runner from the same layer). This module only decides WHICH installed
//! layer a `tool@version` names, or refuses saying why none or more than one.
//!
//! The line index carries no tool versions (DD-043, maintainer decision
//! 2026-11-11), so a version is read from the `eu.pulseengine.tool.version`
//! annotation of an installed layer's signed manifest, and nowhere else.

use crate::layer::LayerId;
use crate::pin::{ToolOverride, ToolSelector};
use crate::store::{Store, StoreError};

/// One `--with tool@version`, parsed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithRequest {
    /// Bare: the source layer is in the pin's realm, as for an override.
    pub tool: String,
    /// Compared byte-for-byte with the manifest's version annotation. No
    /// ranges, no "latest": a version names one release of the tool.
    pub version: String,
}

impl std::fmt::Display for WithRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.tool, self.version)
    }
}

/// Parse `tool@version`. The tool obeys the rule a `[toolchain.override.*]`
/// key obeys (a bare name); the version must be non-empty and carry no
/// whitespace or control character.
pub fn parse_request(spec: &str) -> Result<WithRequest, String> {
    let Some((tool, version)) = spec.split_once('@') else {
        return Err(format!(
            "--with {spec:?}: expected <tool>@<version>, e.g. synth@0.57.0"
        ));
    };
    if !matches!(
        ToolSelector::parse(tool),
        Some(ToolSelector { realm: None, .. })
    ) {
        return Err(format!(
            "--with {spec:?}: {tool:?} is not a bare tool name — an override comes from the \
             pin's own realm, so a realm qualifier or a path names something it cannot do"
        ));
    }
    if version.is_empty() || version.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "--with {spec:?}: the version must be non-empty, with no whitespace"
        ));
    }
    Ok(WithRequest {
        tool: tool.to_string(),
        version: version.to_string(),
    })
}

/// Several `--with` are allowed, one per tool. The same tool twice — in any
/// spelling a case-insensitive shim directory cannot tell apart — is refused,
/// as `[toolchain.override.*]` refuses it, rather than letting the last win.
pub fn check_distinct(requests: &[WithRequest]) -> Result<(), String> {
    for (i, r) in requests.iter().enumerate() {
        if let Some(first) = requests[..i]
            .iter()
            .find(|seen| seen.tool.eq_ignore_ascii_case(&r.tool))
        {
            return Err(format!(
                "--with {first} and --with {r} both name '{}' — one command runs one version \
                 of a tool; pass one --with per tool",
                r.tool
            ));
        }
    }
    Ok(())
}

/// `tool@version`, comma-separated and sorted by tool — the value of
/// `VARVE_WITH`, so a script can record what it asked for beside what it got
/// (`VARVE_OVERRIDES`).
pub fn env_value(requests: &[WithRequest]) -> String {
    let mut sorted = requests.to_vec();
    sorted.sort();
    sorted
        .iter()
        .map(WithRequest::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The varve.toml lines that would pin this override for good.
pub fn toml_lines(tool: &str, layer: &str, digest: &str) -> String {
    format!("[toolchain.override.{tool}]\nlayer = \"{layer}\"\ndigest = \"{digest}\"\n")
}

/// An installed layer that dispatches the tool for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    pub layer: LayerId,
    /// `sha256:<hex>` of the layer's signed manifest.
    pub digest: String,
    /// The version the signed manifest declares for the tool ("" if none).
    pub version: String,
    /// The channel the layer states ("" for a layer from before channels).
    pub channel: String,
    /// The platform the layer was INSTALLED for, where recorded.
    pub platform: Option<String>,
    /// What runs when the tool is dispatched: the tool entry's signed digest,
    /// and — for a runnered entry — its runner contract and the runner entry's
    /// signed digest in the same layer. Two carriers with equal `runs` run
    /// the same bytes the same way.
    pub runs: String,
}

/// Every layer installed in `store` (ONE partition) whose signed manifest
/// declares `tool` as a dispatchable entry for `host`, in store order. Read
/// leniently, as `resolve` reads a stored manifest. A layer whose manifest
/// cannot be read is an error, never "carries nothing".
pub fn carriers(store: &Store, tool: &str, host: &str) -> Result<Vec<Carrier>, StoreError> {
    let mut out = Vec::new();
    for entry in store.list()? {
        let path = entry.root.join("layer.json");
        let bad = |reason: String| StoreError::BadManifest {
            path: path.display().to_string(),
            reason,
        };
        let bytes = std::fs::read(&path).map_err(|source| StoreError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| bad(e.to_string()))?;
        let entries = json["manifests"].as_array().cloned().unwrap_or_default();
        let dispatched = |name: &str| {
            entries.iter().find(|e| {
                let ann = &e["annotations"];
                let tool_kind = match ann[crate::kind::ANN_KIND].as_str() {
                    None => true,
                    Some(kind) => kind
                        .parse::<crate::kind::PayloadKind>()
                        .is_ok_and(|k| k.is_dispatchable()),
                };
                ann["eu.pulseengine.tool"].as_str() == Some(name)
                    && tool_kind
                    && crate::platform::entry_matches(
                        ann[crate::platform::ANN_PLATFORM].as_str(),
                        host,
                    )
            })
        };
        let Some(found) = dispatched(tool) else {
            continue;
        };
        let ann = &found["annotations"];
        let text = |key: &str| ann[key].as_str().unwrap_or_default().to_string();
        let runner = text(crate::bazel::ANN_RUNNER);
        let runner_digest = if runner.is_empty() {
            String::new()
        } else {
            dispatched(&runner)
                .and_then(|r| r["digest"].as_str())
                .unwrap_or("(not carried)")
                .to_string()
        };
        out.push(Carrier {
            layer: entry.layer.clone(),
            digest: entry.digest.clone(),
            version: text("eu.pulseengine.tool.version"),
            channel: entry.channel.clone(),
            platform: entry.platform.clone(),
            runs: format!(
                "{}|{runner}|{}|{}|{runner_digest}",
                found["digest"].as_str().unwrap_or_default(),
                text(crate::bazel::ANN_RUNNER_ARGS),
                text(crate::bazel::ANN_RUNNER_ARG_PREFIX),
            ),
        });
    }
    Ok(out)
}

/// Why a `--with` names no installed layer, or more than one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunWithError {
    #[error(
        "--with {request}: no layer installed from realm {realm} carries {tool} {version}{have}. \
         --with never fetches. The realm's line index names layers, not tool versions, so find \
         the layer that ships {tool} {version} in the realm's release notes (`varve outdated` \
         lists this line's newer layers), then add [toolchain.override.{tool}] with its layer \
         id and digest to varve.toml and run `varve install` — after which --with finds it.",
        tool = request.tool,
        version = request.version,
        have = if have.is_empty() {
            String::new()
        } else {
            format!(" — installed layers carry {}: {have}", request.tool)
        }
    )]
    NotInstalled {
        request: WithRequest,
        realm: String,
        /// `version (layer digest)` of every installed carrier, or empty.
        have: String,
    },
    #[error(
        "--with {request}: {tool} {version} is installed only outside realm {realm}'s store \
         (another realm, or a store no realm vouches for): {found}. --with never fetches, and \
         an override comes from the pin's own realm. To install it from {realm} — fetched and \
         verified against {realm}'s trust root, and refused if {realm} did not sign it — add \
         to varve.toml and run `varve install`:\n{lines}",
        tool = request.tool,
        version = request.version,
    )]
    OnlyElsewhere {
        request: WithRequest,
        realm: String,
        found: String,
        /// The exact `[toolchain.override.<tool>]` lines, one table per layer.
        lines: String,
    },
    #[error(
        "--with {request}: every installed layer that carries {tool} {version} is one this pin \
         cannot take an override from: {why}",
        tool = request.tool,
        version = request.version,
    )]
    NotUsable { request: WithRequest, why: String },
    #[error(
        "--with {request}: {count} installed layers carry {tool} {version}, and they do not run \
         the same bytes — refusing to pick one: {list}. Name the one you mean in varve.toml as \
         [toolchain.override.{tool}] with its layer and digest.",
        tool = request.tool,
        version = request.version,
    )]
    Ambiguous {
        request: WithRequest,
        count: usize,
        list: String,
    },
}

/// Decide which installed layer `request` names (DD-043 (7)).
///
/// `here` are the carriers in the pin's own realm partition, `elsewhere` the
/// carriers in every other partition (named only in a refusal, never used).
/// A carrier on another channel than `pin_channel`, or installed for another
/// platform than `host`, is not a candidate: the pin could not take an
/// override from it. Among the candidates, several layers are accepted only
/// when they all run the same bytes the same way (`Carrier::runs`); the one
/// chosen is then the least by (layer id, digest), so the choice does not
/// depend on install order. Otherwise the refusal lists them.
pub fn choose(
    request: &WithRequest,
    realm: &str,
    pin_channel: &str,
    host: &str,
    here: &[Carrier],
    elsewhere: &[Carrier],
) -> Result<ToolOverride, RunWithError> {
    let matching: Vec<&Carrier> = here
        .iter()
        .filter(|c| c.version == request.version)
        .collect();
    let refusal = |c: &Carrier| -> Option<String> {
        if !c.channel.is_empty() && c.channel != pin_channel {
            return Some(format!(
                "layer {} ({}) is on channel '{}', this pin selects '{pin_channel}'",
                c.layer, c.digest, c.channel
            ));
        }
        match c.platform.as_deref() {
            Some(p) if p != host => Some(format!(
                "layer {} ({}) was installed for {p}, not {host}",
                c.layer, c.digest
            )),
            _ => None,
        }
    };
    let mut usable: Vec<&Carrier> = matching
        .iter()
        .copied()
        .filter(|c| refusal(c).is_none())
        .collect();
    if usable.is_empty() {
        if !matching.is_empty() {
            return Err(RunWithError::NotUsable {
                request: request.clone(),
                why: matching
                    .iter()
                    .filter_map(|c| refusal(c))
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }
        let mut away: Vec<&Carrier> = elsewhere
            .iter()
            .filter(|c| c.version == request.version)
            .collect();
        away.sort_by(|a, b| (&a.layer, &a.digest).cmp(&(&b.layer, &b.digest)));
        away.dedup_by(|a, b| a.digest == b.digest);
        if !away.is_empty() {
            return Err(RunWithError::OnlyElsewhere {
                request: request.clone(),
                realm: realm.to_string(),
                found: away
                    .iter()
                    .map(|c| format!("layer {} ({})", c.layer, c.digest))
                    .collect::<Vec<_>>()
                    .join(", "),
                lines: away
                    .iter()
                    .map(|c| toml_lines(&request.tool, &c.layer.to_string(), &c.digest))
                    .collect::<Vec<_>>()
                    .join("\n"),
            });
        }
        let mut have: Vec<String> = here
            .iter()
            .map(|c| {
                format!(
                    "{} (layer {} {})",
                    if c.version.is_empty() {
                        "no version stated"
                    } else {
                        &c.version
                    },
                    c.layer,
                    c.digest
                )
            })
            .collect();
        have.sort();
        return Err(RunWithError::NotInstalled {
            request: request.clone(),
            realm: realm.to_string(),
            have: have.join(", "),
        });
    }
    usable.sort_by(|a, b| (&a.layer, &a.digest).cmp(&(&b.layer, &b.digest)));
    if usable.iter().any(|c| c.runs != usable[0].runs) {
        return Err(RunWithError::Ambiguous {
            request: request.clone(),
            count: usable.len(),
            list: usable
                .iter()
                .map(|c| {
                    format!(
                        "layer {} ({}) runs {}",
                        c.layer,
                        c.digest,
                        c.runs.split('|').next().unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    let chosen = usable[0];
    Ok(ToolOverride {
        tool: request.tool.clone(),
        layer: chosen.layer.clone(),
        digest: chosen.digest.clone(),
    })
}

// ---- the private shim directory a `--with` command gets first on PATH ----
//
// `varve run --with` spawns its command with a directory of its own first on
// PATH. For each overridden tool the directory holds a wrapper that execs
// `varve run --with-shim-dir <that directory> -- <tool>`: the directory is
// named in the wrapper's own text, never in the environment, so no inherited
// variable can point a shim at an override. The directory also holds the
// record of what the run resolved (`RECORD_FILE`) and a lock the run holds
// for its whole life (`LOCK_FILE`).
//
// A shim reading the directory first checks that the lock is still HELD. An
// advisory lock dies with its holder, whatever kills it — SIGKILL included —
// so a directory that outlived its run (a leak) grants nothing, and its record
// is not even read. While the run lives, the record is re-verified against the
// store exactly as a varve.toml override is (`resolve`), so an edited record
// can name only what the pin could have overridden anyway.

/// The record of what a `--with` run resolved, beside its private shims.
pub const RECORD_FILE: &str = "with.json";
/// Held, exclusively, by the run for its whole life.
pub const LOCK_FILE: &str = "owner.lock";

/// What a private shim directory records: the pin the run resolved (its
/// varve.toml, canonical), the overrides `--with` resolved to, and what was
/// asked. `deny_unknown_fields`: a record this varve cannot fully read is
/// refused, not partly obeyed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimRecord {
    pub pin: std::path::PathBuf,
    pub overrides: Vec<crate::overrides::RecordedOverride>,
    pub with: Vec<WithRequest>,
}

/// The wrapper a private shim directory holds for `tool`. Paths that are not
/// UTF-8 cannot be quoted for `sh` faithfully and are refused.
pub fn wrapper_script(
    varve: &std::path::Path,
    dir: &std::path::Path,
    tool: &str,
) -> Result<String, String> {
    let text = |p: &std::path::Path| {
        p.to_str()
            .map(crate::shellquote::quote_sh)
            .ok_or_else(|| format!("{} is not UTF-8", p.display()))
    };
    Ok(format!(
        "#!/bin/sh\n# varve run --with: a private shim, honoured only while that run lives \
         (REQ-RUNWITH-001).\nexec {} run --with-shim-dir {} -- {} \"$@\"\n",
        text(varve)?,
        text(dir)?,
        crate::shellquote::quote_sh(tool)
    ))
}

/// Fill `dir` (created 0700 by the caller): take the lock FIRST, so no
/// wrapper ever exists without a live owner, then the record, then one
/// wrapper (0700) per override. Returns the lock: the directory is honoured
/// exactly as long as it is held.
#[cfg(unix)]
pub fn fill_shim_dir(
    dir: &std::path::Path,
    record: &ShimRecord,
    varve: &std::path::Path,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::PermissionsExt;
    let io = |what: &str, e: std::io::Error| format!("{what} in {}: {e}", dir.display());
    let lock = std::fs::File::create(dir.join(LOCK_FILE)).map_err(|e| io("lock", e))?;
    lock.lock().map_err(|e| io("lock", e))?;
    let json = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(RECORD_FILE), json).map_err(|e| io("record", e))?;
    for o in &record.overrides {
        let path = dir.join(&o.tool);
        std::fs::write(&path, wrapper_script(varve, dir, &o.tool)?).map_err(|e| io("shim", e))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io("shim", e))?;
    }
    Ok(lock)
}

/// Read a private shim directory, or refuse. Refused: a path that is not a
/// directory of `uid`'s, or that group or others can write or read; a
/// directory whose run is gone (its lock is not held) — then the record is
/// never read; a record this varve cannot read whole.
#[cfg(unix)]
pub fn read_shim_dir(dir: &std::path::Path, uid: u32) -> Result<ShimRecord, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("{}: not a --with shim directory: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{}: not a --with shim directory", dir.display()));
    }
    if meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{}: a --with shim directory is private to the user who made it (0700) — refusing",
            dir.display()
        ));
    }
    let lock = std::fs::File::open(dir.join(LOCK_FILE))
        .map_err(|e| format!("{}: no lock: {e}", dir.display()))?;
    // A SHARED probe: probers never block each other, so only the live run's
    // exclusive lock can fail it. An exclusive probe made a dead directory
    // look alive to every other prober holding it at that instant (review,
    // 2026-11-14: 149 of 1200 concurrent calls into a leaked directory ran).
    match lock.try_lock_shared() {
        // Taken: nobody holds it exclusively, so the run that made this is gone.
        Ok(()) => {
            return Err(format!(
                "{} outlived the `varve run --with` that made it — its shims grant nothing \
                 after that run ends. Remove the directory.",
                dir.display()
            ));
        }
        Err(std::fs::TryLockError::WouldBlock) => {}
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(format!("{}: cannot check its lock: {e}", dir.display()));
        }
    }
    let bytes = std::fs::read(dir.join(RECORD_FILE))
        .map_err(|e| format!("{}: no record: {e}", dir.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: unreadable record: {e}", dir.display()))
}

/// The exit status `varve run --with` passes on: the child's code, or 128 + N
/// for a child killed by signal N (the shell's convention).
pub fn exit_code(code: Option<i32>, signal: Option<i32>) -> i32 {
    match (code, signal) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        (None, None) => 1,
    }
}

/// May `varve run --with` run `name` as a program the layer does not carry?
/// Only an ASCII name (a filesystem may fold a non-ASCII spelling onto a
/// carried tool, as REQ-PASSTHROUGH-001 clause 2 guards), and only a bare
/// name (looked up on PATH) or an explicit path (`/…`, `./…`, `../…`). A
/// selector-shaped `realm/tool` that does not resolve is refused, never taken
/// as a path relative to the working directory.
pub fn may_run_unlisted(name: &str) -> bool {
    name.is_ascii()
        && !name.is_empty()
        && (!name.contains('/')
            || name.starts_with('/')
            || name.starts_with("./")
            || name.starts_with("../"))
}

/// The directory a private shim directory is made in (TMPDIR) must not let
/// anyone else replace what is in it: owned by the user or by root, and not
/// writable by group or others unless sticky (as /tmp is). Otherwise the
/// directory could be swapped between creation and use, and PATH would run a
/// foreign binary without ever reaching a wrapper.
pub fn check_temp_parent(
    parent: &std::path::Path,
    owner: u32,
    mode: u32,
    uid: u32,
) -> Result<(), String> {
    if owner != uid && owner != 0 {
        return Err(format!(
            "{} (TMPDIR or a directory above it) belongs to another user — a --with shim \
             directory is not made under it",
            parent.display()
        ));
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(format!(
            "{} (TMPDIR or a directory above it) is a directory others can write without the \
             sticky bit — a --with shim directory under it could be replaced. Point TMPDIR at a \
             directory whose every parent only you or root can write.",
            parent.display()
        ));
    }
    Ok(())
}

/// `check_temp_parent` for TMPDIR (canonical) and EVERY directory above it,
/// up to `/`, as ssh and sudo check a path: one foreign-writable, non-sticky
/// ancestor lets someone replace a whole path component above the checked
/// directory. `chain` is (path, owner uid, mode) for each.
pub fn check_temp_ancestors(
    chain: &[(std::path::PathBuf, u32, u32)],
    uid: u32,
) -> Result<(), String> {
    for (path, owner, mode) in chain {
        check_temp_parent(path, *owner, *mode, uid)?;
    }
    Ok(())
}

/// The directory just created for the private shims is the one this run
/// made: a real directory (not a link), owned by `uid`, mode exactly 0700.
pub fn check_created_dir(
    path: &std::path::Path,
    is_dir: bool,
    owner: u32,
    mode: u32,
    uid: u32,
) -> Result<(), String> {
    if !is_dir || owner != uid || mode & 0o7777 != 0o700 {
        return Err(format!(
            "{} is not the private directory this run created (a directory of yours, 0700) — \
             refusing to put shims in it",
            path.display()
        ));
    }
    Ok(())
}

/// The private shim directory never lives under the varve root or the
/// project: "nothing persists" there, even while the run lasts. `parent` and
/// `roots` are canonical. Refused rather than moved: TMPDIR is the user's
/// choice, and a guessed fallback would be a second place to get right.
pub fn check_not_inside(
    parent: &std::path::Path,
    roots: &[&std::path::Path],
) -> Result<(), String> {
    match roots.iter().find(|root| parent.starts_with(root)) {
        Some(root) => Err(format!(
            "{} (TMPDIR) is inside {} — a --with shim directory is never made under the varve \
             root or the project. Point TMPDIR elsewhere.",
            parent.display(),
            root.display()
        )),
        None => Ok(()),
    }
}

/// A private shim directory of an outer `varve run --with` on `path`, if any:
/// a PATH entry holding both a record and a lock. Used only to REFUSE a nested
/// `--with` (whose environment would report its own overrides while bare calls
/// still reached the outer's): finding one can never grant anything.
pub fn outer_shim_dir(path: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    std::env::split_paths(path?).find(|dir| {
        dir.is_absolute() && dir.join(RECORD_FILE).is_file() && dir.join(LOCK_FILE).is_file()
    })
}

/// Does a live record say exactly what its `with` resolves to now? `chosen`
/// is what `choose` picks for each request against the store today. An
/// edited record — another layer, another digest, a tool nobody asked for —
/// would make `VARVE_WITH` describe something other than what runs.
pub fn record_matches(record: &ShimRecord, chosen: &[ToolOverride]) -> Result<(), String> {
    let mut expected: Vec<crate::overrides::RecordedOverride> = chosen
        .iter()
        .map(|o| crate::overrides::RecordedOverride {
            tool: o.tool.clone(),
            layer: o.layer.to_string(),
            digest: o.digest.clone(),
        })
        .collect();
    expected.sort();
    let mut recorded = record.overrides.clone();
    recorded.sort();
    if expected == recorded {
        Ok(())
    } else {
        Err(format!(
            "the --with shim record ({}) does not match what --with {} resolves to ({}) — \
             refusing",
            crate::overrides::env_value(&recorded),
            env_value(&record.with),
            crate::overrides::env_value(&expected)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "x86_64-unknown-linux-gnu";

    fn req(tool: &str, version: &str) -> WithRequest {
        WithRequest {
            tool: tool.into(),
            version: version.into(),
        }
    }

    fn carrier(layer: &str, digest: &str, version: &str, runs: &str) -> Carrier {
        Carrier {
            layer: layer.parse().unwrap(),
            digest: digest.into(),
            version: version.into(),
            channel: "qualified".into(),
            platform: None,
            runs: runs.into(),
        }
    }

    fn choose_here(r: &WithRequest, here: &[Carrier]) -> Result<ToolOverride, RunWithError> {
        choose(r, "acme", "qualified", HOST, here, &[])
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_request_is_a_bare_tool_at_a_version() {
        assert_eq!(parse_request("synth@0.57.0"), Ok(req("synth", "0.57.0")));
        // The version may itself hold an '@' — only the first one splits.
        assert_eq!(
            parse_request("synth@0.57.0@x"),
            Ok(req("synth", "0.57.0@x"))
        );
        for bad in [
            "synth",
            "synth@",
            "@0.57.0",
            "acme/synth@0.57.0",
            "../synth@1",
            "synth@0.57 .0",
            "synth@0.57\t",
        ] {
            assert!(parse_request(bad).is_err(), "{bad:?} must be refused");
        }
        let why = parse_request("acme/synth@1").unwrap_err();
        assert!(why.contains("bare tool name"), "{why}");
        assert_eq!(req("synth", "0.57.0").to_string(), "synth@0.57.0");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn one_with_per_tool_in_any_spelling() {
        assert_eq!(
            check_distinct(&[req("synth", "1"), req("loom", "2")]),
            Ok(())
        );
        assert_eq!(check_distinct(&[]), Ok(()));
        let why =
            check_distinct(&[req("synth", "1"), req("loom", "2"), req("SYNTH", "1")]).unwrap_err();
        assert!(
            why.contains("synth@1") && why.contains("SYNTH@1"),
            "names both: {why}"
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_environment_value_is_tool_at_version_sorted() {
        assert_eq!(
            env_value(&[req("synth", "0.57.0"), req("loom", "2.0")]),
            "loom@2.0,synth@0.57.0"
        );
        assert_eq!(env_value(&[]), "");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_version_resolves_to_the_layer_that_carries_it() {
        let here = [
            carrier("2026.11.0", "sha256:b", "0.65.0", "sha256:new||||"),
            carrier("2026.08.0", "sha256:a", "0.57.0", "sha256:old||||"),
        ];
        let o = choose_here(&req("synth", "0.57.0"), &here).unwrap();
        assert_eq!(o.tool, "synth");
        assert_eq!(o.layer.to_string(), "2026.08.0");
        assert_eq!(o.digest, "sha256:a");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn several_layers_with_the_same_bytes_pick_the_least_whatever_the_order() {
        let a = carrier("2026.09.0", "sha256:c", "0.57.0", "sha256:same||||");
        let b = carrier("2026.08.0", "sha256:f", "0.57.0", "sha256:same||||");
        let c = carrier("2026.08.0", "sha256:d", "0.57.0", "sha256:same||||");
        for order in [
            vec![a.clone(), b.clone(), c.clone()],
            vec![c.clone(), b.clone(), a.clone()],
            vec![b.clone(), a.clone(), c.clone()],
        ] {
            let o = choose_here(&req("synth", "0.57.0"), &order).unwrap();
            assert_eq!(
                (o.layer.to_string(), o.digest.as_str()),
                ("2026.08.0".to_string(), "sha256:d")
            );
        }
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn several_layers_with_different_bytes_are_refused_and_listed() {
        let here = [
            carrier("2026.08.0", "sha256:a", "0.57.0", "sha256:one||||"),
            carrier("2026.09.0", "sha256:b", "0.57.0", "sha256:two||||"),
        ];
        let err = choose_here(&req("synth", "0.57.0"), &here).unwrap_err();
        assert!(
            matches!(err, RunWithError::Ambiguous { count: 2, .. }),
            "{err}"
        );
        let msg = err.to_string();
        for part in [
            "2026.08.0",
            "sha256:a",
            "sha256:one",
            "2026.09.0",
            "sha256:two",
        ] {
            assert!(msg.contains(part), "missing {part}: {msg}");
        }
        assert!(
            !msg.contains("||"),
            "the identity is shown as the binary: {msg}"
        );
        // The same binary through another runner is not the same thing run.
        let here = [
            carrier(
                "2026.08.0",
                "sha256:a",
                "0.57.0",
                "sha256:one|wasmtime|||sha256:w1",
            ),
            carrier(
                "2026.09.0",
                "sha256:b",
                "0.57.0",
                "sha256:one|wasmtime|||sha256:w2",
            ),
        ];
        assert!(matches!(
            choose_here(&req("synth", "0.57.0"), &here),
            Err(RunWithError::Ambiguous { .. })
        ));
        // A third, differing carrier that sorts FIRST is still caught.
        let here = [
            carrier("2026.08.0", "sha256:a", "0.57.0", "same"),
            carrier("2026.09.0", "sha256:b", "0.57.0", "same"),
            carrier("2026.07.0", "sha256:c", "0.57.0", "other"),
        ];
        assert!(matches!(
            choose_here(&req("synth", "0.57.0"), &here),
            Err(RunWithError::Ambiguous { count: 3, .. })
        ));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_version_nothing_installed_carries_is_refused_naming_what_is() {
        let here = [carrier("2026.11.0", "sha256:b", "0.65.0", "x")];
        let err = choose_here(&req("synth", "0.57.0"), &here).unwrap_err();
        assert!(matches!(err, RunWithError::NotInstalled { .. }), "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains("installed layers carry synth: 0.65.0 (layer 2026.11.0 sha256:b)"),
            "{msg}"
        );
        assert!(msg.contains("never fetches"), "{msg}");
        assert!(msg.contains("[toolchain.override.synth]"), "{msg}");
        assert!(msg.contains("realm acme"), "{msg}");
        // Nothing at all installed carries the tool.
        let msg = choose_here(&req("synth", "0.57.0"), &[])
            .unwrap_err()
            .to_string();
        assert!(!msg.contains("installed layers carry"), "{msg}");
        // A carrier that states no version says so.
        let msg = choose_here(
            &req("synth", "0.57.0"),
            &[carrier("2026.11.0", "sha256:b", "", "x")],
        )
        .unwrap_err()
        .to_string();
        assert!(msg.contains("no version stated (layer 2026.11.0"), "{msg}");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_version_installed_only_in_another_realm_prints_the_lines_that_would_install_it() {
        let away = [
            carrier("2026.08.0", "sha256:a", "0.57.0", "x"),
            carrier("2026.08.0", "sha256:a", "0.57.0", "x"),
            carrier("2026.09.0", "sha256:z", "0.65.0", "x"),
        ];
        let err = choose(
            &req("synth", "0.57.0"),
            "acme",
            "qualified",
            HOST,
            &[],
            &away,
        )
        .unwrap_err();
        assert!(matches!(err, RunWithError::OnlyElsewhere { .. }), "{err}");
        let msg = err.to_string();
        let lines = toml_lines("synth", "2026.08.0", "sha256:a");
        assert!(msg.ends_with(&lines), "{msg}");
        assert_eq!(
            msg.matches("[toolchain.override.synth]").count(),
            1,
            "deduplicated, and only the matching version: {msg}"
        );
        assert!(!msg.contains("sha256:z"), "{msg}");
        assert_eq!(
            lines,
            "[toolchain.override.synth]\nlayer = \"2026.08.0\"\ndigest = \"sha256:a\"\n"
        );
        // A layer installed here is preferred over one elsewhere.
        let here = [carrier("2026.09.0", "sha256:h", "0.57.0", "y")];
        let o = choose(
            &req("synth", "0.57.0"),
            "acme",
            "qualified",
            HOST,
            &here,
            &away,
        )
        .unwrap();
        assert_eq!(o.digest, "sha256:h");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_layer_the_pin_cannot_take_an_override_from_is_no_candidate() {
        let mut rolling = carrier("2026.08.0", "sha256:r", "0.57.0", "one");
        rolling.channel = "rolling".into();
        let mut foreign = carrier("2026.08.1", "sha256:p", "0.57.0", "two");
        foreign.platform = Some("aarch64-apple-darwin".into());
        let err =
            choose_here(&req("synth", "0.57.0"), &[rolling.clone(), foreign.clone()]).unwrap_err();
        assert!(matches!(err, RunWithError::NotUsable { .. }), "{err}");
        let msg = err.to_string();
        assert!(
            msg.contains("channel 'rolling'") && msg.contains("'qualified'"),
            "{msg}"
        );
        assert!(
            msg.contains("aarch64-apple-darwin") && msg.contains(HOST),
            "{msg}"
        );
        // …and does not make a usable one ambiguous.
        let mut mine = carrier("2026.09.0", "sha256:m", "0.57.0", "three");
        mine.platform = Some(HOST.into());
        let o = choose_here(&req("synth", "0.57.0"), &[rolling, foreign, mine]).unwrap();
        assert_eq!(o.digest, "sha256:m");
        // A layer from before channels contradicts no pin.
        let mut old = carrier("2026.07.0", "sha256:o", "0.57.0", "four");
        old.channel = String::new();
        assert_eq!(
            choose_here(&req("synth", "0.57.0"), &[old]).unwrap().digest,
            "sha256:o"
        );
    }

    fn manifest(layer: &str, channel: &str, entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let entries: Vec<String> = entries
            .iter()
            .map(|(tool, version, extra)| {
                format!(
                    r#"{{"digest":"sha256:{tool}{version}","annotations":{{"eu.pulseengine.tool":"{tool}","eu.pulseengine.tool.version":"{version}"{extra}}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"{channel}"}},"manifests":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn carriers_read_each_installed_layers_signed_version_for_this_host() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path());
        let runnered = r#","eu.pulseengine.runner":"wasmtime","eu.pulseengine.runner-args":"run -S","eu.pulseengine.runner-arg-prefix":"--""#;
        let older = store
            .lay_down(
                &manifest(
                    "2026.08.0",
                    "qualified",
                    &[
                        ("synth", "0.57.0", ""),
                        ("loom", "1.0", runnered),
                        ("wasmtime", "9", ""),
                        ("lonely", "1", r#","eu.pulseengine.runner":"absent""#),
                    ],
                ),
                &[
                    ("synth", b"s"),
                    ("loom", b"l"),
                    ("wasmtime", b"w"),
                    ("lonely", b"x"),
                ],
            )
            .unwrap();
        let riscv_only = r#","eu.pulseengine.platform":"riscv64-unknown-linux-gnu""#;
        store
            .lay_down_payloads(
                &manifest(
                    "2026.11.0",
                    "rolling",
                    &[
                        ("synth", "0.65.0", riscv_only),
                        ("held", "1", r#","eu.pulseengine.varve.kind":"crate""#),
                    ],
                ),
                &[crate::store::Payload::tool("synth", b"s2")],
            )
            .unwrap();
        let synth = carriers(&store, "synth", HOST).unwrap();
        assert_eq!(
            synth.len(),
            1,
            "the other synth is for another platform: {synth:?}"
        );
        let c = &synth[0];
        assert_eq!(c.layer.to_string(), "2026.08.0");
        assert_eq!(c.digest, older);
        assert_eq!(c.version, "0.57.0");
        assert_eq!(c.channel, "qualified");
        assert_eq!(c.platform, None);
        assert_eq!(c.runs, "sha256:synth0.57.0||||");
        // For the platform it ships for, it is a carrier, with its channel.
        let riscv = carriers(&store, "synth", "riscv64-unknown-linux-gnu").unwrap();
        assert_eq!(riscv.len(), 2);
        assert!(
            riscv
                .iter()
                .any(|c| c.version == "0.65.0" && c.channel == "rolling")
        );
        // A held payload is not dispatched, so not a carrier.
        assert!(carriers(&store, "held", HOST).unwrap().is_empty());
        // A runnered tool's identity holds its contract and the runner's bytes.
        let loom = carriers(&store, "loom", HOST).unwrap();
        assert_eq!(
            loom[0].runs,
            "sha256:loom1.0|wasmtime|run -S|--|sha256:wasmtime9"
        );
        let lonely = carriers(&store, "lonely", HOST).unwrap();
        assert_eq!(lonely[0].runs, "sha256:lonely1|absent|||(not carried)");
        // An empty store carries nothing; an unreadable manifest is an error.
        assert!(
            carriers(&Store::at(tmp.path().join("none")), "synth", HOST)
                .unwrap()
                .is_empty()
        );
        let layer_json = tmp
            .path()
            .join("core")
            .join(older.replace(':', "-"))
            .join("layer.json");
        let mut bytes = std::fs::read(&layer_json).unwrap();
        bytes.truncate(bytes.len() - 3);
        std::fs::write(&layer_json, bytes).unwrap();
        assert!(carriers(&store, "synth", HOST).is_err());
    }

    fn record() -> ShimRecord {
        ShimRecord {
            pin: "/p/varve.toml".into(),
            overrides: vec![crate::overrides::RecordedOverride {
                tool: "synth".into(),
                layer: "2026.08.0".into(),
                digest: "sha256:a".into(),
            }],
            with: vec![req("synth", "0.57.0")],
        }
    }

    fn uid_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().uid()
    }

    fn private_dir() -> tempfile::TempDir {
        // 0700 asked for explicitly, as varve's own is: tempfile's default
        // follows the umask, which leaves a directory others can read.
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .prefix("varve-with-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_wrapper_names_its_directory_in_its_own_text_and_quotes_everything() {
        let s = wrapper_script(
            std::path::Path::new("/opt/v arve/varve"),
            std::path::Path::new("/tmp/varve-with-x'y"),
            "synth",
        )
        .unwrap();
        assert_eq!(
            s,
            "#!/bin/sh\n# varve run --with: a private shim, honoured only while that run lives \
             (REQ-RUNWITH-001).\nexec '/opt/v arve/varve' run --with-shim-dir \
             '/tmp/varve-with-x'\\''y' -- 'synth' \"$@\"\n"
        );
        use std::os::unix::ffi::OsStrExt;
        let bad = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
        assert!(wrapper_script(bad, std::path::Path::new("/d"), "synth").is_err());
        assert!(wrapper_script(std::path::Path::new("/v"), bad, "synth").is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_live_directory_is_read_and_a_leaked_one_grants_nothing() {
        let dir = private_dir();
        let uid = uid_of(dir.path());
        let lock = fill_shim_dir(dir.path(), &record(), std::path::Path::new("/v")).unwrap();
        // The wrapper is there, 0700, and the record reads back whole.
        use std::os::unix::fs::PermissionsExt;
        let shim = dir.path().join("synth");
        assert_eq!(
            std::fs::metadata(&shim).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            std::fs::read_to_string(&shim)
                .unwrap()
                .contains("--with-shim-dir")
        );
        assert_eq!(read_shim_dir(dir.path(), uid), Ok(record()));
        // Another user's directory, or one others can read, is refused.
        let why = read_shim_dir(dir.path(), uid + 1).unwrap_err();
        assert!(why.contains("private"), "{why}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(read_shim_dir(dir.path(), uid).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o702)).unwrap();
        assert!(read_shim_dir(dir.path(), uid).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // An edited record is refused when this varve cannot read it whole.
        std::fs::write(dir.path().join(RECORD_FILE), "{\"pin\":\"/p\",\"x\":1}").unwrap();
        let why = read_shim_dir(dir.path(), uid).unwrap_err();
        assert!(why.contains("unreadable record"), "{why}");
        // The run is gone (its lock released): refused, record never read.
        drop(lock);
        let why = read_shim_dir(dir.path(), uid).unwrap_err();
        assert!(why.contains("outlived"), "{why}");
        // No lock file, or not a directory at all.
        std::fs::remove_file(dir.path().join(LOCK_FILE)).unwrap();
        assert!(
            read_shim_dir(dir.path(), uid)
                .unwrap_err()
                .contains("no lock")
        );
        assert!(read_shim_dir(&shim, uid).is_err());
        assert!(read_shim_dir(&dir.path().join("absent"), uid).is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_live_directory_without_a_record_is_refused() {
        let dir = private_dir();
        let uid = uid_of(dir.path());
        let lock = std::fs::File::create(dir.path().join(LOCK_FILE)).unwrap();
        lock.lock().unwrap();
        assert!(
            read_shim_dir(dir.path(), uid)
                .unwrap_err()
                .contains("no record")
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_exit_status_is_the_childs_or_128_plus_its_signal() {
        assert_eq!(exit_code(Some(0), None), 0);
        assert_eq!(exit_code(Some(7), None), 7);
        assert_eq!(exit_code(None, Some(15)), 143);
        assert_eq!(exit_code(None, Some(2)), 130);
        assert_eq!(exit_code(None, None), 1);
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_concurrent_prober_does_not_make_a_leaked_directory_look_alive() {
        // Review finding 1: probing with the EXCLUSIVE lock made the directory
        // look alive to any other prober holding it at that instant.
        let dir = private_dir();
        let uid = uid_of(dir.path());
        drop(fill_shim_dir(dir.path(), &record(), std::path::Path::new("/v")).unwrap());
        let other_prober = std::fs::File::open(dir.path().join(LOCK_FILE)).unwrap();
        other_prober.lock_shared().unwrap();
        let why = read_shim_dir(dir.path(), uid).unwrap_err();
        assert!(why.contains("outlived"), "{why}");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn only_an_ascii_bare_name_or_an_explicit_path_may_run_unlisted() {
        for ok in ["make", "sh", "/bin/sh", "./bench.sh", "../x/run", "a-b_c.1"] {
            assert!(may_run_unlisted(ok), "{ok}");
        }
        for no in [
            "zzz/loom",
            "acme/synth",
            "\u{17f}ynth",
            "b/./x",
            "",
            "x/../y",
        ] {
            assert!(!may_run_unlisted(no), "{no:?}");
        }
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_temp_parent_must_be_ours_or_roots_and_not_open_without_the_sticky_bit() {
        let p = std::path::Path::new("/t");
        assert_eq!(check_temp_parent(p, 501, 0o40700, 501), Ok(()));
        assert_eq!(check_temp_parent(p, 0, 0o41777, 501), Ok(()), "/tmp");
        assert_eq!(check_temp_parent(p, 501, 0o40755, 501), Ok(()));
        let why = check_temp_parent(p, 502, 0o40700, 501).unwrap_err();
        assert!(why.contains("another user"), "{why}");
        for open in [0o40777, 0o40770, 0o40702, 0o40720] {
            let why = check_temp_parent(p, 501, open, 501).unwrap_err();
            assert!(why.contains("others can write"), "{open:o}: {why}");
        }
        assert_eq!(check_temp_parent(p, 501, 0o41770, 501), Ok(()));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_temp_parent_inside_the_varve_root_or_the_project_is_refused() {
        let root = std::path::Path::new("/home/u/.varve");
        let project = std::path::Path::new("/src/proj");
        let roots = [root, project];
        assert_eq!(
            check_not_inside(std::path::Path::new("/tmp"), &roots),
            Ok(())
        );
        assert_eq!(
            check_not_inside(std::path::Path::new("/src/project-tmp"), &roots),
            Ok(()),
            "a path component, not a string prefix"
        );
        for inside in ["/src/proj", "/src/proj/tmp", "/home/u/.varve/tmp"] {
            let why = check_not_inside(std::path::Path::new(inside), &roots).unwrap_err();
            assert!(why.contains("inside"), "{inside}: {why}");
        }
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn an_outer_shim_directory_on_path_is_found() {
        let outer = private_dir();
        let plain = private_dir();
        std::fs::write(outer.path().join(RECORD_FILE), "{}").unwrap();
        std::fs::write(outer.path().join(LOCK_FILE), "").unwrap();
        std::fs::write(plain.path().join(RECORD_FILE), "{}").unwrap();
        let path = std::env::join_paths([plain.path(), outer.path()]).unwrap();
        assert_eq!(
            outer_shim_dir(Some(&path)),
            Some(outer.path().to_path_buf())
        );
        let path = std::env::join_paths([plain.path()]).unwrap();
        assert_eq!(
            outer_shim_dir(Some(&path)),
            None,
            "a record alone is not one"
        );
        assert_eq!(outer_shim_dir(None), None);
        // A relative entry is never taken for one.
        let rel = std::env::join_paths(["relative-dir"]).unwrap();
        assert_eq!(outer_shim_dir(Some(&rel)), None);
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_record_must_say_exactly_what_its_with_resolves_to() {
        let chosen = |layer: &str, digest: &str| ToolOverride {
            tool: "synth".into(),
            layer: layer.parse().unwrap(),
            digest: digest.into(),
        };
        assert_eq!(
            record_matches(&record(), &[chosen("2026.08.0", "sha256:a")]),
            Ok(())
        );
        let why = record_matches(&record(), &[chosen("2026.09.0", "sha256:a")]).unwrap_err();
        assert!(
            why.contains("does not match") && why.contains("2026.09.0"),
            "{why}"
        );
        assert!(record_matches(&record(), &[chosen("2026.08.0", "sha256:b")]).is_err());
        assert!(record_matches(&record(), &[]).is_err());
        let mut two = record();
        two.overrides.push(crate::overrides::RecordedOverride {
            tool: "loom".into(),
            layer: "2026.08.0".into(),
            digest: "sha256:a".into(),
        });
        assert!(record_matches(&two, &[chosen("2026.08.0", "sha256:a")]).is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn every_directory_above_tmpdir_is_checked() {
        let chain = |modes: &[(&str, u32, u32)]| -> Vec<(std::path::PathBuf, u32, u32)> {
            modes.iter().map(|(p, o, m)| (p.into(), *o, *m)).collect()
        };
        let safe = chain(&[
            ("/home/u/tmp", 501, 0o40700),
            ("/home/u", 501, 0o40755),
            ("/home", 0, 0o40755),
            ("/", 0, 0o40755),
        ]);
        assert_eq!(check_temp_ancestors(&safe, 501), Ok(()));
        // A foreign-writable, non-sticky ANCESTOR, the checked dir itself fine.
        let open_above = chain(&[
            ("/v/h/tmp", 501, 0o40700),
            ("/v/h", 501, 0o40775),
            ("/", 0, 0o40755),
        ]);
        let why = check_temp_ancestors(&open_above, 501).unwrap_err();
        assert!(
            why.contains("/v/h ") && why.contains("others can write"),
            "{why}"
        );
        // Another user's ancestor.
        let foreign = chain(&[("/s/tmp", 501, 0o40700), ("/s", 502, 0o40755)]);
        assert!(
            check_temp_ancestors(&foreign, 501)
                .unwrap_err()
                .contains("another user")
        );
        // A sticky world-writable ancestor (as /tmp) is fine.
        let sticky = chain(&[
            ("/tmp/x", 501, 0o40700),
            ("/tmp", 0, 0o41777),
            ("/", 0, 0o40755),
        ]);
        assert_eq!(check_temp_ancestors(&sticky, 501), Ok(()));
        assert_eq!(check_temp_ancestors(&[], 501), Ok(()));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_created_directory_must_be_ours_a_directory_and_0700() {
        let p = std::path::Path::new("/t/varve-with-x");
        assert_eq!(check_created_dir(p, true, 501, 0o40700, 501), Ok(()));
        assert!(
            check_created_dir(p, false, 501, 0o40700, 501).is_err(),
            "a link or file"
        );
        assert!(
            check_created_dir(p, true, 502, 0o40700, 501).is_err(),
            "another owner"
        );
        for mode in [0o40755, 0o40701, 0o40710, 0o41700, 0o40600] {
            assert!(
                check_created_dir(p, true, 501, mode, 501).is_err(),
                "{mode:o}"
            );
        }
    }
}
