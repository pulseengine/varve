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
    if tool.eq_ignore_ascii_case(CONTROL) {
        return Err(format!(
            "--with {spec:?}: {tool:?} is reserved — it names the control directory of a \
             --with run's private shims"
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
// PATH. For each overridden tool the directory holds a wrapper, a one-line
// script whose first line names varve itself (`SHIM_MARKER`): run, it hands
// varve its own path, so the directory is known from where the wrapper IS,
// never from the environment, and no shell ever reads it. The directory also holds the
// record of what the run resolved (`RECORD_FILE`) and a lock the run holds
// for its whole life (`LOCK_FILE`).
//
// A shim reading the directory first checks that the lock is still HELD. An
// advisory lock dies with its holder, whatever kills it — SIGKILL included —
// so a directory that outlived its run (a leak) grants nothing, and its record
// is not even read. While the run lives, the record is re-verified against the
// store exactly as a varve.toml override is (`resolve`), so an edited record
// can name only what the pin could have overridden anyway.

/// The control subdirectory of a private shim directory. The directory on
/// PATH holds nothing but wrappers, one per `--with` tool, and this; the
/// interpreter and every control file live in here, so no tool's wrapper can
/// ever share a name with them (and `.v` itself is a reserved tool name).
pub const CONTROL: &str = ".v";
/// The record of what a `--with` run resolved.
pub const RECORD_FILE: &str = ".v/with.json";
/// Held, exclusively, by the run for its whole life.
pub const LOCK_FILE: &str = ".v/owner.lock";

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

/// The first argument of a private shim's invocation. A wrapper is a one-line
/// script, `#!<varve> --varve-with-shim`: the kernel runs
/// `<varve> --varve-with-shim <the wrapper's path> <args…>`, so varve learns
/// the directory and the tool from the path it was run as. No shell reads the
/// wrapper — `SHELLOPTS`, `BASH_FUNC_*`, `ENV` and `BASH_ENV` cannot reach it.
pub const SHIM_MARKER: &str = "--varve-with-shim";
/// The first argument of the gate (`varve run --with`'s own binary, re-run).
pub const GATE_MARKER: &str = "--varve-with-gate";
/// A wrapper that only proves programs in the directory can be executed.
pub const PROBE: &str = ".v/probe";
/// Written last; the gate execs the command only once it exists.
pub const GO_FILE: &str = ".v/go";
/// varve itself, inside the private directory: the wrappers' interpreter and
/// the gate. A hard link (or copy) that lives exactly as long as the
/// directory, so an upgrade or cleanup of the installed binary meanwhile
/// cannot leave the wrappers naming a file that is gone.
pub const INTERPRETER: &str = ".v/varve";
/// Every private shim directory's name starts with this. Only PATH entries so
/// named are ever looked at (`outer_shim_dirs`): any other entry is skipped
/// without a single system call, so a hung network mount on PATH cannot hang
/// a plain run or a shim.
pub const SHIM_DIR_PREFIX: &str = "varve-with-";

/// The text of every wrapper in a private shim directory. The shebang line
/// holds varve's absolute path and the marker and nothing else: a kernel
/// takes the interpreter up to the first blank, and Linux reads at most 255
/// bytes of the line, so a path with a blank or control character, or one
/// too long, is refused rather than truncated into another program.
pub fn wrapper_text(varve: &std::path::Path) -> Result<String, String> {
    let shown = varve
        .to_str()
        .filter(|s| varve.is_absolute() && !s.chars().any(|c| c.is_whitespace() || c.is_control()))
        .ok_or_else(|| {
            format!(
                "{} cannot be named in a script's first line (it must be an absolute path \
                 without blanks or control characters) — --with cannot make its shims",
                varve.display()
            )
        })?;
    let line = format!("#!{shown} {SHIM_MARKER}\n");
    if line.len() > 255 {
        return Err(format!(
            "{} is too long to name in a script's first line (at most 255 bytes) — --with \
             cannot make its shims",
            varve.display()
        ));
    }
    Ok(line)
}

/// Is `script` the probe wrapper (`<dir>/.v/probe`)?
pub fn is_probe(script: &std::path::Path) -> bool {
    script.ends_with(PROBE)
}

/// Is `argv0` a private interpreter (`…/varve-with-…/.v/varve`)? The kernel
/// runs a wrapper's interpreter under the path its first line names, so the
/// shim marker is honoured only from there — a regular shim whose first
/// argument happens to be the marker is not taken over.
pub fn is_interpreter_path(argv0: &std::path::Path) -> bool {
    argv0.ends_with(INTERPRETER)
        && argv0
            .parent()
            .and_then(|control| control.parent())
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(SHIM_DIR_PREFIX))
}

/// The name of a private shim directory, from two random words.
pub fn shim_dir_name(a: u64, b: u64) -> String {
    format!("{SHIM_DIR_PREFIX}{a:016x}{b:016x}")
}

/// A directory that is put on PATH must not contain `:` (PATH's separator)
/// or a newline: either would split it into other, unchecked directories.
pub fn check_path_chars(path: &std::path::Path) -> Result<(), String> {
    let bytes = path.as_os_str().as_encoded_bytes();
    match bytes.iter().find(|b| matches!(b, b':' | b'\n' | 0)) {
        Some(_) => Err(format!(
            "{} (TMPDIR) contains ':' or a newline, which would split PATH into other, \
             unchecked directories — point TMPDIR elsewhere",
            path.display()
        )),
        None => Ok(()),
    }
}

/// The version of the protocol between varve and its gate (the arguments,
/// the release marker, what the gate checks). Bumped with any change to it.
pub const GATE_PROTOCOL: u32 = 1;

/// This build's identity as a gate partner: varve's version and the gate
/// protocol. varve passes its own to the gate, which refuses a different one:
/// varve replaced by an upgrade between starting and spawning its gate could
/// otherwise pair two builds whose release protocols differ, and the gate
/// would wait forever.
pub fn build_identity() -> String {
    format!("{}+gate{GATE_PROTOCOL}", env!("CARGO_PKG_VERSION"))
}

/// The gate's check of the identity it was given against its own.
pub fn check_identity(asked: &str, ours: &str) -> Result<(), String> {
    if asked == ours {
        Ok(())
    } else {
        Err(format!(
            "this gate is varve {ours}, but the varve that started it is {asked} — varve was \
             replaced while it started (an upgrade?); run the command again"
        ))
    }
}

/// How long a gate waits to be released before giving up. Setup is purely
/// local — make a directory, link or copy one binary, write a few small
/// files, run one probe — so even a large copy on a heavily loaded runner is
/// seconds, not minutes; ten minutes cannot fire on a working setup, and it
/// still bounds a gate whose varve is wedged rather than gone.
pub const GATE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// The gate's arguments:
/// `--varve-with-gate <varve's pid> <identity> <dir> -- <program> <args…>`.
pub fn gate_args(
    parent: u32,
    identity: &str,
    dir: &std::path::Path,
    program: &std::ffi::OsStr,
    args: &[std::ffi::OsString],
) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> = vec![
        GATE_MARKER.into(),
        parent.to_string().into(),
        identity.into(),
        dir.as_os_str().to_os_string(),
        "--".into(),
        program.to_os_string(),
    ];
    out.extend(args.iter().cloned());
    out
}

/// The gate's request, parsed back: (varve's pid, dir, program, args).
pub type GateRequest = (
    u32,
    String,
    std::path::PathBuf,
    std::ffi::OsString,
    Vec<std::ffi::OsString>,
);

/// Parse what follows `--varve-with-gate`.
pub fn parse_gate_args(rest: &[std::ffi::OsString]) -> Result<GateRequest, String> {
    match rest {
        [parent, identity, dir, sep, program, args @ ..] if sep == "--" => {
            let parent = parent
                .to_str()
                .and_then(|p| p.parse::<u32>().ok())
                // varve may be pid 1 (a container's entrypoint, `unshare -pf`):
                // an orphaned gate sees parent 1 only if varve was not pid 1.
                .filter(|p| *p > 0)
                .ok_or("the gate needs varve's pid")?;
            let identity = identity
                .to_str()
                .ok_or("the gate needs varve's identity")?
                .to_string();
            Ok((parent, identity, dir.into(), program.clone(), args.to_vec()))
        }
        _ => {
            Err("usage: varve --varve-with-gate <pid> <identity> <dir> -- <program> [args…]".into())
        }
    }
}

/// What the gate does next: wait, give up (varve is gone, so nobody will
/// release it or clean up), or go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStep {
    Wait,
    Abandon,
    /// Not released within `GATE_DEADLINE`.
    TimedOut,
    Go,
}

pub fn gate_step(
    parent: u32,
    parent_now: u32,
    released: bool,
    waited: std::time::Duration,
) -> GateStep {
    if parent_now != parent {
        GateStep::Abandon
    } else if released {
        GateStep::Go
    } else if waited >= GATE_DEADLINE {
        GateStep::TimedOut
    } else {
        GateStep::Wait
    }
}

/// Before the gate execs, the directory and its release marker must be this
/// user's own: the directory a real directory, mode 0700, the marker a
/// regular file. The directory's name is visible to other users (the gate's
/// arguments); one they made in its place is never run from.
pub fn check_gate_dir(
    dir: &std::path::Path,
    dir_is_dir: bool,
    dir_owner: u32,
    dir_mode: u32,
    go_is_file: bool,
    go_owner: u32,
    uid: u32,
) -> Result<(), String> {
    if dir_is_dir && dir_owner == uid && dir_mode & 0o777 == 0o700 && go_is_file && go_owner == uid
    {
        Ok(())
    } else {
        Err(format!(
            "{} is not the private shim directory this run made — refusing to run from it",
            dir.display()
        ))
    }
}

/// The command's PATH: the private directory, then the inherited PATH. An
/// empty or absent inherited PATH adds nothing — an empty entry would mean
/// the working directory.
pub fn gate_path(
    dir: &std::path::Path,
    inherited: Option<&std::ffi::OsStr>,
) -> Result<std::ffi::OsString, String> {
    let mut entries = vec![dir.to_path_buf()];
    if let Some(inherited) = inherited.filter(|p| !p.is_empty()) {
        entries.extend(std::env::split_paths(inherited));
    }
    std::env::join_paths(entries).map_err(|e| e.to_string())
}

/// Does a record override `tool`, named bare or realm-qualified?
pub fn overrides_tool(record: &ShimRecord, tool: &str) -> bool {
    let bare = tool.rsplit('/').next().unwrap_or(tool);
    record.overrides.iter().any(|o| o.tool == bare)
}

/// Fill `dir` (created 0700 by the caller): take the lock FIRST, so no
/// wrapper ever exists without a live owner, then the record, then one
/// wrapper (0700) per override and the probe wrapper. Returns the lock: the
/// directory is honoured exactly as long as it is held.
#[cfg(unix)]
pub fn fill_shim_dir(
    dir: &std::path::Path,
    record: &ShimRecord,
    varve: &std::path::Path,
) -> Result<std::fs::File, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let io = |what: &str, e: std::io::Error| format!("{what} in {}: {e}", dir.display());
    let text = wrapper_text(varve)?;
    // Every file is created EXCLUSIVELY (O_EXCL): nothing is ever written
    // through a path that already exists, so a name collision refuses.
    let create = |rel: &str, mode: u32| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(dir.join(rel))
    };
    let lock = create(LOCK_FILE, 0o600).map_err(|e| io("lock", e))?;
    lock.lock().map_err(|e| io("lock", e))?;
    let json = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    create(RECORD_FILE, 0o600)
        .and_then(|mut f| f.write_all(&json))
        .map_err(|e| io("record", e))?;
    let names = record
        .overrides
        .iter()
        .map(|o| o.tool.as_str())
        .chain(std::iter::once(PROBE));
    for name in names {
        create(name, 0o700)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .map_err(|e| io(&format!("shim {name:?}"), e))?;
    }
    Ok(lock)
}

/// `O_NONBLOCK | O_NOFOLLOW` for opening a lock file: a FIFO planted under
/// that name must not hang the probe, and a symlink must not redirect it.
/// From the platform's own definitions (they differ between architectures:
/// O_NOFOLLOW is 0o400000 on x86_64 Linux but 0o100000 on aarch64).
#[cfg(unix)]
pub fn lock_open_flags() -> i32 {
    rustix::fs::OFlags::NONBLOCK
        .union(rustix::fs::OFlags::NOFOLLOW)
        .bits() as i32
}

/// What a directory's lock says about its run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Held exclusively: its run is alive.
    Held,
    /// Free: its run is gone.
    Free,
    /// Missing, not a regular file, or not probeable.
    Unusable,
}

/// Probe a directory's lock with a SHARED lock, never blocking: probers
/// never block each other, so only the live run's exclusive lock can fail
/// the probe (an exclusive probe made a dead directory look alive to every
/// other prober at that instant — 149 of 1200 concurrent calls ran).
#[cfg(unix)]
pub fn lock_state(dir: &std::path::Path) -> LockState {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(lock) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(lock_open_flags())
        .open(dir.join(LOCK_FILE))
    else {
        return LockState::Unusable;
    };
    if !lock.metadata().is_ok_and(|m| m.is_file()) {
        return LockState::Unusable;
    }
    match lock.try_lock_shared() {
        Ok(()) => LockState::Free,
        Err(std::fs::TryLockError::WouldBlock) => LockState::Held,
        Err(std::fs::TryLockError::Error(_)) => LockState::Unusable,
    }
}

/// Read a private shim directory, or refuse. Refused: a path that is not a
/// directory of `uid`'s, or that group or others can write or read; a
/// directory whose run is gone (its lock is not held) — then the record is
/// never read; a lock that is not a regular file; a record this varve cannot
/// read whole.
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
    match lock_state(dir) {
        LockState::Held => {}
        LockState::Free => {
            return Err(format!(
                "{} outlived the `varve run --with` that made it — its shims grant nothing \
                 after that run ends. Remove the directory.",
                dir.display()
            ));
        }
        LockState::Unusable => {
            return Err(format!("{}: no usable lock", dir.display()));
        }
    }
    let bytes = std::fs::read(dir.join(RECORD_FILE))
        .map_err(|e| format!("{}: no record: {e}", dir.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: unreadable record: {e}", dir.display()))
}

/// How `varve run --with` ends once its child has: with the child's exit
/// code; for a child killed by a signal that terminates without a core dump
/// (SIGHUP, SIGINT, SIGKILL, SIGPIPE, SIGALRM, SIGTERM), by dying of it
/// itself, after cleaning up — a shell running `varve run --with` in a loop
/// stops on Ctrl-C only if its foreground child died OF SIGINT. For any
/// other signal (the core-dumping SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE,
/// SIGQUIT, SIGTRAP, SIGSYS, and the rest) varve exits 128 + N instead:
/// re-raising those would crash varve and blame it for its child's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    Exit(i32),
    Die(i32),
}

/// The signals varve dies of when its child did: terminating, no core dump,
/// and numbered the same on Linux and macOS.
pub const REDELIVERED: [i32; 6] = [1, 2, 9, 13, 14, 15];

pub fn ending(code: Option<i32>, signal: Option<i32>) -> Ending {
    match (code, signal) {
        (Some(code), _) => Ending::Exit(code),
        (None, Some(signal)) if REDELIVERED.contains(&signal) => Ending::Die(signal),
        (None, Some(signal)) => Ending::Exit(128 + signal),
        (None, None) => Ending::Exit(1),
    }
}

// The signal numbers `varve run --with` decides about. The same on Linux and
// macOS; `varve`'s own tests check them against the platform's.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGTERM: i32 = 15;

/// The signals `varve run --with` catches while it sets up and while its
/// command runs, so that it outlives them to remove the private directory.
/// Every other signal that terminates varve (SIGKILL, and any it does not
/// catch) leaks the directory — which then grants nothing.
pub const CAUGHT: [i32; 4] = [SIGHUP, SIGINT, SIGQUIT, SIGTERM];

/// Is a caught signal passed on to the child? Only SIGTERM, which a
/// supervisor sends to one process. SIGINT, SIGQUIT and SIGHUP come from a
/// terminal to the whole foreground process group, which the child shares:
/// it has them already, and forwarding would deliver one Ctrl-C twice. A
/// SIGTERM sent to the whole group (timeout, systemd, `kill -- -pgid`) does
/// reach the child twice: whether a signal came from a group kill is not
/// visible to the receiver, and dropping SIGTERM would leave a supervisor
/// that signals varve alone waiting on a child that never heard.
pub fn forwards(signal: i32) -> bool {
    signal == SIGTERM
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
/// directory. `stat` gives (owner uid, mode) of a directory without following
/// a link; a directory it cannot read is refused.
pub fn check_temp_tree(
    parent: &std::path::Path,
    uid: u32,
    stat: impl Fn(&std::path::Path) -> Result<(u32, u32), String>,
) -> Result<(), String> {
    for dir in parent.ancestors() {
        let (owner, mode) = stat(dir)?;
        check_temp_parent(dir, owner, mode, uid)?;
    }
    Ok(())
}

/// The private directory is still the one this run made — same device and
/// inode — once its shims are written.
pub fn check_same_dir(
    path: &std::path::Path,
    made: (u64, u64),
    now: (u64, u64),
) -> Result<(), String> {
    if made == now {
        Ok(())
    } else {
        Err(format!(
            "{} was replaced while its shims were written — refusing to run",
            path.display()
        ))
    }
}

/// The program `varve run --with` starts for a command the layer does not
/// carry. A name with a `/` is an explicit path, taken as written. A bare name
/// is looked up in the ABSOLUTE entries of `path` only: an empty, `.` or other
/// relative entry means the working directory — the repository — and is
/// skipped, as passthrough skips it.
pub fn find_program(
    name: &str,
    path: Option<&std::ffi::OsStr>,
    is_program: impl Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    if name.contains('/') {
        let explicit = std::path::PathBuf::from(name);
        return is_program(&explicit).then_some(explicit);
    }
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_program(candidate))
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
    // The permission bits only: a setgid parent (Linux) makes it 02700.
    if !is_dir || owner != uid || mode & 0o777 != 0o700 {
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

/// The LIVE private shim directories on `path`: absolute entries holding a
/// record and a lock its run still holds. A leaked directory, a FIFO or link
/// planted as the lock, or an entry that cannot be read is skipped — never an
/// error, so a stray entry cannot make every run fail. What callers do with
/// one can only be to refuse, never to select a tool: ambient state (PATH,
/// the environment) never chooses what varve runs.
#[cfg(unix)]
pub fn outer_shim_dirs(path: Option<&std::ffi::OsStr>) -> Vec<std::path::PathBuf> {
    let Some(path) = path else {
        return Vec::new();
    };
    std::env::split_paths(path)
        .filter(|dir| {
            dir.is_absolute()
                && dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(SHIM_DIR_PREFIX))
                && std::fs::symlink_metadata(dir.join(RECORD_FILE)).is_ok_and(|m| m.is_file())
                && lock_state(dir) == LockState::Held
        })
        .collect()
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

    /// Tests that spawn processes, and tests that depend on a lock being
    /// RELEASED, take this: a child forked by another test thread holds a
    /// duplicate of every open fd until it execs, a lock's included, so a
    /// released lock could briefly look held. (varve itself spawns its gate
    /// before it creates the lock, and forks nothing else.)
    static FORK_OR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        FORK_OR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `released` becomes true within two seconds. A lock just
    /// released can look held for a moment while a child that another test
    /// (in any module) forked has not yet exec'd: it holds a duplicate of
    /// every open fd until then. A probe that never sees it free still fails.
    fn eventually(released: impl Fn() -> bool) -> bool {
        (0..200).any(|_| {
            released() || {
                std::thread::sleep(std::time::Duration::from_millis(10));
                false
            }
        })
    }

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
        let dir = private_dir_bare();
        std::fs::create_dir(dir.path().join(CONTROL)).unwrap();
        dir
    }

    fn private_dir_bare() -> tempfile::TempDir {
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
    fn a_live_directory_is_read_and_a_leaked_one_grants_nothing() {
        let _serial = serial();
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
        assert_eq!(
            std::fs::read_to_string(&shim).unwrap(),
            "#!/v --varve-with-shim\n"
        );
        assert!(dir.path().join(PROBE).is_file(), "the probe wrapper");
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
        assert!(
            eventually(|| read_shim_dir(dir.path(), uid).is_err_and(|why| why.contains("outlived"))),
            "{:?}",
            read_shim_dir(dir.path(), uid)
        );
        // No lock file, or not a directory at all.
        std::fs::remove_file(dir.path().join(LOCK_FILE)).unwrap();
        assert!(
            read_shim_dir(dir.path(), uid)
                .unwrap_err()
                .contains("no usable lock")
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
    fn a_concurrent_prober_does_not_make_a_leaked_directory_look_alive() {
        let _serial = serial();
        // Review finding 1: probing with the EXCLUSIVE lock made the directory
        // look alive to any other prober holding it at that instant.
        let dir = private_dir();
        let uid = uid_of(dir.path());
        drop(fill_shim_dir(dir.path(), &record(), std::path::Path::new("/v")).unwrap());
        let other_prober = std::fs::File::open(dir.path().join(LOCK_FILE)).unwrap();
        other_prober.lock_shared().unwrap();
        assert!(
            eventually(|| read_shim_dir(dir.path(), uid).is_err_and(|why| why.contains("outlived"))),
            "{:?}",
            read_shim_dir(dir.path(), uid)
        );
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
    fn only_sigterm_is_forwarded() {
        // A mutant forwarding SIGINT (or any terminal signal) fails here.
        assert!(forwards(SIGTERM));
        for terminal in [SIGINT, SIGQUIT, SIGHUP] {
            assert!(!forwards(terminal), "{terminal}");
        }
        assert!(!forwards(10) && !forwards(0));
        assert_eq!(CAUGHT, [SIGHUP, SIGINT, SIGQUIT, SIGTERM]);
        assert_eq!((SIGHUP, SIGINT, SIGQUIT, SIGTERM), (1, 2, 3, 15));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn every_directory_above_tmpdir_is_checked() {
        use std::collections::HashMap;
        let tree = |entries: &[(&str, u32, u32)]| -> HashMap<std::path::PathBuf, (u32, u32)> {
            entries
                .iter()
                .map(|(p, o, m)| (p.into(), (*o, *m)))
                .collect()
        };
        let walk = |fs: &HashMap<std::path::PathBuf, (u32, u32)>, start: &str| {
            check_temp_tree(std::path::Path::new(start), 501, |p| {
                fs.get(p)
                    .copied()
                    .ok_or_else(|| format!("{} unreadable", p.display()))
            })
        };
        let safe = tree(&[
            ("/home/u/tmp", 501, 0o40700),
            ("/home/u", 501, 0o40755),
            ("/home", 0, 0o40755),
            ("/", 0, 0o40755),
        ]);
        assert_eq!(walk(&safe, "/home/u/tmp"), Ok(()));
        // A foreign-writable, non-sticky ANCESTOR, the checked dir itself fine.
        let open_above = tree(&[
            ("/v/h/tmp", 501, 0o40700),
            ("/v/h", 501, 0o40775),
            ("/v", 0, 0o40755),
            ("/", 0, 0o40755),
        ]);
        let why = walk(&open_above, "/v/h/tmp").unwrap_err();
        assert!(
            why.contains("/v/h ") && why.contains("others can write"),
            "{why}"
        );
        // The top of the walk is checked too.
        let open_root = tree(&[("/t", 501, 0o40700), ("/", 0, 0o40777)]);
        assert!(walk(&open_root, "/t").is_err());
        // Another user's ancestor.
        let foreign = tree(&[
            ("/s/tmp", 501, 0o40700),
            ("/s", 502, 0o40755),
            ("/", 0, 0o40755),
        ]);
        assert!(
            walk(&foreign, "/s/tmp")
                .unwrap_err()
                .contains("another user")
        );
        // A sticky world-writable ancestor (as /tmp) is fine.
        let sticky = tree(&[
            ("/tmp/x", 501, 0o40700),
            ("/tmp", 0, 0o41777),
            ("/", 0, 0o40755),
        ]);
        assert_eq!(walk(&sticky, "/tmp/x"), Ok(()));
        // A directory that cannot be read is refused, never skipped.
        let gap = tree(&[("/a/b", 501, 0o40700), ("/", 0, 0o40755)]);
        assert!(walk(&gap, "/a/b").unwrap_err().contains("/a unreadable"));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_created_directory_must_be_ours_a_directory_and_0700() {
        let p = std::path::Path::new("/t/varve-with-x");
        assert_eq!(check_created_dir(p, true, 501, 0o40700, 501), Ok(()));
        assert_eq!(
            check_created_dir(p, true, 501, 0o42700, 501),
            Ok(()),
            "setgid from a Linux parent"
        );
        assert!(
            check_created_dir(p, false, 501, 0o40700, 501).is_err(),
            "a link or file"
        );
        assert!(
            check_created_dir(p, true, 502, 0o40700, 501).is_err(),
            "another owner"
        );
        for mode in [0o40755, 0o40701, 0o40710, 0o40600, 0o40500] {
            assert!(
                check_created_dir(p, true, 501, mode, 501).is_err(),
                "{mode:o}"
            );
        }
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_directory_must_still_be_the_one_made() {
        let p = std::path::Path::new("/t/d");
        assert_eq!(check_same_dir(p, (1, 2), (1, 2)), Ok(()));
        assert!(
            check_same_dir(p, (1, 2), (1, 3))
                .unwrap_err()
                .contains("replaced")
        );
        assert!(check_same_dir(p, (1, 2), (9, 2)).is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_bare_command_is_found_in_absolute_path_entries_only() {
        let exists = |p: &std::path::Path| {
            ["/usr/bin/make", "./make", "rel/make", "/opt/bin/zz"]
                .iter()
                .any(|e| std::path::Path::new(e) == p)
        };
        let path = std::env::join_paths([".", "rel", "", "/usr/bin", "/opt/bin"]).unwrap();
        assert_eq!(
            find_program("make", Some(&path), exists),
            Some("/usr/bin/make".into()),
            "never ./make or rel/make"
        );
        assert_eq!(
            find_program("zz", Some(&path), exists),
            Some("/opt/bin/zz".into())
        );
        let only_relative = std::env::join_paths([".", "rel"]).unwrap();
        assert_eq!(find_program("make", Some(&only_relative), exists), None);
        assert_eq!(find_program("make", None, exists), None);
        assert_eq!(find_program("nothing", Some(&path), exists), None);
        // An explicit path is taken as written — if it is a program at all.
        let explicit = |p: &std::path::Path| p == std::path::Path::new("./x.sh");
        assert_eq!(
            find_program("./x.sh", None, explicit),
            Some("./x.sh".into())
        );
        assert_eq!(find_program("./missing", None, explicit), None);
        assert_eq!(find_program("/bin/nothing", None, explicit), None);
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_wrapper_is_one_shebang_line_naming_varve_and_nothing_a_shell_reads() {
        assert_eq!(
            wrapper_text(std::path::Path::new("/opt/varve/bin/varve")),
            Ok("#!/opt/varve/bin/varve --varve-with-shim\n".to_string())
        );
        // A blank would end the interpreter early; a relative path or a
        // control character cannot be named; too long is truncated by Linux.
        for bad in ["/opt/v arve/varve", "varve", "/opt/v\tarve", "/opt/v\narve"] {
            assert!(wrapper_text(std::path::Path::new(bad)).is_err(), "{bad:?}");
        }
        let long = format!("/{}", "x".repeat(240));
        assert!(wrapper_text(std::path::Path::new(&long)).is_err());
        // The whole line, `#!` and newline included, is at most 127 bytes on
        // Linux (a_shebang_longer_than_an_old_kernel_reads_is_refused_naming_the_limit)
        // and 255 elsewhere.
        #[cfg(target_os = "linux")]
        let max = 127;
        #[cfg(not(target_os = "linux"))]
        let max = 255;
        let fits = format!("/{}", "x".repeat(max - 4 - SHIM_MARKER.len() - 1));
        assert!(
            wrapper_text(std::path::Path::new(&fits)).is_ok(),
            "exactly {max}"
        );
        let over = format!("/{}", "x".repeat(max - 4 - SHIM_MARKER.len()));
        assert!(
            wrapper_text(std::path::Path::new(&over)).is_err(),
            "{max} + 1"
        );
        use std::os::unix::ffi::OsStrExt;
        let not_utf8 = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/opt/\xff"));
        assert!(wrapper_text(not_utf8).is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[cfg(target_os = "linux")]
    #[test]
    fn a_shebang_longer_than_an_old_kernel_reads_is_refused_naming_the_limit() {
        // Linux before 5.1 (RHEL 8 runs 4.18) reads only 128 bytes of a
        // script's first line (BINPRM_BUF_SIZE) and silently cuts the rest, so
        // a long TMPDIR would truncate the interpreter's path to a name another
        // user can create in a sticky /tmp. A realistic shim directory under a
        // 65-byte TMPDIR: well inside the 255 a newer kernel reads, over 127.
        // A Linux build only: macOS reads 512 bytes, and its default TMPDIR
        // alone would push a shim's line past 127.
        let tmpdir = format!("/tmp/{}", "t".repeat(60));
        let varve =
            std::path::PathBuf::from(format!("{tmpdir}/{}/{INTERPRETER}", shim_dir_name(1, 2)));
        let line = 2 + varve.as_os_str().len() + 1 + SHIM_MARKER.len() + 1;
        assert!((128..=255).contains(&line), "{line}");
        let err = wrapper_text(&varve).expect_err("a first line over 127 bytes must be refused");
        assert!(err.contains("127"), "names the limit: {err}");
        assert!(err.contains("TMPDIR"), "says what to shorten: {err}");
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_shim_directory_name_is_two_random_words() {
        assert_eq!(
            shim_dir_name(1, 0xabc),
            "varve-with-00000000000000010000000000000abc"
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_directory_put_on_path_holds_no_separator_or_newline() {
        assert_eq!(check_path_chars(std::path::Path::new("/tmp/x")), Ok(()));
        for bad in ["/tmp/a:b", "/tmp/a\nb", "/t:"] {
            let why = check_path_chars(std::path::Path::new(bad)).unwrap_err();
            assert!(why.contains("split PATH"), "{bad:?}: {why}");
        }
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_gate_is_told_its_parent_directory_and_program() {
        let args = gate_args(
            4242,
            "0.48.0+gate1",
            std::path::Path::new("/t/varve-with-x"),
            std::ffi::OsStr::new("/bin/prog"),
            &["a b".into(), "--".into()],
        );
        let shown: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            shown,
            [
                GATE_MARKER,
                "4242",
                "0.48.0+gate1",
                "/t/varve-with-x",
                "--",
                "/bin/prog",
                "a b",
                "--"
            ]
        );
        assert_eq!(
            parse_gate_args(&args[1..]),
            Ok((
                4242,
                "0.48.0+gate1".into(),
                "/t/varve-with-x".into(),
                "/bin/prog".into(),
                vec!["a b".into(), "--".into()]
            ))
        );
        let s = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(
            parse_gate_args(&s(&["4242", "v", "/d", "/bin/p"])).is_err(),
            "no --"
        );
        assert!(
            parse_gate_args(&s(&["4242", "v", "/d", "x", "/bin/p"])).is_err(),
            "not -- where it belongs"
        );
        assert!(
            parse_gate_args(&s(&["x", "v", "/d", "--", "/bin/p"])).is_err(),
            "pid"
        );
        assert_eq!(
            parse_gate_args(&s(&["1", "v", "/d", "--", "/bin/p"])),
            Ok((1, "v".into(), "/d".into(), "/bin/p".into(), vec![])),
            "varve as pid 1 (a container's entrypoint)"
        );
        assert!(parse_gate_args(&s(&["0", "v", "/d", "--", "/bin/p"])).is_err());
        assert!(
            parse_gate_args(&s(&["4242", "v", "/d", "--"])).is_err(),
            "no program"
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_gate_goes_only_when_released_and_gives_up_when_varve_is_gone() {
        const ZERO: std::time::Duration = std::time::Duration::ZERO;
        // Waiting is bounded: past the deadline an unreleased gate gives up;
        // a release, or varve gone, still decides first.
        let late = GATE_DEADLINE;
        let almost = GATE_DEADLINE - std::time::Duration::from_millis(1);
        assert_eq!(gate_step(100, 100, false, almost), GateStep::Wait);
        assert_eq!(gate_step(100, 100, false, late), GateStep::TimedOut);
        assert_eq!(
            gate_step(100, 100, false, late + std::time::Duration::from_secs(1)),
            GateStep::TimedOut
        );
        assert_eq!(gate_step(100, 100, true, late), GateStep::Go);
        assert_eq!(gate_step(100, 1, false, late), GateStep::Abandon);
        assert!(GATE_DEADLINE >= std::time::Duration::from_secs(600));
        assert_eq!(gate_step(100, 100, false, ZERO), GateStep::Wait);
        assert_eq!(gate_step(1, 1, true, ZERO), GateStep::Go, "varve is pid 1");
        assert_eq!(gate_step(100, 100, true, ZERO), GateStep::Go);
        assert_eq!(gate_step(100, 1, false, ZERO), GateStep::Abandon);
        assert_eq!(
            gate_step(100, 1, true, ZERO),
            GateStep::Abandon,
            "orphaned: never go"
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_gate_runs_only_from_a_directory_and_marker_of_its_own() {
        let d = std::path::Path::new("/t/varve-with-x");
        let ok = |is_dir, dir_owner, mode, go_file, go_owner| {
            check_gate_dir(d, is_dir, dir_owner, mode, go_file, go_owner, 501)
        };
        assert_eq!(ok(true, 501, 0o40700, true, 501), Ok(()));
        assert_eq!(ok(true, 501, 0o42700, true, 501), Ok(()), "setgid parent");
        assert!(ok(false, 501, 0o40700, true, 501).is_err());
        assert!(
            ok(true, 502, 0o40700, true, 501).is_err(),
            "another user's dir"
        );
        assert!(ok(true, 501, 0o40755, true, 501).is_err());
        assert!(ok(true, 501, 0o40700, false, 501).is_err());
        assert!(
            ok(true, 501, 0o40700, true, 502).is_err(),
            "another user's marker"
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_commands_path_is_the_directory_then_the_inherited_path() {
        let d = std::path::Path::new("/t/d");
        assert_eq!(
            gate_path(d, Some(std::ffi::OsStr::new("/usr/bin:/bin"))),
            Ok("/t/d:/usr/bin:/bin".into())
        );
        assert_eq!(
            gate_path(d, Some(std::ffi::OsStr::new(""))),
            Ok("/t/d".into())
        );
        assert_eq!(gate_path(d, None), Ok("/t/d".into()));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_record_overrides_a_tool_by_its_bare_name() {
        assert!(overrides_tool(&record(), "synth"));
        assert!(overrides_tool(&record(), "acme/synth"));
        assert!(!overrides_tool(&record(), "loom"));
        assert!(!overrides_tool(&record(), "synthx"));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn only_non_core_terminating_signals_are_died_of() {
        assert_eq!(ending(Some(0), None), Ending::Exit(0));
        assert_eq!(ending(Some(7), None), Ending::Exit(7));
        for s in [1, 2, 9, 13, 14, 15] {
            assert_eq!(ending(None, Some(s)), Ending::Die(s), "{s}");
        }
        // Core-dumping (and anything else): exit 128 + N, never a crash of varve.
        for s in [3, 4, 5, 6, 8, 10, 11, 12, 24, 31] {
            assert_eq!(ending(None, Some(s)), Ending::Exit(128 + s), "{s}");
        }
        assert_eq!(ending(None, None), Ending::Exit(1));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn only_a_live_shim_directory_on_path_counts_and_nothing_can_hang_or_fail_the_probe() {
        let _serial = serial();
        let live = private_dir();
        let dead = private_dir();
        let fifo = private_dir();
        let link = private_dir();
        // A live-looking directory NOT named varve-with-*: never looked at.
        let other = tempfile::Builder::new()
            .prefix("not-varve-")
            .tempdir()
            .unwrap();
        std::fs::create_dir(other.path().join(CONTROL)).unwrap();
        std::fs::write(other.path().join(RECORD_FILE), "{}").unwrap();
        let other_lock = std::fs::File::create(other.path().join(LOCK_FILE)).unwrap();
        other_lock.lock().unwrap();
        for d in [&live, &dead, &fifo, &link] {
            std::fs::write(d.path().join(RECORD_FILE), "{}").unwrap();
        }
        let lock = std::fs::File::create(live.path().join(LOCK_FILE)).unwrap();
        lock.lock().unwrap();
        std::fs::File::create(dead.path().join(LOCK_FILE)).unwrap();
        // A FIFO named like the lock: opening it blocking would hang forever.
        let made = std::process::Command::new("mkfifo")
            .arg(fifo.path().join(LOCK_FILE))
            .status()
            .unwrap();
        assert!(made.success());
        // A link to the live lock is not a lock of its own.
        std::os::unix::fs::symlink(live.path().join(LOCK_FILE), link.path().join(LOCK_FILE))
            .unwrap();
        let path = std::env::join_paths([
            fifo.path(),
            dead.path(),
            link.path(),
            std::path::Path::new("relative-dir"),
            other.path(),
            live.path(),
        ])
        .unwrap();
        assert_eq!(
            outer_shim_dirs(Some(&path)),
            vec![live.path().to_path_buf()]
        );
        assert_eq!(lock_state(fifo.path()), LockState::Unusable);
        assert_eq!(lock_state(link.path()), LockState::Unusable);
        assert_eq!(lock_state(dead.path()), LockState::Free);
        assert_eq!(lock_state(live.path()), LockState::Held);
        drop(lock);
        assert!(
            eventually(|| outer_shim_dirs(Some(&path)).is_empty()),
            "its run ended"
        );
        assert!(outer_shim_dirs(None).is_empty());
        // read_shim_dir does not hang on a FIFO either.
        let uid = uid_of(fifo.path());
        assert!(
            read_shim_dir(fifo.path(), uid)
                .unwrap_err()
                .contains("no usable lock")
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_lock_is_opened_nonblocking_and_without_following_a_link() {
        let flags = rustix::fs::OFlags::from_bits_retain(lock_open_flags() as _);
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));
        assert!(flags.contains(rustix::fs::OFlags::NOFOLLOW));
        assert_eq!(
            flags,
            rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW
        );
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_tool_named_like_the_control_directory_is_refused_at_parse_time() {
        for name in [".v", ".V"] {
            let why = parse_request(&format!("{name}@1")).unwrap_err();
            assert!(why.contains("reserved"), "{name}: {why}");
        }
        assert!(
            parse_request(".go@1").is_ok(),
            "only the control directory is reserved"
        );
        assert!(parse_request("varve@1").is_ok());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_path_directory_holds_only_wrappers_and_nothing_is_written_through_an_existing_path() {
        let _serial = serial();
        let dir = private_dir();
        let mut rec = record();
        rec.overrides.push(crate::overrides::RecordedOverride {
            tool: "varve".into(),
            layer: "2026.08.0".into(),
            digest: "sha256:a".into(),
        });
        let interpreter = dir.path().join(INTERPRETER);
        std::fs::write(&interpreter, b"THE-INSTALLED-BINARY").unwrap();
        let lock = fill_shim_dir(dir.path(), &rec, &interpreter).unwrap();
        let mut top: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        top.sort();
        assert_eq!(
            top,
            [".v", "synth", "varve"],
            "only wrappers and the control dir"
        );
        assert_eq!(
            std::fs::read(&interpreter).unwrap(),
            b"THE-INSTALLED-BINARY",
            "a wrapper named varve never touches the interpreter"
        );
        for control in [LOCK_FILE, RECORD_FILE, PROBE] {
            assert!(dir.path().join(control).is_file(), "{control}");
        }
        drop(lock);
        // A path that already exists is never written through: refused.
        let taken = private_dir();
        std::fs::write(taken.path().join("synth"), b"already here").unwrap();
        assert!(fill_shim_dir(taken.path(), &record(), &interpreter).is_err());
        assert_eq!(
            std::fs::read(taken.path().join("synth")).unwrap(),
            b"already here"
        );
        let locked = private_dir();
        std::fs::write(locked.path().join(LOCK_FILE), b"").unwrap();
        assert!(fill_shim_dir(locked.path(), &record(), &interpreter).is_err());
        let recorded = private_dir();
        std::fs::write(recorded.path().join(RECORD_FILE), b"{}").unwrap();
        assert!(fill_shim_dir(recorded.path(), &record(), &interpreter).is_err());
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn the_probe_and_the_interpreter_are_known_by_where_they_are() {
        let p = std::path::Path::new;
        assert!(is_probe(p("/t/varve-with-x/.v/probe")));
        assert!(!is_probe(p("/t/varve-with-x/probe")), "a tool named probe");
        assert!(!is_probe(p("/t/varve-with-x/synth")));
        assert!(is_interpreter_path(p("/t/varve-with-x/.v/varve")));
        assert!(
            !is_interpreter_path(p("/t/varve-with-x/varve")),
            "a wrapper named varve"
        );
        assert!(
            !is_interpreter_path(p("/t/other/.v/varve")),
            "not a private dir"
        );
        assert!(!is_interpreter_path(p("/usr/local/bin/varve")));
        assert!(!is_interpreter_path(p("varve")));
    }

    // rivet: verifies REQ-RUNWITH-001
    #[test]
    fn a_gate_refuses_a_varve_of_another_build() {
        let ours = build_identity();
        assert!(ours.starts_with(env!("CARGO_PKG_VERSION")), "{ours}");
        assert!(ours.ends_with(&format!("+gate{GATE_PROTOCOL}")), "{ours}");
        assert_eq!(check_identity(&ours, &ours), Ok(()));
        let why = check_identity("0.0.1+gate1", &ours).unwrap_err();
        assert!(why.contains("0.0.1+gate1") && why.contains(&ours), "{why}");
        assert!(check_identity(&format!("{}+gate0", env!("CARGO_PKG_VERSION")), &ours).is_err());
        assert!(check_identity("", &ours).is_err());
    }
}
