//! What a refused shim can still tell you (REQ-SHIMFALLBACK-001, varve#273).
//!
//! A shim asked for a tool the pinned layer does not carry refuses. By default
//! it never runs an ambient binary: that is the mixed-toolchain hazard varve
//! exists to close, and REQ-SHADOW-001 reports exactly that shadowing as a
//! defect. The one exception is a USER-level opt-in (REQ-PASSTHROUGH-001,
//! further down, decided 2026-11-10 after varve#273); without it, the refusal
//! below is exactly what happens. But a
//! bare refusal leaves the person with a tool installed locally and no way to
//! use it that they can see. So the refusal LISTS the options and runs none:
//! the executable on PATH (with the command that runs it directly, outside
//! varve), and every installed layer that carries the tool (with the pin
//! change that would select it).
//!
//! Everything here is a pure read. Nothing executes, nothing is installed, and
//! no pin is written.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::pin::Channel;
use crate::store::Store;

/// Every executable named `tool` on `path_var`, in PATH order, as a shell
/// would find them — except that `shim_dir` is skipped. The shim directory
/// holds a link to varve under this very name, so without the exclusion the
/// refusal would offer the shim as the way around itself.
///
/// An entry is skipped when it canonicalizes to the shim directory, so a
/// symlinked or `..`-spelled route to it does not slip through. The same
/// executable reached through two PATH entries is listed once.
pub fn on_path(path_var: Option<&OsStr>, tool: &str, shim_dir: &Path) -> Vec<PathBuf> {
    if tool.is_empty() || tool.contains('/') || tool.contains('\\') {
        return Vec::new();
    }
    let Some(path_var) = path_var else {
        return Vec::new();
    };
    let shim_canon = std::fs::canonicalize(shim_dir).ok();
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for dir in std::env::split_paths(path_var) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let dir_canon = std::fs::canonicalize(&dir).ok();
        if dir == shim_dir || (dir_canon.is_some() && dir_canon == shim_canon) {
            continue;
        }
        let candidate = dir.join(tool);
        if !crate::shadow::is_executable_file(&candidate) {
            continue;
        }
        let key = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(candidate);
    }
    out
}

/// One installed layer that carries the tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    /// The realm partition's fingerprint, `None` for the top-level store.
    pub partition: Option<String>,
    /// Whether this is the partition the project's pin resolves in. When it
    /// is not, selecting the layer also means changing realm.
    pub in_pin_partition: bool,
    pub layer: String,
    pub channel: String,
    pub digest: String,
}

/// Every installed layer, in any partition under the varve root, whose
/// dispatchable `bin/` carries `tool`. `exclude_digest` is the layer the pin
/// already resolves (it was just found not to carry it). Sorted by layer,
/// then partition, then digest, so the output is stable run to run.
pub fn carriers(store: &Store, tool: &str, exclude_digest: &str) -> Vec<Carrier> {
    let mut out = Vec::new();
    for (partition, part) in store.partitions() {
        let Ok(layers) = part.list() else { continue };
        for layer in layers {
            if layer.digest == exclude_digest || part.tool_path(&layer, tool).is_none() {
                continue;
            }
            out.push(Carrier {
                in_pin_partition: part.root() == store.root(),
                partition: partition.clone(),
                layer: layer.layer.to_string(),
                channel: layer.channel.clone(),
                digest: layer.digest.clone(),
            });
        }
    }
    out.sort_by(|a, b| {
        (&a.layer, &a.partition, &a.digest).cmp(&(&b.layer, &b.partition, &b.digest))
    });
    out
}

/// The lines to put in `varve.toml` to select `c`, given the current pin.
fn pin_change(c: &Carrier, pin_channel: Channel, pin_realm: Option<&str>) -> String {
    let mut lines = vec![format!("layer = \"{}\"", c.layer)];
    if !c.channel.is_empty() && c.channel != pin_channel.as_str() {
        lines.push(format!("channel = \"{}\"", c.channel));
    }
    if !c.in_pin_partition {
        lines.push(match (&c.partition, pin_realm) {
            (Some(fp), _) => format!(
                "realm = <the realm whose trust-root fingerprint is {fp}> (this layer is \
                 installed under another realm)"
            ),
            (None, Some(r)) => format!(
                "remove the `realm = \"{r}\"` line (this layer is installed outside any realm)"
            ),
            (None, None) => String::new(),
        });
    }
    lines.retain(|l| !l.is_empty());
    lines.join("; ")
}

/// The refusal's second half: what the person can do instead. Never empty —
/// when there is nothing to offer, that is said outright rather than left as
/// two blank headings.
pub fn describe(
    tool: &str,
    args_quoted: &str,
    pin_file: &Path,
    on_path: &[PathBuf],
    carriers: &[Carrier],
    pin_channel: Channel,
    pin_realm: Option<&str>,
) -> String {
    let mut s = String::from("varve ran nothing. ");
    if on_path.is_empty() && carriers.is_empty() {
        s.push_str(&format!(
            "Nothing else provides '{tool}': no executable of that name is on PATH \
             (outside the shim directory) and no installed layer carries it."
        ));
        return s;
    }
    s.push_str("Options (varve will not pick one for you):");
    for p in on_path {
        let suffix = if args_quoted.is_empty() {
            String::new()
        } else {
            format!(" {args_quoted}")
        };
        s.push_str(&format!(
            "\n  - '{tool}' is on PATH at {} — it is NOT part of the pinned layer. Run it \
             directly, outside the layer: {}{suffix}",
            p.display(),
            crate::shellquote::quote_sh(&p.to_string_lossy())
        ));
    }
    for c in carriers {
        s.push_str(&format!(
            "\n  - installed layer {} ({}) carries '{tool}'. To select it, set in {}: {}",
            c.layer,
            c.channel,
            pin_file.display(),
            pin_change(c, pin_channel, pin_realm)
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Passthrough (REQ-PASSTHROUGH-001, revising the decision above)
//
// The refusal above stays the default. A person may now say, in a file that
// belongs to THEM and not to any repository, that the shim for a tool the
// pinned layer does not carry may run the executable found on PATH. Four
// things keep that from reopening the hole REQ-SHADOW-001 closes:
//
//   * the grant lives outside every repository — a committed `varve.toml`
//     cannot carry it, and a file that is inside the repository is refused
//     even when an environment variable the repository controls points at it;
//   * a tool the layer CARRIES never reads this file at all (the caller only
//     asks after the layer has said it does not carry the tool);
//   * the search can never land on a shim — this one's or another root's;
//   * every use is announced on stderr, and every session that allowed it is
//     recorded where verify, exports and attestations can show it.
// ---------------------------------------------------------------------------

/// The user-level configuration, relative to the config home.
pub const USER_CONFIG_FILE: &str = "varve/config.toml";

/// Which tools a user's shims may pass through to PATH.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Allow {
    /// No configuration, or one that lists nothing: the refusal stands.
    #[default]
    Nothing,
    /// `*`: any tool the layer does not carry.
    Everything,
    Tools(std::collections::BTreeSet<String>),
}

impl Allow {
    /// Whether the user's configuration names `tool` (or `*`). This is NOT
    /// the whole decision: the layer carrying the tool overrides it.
    pub fn permits(&self, tool: &str) -> bool {
        match self {
            Allow::Nothing => false,
            Allow::Everything => true,
            Allow::Tools(t) => t.contains(tool),
        }
    }

    /// What gets recorded in a stamp or a statement: `["*"]`, the sorted
    /// names, or nothing at all.
    pub fn recorded(&self) -> Vec<String> {
        match self {
            Allow::Nothing => Vec::new(),
            Allow::Everything => vec!["*".to_string()],
            Allow::Tools(t) => t.iter().cloned().collect(),
        }
    }
}

/// The text of `[shim] passthrough`, shared by every line that reports it.
pub fn describe_allow(recorded: &[String]) -> String {
    if recorded.iter().any(|t| t == "*") {
        "every tool the layer does not carry (`*`)".to_string()
    } else {
        recorded.join(", ")
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    #[serde(default)]
    shim: ShimSection,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ShimSection {
    #[serde(default)]
    passthrough: Vec<String>,
}

/// Parse the user configuration. Unknown keys are an error, not ignored: a
/// misspelt `passthru` that silently allowed nothing is a setting that looks
/// applied and is not.
pub fn parse_config(text: &str) -> Result<Allow, String> {
    let cfg: UserConfig = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut tools = std::collections::BTreeSet::new();
    for name in cfg.shim.passthrough {
        if name == "*" {
            return Ok(Allow::Everything);
        }
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(format!(
                "passthrough entry {name:?} is not a tool name (a bare name, or `*`)"
            ));
        }
        tools.insert(name);
    }
    Ok(if tools.is_empty() {
        Allow::Nothing
    } else {
        Allow::Tools(tools)
    })
}

/// Where the user configuration would be: `$XDG_CONFIG_HOME/varve/config.toml`
/// when that variable is an ABSOLUTE path (the XDG rule: a relative one is
/// invalid and ignored, and it would otherwise resolve against the working
/// directory, which is the repository), else `$HOME/.config/varve/config.toml`.
pub fn config_path(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    let base = match xdg.map(Path::new) {
        Some(x) if x.is_absolute() => x.to_path_buf(),
        _ => {
            let home = Path::new(home?);
            if !home.is_absolute() {
                return None;
            }
            home.join(".config")
        }
    };
    Some(base.join(USER_CONFIG_FILE))
}

/// The repository root above `cwd` that `config` lies inside, if any: the
/// nearest ancestor holding a `varve.toml` or a `.git` that contains it.
/// Both sides are canonicalized, so a symlink (or a `..`) cannot launder a
/// repository file into a "user" one.
pub fn repository_holding(config: &Path, cwd: &Path) -> Option<PathBuf> {
    let config = std::fs::canonicalize(config).ok()?;
    let cwd = std::fs::canonicalize(cwd).ok()?;
    cwd.ancestors()
        .find(|dir| {
            (dir.join("varve.toml").exists() || dir.join(".git").exists())
                && config.starts_with(dir)
        })
        .map(Path::to_path_buf)
}

/// Why the user configuration did not take effect.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigProblem {
    InRepository { config: PathBuf, repo: PathBuf },
    Unreadable { config: PathBuf, why: String },
    Invalid { config: PathBuf, why: String },
}

impl std::fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigProblem::InRepository { config, repo } => write!(
                f,
                "the user configuration {} is inside the repository {}, so it is ignored: \
                 passthrough can only be enabled from a file outside every repository \
                 (a committed file would switch it on for everyone who clones)",
                config.display(),
                repo.display()
            ),
            ConfigProblem::Unreadable { config, why } => {
                write!(
                    f,
                    "cannot read the user configuration {}: {why}",
                    config.display()
                )
            }
            ConfigProblem::Invalid { config, why } => write!(
                f,
                "the user configuration {} is not valid, so passthrough is off: {why}",
                config.display()
            ),
        }
    }
}

/// A loaded user configuration: what it allows and the file that said so.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UserPassthrough {
    pub allow: Allow,
    pub source: Option<PathBuf>,
}

/// Read the user configuration. No file is no passthrough; a file that is
/// inside the repository, unreadable or invalid is a [`ConfigProblem`] and
/// grants nothing.
pub fn load(
    xdg: Option<&OsStr>,
    home: Option<&OsStr>,
    cwd: &Path,
) -> Result<UserPassthrough, ConfigProblem> {
    let Some(config) = config_path(xdg, home) else {
        return Ok(UserPassthrough::default());
    };
    // The repository check comes BEFORE the read: a repository's file is
    // never even opened as configuration.
    if let Some(repo) = repository_holding(&config, cwd) {
        return Err(ConfigProblem::InRepository { config, repo });
    }
    let text = match std::fs::read_to_string(&config) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UserPassthrough::default());
        }
        Err(e) => {
            return Err(ConfigProblem::Unreadable {
                config,
                why: e.to_string(),
            });
        }
    };
    match parse_config(&text) {
        Ok(allow) => Ok(UserPassthrough {
            allow,
            source: Some(config),
        }),
        Err(why) => Err(ConfigProblem::Invalid { config, why }),
    }
}

/// Whether `candidate` is the varve binary itself (a shim is a link to it).
fn is_varve(candidate: &Path, self_exe: Option<&Path>) -> bool {
    let Some(me) = self_exe else { return false };
    match (std::fs::canonicalize(candidate), std::fs::canonicalize(me)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The executable a passed-through shim would run: the first `tool` on PATH
/// that is neither inside `shim_dir` nor varve itself. Skipping only the shim
/// directory is not enough: another varve root's shim directory is a different
/// path to the same binary, and running it would dispatch back through varve.
pub fn ambient_binary(
    path_var: Option<&OsStr>,
    tool: &str,
    shim_dir: &Path,
    self_exe: Option<&Path>,
) -> Option<PathBuf> {
    on_path(path_var, tool, shim_dir)
        .into_iter()
        .find(|p| !is_varve(p, self_exe))
}

/// The one stderr line a passed-through run prints (REQ-PASSTHROUGH-001
/// clause 3): the binary, and that it is not the layer's.
pub fn notice(tool: &str, binary: &Path, layer: &str, config: Option<&Path>) -> String {
    let by = match config {
        Some(c) => format!("allowed by {}", c.display()),
        None => "allowed by your user configuration".to_string(),
    };
    format!(
        "varve: passthrough: '{tool}' is not part of layer {layer}; running {} outside the \
         layer (not verified by varve; {by})",
        binary.display()
    )
}

/// One tool whose shim would currently pass through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    pub tool: String,
    /// What it would run, or `None` when nothing on PATH answers to the name.
    pub binary: Option<PathBuf>,
}

/// The passthroughs in force: every allowed tool the layer does not carry.
/// Under `*` the candidates are the installed shims (there is no other finite
/// list), and only those that actually resolve to something are reported.
pub fn active(
    allow: &Allow,
    carried: &[String],
    shim_names: &[String],
    path_var: Option<&OsStr>,
    shim_dir: &Path,
    self_exe: Option<&Path>,
) -> Vec<Active> {
    let mut names: Vec<String> = match allow {
        Allow::Nothing => Vec::new(),
        Allow::Everything => shim_names.to_vec(),
        Allow::Tools(t) => t.iter().cloned().collect(),
    };
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|n| !carried.iter().any(|c| c.eq_ignore_ascii_case(n)))
        .map(|tool| {
            let binary = ambient_binary(path_var, &tool, shim_dir, self_exe);
            Active { tool, binary }
        })
        .filter(|a| a.binary.is_some() || !matches!(allow, Allow::Everything))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    fn joined(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs).unwrap()
    }

    fn carrier(layer: &str, channel: &str, in_pin: bool, partition: Option<&str>) -> Carrier {
        Carrier {
            partition: partition.map(str::to_string),
            in_pin_partition: in_pin,
            layer: layer.into(),
            channel: channel.into(),
            digest: format!("sha256:{layer}"),
        }
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn the_direct_command_survives_a_path_with_a_space() {
        let p = PathBuf::from("/opt/my tools/ghost");
        let s = describe(
            "ghost",
            "'--version'",
            Path::new("/p/varve.toml"),
            std::slice::from_ref(&p),
            &[],
            Channel::Rolling,
            None,
        );
        assert!(
            s.contains("outside the layer: '/opt/my tools/ghost' '--version'"),
            "the command must paste into a shell as one word: {s}"
        );
    }

    #[test]
    fn on_path_skips_the_shim_directory_however_it_is_spelled() {
        let shims = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        exe(shims.path(), "ghost");
        let real = exe(other.path(), "ghost");
        let spelled = shims
            .path()
            .join("..")
            .join(shims.path().file_name().unwrap());
        let path = joined(&[&spelled, shims.path(), other.path()]);
        assert_eq!(on_path(Some(&path), "ghost", shims.path()), vec![real]);
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn on_path_lists_each_executable_once_in_path_order_and_skips_non_executables() {
        let shims = tempfile::tempdir().unwrap();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(data.path().join("ghost"), "not executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                data.path().join("ghost"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let first = exe(a.path(), "ghost");
        let second = exe(b.path(), "ghost");
        let path = joined(&[data.path(), a.path(), b.path(), a.path()]);
        assert_eq!(
            on_path(Some(&path), "ghost", shims.path()),
            vec![first, second]
        );
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn on_path_refuses_names_that_are_paths_or_empty_and_no_path() {
        let d = tempfile::tempdir().unwrap();
        exe(d.path(), "ghost");
        let path = joined(&[d.path()]);
        let none = tempfile::tempdir().unwrap();
        assert!(on_path(Some(&path), "", none.path()).is_empty());
        assert!(on_path(Some(&path), "./ghost", none.path()).is_empty());
        assert!(on_path(Some(&path), "a\\ghost", none.path()).is_empty());
        assert!(on_path(None, "ghost", none.path()).is_empty());
        assert_eq!(on_path(Some(&path), "ghost", none.path()).len(), 1);
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn describe_says_so_when_nothing_else_provides_the_tool() {
        let s = describe(
            "ghost",
            "",
            Path::new("/p/varve.toml"),
            &[],
            &[],
            Channel::Qualified,
            None,
        );
        assert!(s.contains("Nothing else provides 'ghost'"), "{s}");
        assert!(!s.contains("Options"), "{s}");
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn describe_gives_the_direct_command_with_its_arguments() {
        let s = describe(
            "ghost",
            "'--version'",
            Path::new("/p/varve.toml"),
            &[PathBuf::from("/opt/bin/ghost")],
            &[],
            Channel::Qualified,
            None,
        );
        assert!(s.contains("varve ran nothing"), "{s}");
        assert!(s.contains("'/opt/bin/ghost' '--version'"), "{s}");
        assert!(!s.contains("Nothing else"), "{s}");
        let bare = describe(
            "ghost",
            "",
            Path::new("/p/varve.toml"),
            &[PathBuf::from("/opt/bin/ghost")],
            &[],
            Channel::Qualified,
            None,
        );
        assert!(
            bare.ends_with("directly, outside the layer: '/opt/bin/ghost'"),
            "{bare}"
        );
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn pin_change_names_channel_and_realm_only_when_they_differ() {
        let same = carrier("2026.09.0", "qualified", true, None);
        assert_eq!(
            pin_change(&same, Channel::Qualified, None),
            "layer = \"2026.09.0\""
        );
        let chan = carrier("2026.09.0", "rolling", true, None);
        assert_eq!(
            pin_change(&chan, Channel::Qualified, None),
            "layer = \"2026.09.0\"; channel = \"rolling\""
        );
        let unlabelled = carrier("2026.09.0", "", true, None);
        assert_eq!(
            pin_change(&unlabelled, Channel::Rolling, None),
            "layer = \"2026.09.0\""
        );
        let realmless = carrier("2026.09.0", "qualified", false, None);
        let s = pin_change(&realmless, Channel::Qualified, Some("acme"));
        assert!(s.contains("remove the `realm = \"acme\"` line"), "{s}");
        let other = carrier("2026.09.0", "qualified", false, Some("ab12"));
        let s = pin_change(&other, Channel::Qualified, Some("acme"));
        assert!(s.contains("fingerprint is ab12"), "{s}");
        let s = pin_change(&other, Channel::Qualified, None);
        assert!(s.contains("fingerprint is ab12"), "{s}");
        // Not in the pin's partition, no realm on either side: nothing to say.
        let odd = carrier("2026.09.0", "qualified", false, None);
        assert_eq!(
            pin_change(&odd, Channel::Qualified, None),
            "layer = \"2026.09.0\""
        );
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn describe_lists_every_carrier_with_the_pin_line() {
        let s = describe(
            "ghost",
            "",
            Path::new("/p/varve.toml"),
            &[],
            &[
                carrier("2026.08.0", "qualified", true, None),
                carrier("2026.09.0", "rolling", true, None),
            ],
            Channel::Qualified,
            None,
        );
        assert!(
            s.contains("installed layer 2026.08.0 (qualified) carries 'ghost'"),
            "{s}"
        );
        assert!(
            s.contains("set in /p/varve.toml: layer = \"2026.08.0\"\n"),
            "{s}"
        );
        assert!(
            s.contains("layer = \"2026.09.0\"; channel = \"rolling\""),
            "{s}"
        );
        assert!(!s.contains("Nothing else"), "{s}");
        assert!(!s.contains("on PATH"), "{s}");
    }

    // rivet: verifies REQ-SHIMFALLBACK-001
    #[test]
    fn carriers_are_sorted_exclude_the_pinned_layer_and_span_partitions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path());
        let manifest = |layer: &str, ch: &str| {
            format!(
                r#"{{"schemaVersion":2,"annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"{ch}"}},"manifests":[]}}"#
            )
        };
        let late = store
            .lay_down(
                manifest("2026.09.0", "rolling").as_bytes(),
                &[("ghost", b"x")],
            )
            .unwrap();
        let early = store
            .lay_down(
                manifest("2026.08.0", "qualified").as_bytes(),
                &[("ghost", b"x")],
            )
            .unwrap();
        store
            .lay_down(
                manifest("2026.07.0", "qualified").as_bytes(),
                &[("other", b"x")],
            )
            .unwrap();
        let realm = Store::at(tmp.path().join("realms").join("ab12"));
        let in_realm = realm
            .lay_down(
                manifest("2026.06.0", "qualified").as_bytes(),
                &[("ghost", b"x")],
            )
            .unwrap();

        let got = carriers(&store, "ghost", "sha256:none");
        let layers: Vec<&str> = got.iter().map(|c| c.layer.as_str()).collect();
        assert_eq!(layers, ["2026.06.0", "2026.08.0", "2026.09.0"]);
        assert_eq!(got[0].digest, in_realm);
        assert_eq!(got[0].partition.as_deref(), Some("ab12"));
        assert!(!got[0].in_pin_partition);
        assert_eq!(got[1].digest, early);
        assert!(got[1].in_pin_partition && got[1].partition.is_none());
        assert_eq!(got[2].channel, "rolling");

        // From the realm partition's point of view the pin partition flips.
        let from_realm = carriers(&realm, "ghost", "sha256:none");
        let flags: Vec<(&str, bool)> = from_realm
            .iter()
            .map(|c| (c.layer.as_str(), c.in_pin_partition))
            .collect();
        assert_eq!(
            flags,
            [
                ("2026.06.0", true),
                ("2026.08.0", false),
                ("2026.09.0", false)
            ]
        );

        // The layer the pin already resolves is never offered back.
        let without = carriers(&store, "ghost", &late);
        assert_eq!(without.len(), 2);
        assert!(without.iter().all(|c| c.digest != late));
        assert!(carriers(&store, "nobody-has-this", "x").is_empty());
    }
}

#[cfg(test)]
mod passthrough_tests {
    use super::*;
    use std::ffi::OsString;

    fn tools(names: &[&str]) -> Allow {
        Allow::Tools(names.iter().map(|s| s.to_string()).collect())
    }

    #[cfg(unix)]
    fn exe(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn os(p: &Path) -> OsString {
        p.as_os_str().to_os_string()
    }

    fn write_config(home: &Path, body: &str) -> PathBuf {
        let cfg = home.join(USER_CONFIG_FILE);
        std::fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        std::fs::write(&cfg, body).unwrap();
        cfg
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn the_config_names_tools_or_star_and_nothing_else() {
        assert_eq!(parse_config("").unwrap(), Allow::Nothing);
        assert_eq!(parse_config("[shim]\n").unwrap(), Allow::Nothing);
        assert_eq!(
            parse_config("[shim]\npassthrough = []\n").unwrap(),
            Allow::Nothing
        );
        assert_eq!(
            parse_config("[shim]\npassthrough = [\"b\", \"a\", \"b\"]\n").unwrap(),
            tools(&["a", "b"])
        );
        assert_eq!(
            parse_config("[shim]\npassthrough = [\"*\"]\n").unwrap(),
            Allow::Everything
        );
        assert_eq!(
            parse_config("[shim]\npassthrough = [\"a\", \"*\"]\n").unwrap(),
            Allow::Everything
        );
        for bad in [
            "[shim]\npassthrough = [\"\"]\n",
            "[shim]\npassthrough = [\"a/b\"]\n",
            "[shim]\npassthrough = [\"a\\\\b\"]\n",
            "[shim]\npassthru = [\"a\"]\n",
            "[shim]\npassthrough = [\"a\"]\nextra = 1\n",
            "[other]\nx = 1\n",
            "passthrough = [\"a\"]\n",
            "[shim\n",
        ] {
            assert!(parse_config(bad).is_err(), "accepted {bad:?}");
        }
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn what_is_allowed_is_recorded_as_star_or_sorted_names() {
        assert!(!Allow::Nothing.permits("a"));
        assert!(Allow::Everything.permits("anything"));
        assert!(tools(&["a"]).permits("a"));
        assert!(!tools(&["a"]).permits("b"));
        assert!(Allow::Nothing.recorded().is_empty());
        assert_eq!(Allow::Everything.recorded(), ["*"]);
        assert_eq!(tools(&["b", "a"]).recorded(), ["a", "b"]);
        assert!(describe_allow(&["*".to_string()]).contains("every tool"));
        assert_eq!(describe_allow(&["a".to_string(), "b".to_string()]), "a, b");
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn the_config_home_is_absolute_xdg_else_home_dot_config() {
        let abs = OsString::from("/x/cfg");
        let home = OsString::from("/h");
        let rel = OsString::from("rel");
        let want = |base: &str| PathBuf::from(base).join(USER_CONFIG_FILE);
        assert_eq!(config_path(Some(&abs), Some(&home)), Some(want("/x/cfg")));
        assert_eq!(config_path(Some(&abs), None), Some(want("/x/cfg")));
        assert_eq!(config_path(None, Some(&home)), Some(want("/h/.config")));
        // A relative or empty XDG_CONFIG_HOME is invalid: fall back, never use it.
        assert_eq!(
            config_path(Some(&rel), Some(&home)),
            Some(want("/h/.config"))
        );
        assert_eq!(
            config_path(Some(OsStr::new("")), Some(&home)),
            Some(want("/h/.config"))
        );
        assert_eq!(config_path(Some(&rel), None), None);
        assert_eq!(config_path(None, None), None);
        assert_eq!(config_path(None, Some(&rel)), None);
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn a_config_is_in_the_repository_when_an_ancestor_marker_contains_it() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let sub = repo.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let canon = std::fs::canonicalize(&repo).unwrap();
        let inside = write_config(&repo.join(".cfg"), "");
        let outside = write_config(&tmp.path().join("home"), "");

        // No marker yet: not a repository.
        assert_eq!(repository_holding(&inside, &sub), None);
        // `.git` marks it, and a file outside it is not inside it.
        std::fs::create_dir(repo.join(".git")).unwrap();
        assert_eq!(repository_holding(&inside, &sub), Some(canon.clone()));
        assert_eq!(repository_holding(&outside, &sub), None);
        // `varve.toml` marks one too.
        std::fs::remove_dir(repo.join(".git")).unwrap();
        assert_eq!(repository_holding(&inside, &sub), None);
        std::fs::write(repo.join("varve.toml"), "").unwrap();
        assert_eq!(repository_holding(&inside, &sub), Some(canon));
        // A marker NEARER the config than the cwd is not an ancestor of cwd.
        std::fs::remove_file(repo.join("varve.toml")).unwrap();
        std::fs::create_dir(repo.join(".cfg/.git")).unwrap();
        assert_eq!(repository_holding(&inside, &sub), None);
        // A missing config cannot be placed.
        assert_eq!(repository_holding(&repo.join("nope"), &sub), None);
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_launder_a_repository_config() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(repo.join("cfg")).unwrap();
        std::fs::create_dir(repo.join(".git")).unwrap();
        let real = write_config(&repo.join("cfg"), "");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(repo.join("cfg"), &link).unwrap();
        let spelled = link.join(USER_CONFIG_FILE);
        assert!(spelled.exists() && real.exists());
        assert!(repository_holding(&spelled, &repo).is_some());
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn load_grants_only_from_a_valid_file_outside_the_repository() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("varve.toml"), "").unwrap();
        let home = tmp.path().join("home");

        // No file at all, and no variable at all.
        assert_eq!(
            load(Some(&os(&home)), None, &repo).unwrap(),
            UserPassthrough::default()
        );
        assert_eq!(load(None, None, &repo).unwrap(), UserPassthrough::default());

        // A good file.
        let cfg = write_config(&home, "[shim]\npassthrough = [\"a\"]\n");
        let got = load(Some(&os(&home)), None, &repo).unwrap();
        assert_eq!(got.allow, tools(&["a"]));
        assert_eq!(got.source, Some(cfg));

        // The same kind of file named through HOME.
        let h = tmp.path().join("h2");
        write_config(&h.join(".config"), "[shim]\npassthrough = [\"*\"]\n");
        assert_eq!(
            load(None, Some(&os(&h)), &repo).unwrap().allow,
            Allow::Everything
        );

        // A bad file grants nothing and says why.
        let bad = tmp.path().join("bad");
        let badcfg = write_config(&bad, "[shim]\npassthru = []\n");
        match load(Some(&os(&bad)), None, &repo).unwrap_err() {
            ConfigProblem::Invalid { config, why } => {
                assert_eq!(config, badcfg);
                assert!(why.contains("unknown field"), "{why}");
            }
            other => panic!("{other:?}"),
        }

        // A directory where the file should be is unreadable, not absent.
        let dir = tmp.path().join("dirhome");
        std::fs::create_dir_all(dir.join(USER_CONFIG_FILE)).unwrap();
        assert!(matches!(
            load(Some(&os(&dir)), None, &repo).unwrap_err(),
            ConfigProblem::Unreadable { .. }
        ));

        // Inside the repository: never read, even though it is valid.
        let in_repo = repo.join("xdg");
        write_config(&in_repo, "[shim]\npassthrough = [\"*\"]\n");
        match load(Some(&os(&in_repo)), None, &repo).unwrap_err() {
            ConfigProblem::InRepository { repo: r, .. } => {
                assert_eq!(r, std::fs::canonicalize(&repo).unwrap());
            }
            other => panic!("{other:?}"),
        }
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn each_problem_says_what_it_is() {
        let c = PathBuf::from("/c/config.toml");
        let in_repo = ConfigProblem::InRepository {
            config: c.clone(),
            repo: PathBuf::from("/r"),
        }
        .to_string();
        assert!(in_repo.contains("inside the repository /r"), "{in_repo}");
        assert!(in_repo.contains("/c/config.toml"), "{in_repo}");
        let bad = ConfigProblem::Invalid {
            config: c.clone(),
            why: "boom".into(),
        }
        .to_string();
        assert!(
            bad.contains("boom") && bad.contains("passthrough is off"),
            "{bad}"
        );
        let unreadable = ConfigProblem::Unreadable {
            config: c,
            why: "denied".into(),
        }
        .to_string();
        assert!(unreadable.contains("denied") && unreadable.contains("cannot read"));
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[cfg(unix)]
    #[test]
    fn the_ambient_binary_is_never_a_shim_of_any_root() {
        let shims = tempfile::tempdir().unwrap();
        let other_shims = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        let varve = exe(real.path(), "varve");
        std::os::unix::fs::symlink(&varve, shims.path().join("ghost")).unwrap();
        std::os::unix::fs::symlink(&varve, other_shims.path().join("ghost")).unwrap();
        let path = std::env::join_paths([shims.path(), other_shims.path()]).unwrap();

        // Only shims on PATH: nothing to run.
        assert_eq!(
            ambient_binary(Some(&path), "ghost", shims.path(), Some(&varve)),
            None
        );
        // Another root's shim is skipped by identity, the real one is found.
        let ghost = exe(real.path(), "ghost");
        let path = std::env::join_paths([other_shims.path(), real.path()]).unwrap();
        assert_eq!(
            ambient_binary(Some(&path), "ghost", shims.path(), Some(&varve)),
            Some(ghost.clone())
        );
        // Without a known self, only the shim directory itself is skipped.
        assert_eq!(
            ambient_binary(Some(&path), "ghost", other_shims.path(), None),
            Some(ghost)
        );
        assert_eq!(ambient_binary(None, "ghost", shims.path(), None), None);
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[test]
    fn the_notice_names_the_tool_the_binary_the_layer_and_the_grant() {
        let n = notice(
            "ghost",
            Path::new("/opt/ghost"),
            "2026.07.0",
            Some(Path::new("/u/config.toml")),
        );
        assert!(n.starts_with("varve: passthrough: 'ghost'"), "{n}");
        assert!(n.contains("2026.07.0"), "{n}");
        assert!(n.contains("running /opt/ghost outside the layer"), "{n}");
        assert!(n.contains("allowed by /u/config.toml"), "{n}");
        assert!(!n.contains('\n'));
        let anon = notice("ghost", Path::new("/opt/ghost"), "l", None);
        assert!(
            anon.contains("allowed by your user configuration"),
            "{anon}"
        );
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[cfg(unix)]
    #[test]
    fn active_passthroughs_are_the_allowed_tools_the_layer_does_not_carry() {
        let shims = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let ghost = exe(bin.path(), "ghost");
        exe(bin.path(), "probe");
        let path = os(bin.path());
        let carried = vec!["probe".to_string()];
        let names = vec!["ghost".to_string(), "probe".to_string(), "mute".to_string()];
        let act = |allow: &Allow| active(allow, &carried, &names, Some(&path), shims.path(), None);

        assert!(act(&Allow::Nothing).is_empty());
        // Listed: carried tools drop out (clause 2); an unanswered name stays.
        assert_eq!(
            act(&tools(&["probe", "ghost", "absent"])),
            vec![
                Active {
                    tool: "absent".into(),
                    binary: None
                },
                Active {
                    tool: "ghost".into(),
                    binary: Some(ghost.clone())
                },
            ]
        );
        // `*`: the shims, minus carried, minus those nothing answers to.
        assert_eq!(
            act(&Allow::Everything),
            vec![Active {
                tool: "ghost".into(),
                binary: Some(ghost)
            }]
        );
    }

    // rivet: verifies REQ-PASSTHROUGH-001
    #[cfg(unix)]
    #[test]
    fn a_carried_name_blocks_a_spelling_in_another_case() {
        let shims = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        exe(bin.path(), "PROBE");
        let path = os(bin.path());
        let carried = vec!["probe".to_string()];
        let names = vec!["PROBE".to_string()];
        assert!(
            active(
                &Allow::Everything,
                &carried,
                &names,
                Some(&path),
                shims.path(),
                None
            )
            .is_empty()
        );
    }
}
