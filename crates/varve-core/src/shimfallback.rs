//! What a refused shim can still tell you (REQ-SHIMFALLBACK-001, varve#273).
//!
//! A shim asked for a tool the pinned layer does not carry refuses. It never
//! runs an ambient binary: that is the mixed-toolchain hazard varve exists to
//! close, and REQ-SHADOW-001 reports exactly that shadowing as a defect. But a
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
            p.display()
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
        assert!(s.contains("/opt/bin/ghost '--version'"), "{s}");
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
            bare.ends_with("directly, outside the layer: /opt/bin/ghost"),
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
