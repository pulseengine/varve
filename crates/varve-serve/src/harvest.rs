//! Running a pinned tool's `--help`, in a box, and remembering the answer.
//!
//! **What is run.** Only a binary out of the verified store, whose path the
//! caller got from the signed manifest. Never a name looked up on `PATH`: an
//! ambient `rivet` is not the pinned `rivet`, and describing the wrong one is
//! worse than describing none.
//!
//! **What is run with it.** `--help`, and — only when that help LISTS a `docs`
//! subcommand — `docs` and `docs <topic>`. Never a bare `<tool> docs` on a
//! guess: `kilnd docs` starts the runtime.
//!
//! **The box.** A scrubbed environment (`PATH=/usr/bin:/bin`, `HOME` a fresh
//! empty directory), a fresh working directory, no stdin, output to files
//! bounded when read, and a timeout after which the child is killed and the
//! tool is recorded as having no help. This is hygiene against a tool that
//! reads its environment or its cwd, not a security sandbox: the binary is
//! already one the signed manifest vouches for and the user already runs.
//! There is no process-group kill, so a tool that forks and outlives its
//! parent can leave a grandchild behind on timeout.
//!
//! **The cache.** Keyed by the layer's manifest digest and bound to each
//! tool's signed binary digest, stored under the layer's store. A second
//! `context` therefore runs nothing. The cache is advisory and unsigned: it is
//! read only AFTER the layer verified, an entry whose binary digest differs is
//! ignored, and a cache that cannot be written is not an error.
//!
//! **Not here.** The signed `summary` / `docs-command` fields of a `[[tool]]`
//! entry in `layer.toml` (REQ-AGENTDOCS-001 clause 2) do not exist yet. When
//! they do, they take precedence over anything harvested; the seam is
//! [`Signed`], which `context::build` consults first. Nothing here reads or
//! writes it, and every harvested field says `harvested`.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::help::{self, parse_help, parse_topics};

/// How long one invocation may run.
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// The most output read from one stream of one invocation.
pub const MAX_OUTPUT: u64 = 262_144; // 256 KiB
/// The most topics fetched per tool.
pub const MAX_TOPICS: usize = 64;
/// Bumped when the cache's shape or the harvesting rules change.
pub const CACHE_VERSION: u64 = 1;

/// Values a layer's signer may declare for a tool, which win over harvested
/// ones. Deliberately empty and unused: the fields are not in `layer.toml`
/// yet (REQ-AGENTDOCS-001 clause 2), and a seam with a type is a seam a
/// reviewer can find.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signed {
    pub summary: Option<String>,
    pub docs_command: Option<String>,
}

/// The limits one run lives within. A struct so tests can shorten the clock.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub timeout: Duration,
    pub max_output: u64,
}

impl Default for Sandbox {
    fn default() -> Self {
        Sandbox {
            timeout: TIMEOUT,
            max_output: MAX_OUTPUT,
        }
    }
}

/// How many times a busy executable is retried before giving up.
const SPAWN_RETRIES: u32 = 20;

/// Run `f`, retrying only while it fails with "text file busy".
///
/// A script written a moment ago can be busy while another thread forks; that
/// is a race, not a refusal, and the next try succeeds. Any other error, or
/// twenty busy answers in a row, is returned as it is.
fn retrying<T>(pause: Duration, mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    // A bounded `for`, not a counter in a `loop`: a counter that fails to
    // count (or a guard that is always true) would make an endless loop,
    // and that was reported as a timeout rather than caught.
    for _ in 0..SPAWN_RETRIES {
        match f() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(pause);
            }
            other => return other,
        }
    }
    f()
}

/// What one invocation printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// Standard output, then standard error.
    pub text: String,
    pub success: bool,
}

static SCRATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn read_capped(path: &Path, cap: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(cap).read_to_end(&mut buf);
    }
    buf
}

impl Sandbox {
    /// Run `bin` with `args`; `None` if it could not start or did not finish
    /// in time (in which case it was killed).
    pub fn run(&self, bin: &Path, args: &[&str]) -> Option<Ran> {
        let n = SCRATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scratch = std::env::temp_dir().join(format!(
            "varve-serve-harvest-{}-{n}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let (home, cwd) = (scratch.join("home"), scratch.join("cwd"));
        std::fs::create_dir_all(&home).ok()?;
        std::fs::create_dir_all(&cwd).ok()?;
        let result = self.run_in(bin, args, &scratch, &home, &cwd);
        let _ = std::fs::remove_dir_all(&scratch);
        result
    }

    fn run_in(
        &self,
        bin: &Path,
        args: &[&str],
        scratch: &Path,
        home: &Path,
        cwd: &Path,
    ) -> Option<Ran> {
        let (out_path, err_path) = (scratch.join("stdout"), scratch.join("stderr"));
        let mut child = retrying(Duration::from_millis(25), || {
            std::process::Command::new(bin)
                .args(args)
                .current_dir(cwd)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", home)
                .env("TERM", "dumb")
                .env("NO_COLOR", "1")
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::null())
                .stdout(std::fs::File::create(&out_path)?)
                .stderr(std::fs::File::create(&err_path)?)
                .spawn()
        })
        .ok()?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() >= self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return None,
            }
        };
        let mut text =
            String::from_utf8_lossy(&read_capped(&out_path, self.max_output)).into_owned();
        let err = String::from_utf8_lossy(&read_capped(&err_path, self.max_output)).into_owned();
        if !text.is_empty() && !text.ends_with('\n') && !err.is_empty() {
            text.push('\n');
        }
        text.push_str(&err);
        Some(Ran {
            text,
            success: status.success(),
        })
    }
}

/// One topic of a tool's built-in documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    pub name: String,
    pub desc: String,
    /// The text of the topic. Used only to answer `ask`; never printed into an
    /// orientation.
    pub body: String,
}

/// What was learned from one tool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Harvested {
    /// The raw `--help` text, or `None`: "no help available".
    pub help: Option<String>,
    pub topics: Vec<Topic>,
}

/// Harvest one tool. See the module comment for what is and is not run.
pub fn harvest_tool(sb: &Sandbox, bin: &Path, tool: &str) -> Harvested {
    let Some(ran) = sb.run(bin, &["--help"]) else {
        return Harvested::default();
    };
    let parsed = parse_help(tool, &ran.text);
    // A failing `--help` that still printed a command list (spar) is help; a
    // failing one that printed only an error ("Unknown command: --help") is not.
    if ran.text.trim().is_empty() || (!ran.success && parsed.subcommands.is_empty()) {
        return Harvested::default();
    }
    let mut topics = Vec::new();
    if parsed.lists_docs()
        && let Some(listing) = sb.run(bin, &["docs"])
    {
        for (name, desc) in parse_topics(&listing.text).into_iter().take(MAX_TOPICS) {
            let body = sb
                .run(bin, &["docs", &name])
                .map(|r| help::clean_block(&r.text))
                .unwrap_or_default();
            topics.push(Topic { name, desc, body });
        }
    }
    Harvested {
        help: Some(help::clean_block(&ran.text)),
        topics,
    }
}

/// One tool to harvest, as the caller found it in the verified store.
#[derive(Debug, Clone)]
pub struct ToolSource {
    pub name: String,
    pub version: String,
    pub realm: String,
    pub layer: String,
    /// Manifest digest of the layer that carries it: the cache key.
    pub layer_digest: String,
    /// The signed digest of the binary: what binds a cache entry to it.
    pub digest: String,
    /// Where the verified binary is, if it is laid down here.
    pub path: Option<PathBuf>,
    /// Where this layer's cache lives.
    pub cache_file: Option<PathBuf>,
}

fn key(t: &ToolSource) -> String {
    format!("{}@{}", t.name, t.digest)
}

fn topic_json(t: &Topic) -> serde_json::Value {
    serde_json::json!({"name": t.name, "desc": t.desc, "body": t.body})
}

fn load(path: &Path, layer_digest: &str) -> BTreeMap<String, Harvested> {
    let mut out = BTreeMap::new();
    let Ok(bytes) = std::fs::read(path) else {
        return out;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return out;
    };
    if v["version"] != CACHE_VERSION || v["layer"] != layer_digest {
        return out;
    }
    let Some(tools) = v["tools"].as_object() else {
        return out;
    };
    for (k, t) in tools {
        let s = |v: &serde_json::Value| v.as_str().map(str::to_string);
        let topics = t["topics"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some(Topic {
                            name: s(&x["name"])?,
                            desc: s(&x["desc"])?,
                            body: s(&x["body"])?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.insert(
            k.clone(),
            Harvested {
                help: s(&t["help"]),
                topics,
            },
        );
    }
    out
}

fn save(path: &Path, layer_digest: &str, tools: &BTreeMap<String, Harvested>) {
    let doc = serde_json::json!({
        "version": CACHE_VERSION,
        "layer": layer_digest,
        "tools": tools.iter().map(|(k, h)| (k.clone(), serde_json::json!({
            "help": h.help,
            "topics": h.topics.iter().map(topic_json).collect::<Vec<_>>(),
        }))).collect::<serde_json::Map<_, _>>(),
    });
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Written beside and renamed, so a reader never sees half a cache.
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, doc.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Harvest every tool, reading a layer's cache first and writing it after.
///
/// Returns one entry per tool, keyed by [`key`]. A tool with no path on disk
/// has no help and is not cached: that is a fact about this machine.
pub fn harvest_all(sb: &Sandbox, tools: &[ToolSource]) -> BTreeMap<String, Harvested> {
    let mut caches: BTreeMap<(PathBuf, String), BTreeMap<String, Harvested>> = BTreeMap::new();
    let mut dirty: Vec<(PathBuf, String)> = Vec::new();
    let mut out = BTreeMap::new();
    for t in tools {
        let k = key(t);
        let slot = t.cache_file.clone().map(|p| (p, t.layer_digest.clone()));
        if let Some(slot) = &slot {
            let cache = caches
                .entry(slot.clone())
                .or_insert_with(|| load(&slot.0, &slot.1));
            if let Some(hit) = cache.get(&k) {
                out.insert(k, hit.clone());
                continue;
            }
        }
        let h = match &t.path {
            Some(p) => harvest_tool(sb, p, &t.name),
            None => {
                out.insert(k, Harvested::default());
                continue;
            }
        };
        if let Some(slot) = slot {
            caches
                .get_mut(&slot)
                .expect("inserted above")
                .insert(k.clone(), h.clone());
            if !dirty.contains(&slot) {
                dirty.push(slot);
            }
        }
        out.insert(k, h);
    }
    for slot in dirty {
        save(&slot.0, &slot.1, &caches[&slot]);
    }
    out
}

/// The key a tool's harvest is filed under in [`harvest_all`]'s result.
pub fn key_of(t: &ToolSource) -> String {
    key(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Generous: a loaded machine can take a second to start a shell.
    fn fast() -> Sandbox {
        Sandbox {
            timeout: Duration::from_secs(10),
            max_output: MAX_OUTPUT,
        }
    }

    /// Short, for the one test that wants the clock to run out.
    fn impatient() -> Sandbox {
        Sandbox {
            timeout: Duration::from_millis(300),
            max_output: MAX_OUTPUT,
        }
    }

    /// The child sees a scrubbed environment, a fresh HOME and a fresh cwd.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn the_child_gets_a_scrubbed_environment_and_a_fresh_directory() {
        let d = tempfile::tempdir().unwrap();
        let bin = script(d.path(), "t", "env; pwd");
        let ran = Sandbox::default().run(&bin, &[]).expect("runs");
        let allowed = [
            "PATH", "HOME", "TERM", "NO_COLOR", "LC_ALL", "PWD", "SHLVL", "_", "OLDPWD",
        ];
        for (k, _) in std::env::vars() {
            if !allowed.contains(&k.as_str()) {
                assert!(
                    !ran.text.lines().any(|l| l.starts_with(&format!("{k}="))),
                    "{k} leaked into the child:\n{}",
                    ran.text
                );
            }
        }
        assert!(ran.text.contains("PATH=/usr/bin:/bin"), "{}", ran.text);
        let home = ran
            .text
            .lines()
            .find_map(|l| l.strip_prefix("HOME="))
            .unwrap();
        assert!(home.contains("varve-serve-harvest"), "{home}");
        assert_ne!(Some(home.to_string()), std::env::var("HOME").ok());
        let cwd = ran.text.lines().last().unwrap();
        assert!(cwd.contains("varve-serve-harvest"), "{cwd}");
        assert!(
            !Path::new(home).exists(),
            "the scratch directory was left behind"
        );
    }

    /// Standard input is closed, so a tool that reads it ends rather than
    /// waiting on the harness.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn stdin_is_null() {
        let d = tempfile::tempdir().unwrap();
        let bin = script(d.path(), "t", "cat; echo done");
        let ran = fast()
            .run(&bin, &[])
            .expect("a tool reading stdin ends at EOF");
        assert_eq!(ran.text, "done\n");
    }

    /// A tool that does not finish is killed, and says nothing.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_tool_that_outlives_the_timeout_is_killed() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("survived");
        let bin = script(
            d.path(),
            "t",
            &format!("sleep 2; touch {}", marker.display()),
        );
        let started = Instant::now();
        assert_eq!(impatient().run(&bin, &[]), None);
        assert!(
            started.elapsed() < Duration::from_millis(1800),
            "it waited for the child"
        );
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!marker.exists(), "the child was not killed");
        let h = harvest_tool(&impatient(), &bin, "t");
        assert_eq!(h, Harvested::default(), "no help available");
    }

    /// Only "busy" is retried, and only twenty times.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_busy_executable_is_retried_and_nothing_else_is() {
        let busy = || Err::<u8, _>(std::io::Error::from(std::io::ErrorKind::ExecutableFileBusy));
        let mut calls = 0;
        let ok = retrying(Duration::ZERO, || {
            calls += 1;
            if calls < 4 { busy() } else { Ok(7) }
        });
        assert_eq!((ok.unwrap(), calls), (7, 4));
        let mut calls = 0;
        let e = retrying(Duration::ZERO, || {
            calls += 1;
            busy()
        });
        assert!(e.is_err());
        assert_eq!(calls, SPAWN_RETRIES + 1, "twenty retries, then the error");
        let mut calls = 0;
        let e = retrying(Duration::ZERO, || {
            calls += 1;
            Err::<u8, _>(std::io::Error::from(std::io::ErrorKind::NotFound))
        });
        assert_eq!(
            (e.unwrap_err().kind(), calls),
            (std::io::ErrorKind::NotFound, 1)
        );
        let started = Instant::now();
        let mut n = 0;
        let _ = retrying(Duration::from_millis(100), || {
            n += 1;
            if n < 3 { busy() } else { Ok(0) }
        });
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "it did not pause between tries"
        );
    }

    #[test]
    fn the_limits_are_what_the_docs_say() {
        assert_eq!(MAX_OUTPUT, 256 * 1024);
        assert_eq!(TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn a_missing_binary_is_no_help() {
        assert_eq!(fast().run(Path::new("/nonexistent/varve-tool"), &[]), None);
    }

    /// Output past the cap is not read, and stdout precedes stderr.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn output_is_capped_and_joined_stdout_first() {
        let d = tempfile::tempdir().unwrap();
        let bin = script(d.path(), "t", "printf out; echo err >&2; exit 3");
        let ran = fast().run(&bin, &[]).unwrap();
        assert_eq!(ran.text, "out\nerr\n");
        let plain = script(d.path(), "plain", "printf out");
        assert_eq!(
            fast().run(&plain, &[]).unwrap().text,
            "out",
            "no newline invented"
        );
        let errs = script(d.path(), "errs", "echo err >&2");
        assert_eq!(fast().run(&errs, &[]).unwrap().text, "err\n");
        assert!(!ran.success);
        let big = script(d.path(), "big", "yes x | head -c 100000");
        let capped = Sandbox {
            timeout: Duration::from_secs(10),
            max_output: 1000,
        };
        assert_eq!(capped.run(&big, &[]).unwrap().text.len(), 1000);
    }

    fn fake(d: &Path, help: &str, docs: &str) -> PathBuf {
        script(
            d,
            "fake",
            &format!(
                "echo \"$@\" >> {calls}\ncase \"$1\" in\n--help) cat <<'EOF'\n{help}\nEOF\n;;\ndocs) {docs} ;;\nesac",
                calls = d.join("calls").display()
            ),
        )
    }

    fn calls(d: &Path) -> Vec<String> {
        std::fs::read_to_string(d.join("calls"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    const WITH_DOCS: &str = "Fake\n\nCommands:\n  run   Run\n  docs  Docs";
    const NO_DOCS: &str = "Fake\n\nCommands:\n  run   Run";

    /// `docs` is run ONLY when `--help` lists it; without it the tool is
    /// started once, with `--help`.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn docs_is_run_only_where_help_lists_it() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("MARKER");
        let bin = fake(d.path(), NO_DOCS, &format!("touch {}", marker.display()));
        let h = harvest_tool(&fast(), &bin, "fake");
        assert!(h.help.is_some() && h.topics.is_empty());
        assert_eq!(calls(d.path()), ["--help"]);
        assert!(!marker.exists());

        let d2 = tempfile::tempdir().unwrap();
        let docs = "if [ -n \"$2\" ]; then echo \"body of $2\"; else printf '  alpha   First\\n  beta    Second\\n'; fi";
        let bin = fake(d2.path(), WITH_DOCS, docs);
        let h = harvest_tool(&fast(), &bin, "fake");
        assert_eq!(
            calls(d2.path()),
            ["--help", "docs", "docs alpha", "docs beta"]
        );
        assert_eq!(h.topics.len(), 2);
        assert_eq!(h.topics[0].name, "alpha");
        assert_eq!(h.topics[0].desc, "First");
        assert_eq!(h.topics[0].body, "body of alpha");
    }

    /// A failing `--help` that printed only an error is not help; one that
    /// printed commands is.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_help_that_only_errors_is_no_help() {
        let d = tempfile::tempdir().unwrap();
        let bad = script(
            d.path(),
            "bad",
            "echo 'Unknown command: --help' >&2; exit 1",
        );
        assert_eq!(harvest_tool(&fast(), &bad, "bad").help, None);
        let spar = script(
            d.path(),
            "spar",
            "echo 'Usage: spar <command>\n\nCommands:\n  parse  Parse it' >&2; exit 1",
        );
        assert!(harvest_tool(&fast(), &spar, "spar").help.is_some());
        let silent = script(d.path(), "silent", "exit 0");
        assert_eq!(harvest_tool(&fast(), &silent, "silent").help, None);
    }

    fn source(d: &Path, bin: Option<PathBuf>) -> ToolSource {
        ToolSource {
            name: "fake".into(),
            version: "1".into(),
            realm: "r".into(),
            layer: "2026.10.1".into(),
            layer_digest: "sha256:aa".into(),
            digest: "sha256:bb".into(),
            path: bin,
            cache_file: Some(d.join("cache/ctx/sha256-aa.json")),
        }
    }

    /// The second harvest of the same layer starts nothing.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_cached_harvest_runs_nothing() {
        let d = tempfile::tempdir().unwrap();
        let bin = fake(d.path(), NO_DOCS, "true");
        let t = source(d.path(), Some(bin));
        let first = harvest_all(&fast(), std::slice::from_ref(&t));
        assert_eq!(calls(d.path()).len(), 1);
        let second = harvest_all(&fast(), std::slice::from_ref(&t));
        assert_eq!(calls(d.path()).len(), 1, "the cache was not used");
        assert_eq!(first, second);
        assert!(first[&key_of(&t)].help.is_some());
    }

    /// A cache for another layer, another binary, another version, or garbage
    /// is ignored, and a tool with no binary here is not run or cached.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_stale_or_foreign_cache_is_not_believed() {
        let d = tempfile::tempdir().unwrap();
        let bin = fake(d.path(), NO_DOCS, "true");
        let t = source(d.path(), Some(bin));
        harvest_all(&fast(), std::slice::from_ref(&t));
        let cache = t.cache_file.clone().unwrap();

        let mut other_bin = t.clone();
        other_bin.digest = "sha256:cc".into();
        harvest_all(&fast(), &[other_bin]);
        assert_eq!(
            calls(d.path()).len(),
            2,
            "a different binary digest reused an entry"
        );

        let mut other_layer = t.clone();
        other_layer.layer_digest = "sha256:zz".into();
        harvest_all(&fast(), &[other_layer]);
        assert_eq!(calls(d.path()).len(), 3, "a different layer reused a cache");

        let text = std::fs::read_to_string(&cache).unwrap();
        std::fs::write(&cache, text.replace("\"version\":1", "\"version\":999")).unwrap();
        harvest_all(&fast(), std::slice::from_ref(&t));
        assert_eq!(
            calls(d.path()).len(),
            4,
            "a cache from another harvester was believed"
        );

        std::fs::write(&cache, "not json").unwrap();
        harvest_all(&fast(), std::slice::from_ref(&t));
        assert_eq!(calls(d.path()).len(), 5);

        let mut absent = source(d.path(), None);
        absent.name = "gone".into();
        let out = harvest_all(&fast(), std::slice::from_ref(&absent));
        assert_eq!(out[&key_of(&absent)], Harvested::default());
        assert_eq!(calls(d.path()).len(), 5);
    }

    /// An unwritable cache location is not an error: the answer still comes.
    #[test]
    fn a_cache_that_cannot_be_written_is_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let bin = fake(d.path(), NO_DOCS, "true");
        let mut t = source(d.path(), Some(bin));
        t.cache_file = Some(PathBuf::from("/proc/nope/cache.json"));
        let out = harvest_all(&fast(), std::slice::from_ref(&t));
        assert!(out[&key_of(&t)].help.is_some());
    }

    /// Topics survive the round trip through the cache with their bodies.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn topic_text_is_cached_so_ask_runs_nothing() {
        let d = tempfile::tempdir().unwrap();
        let docs =
            "if [ -n \"$2\" ]; then echo \"body of $2\"; else printf '  alpha   First\\n'; fi";
        let bin = fake(d.path(), WITH_DOCS, docs);
        let t = source(d.path(), Some(bin));
        harvest_all(&fast(), std::slice::from_ref(&t));
        let n = calls(d.path()).len();
        let again = harvest_all(&fast(), std::slice::from_ref(&t));
        assert_eq!(calls(d.path()).len(), n);
        assert_eq!(again[&key_of(&t)].topics[0].body, "body of alpha");
        assert_eq!(
            Signed::default(),
            Signed {
                summary: None,
                docs_command: None
            }
        );
    }
}
