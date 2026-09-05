//! Documentation that goes stale silently (REQ-DOCS-001).
//!
//! Two kinds of value appear in these docs and only one of them is a hazard.
//!
//! **Historical prose** — "from v0.26.0", "From v0.14.0 each release …" —
//! records when something happened and must never be rewritten. A gate that
//! flagged it would be actively harmful.
//!
//! **Values a reader copies** — an install snippet's version, a pin example's
//! layer id — must be current, because a reader who pastes a stale one gets a
//! working, verifying, four-releases-old toolchain and no indication anything
//! is wrong. That is worse than showing nothing.
//!
//! Both hazards were live: the README pinned `2026.08.2` for four releases
//! after it stopped being current, and told users `cargo install varve` was
//! unavailable until v0.26.0 long after it shipped.

use std::path::{Path, PathBuf};

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn read(rel: &str) -> String {
    let p = repo(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The fenced code blocks of a markdown file — the parts a reader copies.
fn code_blocks(md: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            match cur.take() {
                Some(b) => out.push(b),
                None => cur = Some(String::new()),
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    out
}

fn current_layer() -> String {
    read("docs/current-layer.txt").trim().to_string()
}

/// A snippet that pins a varve version is one that is wrong on the next
/// release. The install path resolves it instead.
// rivet: verifies REQ-DOCS-001
#[test]
fn no_readme_snippet_pins_a_varve_version() {
    let mut bad = Vec::new();
    for block in code_blocks(&read("README.md")) {
        for line in block.lines() {
            let t = line.trim();
            if t.starts_with("VERSION=") && t.contains("v0.") {
                bad.push(t.to_string());
            }
        }
    }
    assert!(
        bad.is_empty(),
        "README snippets pin a varve version, which is stale on the next \
         release — resolve it instead (`gh release view … -q .tagName`):\n  {}",
        bad.join("\n  ")
    );
}

/// Every pin example must name the layer `docs/current-layer.txt` names.
///
/// Narrow on purpose: this is about values pasted into a `varve.toml`, where a
/// stale id silently governs someone's build. Illustrative ids in command
/// examples (`varve archive 2026.07.0 ./core`) teach a shape and are left
/// alone.
// rivet: verifies REQ-DOCS-001
#[test]
fn the_docs_pin_the_layer_they_say_they_do() {
    let current = current_layer();
    assert!(
        current
            .split('.')
            .zip(["2026", "09", "0"])
            .count()
            == 3,
        "docs/current-layer.txt does not look like a layer id: {current:?}"
    );

    let mut stale = Vec::new();
    for (file, md) in [("README.md", read("README.md"))] {
        for block in code_blocks(&md) {
            for line in block.lines() {
                let t = line.trim();
                // A pin assignment: `layer = "…"` / `layer   = "…"`.
                if let Some(rest) = t.strip_prefix("layer")
                    && let Some(v) = rest.trim_start().strip_prefix('=')
                    && let Some(open) = v.find('"')
                    && let Some(close) = v[open + 1..].find('"')
                {
                    let id = &v[open + 1..open + 1 + close];
                    if id != current {
                        stale.push(format!("{file}: layer = \"{id}\""));
                    }
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "these pin examples name a layer other than the current one ({current}). \
         A reader who copies a stale pin gets an old toolchain that verifies \
         perfectly and is not what they meant — update them, or update \
         docs/current-layer.txt:\n  {}",
        stale.join("\n  ")
    );
}

/// The claim that broke: the README told users an install path did not work,
/// long after it did. There is no general way to catch that, so the specific
/// dead claims are pinned as they are found.
// rivet: verifies REQ-DOCS-001
#[test]
fn the_readme_does_not_repeat_claims_it_has_already_outlived() {
    let readme = read("README.md");
    for dead in [
        // `varve` has been on crates.io continuously since 0.26.0.
        "Not available until v0.26.0",
    ] {
        assert!(
            !readme.contains(dead),
            "README repeats a claim that is no longer true: {dead:?}"
        );
    }
}
