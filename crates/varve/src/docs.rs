//! Embedded, queryable documentation (REQ-DOCS-001) — modelled on `rivet docs`.
//!
//! Topics are compiled INTO the binary (`include_str!`), so `varve docs` works
//! with no files and no network — air-gapped by construction. Coverage is a
//! mechanical invariant: `varve docs check --coverage` walks the clap
//! subcommand tree and reports any command without a topic; `--strict` exits
//! non-zero, so an undocumented subcommand cannot ship (a gate, not review
//! discipline).

/// One documentation topic: a stable slug, a title, and markdown body.
pub struct Topic {
    pub slug: &'static str,
    pub title: &'static str,
    pub body: &'static str,
}

macro_rules! topic {
    ($slug:literal, $title:literal, $file:literal) => {
        Topic {
            slug: $slug,
            title: $title,
            body: include_str!(concat!("../docs/", $file)),
        }
    };
}

/// The embedded topic registry. Command topics use the exact clap subcommand
/// name (kebab-case) so the coverage check can match them mechanically.
pub const TOPICS: &[Topic] = &[
    // ── concepts ──────────────────────────────────────────────────────
    topic!(
        "pins",
        "Pins — how a project names its toolchain",
        "concept-pins.md"
    ),
    topic!("realms", "Realms — trust universes", "concept-realms.md"),
    topic!(
        "layers",
        "Layers — one signed, dated bundle per release",
        "concept-layers.md"
    ),
    topic!(
        "trust-roots",
        "Trust roots — the pinned signing key",
        "concept-trust-roots.md"
    ),
    topic!(
        "payload-kinds",
        "Payload kinds — tool, crate, wit, …",
        "concept-payload-kinds.md"
    ),
    topic!("air-gap", "Air-gapped operation", "concept-air-gap.md"),
    // ── one per CLI subcommand (slug == clap name) ────────────────────
    topic!("which", "which — which binary runs here", "cmd-which.md"),
    topic!("list", "list — layers in the core", "cmd-list.md"),
    topic!(
        "install",
        "install — verify and lay down the pinned layer",
        "cmd-install.md"
    ),
    topic!(
        "verify",
        "verify — re-check the pinned layer",
        "cmd-verify.md"
    ),
    topic!(
        "archive",
        "archive — export the offline core",
        "cmd-archive.md"
    ),
    topic!(
        "run",
        "run — dispatch a tool with layer provenance",
        "cmd-run.md"
    ),
    topic!(
        "deposit",
        "deposit — assemble and sign a layer (CI)",
        "cmd-deposit.md"
    ),
    topic!(
        "export-bazel",
        "export-bazel — checksum registries",
        "cmd-export-bazel.md"
    ),
    topic!(
        "export-cargo",
        "export-cargo — a Cargo local registry",
        "cmd-export-cargo.md"
    ),
    topic!(
        "export-crates-vendor",
        "export-crates-vendor — a cargo-vendor tree",
        "cmd-export-crates-vendor.md"
    ),
    topic!(
        "export-bazel-distdir",
        "export-bazel-distdir — the air-gap Bazel distdir",
        "cmd-export-bazel-distdir.md"
    ),
    topic!(
        "status",
        "status — support window, yanks, known problems",
        "cmd-status.md"
    ),
    topic!(
        "sign-status",
        "sign-status — sign a line-status document (CI)",
        "cmd-sign-status.md"
    ),
    topic!(
        "attach-status",
        "attach-status — attach a baseline status (CI)",
        "cmd-attach-status.md"
    ),
    topic!("shim", "shim — PATH dispatchers", "cmd-shim.md"),
    topic!("env", "env — shell setup", "cmd-env.md"),
    topic!(
        "completions",
        "completions — shell completion scripts",
        "cmd-completions.md"
    ),
    topic!(
        "sign-sums",
        "sign-sums — sign release sums (CI)",
        "cmd-sign-sums.md"
    ),
    topic!(
        "self-update",
        "self-update — update the updater",
        "cmd-self-update.md"
    ),
    topic!(
        "self-verify",
        "self-verify — verify a release file",
        "cmd-self-verify.md"
    ),
    topic!("docs", "docs — this documentation", "cmd-docs.md"),
];

pub fn find(slug: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|t| t.slug == slug)
}

/// Command names (clap subcommands) that have NO topic — the coverage gap.
pub fn coverage_gaps(cmd: &clap::Command) -> Vec<String> {
    cmd.get_subcommands()
        .map(|c| c.get_name().to_string())
        .filter(|name| find(name).is_none())
        .collect()
}

/// Render the topic list (slug + title).
pub fn render_list() -> String {
    let mut out = String::from("varve docs — topics (varve docs <topic>):\n\n");
    for t in TOPICS {
        out.push_str(&format!("  {:<22} {}\n", t.slug, t.title));
    }
    out
}

/// grep across all topic bodies + titles; returns (slug, matching line).
pub fn grep(query: &str) -> Vec<(&'static str, String)> {
    let q = query.to_lowercase();
    let mut hits = Vec::new();
    for t in TOPICS {
        for line in t.body.lines() {
            if line.to_lowercase().contains(&q) {
                hits.push((t.slug, line.trim().to_string()));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-DOCS-001
    #[test]
    fn every_cli_subcommand_has_a_documented_topic() {
        use clap::CommandFactory;
        let cmd = crate::Cli::command();
        let gaps = coverage_gaps(&cmd);
        assert!(
            gaps.is_empty(),
            "these subcommands have no `varve docs` topic (REQ-DOCS-001): {gaps:?}"
        );
    }

    // rivet: verifies REQ-DOCS-001
    #[test]
    fn topics_are_findable_and_greppable() {
        assert!(find("air-gap").is_some());
        assert!(find("install").is_some());
        assert!(find("nonexistent").is_none());
        // A concept every topic set should mention.
        assert!(
            !grep("verify").is_empty(),
            "grep should find 'verify' somewhere"
        );
    }

    // rivet: verifies REQ-DOCS-001
    #[test]
    fn no_topic_body_is_empty() {
        for t in TOPICS {
            assert!(
                t.body.trim().len() > 40,
                "topic {} is too short to be real documentation",
                t.slug
            );
        }
    }
}
