//! Embedded, queryable documentation (REQ-DOCS-001) — modelled on `rivet docs`.
//!
//! Topics are compiled INTO the binary (`include_str!`), so `varve docs` works
//! with no files and no network — air-gapped by construction. `--format json`
//! makes the same content machine-queryable (modelled on `rivet docs`).
//! Coverage is a mechanical invariant: `varve docs check --coverage`
//! enumerates the CLI's top-level subcommands and reports any without a topic;
//! `--strict` exits non-zero, so an undocumented subcommand cannot ship (a
//! gate, not review discipline).

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
        "config-reference",
        "Configuration reference — every file, every field",
        "concept-config-reference.md"
    ),
    topic!(
        "getting-started",
        "Getting started — nothing to a dispatched tool",
        "concept-getting-started.md"
    ),
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
        "signing-keys",
        "Signing keys — the format, and what varve checks",
        "concept-signing-keys.md"
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
    topic!(
        "environment",
        "Environment — VARVE_ROOT, VARVE_TRUST_ROOT, and precedence",
        "concept-environment.md"
    ),
    topic!(
        "own-realm",
        "Running your own realm — key to consumer, end to end",
        "concept-own-realm.md"
    ),
    topic!(
        "composition",
        "Composition — one pin, two trust universes",
        "concept-composition.md"
    ),
    topic!(
        "threat-model",
        "What verification does and does not prove",
        "concept-threat-model.md"
    ),
    topic!(
        "deploy",
        "Deploying a layer — the push, and what consumers need",
        "concept-deploy.md"
    ),
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
        "keygen",
        "keygen — mint a signing key and its public half",
        "cmd-keygen.md"
    ),
    topic!(
        "pubkey",
        "pubkey — the value a realm pins as trust-root",
        "cmd-pubkey.md"
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
        "sbom",
        "sbom — the signed manifest as a bill of materials",
        "cmd-sbom.md"
    ),
    topic!(
        "status",
        "status — support window, yanks, known problems",
        "cmd-status.md"
    ),
    topic!(
        "sign-attestation",
        "sign-attestation — bind an attestation to a layer (CI)",
        "cmd-sign-attestation.md"
    ),
    topic!(
        "check-attestation",
        "check-attestation — does this attestation belong here?",
        "cmd-check-attestation.md"
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

/// Topics that must exist because a user cannot do the job without them. The
/// per-subcommand check cannot see these: a FILE is not a subcommand, a TASK is
/// not a subcommand, and an environment variable is not a subcommand — which is
/// why the gate reported green through two audits that found the docs unusable
/// for exactly those things (REQ-DOCS-003).
pub const REQUIRED_TOPICS: &[&str] = &[
    "getting-started",
    "config-reference",
    "environment",
    "own-realm",
    "composition",
    "threat-model",
    "deploy",
    "signing-keys",
];

/// Topics a user must ACT on, which therefore have to show a literal example
/// rather than describe one. A topic can exist and teach nothing: eight topic
/// files were under 30 words when this was written, and personas recovered the
/// file formats from serde errors instead.
pub const TOPICS_NEEDING_EXAMPLES: &[&str] = &[
    "getting-started",
    "config-reference",
    "own-realm",
    "deploy",
    "deposit",
    "realms",
    "pins",
    "air-gap",
];

/// Required topics that are missing entirely.
pub fn missing_required_topics() -> Vec<&'static str> {
    REQUIRED_TOPICS
        .iter()
        .copied()
        .filter(|slug| find(slug).is_none())
        .collect()
}

/// Topics that must show a worked example and do not. A fenced block is the
/// mechanical proxy for "you can copy this and it works".
pub fn topics_without_examples() -> Vec<&'static str> {
    TOPICS_NEEDING_EXAMPLES
        .iter()
        .copied()
        .filter(|slug| match find(slug) {
            Some(t) => !t.body.contains("```"),
            // Absence is reported by `missing_required_topics`; not double-counted.
            None => false,
        })
        .collect()
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

/// Machine-readable JSON, modelled on `rivet docs --format json` so the docs
/// can be queried by tooling, not just read. `None` → the topic list (slug +
/// title per entry, no bodies); `Some(slug)` → that one topic with its full
/// body (an empty `{}` if the slug is unknown, mirroring the human path).
pub fn render_json(slug: Option<&str>) -> String {
    match slug {
        None => {
            let list: Vec<_> = TOPICS
                .iter()
                .map(|t| serde_json::json!({"slug": t.slug, "title": t.title}))
                .collect();
            serde_json::to_string_pretty(&list).expect("topic list serialises")
        }
        Some(s) => match find(s) {
            Some(t) => serde_json::to_string_pretty(
                &serde_json::json!({"slug": t.slug, "title": t.title, "body": t.body}),
            )
            .expect("topic serialises"),
            None => "{}".to_string(),
        },
    }
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

    // rivet: verifies REQ-DOCS-002
    #[test]
    fn the_docs_teach_the_facts_a_user_is_rejected_for_not_knowing() {
        // Not "a topic exists" — the audit's specific findings. Every entry is
        // something 10 of 10 personas learned from a serde parse error instead
        // of from the docs, and each one REJECTS a file when it is missing.
        let must_appear: &[(&str, &str)] = &[
            // Required, appeared in no topic at all: a pin written strictly
            // from the docs was rejected.
            ("manifest-version", "config-reference"),
            // How a crate is deposited. Undocumented, which made three of four
            // export adapters unexercisable outside the project.
            ("kind = \"crate\"", "config-reference"),
            // "no topic matches"
            ("VARVE_ROOT", "environment"),
            ("VARVE_TRUST_ROOT", "environment"),
            // The four hand-authored file formats.
            ("varve.toml", "config-reference"),
            ("varve-realms.toml", "config-reference"),
            ("trust-root", "config-reference"),
            ("[[include]]", "config-reference"),
        ];
        for (fact, topic) in must_appear {
            let body = TOPICS
                .iter()
                .find(|t| t.slug == *topic)
                .unwrap_or_else(|| panic!("topic '{topic}' must exist"))
                .body;
            assert!(
                body.contains(fact),
                "topic '{topic}' must teach `{fact}` — a user who does not know it \
                 has their file REJECTED (REQ-DOCS-002)"
            );
        }
    }

    // rivet: verifies REQ-DOCS-002
    #[test]
    fn the_task_topics_walk_a_user_through_a_sequence() {
        // A task topic that names one command is a reference page wearing a
        // task's title. The audit found no task-shaped topic anywhere, so the
        // three flagship features shipped with no entry point.
        for name in ["getting-started", "own-realm"] {
            let body = TOPICS.iter().find(|t| t.slug == name).unwrap().body;
            let commands = body.matches("varve ").count();
            assert!(
                commands >= 4,
                "task topic '{name}' names {commands} varve invocation(s); a task is a \
                 SEQUENCE, not a single command (REQ-DOCS-002)"
            );
        }
    }

    // rivet: verifies REQ-DOCS-003
    #[test]
    fn the_workflow_topics_exist() {
        // Two audits found the docs unusable for files and tasks while the
        // subcommand gate reported green — "the gate is not merely weak; it
        // actively certifies the hole".
        let missing = missing_required_topics();
        assert!(
            missing.is_empty(),
            "required workflow topics missing (REQ-DOCS-003): {missing:?}"
        );
    }

    // rivet: verifies REQ-DOCS-003
    #[test]
    fn topics_a_user_must_act_on_show_a_worked_example() {
        // A topic can exist and teach nothing. Personas recovered four file
        // formats from serde parse errors rather than from these pages.
        let bare = topics_without_examples();
        assert!(
            bare.is_empty(),
            "these topics must show a literal example, not describe one \
             (REQ-DOCS-003): {bare:?}"
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
    fn topic_list_renders_as_machine_readable_json() {
        let v: serde_json::Value = serde_json::from_str(&render_json(None)).unwrap();
        let arr = v.as_array().expect("--format json list is a JSON array");
        assert_eq!(arr.len(), TOPICS.len());
        // Every entry carries slug + title; the list form omits the body.
        let first = &arr[0];
        assert!(first.get("slug").and_then(|s| s.as_str()).is_some());
        assert!(first.get("title").and_then(|s| s.as_str()).is_some());
        assert!(first.get("body").is_none(), "list form omits bodies");
    }

    // rivet: verifies REQ-DOCS-001
    #[test]
    fn single_topic_renders_as_json_with_body() {
        let v: serde_json::Value = serde_json::from_str(&render_json(Some("air-gap"))).unwrap();
        assert_eq!(v.get("slug").and_then(|s| s.as_str()), Some("air-gap"));
        assert!(
            v.get("body").and_then(|s| s.as_str()).unwrap().len() > 40,
            "single-topic JSON carries the full body"
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
