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
        "bootstrap",
        "Bootstrap — getting varve itself, verified",
        "concept-install.md"
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
        "Environment — every variable varve reads, and precedence",
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
        "recovery",
        "Recovery — repairing, removing, and going back",
        "concept-recovery.md"
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
        "export-vsix",
        "export-vsix — VS Code extensions `code` installs",
        "cmd-export-vsix.md"
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
    // Step 0. Until v0.26.0 the docs began at `varve install` — which needs a
    // varve you do not have. A tool for verified distribution that has no
    // documented verified way to obtain ITSELF is the hole this closes
    // (REQ-BOOTSTRAP-001).
    "bootstrap",
    "getting-started",
    "config-reference",
    "environment",
    "own-realm",
    "composition",
    "threat-model",
    "deploy",
    "signing-keys",
    // A ten-persona audit graded the hostile tester's path BLOCKED: a store
    // that fails to read has no documented way out, and the fix every command
    // suggested was one they had already been refused.
    "recovery",
];

/// Topics a user must ACT on, which therefore have to show a literal example
/// rather than describe one. A topic can exist and teach nothing: eight topic
/// files were under 30 words when this was written, and personas recovered the
/// file formats from serde errors instead.
pub const TOPICS_NEEDING_EXAMPLES: &[&str] = &[
    // The bootstrap is nothing BUT commands: describing "verify the script
    // before running it" without the literal transcript leaves the reader with
    // the piped one-liner, which is the form this topic exists to demote.
    "bootstrap",
    "recovery",
    "environment",
    "composition",
    // NOT threat-model. REQ-DOCS-002 says each new topic carries a literal
    // example, and for five of the six that is right. threat-model is a list
    // of LIMITS — "verify does not seal the directory" has no copy-pasteable
    // form, and a fence added to satisfy a counter would be exactly the
    // box-ticking this gate exists to stop. It is covered instead by
    // `the_two_flagship_topics_teach_their_feature_not_just_its_name`, which
    // asserts the specific limits a reader who cannot reach SECURITY.md needs.
    "getting-started",
    "config-reference",
    "own-realm",
    "deploy",
    "deposit",
    "realms",
    "pins",
    "air-gap",
    // REQ-VSIX-001 clause 5. The topic's whole job is a worked example: the
    // spec stanza that deposits an extension and the exact `code
    // --install-extension` line, because the file NAME is what `code`
    // dispatches on. A prose description of that teaches nothing.
    "export-vsix",
];

/// Required topics that are missing entirely.
pub fn missing_required_topics() -> Vec<&'static str> {
    missing_required_topics_in(TOPICS)
}

/// The gate, over an arbitrary topic set. Split out so a test can hand it a
/// set it KNOWS is broken: a gate whose test only ever asserts an empty result
/// cannot tell "nothing is wrong" from "I stopped looking", which is the
/// vacuous-gate shape an independent review found by neutering both functions
/// to `return Vec::new()` and watching the whole suite stay green.
pub fn missing_required_topics_in(topics: &[Topic]) -> Vec<&'static str> {
    REQUIRED_TOPICS
        .iter()
        .copied()
        .filter(|slug| !topics.iter().any(|t| t.slug == *slug))
        .collect()
}

/// Topics that must show a worked example and do not.
pub fn topics_without_examples() -> Vec<&'static str> {
    topics_without_examples_in(TOPICS)
}

/// A fenced block is the proxy for "you can copy this and it works" — so an
/// EMPTY fence must not satisfy it. A review stubbed four topics to a title
/// plus ```` ```sh ```` with nothing inside and the gate printed
/// "9 topic(s) carry a worked example", exit 0.
pub fn topics_without_examples_in(topics: &[Topic]) -> Vec<&'static str> {
    TOPICS_NEEDING_EXAMPLES
        .iter()
        .copied()
        .filter(|slug| match topics.iter().find(|t| t.slug == *slug) {
            Some(t) => !has_a_non_empty_fence(t.body),
            // Absence is reported by `missing_required_topics`; not double-counted.
            None => false,
        })
        .collect()
}

/// True when the body holds a fenced block with at least one non-blank line
/// of content in it.
fn has_a_non_empty_fence(body: &str) -> bool {
    let mut inside = false;
    for line in body.lines() {
        if line.starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside && !line.trim().is_empty() {
            return true;
        }
    }
    false
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

    /// Every fenced block in the docs, with the topic it came from.
    fn fenced_blocks(slug: &str) -> Vec<(String, String)> {
        let body = TOPICS
            .iter()
            .find(|t| t.slug == slug)
            .unwrap_or_else(|| panic!("topic '{slug}' must exist"))
            .body;
        let mut out = Vec::new();
        let mut lang: Option<String> = None;
        let mut buf = String::new();
        for line in body.lines() {
            match (&lang, line.strip_prefix("```")) {
                (None, Some(l)) => lang = Some(l.trim().to_string()),
                (Some(l), Some(_)) => {
                    out.push((l.clone(), std::mem::take(&mut buf)));
                    lang = None;
                }
                (Some(_), None) => {
                    buf.push_str(line);
                    buf.push('\n');
                }
                (None, None) => {}
            }
        }
        out
    }

    // rivet: verifies REQ-DOCS-003
    #[test]
    fn the_gate_detects_a_broken_topic_set_not_merely_a_healthy_one() {
        // Both gate functions assert EMPTINESS over the real topic set, so
        // neutering them to `return Vec::new()` left the entire workspace
        // green — a review proved it. A gate that cannot fail is not a gate.
        // These hand it sets it must reject.
        const EMPTY: &[Topic] = &[];
        let missing = missing_required_topics_in(EMPTY);
        assert_eq!(
            missing.len(),
            REQUIRED_TOPICS.len(),
            "with no topics at all, every required topic must be reported missing"
        );

        // A topic that exists and teaches nothing: a title plus an EMPTY
        // fence, which is exactly what the reviewer used to get exit 0.
        const STUBBED: &[Topic] = &[Topic {
            slug: "getting-started",
            title: "Getting started",
            body: "# Getting started\n\nRead the other topics.\n\n```sh\n```\n",
        }];
        assert!(
            topics_without_examples_in(STUBBED).contains(&"getting-started"),
            "an empty fence is not a worked example"
        );

        // …and a real one is accepted, so the check is not simply always-fail.
        const REAL: &[Topic] = &[Topic {
            slug: "getting-started",
            title: "Getting started",
            body: "# Getting started\n\n```sh\nvarve install\n```\n",
        }];
        assert!(
            !topics_without_examples_in(REAL).contains(&"getting-started"),
            "a fence with a command in it IS a worked example"
        );
    }

    // rivet: verifies REQ-DOCS-002
    #[test]
    fn the_two_flagship_topics_teach_their_feature_not_just_its_name() {
        // `composition` and `threat-model` had NO content assertion anywhere in
        // the workspace: reduced to a title plus a line of filler with no code
        // fence at all, every gate stayed green. They are two of the three
        // flagship features the requirement says shipped with no entry point.
        let composition = TOPICS
            .iter()
            .find(|t| t.slug == "composition")
            .unwrap()
            .body;
        for needle in [
            "[[include]]",        // how you produce one
            "varve install",      // how you install one, in order
            "cycle",              // the rules that make it safe
            "realm's trust root", // the property that makes composing safe at all
        ] {
            assert!(
                composition.contains(needle),
                "the composition topic must teach `{needle}`"
            );
        }

        let threat = TOPICS
            .iter()
            .find(|t| t.slug == "threat-model")
            .unwrap()
            .body;
        // The topic's whole purpose is the LIMITS. A version that lists only
        // what verification proves is worse than none, so assert the negatives.
        for needle in [
            "does not seal the directory",
            "do not re-verify",
            "No transparency log",
            "No key rotation",
            "signer equivocation",
        ] {
            assert!(
                threat.contains(needle),
                "the threat-model topic must state the limit `{needle}` — a reader \
                 who cannot reach SECURITY.md has only this"
            );
        }
    }

    fn body(slug: &str) -> &'static str {
        TOPICS
            .iter()
            .find(|t| t.slug == slug)
            .unwrap_or_else(|| panic!("topic {slug} must exist"))
            .body
    }

    // rivet: verifies REQ-DOCS-002
    #[test]
    fn the_topics_state_the_limits_a_ten_persona_audit_found_them_denying() {
        // varve#78. Each of these was a documented claim that the binary
        // contradicts. The claim is cheap to reintroduce and expensive to
        // catch by review, so each correction is pinned by the phrase that
        // carries it — a doc that says the true thing passes, and the false
        // predecessor cannot come back quietly.

        // THE one a security reviewer's mental model rests on: a planted file
        // is not inert. `run`, `which` and `shim install` all take it, because
        // dispatch enumerates the DIRECTORY and the signature covers only what
        // the manifest names.
        let threat = body("threat-model");
        for needle in [
            "unnamed files ARE dispatched",
            "enumerates the **directory**",
            "varve shim install",
            "equivalent to code execution",
        ] {
            assert!(
                threat.contains(needle),
                "the threat-model topic must say `{needle}` — the previous text \
                 read as though a planted file were inert, and it is dispatched"
            );
        }

        // An `[[include]]` with no `realm` is not "optional": it installs
        // clean and then accuses a correctly-signed layer of a bad signature.
        for slug in ["layers", "config-reference"] {
            let t = body(slug);
            assert!(
                t.contains("required in practice"),
                "{slug} must not present `[[include]].realm` as merely optional"
            );
            assert!(
                t.contains("re-deposit") || t.contains("re-depositing"),
                "{slug} must say the include annotation is inside the SIGNED \
                 payload, so it cannot be added afterwards"
            );
        }

        // The parser knows seven `[[tool]]` kinds; the reference listed six.
        let cfg = body("config-reference");
        for kind in [
            "tool",
            "crate",
            "wit",
            "zephyr-module",
            "sdk",
            "wasm-component",
            "vsix",
        ] {
            assert!(
                cfg.contains(kind),
                "config-reference must list the `{kind}` payload kind"
            );
        }

        // `varve list` labels by trust-root FINGERPRINT; a realm name appears
        // only when a realms file in scope maps it back.
        let env = body("environment");
        assert!(
            env.contains("fingerprint") && env.contains("varve-realms.toml"),
            "environment must say `list` labels by fingerprint, not by realm"
        );
        // The variable that appeared in no topic at all.
        for needle in ["VARVE_REGISTRY_AUTH", "VARVE_UPDATE_API", "VARVE_ROOT"] {
            assert!(env.contains(needle), "environment must document {needle}");
        }

        // The claim I wrote after testing only the happy path: re-installing
        // does NOT repair a layer once its line's counter has moved past it.
        let rec = body("recovery");
        for needle in [
            "does not work",
            "rollback refused",
            "Deleting the layer directory does not help",
            "verify --all",
        ] {
            assert!(
                rec.contains(needle),
                "recovery must state `{needle}` — repair-in-place holds only \
                 while no higher counter in the line has been installed"
            );
        }
    }

    // rivet: verifies REQ-DOCS-003
    #[test]
    fn every_documented_command_is_a_real_command() {
        // The parse gate classified only toml/json, so all 19 `sh` blocks were
        // unchecked — a review demonstrated it by adding
        // `varve frobnicate --nonexistent-flag` to a topic and watching every
        // gate stay green. A shell transcript is the form users copy MOST.
        use clap::CommandFactory;
        let cmd = crate::Cli::command();
        let known: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();
        let mut checked = 0;
        for topic in TOPICS.iter() {
            for (lang, block) in fenced_blocks(topic.slug) {
                if lang != "sh" && lang != "bash" && lang != "console" {
                    continue;
                }
                for line in block.lines() {
                    // The invocation may be mid-line (`$ varve x`, `then varve y`),
                    // but must be a whole word.
                    let mut words = line.split_whitespace().peekable();
                    while let Some(w) = words.next() {
                        if w != "varve" {
                            continue;
                        }
                        // The next word is the subcommand unless it is a flag
                        // (`varve --help`) or the line is prose about `varve`.
                        let Some(next) = words.peek() else { continue };
                        let sub = next.trim_matches(|c: char| {
                            !c.is_ascii_alphanumeric() && c != '-' && c != '_'
                        });
                        if sub.is_empty() || sub.starts_with('-') {
                            continue;
                        }
                        assert!(
                            known.iter().any(|k| k == sub),
                            "topic '{}' documents `varve {sub}`, which is not a \
                             subcommand — known: {known:?}",
                            topic.slug
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(
            checked >= 20,
            "only {checked} documented invocation(s) were checked; the shell \
             transcripts are the form users copy most"
        );
    }

    // rivet: verifies REQ-BOOTSTRAP-001
    #[test]
    fn the_bootstrap_topic_states_what_the_first_hop_cannot_prove() {
        // Clause 8 shipped as prose with no mechanical check, which is exactly
        // the shape that let requirement text outrun code four releases
        // running. The honest limits are the most deletable part of a page
        // whose other job is to make installing easy, so they are the part
        // that needs a gate.
        let body = TOPICS.iter().find(|t| t.slug == "bootstrap").unwrap().body;
        for needle in [
            // The limit itself, named.
            "trust on first use",
            // …and specifically that a signature does not vouch for the signer.
            "not tell you the repository was not compromised",
            // What the first hop DOES buy, or a reader concludes it is useless.
            "self-update",
            // The refuse-rather-than-degrade stance, which is the reason the
            // script has no --skip-verify and must not grow one.
            "refuses rather than degrades",
        ] {
            assert!(
                body.contains(needle),
                "the bootstrap topic must state `{needle}` — a page that teaches \
                 people to install a verification tool must say what its own \
                 first hop does not prove (REQ-BOOTSTRAP-001 clause 8)"
            );
        }
    }

    // rivet: verifies REQ-DOCS-002
    #[test]
    fn a_topic_showing_the_published_realm_shows_the_published_key() {
        // The worst outcome an example can have is not "rejected" — it is
        // "accepted and WRONG". An independent review found this topic
        // teaching a fabricated 64-hex value LABELLED as the published
        // rolling.pub, in the topic whose first line says "Every file here is
        // literal — copy it". A user who copied it got
        //   error: manifest signature verification failed: … No valid signatures
        // The elided `83a699…` that a previous gate caught was fixed by padding
        // the placeholder until the PARSER accepted it, which is how a shape
        // check certifies a false fact. The published key is a fact, so this
        // test compares against the file the release actually ships.
        let published = include_str!("../../../trust-roots/rolling.pub").trim();
        assert_eq!(published.len(), 64, "the shipped root must be 64 hex chars");
        for topic in TOPICS.iter() {
            for (lang, block) in fenced_blocks(topic.slug) {
                if lang != "toml" || !block.contains("[realm.pulseengine]") {
                    continue;
                }
                for line in block.lines() {
                    let l = line.trim_start();
                    // Only an INLINE key, not `trust-root-file`, and not a
                    // commented-out alternative.
                    if !l.starts_with("trust-root ") && !l.starts_with("trust-root=") {
                        continue;
                    }
                    let value = l.split('"').nth(1).unwrap_or("");
                    assert_eq!(
                        value, published,
                        "topic '{}' shows a trust-root for realm 'pulseengine' that is NOT \
                         the published rolling.pub — a user who copies it gets \
                         'No valid signatures'",
                        topic.slug
                    );
                }
            }
        }
    }

    // rivet: verifies REQ-DOCS-004
    #[test]
    fn the_adapter_topic_names_every_adapter_and_what_selects_it() {
        // "The kind selects which export adapter applies" was false in both
        // directions: export-bazel ignores kind and keys on platform plus
        // [tool.source], while three adapters share kind = "crate". A build
        // engineer whose whole brief is choosing an adapter was misdirected by
        // the one topic that addresses it.
        let body = TOPICS
            .iter()
            .find(|t| t.slug == "payload-kinds")
            .unwrap()
            .body;
        assert!(
            !body.contains("The kind selects which export adapter applies"),
            "the refuted claim must not come back"
        );
        for adapter in [
            "export-cargo",
            "export-crates-vendor",
            "export-bazel-distdir",
            "export-bazel",
        ] {
            assert!(body.contains(adapter), "the table must name `{adapter}`");
        }
        // …and the two annotations that actually select export-bazel, which
        // appeared in no topic and no --help.
        assert!(
            body.contains("[tool.source]") && body.contains("platform"),
            "the topic must name what selects export-bazel, not just its name"
        );
    }

    // rivet: verifies REQ-DOCS-004
    #[test]
    fn the_recovery_topic_states_what_repairs_and_what_is_refused() {
        // The hostile tester's path was BLOCKED: a store that fails to read had
        // no documented way out, and they believed anti-rollback refused the
        // repair. Running it proves an EQUAL counter is not a regression, so
        // re-installing repairs in place; the refused case is going BACKWARDS.
        let body = TOPICS.iter().find(|t| t.slug == "recovery").unwrap().body;
        assert!(
            body.contains("varve install --from"),
            "the repair must be a command, not a description"
        );
        assert!(
            body.contains("equal") || body.contains("**equal**"),
            "it must say WHY re-installing is allowed — an equal counter is no \
             regression — or a reader stops at the rollback error"
        );
        assert!(
            body.contains("high-water-marks.json"),
            "deliberate rollback means editing local state; name the file"
        );
        assert!(
            body.contains("no `uninstall`") || body.contains("no `uninstall`, `repair`"),
            "a missing command must be stated as missing, not left to be searched for"
        );
    }

    // rivet: verifies REQ-DEPLOY-001
    #[test]
    fn nothing_shipped_claims_varve_publishes() {
        // The requirement exists to RETRACT a claim. An independent review
        // found `varve deposit  # (CI) assemble, sign and publish a layer` at
        // README.md:100 — unchanged since before the requirement was written,
        // and cited twice in its own text. The --help was fixed and the
        // most-read surface was not, so the clause was factually unmet while
        // marked verified.
        let readme = include_str!("../../../README.md");
        for (surface, text) in [
            ("README.md", readme),
            (
                "the deposit topic",
                TOPICS.iter().find(|t| t.slug == "deposit").unwrap().body,
            ),
            (
                "the deploy topic",
                TOPICS.iter().find(|t| t.slug == "deploy").unwrap().body,
            ),
        ] {
            for line in text.lines() {
                let l = line.to_lowercase();
                // "does NOT publish" and "to publish it, see …" are the point;
                // "deposit … publishes" is the retracted claim.
                // The retracted claim is deposit ACTING as a publisher. Prose
                // that says it does not publish, or points at how to publish,
                // is the fix and must not trip the gate.
                for claim in [
                    "and publish a layer",
                    "sign and publish",
                    "deposit publishes",
                    "deposit will publish",
                ] {
                    assert!(
                        !l.contains(claim),
                        "{surface} still says deposit publishes — varve runs no server \
                         and pushes nothing (REQ-DEPLOY-001): {line}"
                    );
                }
            }
        }
    }

    // rivet: verifies REQ-DEPLOY-001
    #[test]
    fn the_deploy_topic_carries_a_sequence_a_producer_can_actually_run() {
        // An independent review replaced this topic with a three-line stub
        // holding one empty ```sh fence, and BOTH gates stayed green: `docs
        // check --coverage --strict` printed OK and the workspace suite passed.
        // The recorded evidence was three shell greps that no CI job runs.
        let body = TOPICS.iter().find(|t| t.slug == "deploy").unwrap().body;
        // The push itself.
        for needle in ["oras blob push", "oras manifest push"] {
            assert!(body.contains(needle), "the push must show `{needle}`");
        }
        // …with the part that makes the upload CONSUMABLE. A manifest without
        // the role annotations uploads fine and no consumer can read it.
        for role in ["\"envelope\"", "\"payload\"", "\"line-status\""] {
            assert!(
                body.contains(role),
                "the artifact manifest must annotate the {role} role, or every \
                 consumer fails to read what was pushed"
            );
        }
        // No unexecutable placeholder standing in for the one line that matters.
        assert!(
            !body.contains("<your artifact manifest>"),
            "a producer cannot execute a placeholder"
        );
        // What a consumer needs, the first-time bootstrap, and the air-gapped
        // alternative — the remaining three clauses.
        for (clause, needle) in [
            ("the realm registry field", "registry"),
            ("the trust root", "trust-root"),
            (
                "first-time bootstrap",
                "varve cannot verify the first realms file",
            ),
            ("the air-gapped alternative", "varve archive"),
        ] {
            assert!(
                body.contains(needle),
                "the deploy topic must cover {clause} (REQ-DEPLOY-001)"
            );
        }
    }

    // rivet: verifies REQ-DOCS-003
    #[test]
    fn every_documented_file_example_parses_with_the_real_parser() {
        // A gate that checks an example EXISTS is the same mistake as a gate
        // that checks a topic exists: `known-problems` shipped documented as an
        // array of strings while the parser wanted an array of structs, so the
        // one file the docs taught was the one file varve rejected — and the
        // reader had nothing to recover with. These run the SHIPPING parsers.
        let tmp = std::env::temp_dir().join(format!("varve-docs-parse-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut checked = 0;

        // Every topic, not just config-reference: the elided `sha256:83a699…`
        // and `trust-root = "83a699…"` that this gate first caught were copied
        // across five topics, and a user pastes whichever one they read.
        let blocks: Vec<(String, String)> =
            TOPICS.iter().flat_map(|t| fenced_blocks(t.slug)).collect();
        let mut unclassified: Vec<String> = Vec::new();
        for (lang, block) in blocks {
            if matches!(lang.as_str(), "toml" | "json") {
                let recognised = block.contains("[toolchain]")
                    || block.contains("[realm.")
                    || block.contains("[[tool]]")
                    || block.contains("[tool.runner]")
                    || block.contains("\"line\"");
                if !recognised {
                    unclassified.push(block.lines().next().unwrap_or("").trim().to_string());
                }
            }
            match lang.as_str() {
                // `[toolchain]`, NOT `manifest-version`: a review appended a
                // varve.toml example MISSING manifest-version — the exact
                // defect REQ-DOCS-002 exists to fix — and the old arm skipped
                // it precisely because the field was absent. The classifier
                // must key on what makes a block A PIN, not on the field being
                // tested.
                "toml" if block.contains("[toolchain]") => {
                    varve_core::pin::Pin::parse(&block, "docs")
                        .expect("the documented varve.toml must parse as a pin");
                    checked += 1;
                }
                "toml" if block.contains("[realm.") => {
                    std::fs::write(tmp.join(varve_core::realm::REALMS_FILE), &block).unwrap();
                    let names = varve_core::realm::realm_names(&tmp)
                        .expect("the documented varve-realms.toml must parse");
                    let first = names.first().expect("it must define a realm").clone();
                    varve_core::realm::resolve_realm(&tmp, &first)
                        .expect("the documented realm must RESOLVE, not merely parse");
                    checked += 1;
                }
                "toml" if block.contains("[[tool]]") || block.contains("[tool.runner]") => {
                    varve_core::deposit::parse_deposit_spec(&block)
                        .expect("the documented deposit spec must parse");
                    checked += 1;
                }
                "json" if block.contains("\"line\"") => {
                    serde_json::from_str::<varve_core::linestatus::LineStatus>(&block)
                        .expect("the documented line-status document must parse");
                    checked += 1;
                }
                _ => {}
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
        // Every structured block must reach a parser. `sh` and text blocks are
        // handled by `every_documented_command_is_a_real_command`; a toml or
        // json block that matches no arm is a silent hole, which is how a
        // broken pin example survived.
        assert!(
            unclassified.is_empty(),
            "{} structured block(s) reached no parser — a silent skip is how a \
             broken example survives the gate: {unclassified:?}",
            unclassified.len()
        );
        assert!(
            checked >= 6,
            "the docs claim to cover every hand-written file; only {checked} \
             example(s) were machine-checked against a real parser (REQ-DOCS-003)"
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
    // rivet: verifies REQ-DOCS-004
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
