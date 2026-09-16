//! Embedded, queryable documentation for the producer (REQ-PRODUCERDOCS-001).
//!
//! varve gates its own documentation: every subcommand must have a topic,
//! mechanically, so a new one cannot ship undocumented. That gate covered ONE
//! of the two shipped binaries. varve-producer had nine subcommands and zero
//! topics — while being the program other repositories' CI actually runs, and
//! the one whose asset-template language has silently dropped a tool from a
//! published layer.
//!
//! Documenting it inside `varve docs` would not fix that: a CI job holding the
//! producer may not hold varve, and sending someone to another binary for the
//! manual is the friction this removes. So the topics are compiled in here.

/// One documentation topic, compiled into the binary.
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

/// Every topic, in the order `docs` lists them: the commands in pipeline order,
/// then the concepts.
pub fn topics() -> &'static [Topic] {
    const T: &[Topic] = &[
        topic!(
            "forge",
            "forge — which instance, which authority",
            "cmd-forge.md"
        ),
        topic!("plan", "plan — what a deposit would do", "cmd-plan.md"),
        topic!("scan", "scan — what moved upstream", "cmd-scan.md"),
        topic!(
            "next-layer",
            "next-layer — the id and counter the record implies",
            "cmd-next-layer.md"
        ),
        topic!(
            "assets",
            "assets — which asset a template selects",
            "cmd-assets.md"
        ),
        topic!(
            "arch",
            "arch — architecture without executing",
            "cmd-arch.md"
        ),
        topic!(
            "publish-check",
            "publish-check — is this id already published",
            "cmd-publish-check.md"
        ),
        topic!(
            "deposit",
            "deposit — assemble and stage a layer",
            "cmd-deposit.md"
        ),
        topic!("docs", "docs — this documentation", "cmd-docs.md"),
        topic!(
            "ingest-ladder",
            "ingest-ladder — how a payload is vouched for",
            "concept-ingest-ladder.md"
        ),
    ];
    T
}

/// One topic by slug.
pub fn find(slug: &str) -> Option<&'static Topic> {
    topics().iter().find(|t| t.slug == slug)
}

/// Subcommands with no topic (REQ-PRODUCERDOCS-001 clause 2).
///
/// Enumerates the CLI rather than a list someone maintains, which is the
/// difference between an invariant and a habit.
///
/// No `help` filter: clap does not report its generated `help` subcommand from
/// `get_subcommands()` here, so a filter for it could never fire — mutation
/// testing showed the comparison could be inverted with nothing noticing. A
/// guard that cannot change an outcome is not caution, and the same reasoning
/// removed the `-1` that used to correct a count for a subcommand that was
/// never in it.
pub fn coverage_gaps(cmd: &clap::Command) -> Vec<String> {
    cmd.get_subcommands()
        .map(|c| c.get_name().to_string())
        .filter(|n| find(n).is_none())
        .collect()
}

/// The topic list, for humans.
pub fn render_list() -> String {
    let mut out = String::from("varve-producer docs — topics (varve-producer docs <topic>):\n\n");
    for t in topics() {
        out.push_str(&format!("  {:<16} {}\n", t.slug, t.title));
    }
    out
}

/// Topics whose body contains `needle`, case-insensitively.
pub fn grep(needle: &str) -> Vec<&'static Topic> {
    let n = needle.to_lowercase();
    topics()
        .iter()
        .filter(|t| t.body.to_lowercase().contains(&n) || t.slug.contains(&n))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// THE GATE. Every subcommand this binary offers has a topic.
    ///
    /// Enumerated from the CLI itself, so adding a subcommand fails the build
    /// until someone writes down what it does. `scan` and `next-layer` were
    /// added the same day this gate was, and would both have shipped
    /// undocumented without it.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn every_subcommand_has_a_topic() {
        let gaps = coverage_gaps(&crate::cli::Cli::command());
        assert!(
            gaps.is_empty(),
            "these subcommands have no documentation topic: {gaps:?}\n\
             Add one under crates/varve-producer/docs/ and register it in topics()."
        );
    }

    /// The gate must be able to FAIL. Asserting only that the real CLI has no
    /// gaps is satisfied by a function that returns an empty list for
    /// everything — which is exactly the mutant that survived until this test
    /// existed.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn the_coverage_gate_detects_an_undocumented_subcommand() {
        let synthetic = clap::Command::new("probe")
            .subcommand(clap::Command::new("scan")) // has a topic
            .subcommand(clap::Command::new("undocumented-thing"));
        let gaps = coverage_gaps(&synthetic);
        assert_eq!(
            gaps,
            vec!["undocumented-thing".to_string()],
            "the gate must name the subcommand that has no topic"
        );
    }

    /// The list is what a human reads first, so it must actually contain the
    /// topics. `render_list` was replaceable by an empty string and by
    /// "xyzzy" with nothing noticing.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn the_rendered_list_names_every_topic_and_its_title() {
        let out = render_list();
        assert!(out.contains("varve-producer docs"), "{out}");
        for t in topics() {
            assert!(out.contains(t.slug), "the list omits {:?}", t.slug);
            assert!(
                out.contains(t.title),
                "the list omits the title of {:?}",
                t.slug
            );
        }
        assert!(
            out.lines().count() > topics().len(),
            "a list shorter than the topics it lists: {out}"
        );
    }

    /// And the reverse: a topic naming a subcommand that no longer exists is a
    /// rename's leftover, and it documents nothing while appearing to.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn no_topic_documents_a_subcommand_that_is_gone() {
        let cmds: Vec<String> = crate::cli::Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        // Concept topics are not commands; command topics must match one.
        let concepts = ["ingest-ladder"];
        for t in topics() {
            if concepts.contains(&t.slug) {
                continue;
            }
            assert!(
                cmds.iter().any(|c| c == t.slug),
                "topic {:?} documents no subcommand — a rename's leftover",
                t.slug
            );
        }
    }

    /// A topic with no body is a file someone created and did not fill in.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn every_topic_has_a_title_and_a_body() {
        for t in topics() {
            assert!(!t.slug.is_empty());
            assert!(!t.title.is_empty(), "{} has no title", t.slug);
            assert!(
                t.body.len() > 200,
                "{} is {} bytes — a stub, not a topic",
                t.slug,
                t.body.len()
            );
            assert!(
                t.body.starts_with("# "),
                "{} does not start with a heading",
                t.slug
            );
        }
    }

    /// Slugs are unique, or `find` returns whichever came first and the second
    /// topic is unreachable.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn slugs_are_unique_and_findable() {
        let mut seen = std::collections::BTreeSet::new();
        for t in topics() {
            assert!(seen.insert(t.slug), "duplicate slug {:?}", t.slug);
            assert_eq!(find(t.slug).map(|x| x.slug), Some(t.slug));
        }
        assert!(find("no-such-topic").is_none());
    }

    /// The template language and the ingest ladder are the two things that have
    /// actually produced silently wrong results, and clause 4 names them.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn the_things_that_went_wrong_before_are_documented() {
        let assets = find("assets").expect("the template language has a topic");
        for placeholder in ["%V", "%R", "%T", "%U", "%H", "%P"] {
            assert!(
                assets.body.contains(placeholder),
                "the asset topic does not document {placeholder}"
            );
        }
        let ladder = find("ingest-ladder").expect("the ingest ladder has a topic");
        for rung in [
            "cosign-sums",
            "build-provenance",
            "upstream-sums",
            "unverified",
        ] {
            assert!(ladder.body.contains(rung), "the ladder omits {rung}");
        }
    }

    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn grep_finds_a_topic_by_its_content() {
        let hits = grep("GH_HOST");
        assert!(
            hits.iter().any(|t| t.slug == "scan"),
            "searching for GH_HOST should reach the scan topic"
        );
        assert!(grep("zzz-nothing-matches-this").is_empty());
    }
}
