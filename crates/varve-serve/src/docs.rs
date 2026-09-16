//! Embedded documentation for `varve-serve` (REQ-PRODUCERDOCS-001 clause 3).
//!
//! Every shipped binary carries its own documentation gate. varve's gate was
//! real, worked, and covered one of two binaries; naming the third one in the
//! second one's gate would repeat that mistake a binary later, so the gate
//! enumerates `crates/*/src/main.rs` and this file is what it looks for.
//!
//! **This binary has no subcommands**, so a subcommand-shaped gate would pass
//! unconditionally — and a gate that cannot fail is the exact defect mutation
//! testing found in varve's own docs gate in v0.34.0 (`coverage_gaps` was
//! replaceable by `vec![]` and every test still passed). So what is enumerated
//! here is the thing this CLI actually has: its FLAGS. A flag that no topic
//! mentions fails the build, which makes adding one require saying what it
//! does.

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

pub fn topics() -> &'static [Topic] {
    const T: &[Topic] = &[
        topic!(
            "serve",
            "serve — reading a document without copying it",
            "cmd-serve.md"
        ),
        topic!(
            "security",
            "security — what listening on a socket does and does not expose",
            "concept-security.md"
        ),
    ];
    T
}

pub fn find(slug: &str) -> Option<&'static Topic> {
    topics().iter().find(|t| t.slug == slug)
}

/// Flags and subcommands no topic mentions.
///
/// Lives in the LIBRARY, so `--lib` tests reach it and the mutation gate can
/// cover it. A gate that no mutant can be run against is the same kind of
/// unchecked boundary it exists to prevent.
///
/// Enumerated from the CLI rather than from a list someone maintains, which is
/// the difference between an invariant and a habit. `help` and `version` are
/// clap's own and are excluded: they are not this program's surface, and a
/// guard that can never fire is not caution.
pub fn coverage_gaps(cmd: &clap::Command) -> Vec<String> {
    let mentioned = |needle: &str| {
        topics()
            .iter()
            .any(|t| t.body.contains(&format!("--{needle}")))
    };
    let mut gaps: Vec<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_long())
        .filter(|l| !matches!(*l, "help" | "version"))
        .filter(|l| !mentioned(l))
        .map(|l| format!("--{l}"))
        .collect();
    // Subcommands too, so this keeps working if the binary ever grows one.
    gaps.extend(
        cmd.get_subcommands()
            .map(|c| c.get_name().to_string())
            .filter(|n| find(n).is_none()),
    );
    gaps
}

pub fn render_list() -> String {
    let mut out = String::from("varve-serve docs — topics (varve-serve --docs <topic>):\n\n");
    for t in topics() {
        out.push_str(&format!("  {:<10} {}\n", t.slug, t.title));
    }
    out
}

/// `--docs` with no argument lists; with one, shows it.
pub fn show(topic: &str) -> anyhow::Result<()> {
    if topic.is_empty() {
        print!("{}", render_list());
        return Ok(());
    }
    match find(topic) {
        Some(t) => {
            print!("{}", t.body);
            Ok(())
        }
        None => {
            let known: Vec<&str> = topics().iter().map(|t| t.slug).collect();
            anyhow::bail!("no such topic {topic:?}. Known: {}", known.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// THE GATE. Every flag this binary offers is mentioned by some topic.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn every_flag_is_documented() {
        let gaps = coverage_gaps(&crate::cli::Cli::command());
        assert!(
            gaps.is_empty(),
            "these flags are mentioned by no topic: {gaps:?}\n\
             Document them under crates/varve-serve/docs/ — a flag nobody wrote down \
             is one nobody can be expected to find."
        );
    }

    /// NEGATIVE CONTROL: the gate must be able to fail.
    ///
    /// varve's own docs gate shipped in a state where `coverage_gaps` could be
    /// replaced by `vec![]` with every test still green — the only assertion
    /// was that the real CLI has no gaps, which an empty list satisfies for
    /// everything. So this hands it a flag that is certainly undocumented and
    /// requires it to say so.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn the_gate_reports_a_flag_that_is_not_documented() {
        let probe = clap::Command::new("probe").arg(
            clap::Arg::new("undocumented-probe")
                .long("undocumented-probe")
                .action(clap::ArgAction::SetTrue),
        );
        assert_eq!(
            coverage_gaps(&probe),
            vec!["--undocumented-probe".to_string()],
            "a gate that cannot report a gap is not a gate"
        );
    }

    /// clap's own flags are not this program's surface, and a filter that can
    /// never fire is not caution — so assert it actually fires.
    // rivet: verifies REQ-PRODUCERDOCS-001
    #[test]
    fn claps_own_flags_are_not_demanded() {
        let probe = clap::Command::new("probe").arg(
            clap::Arg::new("help")
                .long("help")
                .action(clap::ArgAction::SetTrue),
        );
        assert!(coverage_gaps(&probe).is_empty());
    }

    /// The security posture is the reason this is a separate binary, so it is
    /// not optional prose. A reader deciding whether to run a listening
    /// process needs the answer in the program, not in a commit message.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn the_security_topic_states_what_it_must() {
        let body = find("security").expect("the security topic exists").body;
        for needle in [
            // loopback, not the network
            "127.0.0.1",
            // why traversal is impossible rather than defended
            "in memory",
            // the uncomfortable part: a document is an execution context
            "JavaScript",
        ] {
            assert!(
                body.contains(needle),
                "the security topic must state {needle:?} — someone deciding whether to run \
                 a process that listens needs it said outright"
            );
        }
    }
}
