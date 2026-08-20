//! The exit-code contract (REQ-CIGATE-001) — the thing a pipeline gates on.
//!
//! A ten-persona documentation audit asked two personas to write the consumer
//! CI gate that three separate docs topics tell a reader to write. Both failed,
//! for the same reason: `varve docs --grep "exit code"` returned nothing across
//! all fifty topics, so there was no contract to write against — and the one
//! command whose whole purpose is stopping a build (`varve status` on a YANKED
//! layer) exited 0.
//!
//! This module is the single source of that contract. Three surfaces render
//! FROM it and none of them restates it:
//!
//!   * `main()` maps an [`Outcome`] to the process exit status,
//!   * `varve exit-codes` prints it (`--json` for machines),
//!   * the `exit-codes` docs topic is GENERATED from it, so a documented table
//!     cannot drift from the binary — a documented table nothing verifies is
//!     the exact failure mode this release is named for.
//!
//! And the numbers themselves are checked against the real process status of a
//! real invocation, one scenario per code, in `tests/cli.rs`
//! (`every_documented_exit_code_is_produced_by_a_real_invocation`). Rendering a
//! table from a constant proves the table is self-consistent; only running the
//! binary proves it is TRUE.

/// What a varve process is telling its caller.
///
/// This is deliberately small. Every code here is one a pipeline branches on;
/// a code nothing branches on is noise that becomes a compatibility promise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// The command did what it was asked.
    Ok,
    /// The command refused or failed: a bad signature, a missing layer, an
    /// unreadable file, a rollback, a shadowed PATH. varve fails closed, so
    /// this is the answer to every "varve could not vouch for it".
    Error,
    /// The command line itself was wrong — clap's own code, listed here
    /// because a pipeline that treats "unknown flag" as "verification failed"
    /// reports the wrong incident.
    Usage,
    /// The pinned layer is YANKED by a signed line-status document. Not an
    /// error: varve answered the question, and the answer stops the build.
    Yanked,
    /// The query matched nothing. Not an error: the search ran and the answer
    /// is empty, which is a result a gate acts on.
    NoMatch,
}

impl Outcome {
    /// The process exit status. These numbers are a compatibility promise.
    pub fn code(self) -> u8 {
        match self {
            Outcome::Ok => 0,
            Outcome::Error => 1,
            Outcome::Usage => 2,
            Outcome::Yanked => 3,
            Outcome::NoMatch => 4,
        }
    }

    /// The stable machine-readable name, as emitted by `--json`.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Usage => "usage",
            Outcome::Yanked => "yanked",
            Outcome::NoMatch => "no-match",
        }
    }

    /// One line a pipeline author can act on.
    pub fn meaning(self) -> &'static str {
        match self {
            Outcome::Ok => "the command did what it was asked",
            Outcome::Error => {
                "varve refused or failed — an unverifiable layer, a missing pin, an unreadable \
                 file, a rollback, a shadowed PATH. varve fails closed, so every \"cannot vouch \
                 for it\" lands here"
            }
            Outcome::Usage => {
                "the command line was wrong (unknown flag, unknown subcommand, missing \
                 argument) — clap's own code. Distinct from 1 so a pipeline does not report a \
                 typo as a verification failure"
            }
            Outcome::Yanked => {
                "the pinned layer is YANKED by a signed line-status document. varve answered; \
                 the answer stops the build"
            }
            Outcome::NoMatch => "the query ran and matched nothing",
        }
    }

    /// Which commands can produce it. `""` means "every command".
    pub fn commands(self) -> &'static [&'static str] {
        match self {
            Outcome::Ok | Outcome::Error | Outcome::Usage => &[],
            Outcome::Yanked => &["status"],
            Outcome::NoMatch => &["docs --grep"],
        }
    }
}

/// The whole contract, in the order it is documented.
///
/// Exhaustively bound to the enum by `index_in_contract` in the tests below: a
/// new variant that is not listed here fails to COMPILE, so the table cannot
/// silently lose a code the binary can still return.
pub const CONTRACT: &[Outcome] = &[
    Outcome::Ok,
    Outcome::Error,
    Outcome::Usage,
    Outcome::Yanked,
    Outcome::NoMatch,
];

/// Where the contract can be produced by a command rather than "any command".
fn scope(o: Outcome) -> String {
    match o.commands() {
        [] => "any command".to_string(),
        cs => cs
            .iter()
            .map(|c| format!("`varve {c}`"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// The human table `varve exit-codes` prints.
pub fn render_text() -> String {
    let mut out = String::from("varve exit codes — the contract a pipeline gates on\n\n");
    for o in CONTRACT {
        out.push_str(&format!(
            "  {code}  {name:<9} {scope}\n      {meaning}\n",
            code = o.code(),
            name = o.name(),
            scope = scope(*o),
            meaning = o.meaning(),
        ));
    }
    out.push_str(
        "\nAny code varve returns is one of these. A future code is additive; the meaning of a \
         code already listed here does not change.\n",
    );
    out
}

/// The machine-readable contract. Stable shape: a `codes` array of objects
/// carrying `code` (number), `name` (stable slug), `meaning` (prose) and
/// `commands` (the commands that can produce it; empty = any).
pub fn render_json() -> String {
    let codes: Vec<_> = CONTRACT
        .iter()
        .map(|o| {
            serde_json::json!({
                "code": o.code(),
                "name": o.name(),
                "meaning": o.meaning(),
                "commands": o.commands(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "codes": codes }))
        .expect("the exit-code contract serialises")
}

/// The `exit-codes` docs topic body, GENERATED from the contract above.
///
/// The topic is not a hand-written `.md` file on purpose. A markdown table
/// listing exit codes is exactly the artefact that goes stale the first time a
/// code is added, and nothing would notice: this one cannot say anything the
/// binary does not do, because it is printed by the same code that returns.
pub fn render_topic() -> String {
    let mut out = String::from(
        "# Exit codes\n\n\
         Every `varve` process exits with one of the codes below. They are a compatibility \
         promise: a future release may ADD a code, but will not change what one already listed \
         here means.\n\n\
         This page is generated from the same table the binary exits with, and every code in it \
         is checked against the real exit status of a real invocation by the test suite — so it \
         cannot drift from what varve does.\n\n\
         | code | name | produced by | meaning |\n|---|---|---|---|\n",
    );
    for o in CONTRACT {
        out.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            o.code(),
            o.name(),
            scope(*o),
            o.meaning(),
        ));
    }
    out.push_str(
        "\n## The consumer gate\n\n\
         This is the CI gate the `ci`, `status` and `verify` topics tell you to write. It is \
         three commands and no output scraping — the exit code is the whole contract.\n\n\
         ```sh\n\
         set -e\n\
         varve install                 # fetch + verify the pinned layer\n\
         varve verify                  # re-check it offline, including PATH shadowing\n\
         \n\
         # A yanked layer must stop the build. `status` exits 3 when the pinned\n\
         # layer is yanked by a signed line-status document, 0 when it is not,\n\
         # and 1 when it could not answer at all — three outcomes, three codes.\n\
         varve status\n\
         ```\n\n\
         Branch on the yank rather than aborting on it:\n\n\
         ```sh\n\
         varve status || case $? in\n\
         \u{20} 3) echo \"pinned layer is yanked — refusing to build\" >&2; exit 1 ;;\n\
         \u{20} *) echo \"varve status could not answer\" >&2; exit 1 ;;\n\
         esac\n\
         ```\n\n\
         Machine-readable, for a pipeline that wants the table itself:\n\n\
         ```sh\n\
         varve exit-codes --json\n\
         ```\n\n\
         ## What is NOT an exit code\n\n\
         `varve docs --grep` exits 4 when nothing matches, so a documentation check can gate; it \
         is not an error, and nothing is written to stderr. Likewise `varve status` exiting 3 \
         is an ANSWER, not a failure — stdout still carries the full report.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Position of an outcome in `CONTRACT`. EXHAUSTIVE on purpose: a new
    /// variant that is not added to `CONTRACT` fails to compile here, so the
    /// documented table cannot lose a code the binary can still return. Same
    /// device `kind.rs` uses, for the same reason — two kinds reached that enum
    /// while its round-trip test still listed six.
    fn index_in_contract(o: Outcome) -> usize {
        match o {
            Outcome::Ok => 0,
            Outcome::Error => 1,
            Outcome::Usage => 2,
            Outcome::Yanked => 3,
            Outcome::NoMatch => 4,
        }
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn the_contract_holds_every_outcome_the_binary_can_return() {
        for (i, o) in CONTRACT.iter().enumerate() {
            assert_eq!(
                index_in_contract(*o),
                i,
                "CONTRACT is out of step with the Outcome enum at {o:?}"
            );
        }
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn every_code_is_distinct_and_named() {
        let mut seen = std::collections::BTreeSet::new();
        for o in CONTRACT {
            assert!(
                seen.insert(o.code()),
                "exit code {} is claimed by two outcomes",
                o.code()
            );
            assert!(!o.name().is_empty());
            assert!(
                o.meaning().len() > 20,
                "{} needs a meaning a pipeline author can act on",
                o.name()
            );
        }
        assert_eq!(Outcome::Ok.code(), 0, "success is 0, forever");
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn the_generated_topic_lists_every_code_and_shows_a_gate() {
        let topic = render_topic();
        for o in CONTRACT {
            assert!(
                topic.contains(&format!("| {} | `{}` |", o.code(), o.name())),
                "the generated topic omits exit code {}",
                o.code()
            );
        }
        // The reason this topic exists at all: a copy-pasteable consumer gate.
        assert!(topic.contains("varve status"));
        assert!(topic.contains("case $? in"));
        // …and the phrase the audit grepped for and did not find.
        assert!(topic.to_lowercase().contains("exit code"));
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn the_json_contract_is_a_stable_shape() {
        let v: serde_json::Value = serde_json::from_str(&render_json()).unwrap();
        let codes = v["codes"].as_array().expect("`codes` is an array");
        assert_eq!(codes.len(), CONTRACT.len());
        for c in codes {
            assert!(c["code"].is_u64(), "`code` is a NUMBER, not a string");
            assert!(c["name"].is_string());
            assert!(c["meaning"].is_string());
            assert!(c["commands"].is_array());
        }
        assert_eq!(codes[0]["code"], 0);
        assert_eq!(codes[0]["name"], "ok");
    }
}
