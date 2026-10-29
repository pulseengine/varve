//! Reading what a tool says about itself, without trusting its layout.
//!
//! Everything here is a PURE function of text. Running a tool is
//! `harvest.rs`'s job and is deliberately kept away from this file, so that
//! every rule below can be tested against a string and mutated without a
//! subprocess in the way.
//!
//! The rules came from measurement, not taste (evals/agent-context): fresh
//! agents were given orientations built by earlier drafts of this parser and
//! the failures are what the rules guard.
//!
//! * a description is never cut mid-word, and a caveat ("NOT YET IMPLEMENTED",
//!   "deprecated", "always exits 2") always survives, because an agent that
//!   was told `loom verify` exists and not that it always exits 2 will try it;
//! * a tool's purpose line is the first paragraph of its help, not the first
//!   line that happens to follow a banner — spar printed a bare `Commands:`
//!   and that was reported as its purpose;
//! * a warning the tool prints about itself is kept verbatim.

/// One subcommand a tool lists in its help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sub {
    pub name: String,
    /// The first sentence of what the tool says, plus any sentence carrying a
    /// caveat. Never truncated mid-word.
    pub desc: String,
}

/// What a tool's `--help` text yields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Help {
    /// The tool's own one-line purpose, if it printed one.
    pub about: Option<String>,
    /// A line the tool printed starting `warning`, verbatim.
    pub warning: Option<String>,
    pub subcommands: Vec<Sub>,
}

impl Help {
    /// Does the tool advertise a `docs` subcommand?
    ///
    /// The ONLY condition under which `<tool> docs` may be run. `kilnd docs`
    /// starts the runtime, so "try it and see" is not an available method.
    pub fn lists_docs(&self) -> bool {
        self.subcommands.iter().any(|s| s.name == "docs")
    }
}

/// Phrases that mark a description as carrying a caveat an agent must see.
const CAVEATS: &[&str] = &[
    "not yet",
    "not implemented",
    "unimplemented",
    "deprecated",
    "experimental",
    "unsupported",
    "always exits",
    "removed in",
    "stub",
];

/// Does this text say the thing it describes does not (fully) work or is going
/// away?
pub fn is_caveat(text: &str) -> bool {
    let lower = text.to_lowercase();
    CAVEATS.iter().any(|c| lower.contains(c))
}

/// Drop control characters and collapse whitespace. Harvested text is data
/// printed into an agent's context, so it carries no terminal escapes.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Like [`clean`] but keeps line structure, for text that is stored whole
/// (help text, topic bodies): control characters other than newline are
/// blanked, and the text is bounded by what the caller read.
pub fn clean_block(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Words that end in a full stop without ending a sentence.
const ABBREVIATIONS: &[&str] = &["e.g", "i.e", "etc", "vs", "cf", "approx", "no"];

/// Split text into sentences at a full stop followed by a space and a capital.
///
/// Conservative on purpose: a wrong split loses the tail of a description,
/// which is how a caveat disappears, while a missed split only keeps a longer
/// sentence. `v0.39 (#109) — ...` and `e.g. foo` therefore do not split.
fn sentences(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    for i in 0..chars.len() {
        if chars[i] != '.' {
            continue;
        }
        let prev_ok = i > 0 && (chars[i - 1].is_alphabetic() || chars[i - 1] == ')');
        let next_ok = i + 2 < chars.len() && chars[i + 1] == ' ' && chars[i + 2].is_uppercase();
        if !prev_ok || !next_ok {
            continue;
        }
        let word: String = chars[start..i]
            .iter()
            .rev()
            .take_while(|c| !c.is_whitespace())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if ABBREVIATIONS.contains(&word.to_lowercase().as_str()) {
            continue;
        }
        out.push(chars[start..i].iter().collect::<String>());
        start = i + 2;
    }
    out.push(chars[start..].iter().collect::<String>());
    out.into_iter()
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The first sentence of `text`, plus every later sentence that carries a
/// caveat, so collapsing a long description cannot drop one.
pub fn summarize(text: &str) -> String {
    let all = sentences(&clean(text));
    let Some(first) = all.first() else {
        return String::new();
    };
    let mut out = first.clone();
    if !is_caveat(first) {
        for s in all.iter().skip(1).filter(|s| is_caveat(s)) {
            out.push_str(". ");
            out.push_str(s);
        }
    }
    out
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// `  name   description` with at least two spaces between them, indented by
/// at least `min` columns. Returns the name and the description.
fn entry(line: &str, min: usize) -> Option<(&str, &str)> {
    if indent(line) < min {
        return None;
    }
    let t = line.trim_start();
    let end = t.find(char::is_whitespace)?;
    let (name, rest) = t.split_at(end);
    if !is_ident(name) || !rest.starts_with("  ") || rest.trim().is_empty() {
        return None;
    }
    Some((name, rest.trim()))
}

fn is_banner(tool: &str, line: &str) -> bool {
    let Some(rest) = line.strip_prefix(tool).map(str::trim) else {
        return false;
    };
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    rest.starts_with(|c: char| c.is_ascii_digit())
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
}

fn starts_with_ci(line: &str, prefix: &str) -> bool {
    line.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

fn is_heading(t: &str) -> bool {
    starts_with_ci(t, "usage") || t.ends_with(':')
}

/// The tool's purpose: its first paragraph, minus banner, warning and heading
/// lines, ending at the first `Usage:` or `Section:` line.
fn about_of(tool: &str, text: &str) -> Option<String> {
    let mut para: Vec<&str> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            if para.is_empty() {
                continue;
            }
            break;
        }
        if is_banner(tool, t) || starts_with_ci(t, "warning") {
            continue;
        }
        if is_heading(t) || t.starts_with('-') {
            if para.is_empty() {
                // The help opens with a heading, so it states no purpose.
                // Reporting the heading AS the purpose is the spar defect.
                return None;
            }
            break;
        }
        para.push(t);
    }
    let s = summarize(&para.join(" "));
    (!s.is_empty()).then_some(s)
}

/// Parse a tool's `--help` text.
pub fn parse_help(tool: &str, text: &str) -> Help {
    let text_lines: Vec<&str> = text.lines().collect();
    let warning = text_lines
        .iter()
        .map(|l| l.trim())
        .find(|l| starts_with_ci(l, "warning"))
        .map(clean);

    let mut subcommands: Vec<Sub> = Vec::new();
    let mut in_section = false;
    let mut entry_indent: Option<usize> = None;
    for line in &text_lines {
        let t = line.trim();
        if !in_section {
            in_section =
                t.eq_ignore_ascii_case("commands:") || t.eq_ignore_ascii_case("subcommands:");
            continue;
        }
        if t.is_empty() {
            break;
        }
        let base = *entry_indent.get_or_insert(indent(line));
        if indent(line) > base {
            // A wrapped description. It may be the half that carries the caveat.
            if let Some(last) = subcommands.last_mut() {
                last.desc.push(' ');
                last.desc.push_str(t);
            }
            continue;
        }
        if let Some((name, desc)) = entry(line, base)
            && name != "help"
            && !subcommands.iter().any(|s| s.name == name)
        {
            subcommands.push(Sub {
                name: name.to_string(),
                desc: desc.to_string(),
            });
        }
    }
    for s in &mut subcommands {
        s.desc = summarize(&s.desc);
    }
    Help {
        about: about_of(tool, text),
        warning,
        subcommands,
    }
}

/// Topic names and one-line descriptions out of a tool's `<tool> docs` listing.
///
/// Names are restricted to `[a-z0-9-]`, which is also what makes them safe to
/// print as a command: a name is never free text.
pub fn parse_topics(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some((name, desc)) = entry(line, 2) {
            let ident = name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if ident && !out.iter().any(|(n, _)| n == name) {
                out.push((name.to_string(), clean(desc)));
            }
        }
    }
    out
}

/// Tool names a warning points at: every backticked identifier that is not the
/// tool itself.
pub fn names_in_warning(tool: &str, warning: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, part) in warning.split('`').enumerate() {
        if i % 2 == 1 && is_ident(part) && part != tool && !out.iter().any(|n| n == part) {
            out.push(part.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MELD: &str = "Static WebAssembly component fusion\n\nUsage: meld [OPTIONS] [COMMAND]\n\nCommands:\n  fuse     Fuse multiple WebAssembly components into a single module\n  inspect  Inspect a WebAssembly component\n  docs     Show embedded, queryable documentation (offline)\n  help     Print this message or the help of the given subcommand(s)\n\nOptions:\n  -v, --verbose  Enable verbose logging\n";

    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_help_text_yields_purpose_and_subcommands_but_not_clap_help() {
        let h = parse_help("meld", MELD);
        assert_eq!(
            h.about.as_deref(),
            Some("Static WebAssembly component fusion")
        );
        let names: Vec<&str> = h.subcommands.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["fuse", "inspect", "docs"]);
        assert_eq!(
            h.subcommands[0].desc,
            "Fuse multiple WebAssembly components into a single module"
        );
        assert_eq!(h.warning, None);
    }

    /// A tool that lists `docs` advertises it; one that does not, does not.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn docs_is_advertised_only_when_the_help_lists_it() {
        assert!(parse_help("meld", MELD).lists_docs());
        let no_docs = MELD.replace(
            "  docs     Show embedded, queryable documentation (offline)\n",
            "",
        );
        assert!(!parse_help("meld", &no_docs).lists_docs());
        // Mentioning docs in prose, or in an option, is not advertising it.
        let prose = "Tool\n\nCommands:\n  run  Run it, see docs for more\n";
        assert!(!parse_help("t", prose).lists_docs());
    }

    /// spar printed `Usage:` then a bare `Commands:` and no purpose line; the
    /// first draft reported "Commands:" as its purpose.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_help_that_opens_with_a_heading_states_no_purpose() {
        let spar = "Usage: spar <command> [options] <file...>\n\nCommands:\n  parse      Parse AADL file(s) and report diagnostics\n  items      Show item tree (declarations) for file(s)\n";
        let h = parse_help("spar", spar);
        assert_eq!(h.about, None);
        assert_eq!(h.subcommands.len(), 2);
        let bare = "Commands:\n  parse  Parse it\n";
        assert_eq!(parse_help("spar", bare).about, None);
    }

    /// The purpose may run over several lines, and a `Usage:` line directly
    /// after it (no blank) ends it. A version banner is not a purpose.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn the_purpose_is_the_first_paragraph_not_the_first_line() {
        let synth = "Synth compiles WebAssembly (WASM/WAT) to native ARM Cortex-M machine code,\nproducing bare-metal ELF binaries for embedded targets.\n\nExamples:\n  synth compile input.wat\n";
        assert_eq!(
            parse_help("synth", synth).about.as_deref(),
            Some(
                "Synth compiles WebAssembly (WASM/WAT) to native ARM Cortex-M machine code, producing bare-metal ELF binaries for embedded targets"
            )
        );
        let kilnd = "WebAssembly Runtime Daemon (kilnd)\nUsage: kilnd [OPTIONS] <module.wasm>\n\nOptions:\n  --fuel <n>  limit\n";
        assert_eq!(
            parse_help("kilnd", kilnd).about.as_deref(),
            Some("WebAssembly Runtime Daemon (kilnd)")
        );
        let ordeal = "ordeal 0.14.0\ncertificate-checked QF_BV SMT solver\n\nusage:\n  ordeal check <file>\n";
        assert_eq!(
            parse_help("ordeal", ordeal).about.as_deref(),
            Some("certificate-checked QF_BV SMT solver")
        );
        // A tool whose name merely starts a sentence is not a banner.
        let prose = "meld fuses components\n\nUsage: meld\n";
        assert_eq!(
            parse_help("meld", prose).about.as_deref(),
            Some("meld fuses components")
        );
    }

    /// kilnd said it is deprecated in favour of `kiln`; the warning is shown
    /// verbatim and names the tool it points at.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_warning_the_tool_prints_is_kept_and_its_named_tool_is_found() {
        let text = "WebAssembly Runtime Daemon (kilnd)\nUsage: kilnd [OPTIONS]\n\nwarning: `kilnd` is deprecated and will be removed in v0.7.0; use `kiln` instead\n";
        let h = parse_help("kilnd", text);
        let w = h.warning.expect("the warning line is found");
        assert_eq!(
            w,
            "warning: `kilnd` is deprecated and will be removed in v0.7.0; use `kiln` instead"
        );
        assert_eq!(names_in_warning("kilnd", &w), ["kiln"]);
        // flags and phrases are not tool names
        assert!(names_in_warning("t", "Warning: use `--new-flag` or `a b`").is_empty());
        assert_eq!(names_in_warning("t", "warning: use `x` or `x`"), ["x"]);
        assert_eq!(
            names_in_warning("t", "use `a` and `b` or `c`"),
            ["a", "b", "c"]
        );
        assert_eq!(parse_help("t", "Tool\n").warning, None);
    }

    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_caveat_survives_in_the_first_sentence_and_in_a_later_one() {
        let loom = "Tool\n\nCommands:\n  verify    Verify ISLE optimization rules (NOT YET IMPLEMENTED — always exits 2)\n";
        let h = parse_help("loom", loom);
        assert_eq!(
            h.subcommands[0].desc,
            "Verify ISLE optimization rules (NOT YET IMPLEMENTED — always exits 2)"
        );
        let later = summarize("Run the thing. Used by CI. This is experimental and may change.");
        assert_eq!(later, "Run the thing. This is experimental and may change");
        // No caveat, no extra sentences.
        assert_eq!(summarize("Run the thing. Used by CI."), "Run the thing");
        // Already in the first sentence: not repeated.
        assert_eq!(summarize("Deprecated thing. Other."), "Deprecated thing");
        assert!(is_caveat("always exits 2") && is_caveat("Not Yet done") && !is_caveat("works"));
        for c in [
            "not implemented",
            "unimplemented",
            "experimental",
            "unsupported",
            "removed in 1.0",
            "stub",
            "deprecated",
        ] {
            assert!(is_caveat(c), "{c}");
        }
    }

    /// A description is cut at a sentence, never at a width, and a full stop
    /// inside an abbreviation or a version is not a sentence.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn descriptions_are_cut_at_sentences_not_in_words() {
        assert_eq!(
            summarize("Compile (e.g. synth compile a.wat) to ELF. Other."),
            "Compile (e.g. synth compile a.wat) to ELF"
        );
        assert_eq!(
            summarize("v0.39 (#109) — reconcile a manifest. Used by CI."),
            "v0.39 (#109) — reconcile a manifest"
        );
        assert_eq!(summarize("one two. three"), "one two. three");
        assert_eq!(summarize("   "), "");
        let long = "a ".repeat(500);
        assert_eq!(summarize(&long), long.trim());
    }

    /// A full stop at the very end, or before a capital after an abbreviation,
    /// is handled without panicking and without splitting.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn sentence_splitting_handles_edges() {
        assert_eq!(sentences("Hello. "), ["Hello"]);
        assert_eq!(sentences("A. B"), ["A", "B"]);
        assert_eq!(sentences("end."), ["end"]);
        // a leading stop has nothing before it, and a stop after `)` ends one
        assert_eq!(sentences(". Foo"), [". Foo"]);
        assert_eq!(
            sentences("Do it (carefully). Then rest"),
            ["Do it (carefully)", "Then rest"]
        );
        assert_eq!(
            summarize("Use it, e.g. Cargo for builds. Other."),
            "Use it, e.g. Cargo for builds"
        );
        assert_eq!(
            summarize("See cf. Foo for more. Other."),
            "See cf. Foo for more"
        );
        // a stop after a digit is not a sentence end
        assert_eq!(summarize("Needs v2. Then more"), "Needs v2. Then more");
    }

    /// A line that only starts with the tool's name is prose, not a banner.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_banner_needs_a_version_and_nothing_else() {
        assert!(is_banner("meld", "meld 0.65.1"));
        assert!(is_banner("meld", "meld v1.0.0-rc.1+build"));
        assert!(!is_banner("meld", "meld fuses"));
        assert!(!is_banner("meld", "meld 5 things to do"));
        assert!(!is_banner("meld", "other 1.0"));
        assert_eq!(
            parse_help("meld", "meld fuses\n").about.as_deref(),
            Some("meld fuses")
        );
    }

    /// A wrapped description keeps its second line, which may hold the caveat.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn a_wrapped_description_is_joined() {
        let t = "Tool\n\nCommands:\n  go    Go somewhere\n          and this part is deprecated\n  stop  Stop\n";
        let h = parse_help("t", t);
        assert_eq!(
            h.subcommands[0].desc,
            "Go somewhere and this part is deprecated"
        );
        assert_eq!(h.subcommands[1].desc, "Stop");
    }

    /// Only the Commands section is read, a repeated name is one entry, and
    /// options are never subcommands.
    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn only_the_commands_section_is_read() {
        let t = "Tool\n\nUsage: t\n\nCommands:\n  a  First\n  a  Again\n  Bad-name  nope\n\nOptions:\n  verbose  Not a command\n";
        let h = parse_help("t", t);
        let names: Vec<&str> = h.subcommands.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a"]);
        let upper = "Tool\n\nSUBCOMMANDS:\n  x  Do x\n";
        assert_eq!(parse_help("t", upper).subcommands.len(), 1, "clap 2 style");
        let other = "Tool\n\nFlags:\n  x  Do x\n";
        assert_eq!(parse_help("t", other).subcommands.len(), 0);
        let sub = "Tool\n\nSubcommands:\n  x  Do x\n";
        assert_eq!(parse_help("t", sub).subcommands.len(), 1);
    }

    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn topics_are_names_with_descriptions_and_nothing_else() {
        let t = "meld docs — topics (meld docs <topic>):\n\n  fusion               Static fusion — what meld does\n  memory-strategies    Memory strategies\n  fusion               duplicate\n  Getting started\n    quickstart               10-step quickstart\n\nUsage: wsc docs <topic>\n       wsc docs --search <query>\n";
        let topics = parse_topics(t);
        let names: Vec<&str> = topics.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["fusion", "memory-strategies", "quickstart"]);
        assert_eq!(topics[0].1, "Static fusion — what meld does");
        assert!(parse_topics("no topics here\n").is_empty());
    }

    // rivet: verifies REQ-AGENTDOCS-001
    #[test]
    fn harvested_text_loses_control_characters() {
        assert_eq!(clean("a\u{1b}[31mb\tc\n d"), "a [31mb c d");
        assert_eq!(clean_block("a\u{1b}b\tc\nd\n\n"), "a b c\nd");
    }
}
