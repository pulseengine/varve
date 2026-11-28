//! `varve --help` with its subcommands grouped by task.
//!
//! clap 4 puts every subcommand under one heading, and on a narrow terminal
//! it moves every description onto the line under its name once the name
//! column passes 40% of the width. varve has some forty subcommands, so the
//! list is laid out here: grouped under [`GROUPS`], names in one column,
//! descriptions wrapped in their own column at the width clap uses for the
//! rest of the help.

use clap::{Command, CommandFactory};

/// The widest help varve prints, whatever the terminal.
pub(crate) const MAX_WIDTH: usize = 100;

/// Every subcommand, in the group a reader looks for it under.
///
/// A subcommand missing here is still printed, under "Other", so a new
/// command can never vanish from `--help`; the test
/// `every_subcommand_is_in_exactly_one_group` keeps "Other" empty.
pub(crate) const GROUPS: &[(&str, &[&str])] = &[
    (
        "Layers",
        &["install", "verify", "status", "outdated", "list", "diff"],
    ),
    (
        "Inspect",
        &["which", "inspect", "sbom", "check-attestation"],
    ),
    ("Run", &["run", "shim", "env", "completions"]),
    (
        "Export",
        &[
            "archive",
            "seed",
            "export-bazel",
            "export-bazel-distdir",
            "export-cargo",
            "export-crates-vendor",
            "export-docs",
            "export-sdk",
            "export-vsix",
            "export-wit",
            "export-zephyr-modules",
        ],
    ),
    (
        "Producer",
        &[
            "layer-spec",
            "deposit",
            "support-horizon",
            "sign-attestation",
            "sign-status",
            "sign-index",
            "attach-index",
            "attach-status",
            "sign-sums",
        ],
    ),
    (
        "Admin",
        &[
            "keygen",
            "pubkey",
            "sign-delegation",
            "self-update",
            "self-verify",
        ],
    ),
    ("Help", &["docs", "exit-codes", "help"]),
];

const EXAMPLES: &str = "\
Examples:
  Install the pinned layer and put its tools on PATH:
    varve install && varve shim install
  Which binary runs here, and from which layer:
    varve which rivet
  Ask the realm's signed index for a newer layer:
    varve outdated --json

`varve <command> --help` describes one command.
`varve docs` lists the documentation topics.";

/// The command varve parses with: the derived one, with the grouped list.
pub(crate) fn command() -> Command {
    let width = width();
    let mut built = crate::Cli::command();
    built.build();
    let cmd = wrap_usages(
        crate::Cli::command().max_term_width(MAX_WIDTH),
        &built,
        width,
    );
    let groups = grouped(&cmd, width);
    let header = cmd.get_styles().get_header();
    let template = format!(
        "{{about-with-newline}}\n{{usage-heading}} {{usage}}\n\n{groups}\
         {header}Options:{header:#}\n{{options}}{{after-help}}"
    );
    cmd.help_template(template).after_long_help(EXAMPLES)
}

/// The width clap wraps the rest of the help to: the terminal's, else
/// `COLUMNS`, else 100; never more than [`MAX_WIDTH`].
fn width() -> usize {
    terminal_size::terminal_size()
        .map(|(w, _)| usize::from(w.0))
        .or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
        .unwrap_or(MAX_WIDTH)
        .min(MAX_WIDTH)
}

/// Every subcommand of `cmd`, at any depth, with its usage line wrapped to
/// `width`: clap wraps the rest of the help but prints `Usage:` on one line,
/// and `deposit`'s runs past 100 columns. `built` is the same command after
/// `build()`, which gives each subcommand its full `varve <name>` usage.
fn wrap_usages(cmd: Command, built: &Command, width: usize) -> Command {
    let mut cmd = cmd;
    for sub in built.get_subcommands().filter(|s| s.get_name() != "help") {
        let rendered = sub.clone().render_usage().to_string();
        let usage = rendered.trim().trim_start_matches("Usage:").trim();
        let wrapped = wrap_usage(usage, width);
        cmd = cmd.mut_subcommand(sub.get_name(), |s| {
            wrap_usages(s.override_usage(wrapped), sub, width)
        });
    }
    cmd
}

/// `usage` laid out after clap's `Usage: ` within `width`, continuation
/// lines indented under the first. An option stays on one line with its
/// value (`--out <DIR>`).
fn wrap_usage(usage: &str, width: usize) -> String {
    const LEAD: usize = "Usage: ".len();
    let mut tokens: Vec<String> = Vec::new();
    for word in usage.split_whitespace() {
        match tokens.last_mut() {
            Some(prev) if word.starts_with('<') && prev.starts_with("-") => {
                prev.push(' ');
                prev.push_str(word);
            }
            _ => tokens.push(word.to_string()),
        }
    }
    let lines = wrap_tokens(&tokens, width.saturating_sub(LEAD).max(20));
    lines.join(&format!("\n{}", " ".repeat(LEAD)))
}

/// The subcommand list under the [`GROUPS`] headings, laid out for `width`.
fn grouped(cmd: &Command, width: usize) -> String {
    let styles = cmd.get_styles();
    let (header, literal) = (styles.get_header(), styles.get_literal());
    let mut entries: Vec<(String, String)> = cmd
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .map(|c| {
            let about = c.get_about().map(|a| a.to_string()).unwrap_or_default();
            (c.get_name().to_string(), about)
        })
        .collect();
    entries.push((
        "help".into(),
        "Print this message or the help of the given subcommand(s)".into(),
    ));

    let name_w = entries.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    let indent = 2 + name_w + 2;
    // Below 20 columns for descriptions nothing reads well; wrap anyway.
    let text_w = width.saturating_sub(indent).max(20);

    let mut sections: Vec<(&str, Vec<&(String, String)>)> = GROUPS
        .iter()
        .map(|(title, names)| {
            let members = names
                .iter()
                .filter_map(|n| entries.iter().find(|(e, _)| e == n))
                .collect();
            (*title, members)
        })
        .collect();
    let other = entries
        .iter()
        .filter(|(n, _)| !GROUPS.iter().any(|(_, g)| g.contains(&n.as_str())))
        .collect();
    sections.push(("Other", other));

    let mut out = String::new();
    for (title, members) in sections.into_iter().filter(|(_, m)| !m.is_empty()) {
        out.push_str(&format!("{header}{title}:{header:#}\n"));
        for (name, about) in members {
            let pad = " ".repeat(name_w - name.len() + 2);
            out.push_str(&format!("  {literal}{name}{literal:#}{pad}"));
            for (i, line) in wrap(about, text_w).iter().enumerate() {
                if i > 0 {
                    out.push_str(&" ".repeat(indent));
                }
                out.push_str(line);
                out.push('\n');
            }
            if about.is_empty() {
                out.push('\n');
            }
        }
        out.push('\n');
    }
    out
}

/// `text` broken at spaces into lines of at most `width` characters; a word
/// longer than `width` gets a line of its own.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    wrap_tokens(&words, width)
}

/// `words` joined by spaces into lines of at most `width` characters.
fn wrap_tokens(words: &[String], width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in words {
        let fits = line.chars().count() + 1 + word.chars().count() <= width;
        if !line.is_empty() && !fits {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(cmd: &Command) -> Vec<String> {
        cmd.get_subcommands()
            .map(|c| c.get_name().to_string())
            .chain(std::iter::once("help".to_string()))
            .collect()
    }

    #[test]
    fn every_subcommand_is_in_exactly_one_group() {
        let cmd = crate::Cli::command();
        let all = names(&cmd);
        assert!(all.len() >= 30, "found {} subcommands", all.len());
        for n in &all {
            let homes: Vec<&str> = GROUPS
                .iter()
                .filter(|(_, g)| g.contains(&n.as_str()))
                .map(|(t, _)| *t)
                .collect();
            assert_eq!(homes.len(), 1, "`{n}` is in groups {homes:?}");
        }
        for (title, g) in GROUPS {
            for n in *g {
                assert!(
                    all.contains(&n.to_string()),
                    "{title} names `{n}`, no such command"
                );
            }
        }
    }

    #[test]
    fn short_descriptions_are_one_short_phrase() {
        for sub in crate::Cli::command().get_subcommands() {
            let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
            assert!(
                about.chars().count() <= 60 && !about.contains('\n'),
                "`{}` has a {}-character summary: {about:?}",
                sub.get_name(),
                about.chars().count()
            );
        }
    }

    #[test]
    fn descriptions_name_no_requirement_issue_or_decision() {
        // The reader of --help has no rivet graph and no issue tracker.
        let pat = |s: &str| {
            s.contains("REQ-")
                || s.contains("DD-0")
                || s.contains("varve#")
                || s.split(|c: char| !c.is_ascii_alphanumeric() && c != '#')
                    .any(|w| w.starts_with('#') && w.len() > 1)
        };
        for sub in crate::Cli::command().get_subcommands() {
            let long = sub
                .get_long_about()
                .or(sub.get_about())
                .map(|a| a.to_string())
                .unwrap_or_default();
            assert!(!pat(&long), "`{}` help cites an id: {long}", sub.get_name());
        }
    }

    #[test]
    fn wrap_keeps_lines_within_the_width() {
        let lines = wrap("Write a WIT package and its dependencies from a layer", 20);
        assert_eq!(
            lines,
            [
                "Write a WIT package",
                "and its dependencies",
                "from a layer"
            ]
        );
        assert_eq!(wrap("", 20), Vec::<String>::new());
        assert_eq!(
            wrap("export-zephyr-modules x", 10),
            ["export-zephyr-modules", "x"]
        );
    }

    #[test]
    fn wrap_usage_keeps_options_with_their_values() {
        let u = "varve deposit [OPTIONS] --issued-at <RFC3339> --key <FILE> --out <DIR>";
        assert_eq!(
            wrap_usage(u, 40),
            "varve deposit [OPTIONS]\n       --issued-at <RFC3339>\n       --key <FILE> --out <DIR>"
        );
        assert_eq!(wrap_usage("varve list", 40), "varve list");
    }

    #[test]
    fn the_grouped_list_fits_and_keeps_descriptions_in_their_column() {
        let cmd = crate::Cli::command().styles(clap::builder::Styles::plain());
        for width in [60, 80, 100] {
            let text = grouped(&cmd, width);
            let indent = text
                .lines()
                .find_map(|l| l.strip_prefix("  install"))
                .map(|rest| 2 + "install".len() + rest.len() - rest.trim_start().len())
                .expect("install is listed");
            for line in text.lines() {
                assert!(line.chars().count() <= width, "{width}: {line:?}");
                // A line is a heading, a blank, a name with its description,
                // or a description continued in the description column.
                let lead = line.len() - line.trim_start().len();
                assert!(
                    line.is_empty() || lead == 0 || lead == 2 || lead == indent,
                    "{width}: {line:?} starts at column {lead}, not {indent}"
                );
            }
        }
    }
}
