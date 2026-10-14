//! Literal quoting for the paths `varve env` interpolates into shell text
//! (REQ-ENVQUOTE-001).
//!
//! `varve env` prints a script the user is told to run with
//! `eval "$(varve env)"`. It used to interpolate the store root — read from
//! `$VARVE_ROOT` or `$HOME`, so attacker-controlled in exactly the
//! environments that matter (CI, a container, a shared machine) — inside sh
//! DOUBLE quotes, where `$`, backticks and `"` stay live:
//!
//! ```text
//! $ VARVE_ROOT='/tmp/vr$(id>|/tmp/pwned)x' varve env --shell sh
//!   *) export PATH="/tmp/vr$(id>|/tmp/pwned)x/shims:$PATH" ;;
//! ```
//!
//! `eval`ing that line runs `id>|/tmp/pwned` as the user who ran `varve env`.
//! Every shell `varve env` (or `varve_core::env_lines`) supports gets a quoting
//! function here that makes an interpolated path LITERAL — one escaping rule
//! per shell, used everywhere a path is interpolated for that shell, so there
//! is exactly one place to get it right.

/// POSIX sh / bash / zsh: wrap `s` in single quotes. Inside single quotes
/// nothing is special except `'` itself — not `$`, not backticks, not `"` —
/// so the only escaping needed is for an embedded `'`, written as `'\''`
/// (close the quote, an escaped literal quote, reopen the quote).
pub fn quote_sh(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// fish: wrap `s` in single quotes. fish's single-quoted strings are almost
/// as plain as sh's, but `\` is also special inside them (so a literal `\`
/// must be escaped too, not only `'`).
pub fn quote_fish(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\\' || c == '\'' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// PowerShell: wrap `s` in single quotes, doubling any embedded `'` — a
/// PowerShell single-quoted string has no other metacharacter, so that is
/// the whole rule.
pub fn quote_powershell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-ENVQUOTE-001
    #[test]
    fn quote_sh_leaves_plain_text_alone_and_escapes_only_the_quote() {
        assert_eq!(quote_sh("plain"), "'plain'");
        assert_eq!(quote_sh("it's"), "'it'\\''s'");
    }

    // rivet: verifies REQ-ENVQUOTE-001
    #[test]
    fn quote_sh_makes_every_sh_metacharacter_literal() {
        // The exact hostile root from the issue report, plus a backtick
        // command substitution, a double quote, a backslash, a space and a
        // semicolon — every character that stays live inside the old double
        // quoting.
        let hostile = r#"/tmp/vr$(id>|/tmp/pwned)x`id`"dq"\bs sp;semi"#;
        let quoted = quote_sh(hostile);
        // Single-quoted and containing the metacharacters verbatim: no `$`,
        // backtick or `"` was consumed turning this into an escape.
        assert_eq!(quoted, format!("'{hostile}'"));
        // No unescaped single quote was introduced, so when re-parsed by a
        // POSIX shell as a single quoted string the whole thing stays one
        // word (the lack of a bare `'` other than the delimiters is exactly
        // what makes that true).
        assert_eq!(quoted.matches('\'').count(), 2);
    }

    // rivet: verifies REQ-ENVQUOTE-001
    #[test]
    fn quote_fish_escapes_backslash_and_single_quote_only() {
        assert_eq!(quote_fish("plain"), "'plain'");
        assert_eq!(quote_fish("it's"), r"'it\'s'");
        assert_eq!(quote_fish(r"back\slash"), r"'back\\slash'");
        // `$`, backticks, `"`, space and `;` are NOT special inside fish
        // single quotes, so they pass through unescaped.
        let hostile = r#"/tmp/vr$(id>|/tmp/pwned)x`id`"dq" sp;semi"#;
        assert_eq!(quote_fish(hostile), format!("'{hostile}'"));
    }

    // rivet: verifies REQ-ENVQUOTE-001
    #[test]
    fn quote_powershell_doubles_embedded_single_quotes_only() {
        assert_eq!(quote_powershell("plain"), "'plain'");
        assert_eq!(quote_powershell("it's"), "'it''s'");
        // `$`, backticks, `"`, space and `;` are NOT special inside a
        // PowerShell single-quoted string.
        let hostile = r#"/tmp/vr$(id>|/tmp/pwned)x`id`"dq" sp;semi"#;
        assert_eq!(quote_powershell(hostile), format!("'{hostile}'"));
    }
}
