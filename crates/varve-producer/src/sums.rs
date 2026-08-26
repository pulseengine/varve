//! Reading a `SHA256SUMS.txt` (REQ-PRODUCER-002, REQ-INGEST-001).
//!
//! The digest recorded in a payload's `[tool.source]` is transcribed from the
//! sums file that a mechanism vouched for. It is the number a consumer's
//! Bazel lockfile inherits, so looking up the wrong line is not a cosmetic
//! error: it writes a digest into a signed layer that does not describe the
//! bytes shipped beside it.
//!
//! ## Why this is not a `grep`
//!
//! The shell looked an asset up with:
//!
//! ```text
//! grep -E "[ /]$asset\$" SHA256SUMS.txt | awk '{print $1}' | head -1
//! ```
//!
//! The asset name is interpolated into a **regular expression**, so every `.`
//! in it is a wildcard. `rivet-v0.34.0-x86_64-apple-darwin.tar.gz` matches
//! `rivet-v0X34.0-x86_64-apple-darwin.tar.gz` just as happily, and `head -1`
//! then takes whichever line came first. A release whose asset names differ
//! only where a dot sits — or an upstream that simply chooses its names — can
//! hand back a digest belonging to a different file, silently.
//!
//! Parsing the file and comparing names for equality removes the whole class.
//! A name is a name, not a pattern.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SumsError {
    /// A line that is not `<64 hex><space(s)>[*]<name>`.
    Malformed { line_no: usize, line: String },
    /// One name listed twice with different digests. Which one is right is not
    /// ours to guess.
    Conflicting {
        name: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for SumsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SumsError::Malformed { line_no, line } => write!(
                f,
                "SHA256SUMS.txt line {line_no} is not a checksum line: {line:?}. \
                 Expected a 64-character hex digest, whitespace, then a file \
                 name. A line this parser cannot read is a line whose digest \
                 would be silently skipped."
            ),
            SumsError::Conflicting {
                name,
                first,
                second,
            } => write!(
                f,
                "SHA256SUMS.txt lists {name:?} twice with different digests \
                 ({first} and {second}). Which describes the shipped bytes is \
                 not something varve can decide, and recording either would be \
                 a coin flip signed into a layer."
            ),
        }
    }
}

impl std::error::Error for SumsError {}

/// A parsed sums file: file name -> lowercase hex digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sums {
    entries: BTreeMap<String, String>,
}

/// `./varve-0.29.0.tar.gz` and `*varve-0.29.0.tar.gz` both name the same file.
///
/// `sha256sum` writes a leading `./` when given `./*`, and a `*` marker for
/// binary mode. Neither is part of the name.
fn normalise(name: &str) -> &str {
    let name = name.strip_prefix('*').unwrap_or(name);
    name.strip_prefix("./").unwrap_or(name)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Sums {
    pub fn parse(text: &str) -> Result<Sums, SumsError> {
        let mut entries: BTreeMap<String, String> = BTreeMap::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let (digest, rest) = match line.split_once(char::is_whitespace) {
                Some(parts) => parts,
                None => {
                    return Err(SumsError::Malformed {
                        line_no: i + 1,
                        line: raw.to_string(),
                    });
                }
            };
            if !is_hex64(digest) {
                return Err(SumsError::Malformed {
                    line_no: i + 1,
                    line: raw.to_string(),
                });
            }
            let name = normalise(rest.trim_start());
            if name.is_empty() {
                return Err(SumsError::Malformed {
                    line_no: i + 1,
                    line: raw.to_string(),
                });
            }
            let digest = digest.to_ascii_lowercase();
            if let Some(prev) = entries.get(name)
                && *prev != digest
            {
                return Err(SumsError::Conflicting {
                    name: name.to_string(),
                    first: prev.clone(),
                    second: digest,
                });
            }
            entries.insert(name.to_string(), digest);
        }
        Ok(Sums { entries })
    }

    /// Build from `(name, digest)` pairs — the shape a build attestation's
    /// subject list arrives in.
    ///
    /// Deliberately the same door as [`Sums::parse`]: an attestation-derived
    /// digest gets the identical checks a sums-file digest gets, so
    /// "which mechanism vouched" never changes how carefully the number is
    /// handled.
    pub fn from_pairs<I, N, D>(pairs: I) -> Result<Sums, SumsError>
    where
        I: IntoIterator<Item = (N, D)>,
        N: AsRef<str>,
        D: AsRef<str>,
    {
        let mut entries: BTreeMap<String, String> = BTreeMap::new();
        for (line_no, (name, digest)) in pairs.into_iter().enumerate() {
            let name = normalise(name.as_ref().trim());
            let digest = digest.as_ref().trim().to_ascii_lowercase();
            if name.is_empty() || !is_hex64(&digest) {
                return Err(SumsError::Malformed {
                    line_no: line_no + 1,
                    line: format!("{digest}  {name}"),
                });
            }
            if let Some(prev) = entries.get(name)
                && *prev != digest
            {
                return Err(SumsError::Conflicting {
                    name: name.to_string(),
                    first: prev.clone(),
                    second: digest,
                });
            }
            entries.insert(name.to_string(), digest);
        }
        Ok(Sums { entries })
    }

    /// The digest for exactly this name. `None` when the release does not
    /// publish it — an expected answer, since not every tool builds for every
    /// platform.
    pub fn digest_of(&self, asset: &str) -> Option<&str> {
        self.entries.get(normalise(asset)).map(String::as_str)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "\
7e83a151afddc72ffce3fa5402874ac18089a466777e10119dfd62cce6fbf77e  ./install.sh
8a7f3d92a15f251395294aec37267c1635887397f49bb79661747b657bfb7a80  ./rolling.pub
09fb5f0445f6dbca49a46e1f662272ccc1a3971076eb1003f3dd526f8869762a  ./varve-0.29.0-rivet-artifacts.tar.gz
";

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_real_sums_file_parses_and_strips_the_leading_dot_slash() {
        let s = Sums::parse(REAL).expect("parses");
        assert_eq!(
            s.digest_of("install.sh"),
            Some("7e83a151afddc72ffce3fa5402874ac18089a466777e10119dfd62cce6fbf77e")
        );
        // Callers hold the name either way round; both must resolve.
        assert_eq!(s.digest_of("./install.sh"), s.digest_of("install.sh"));
    }

    /// THE reason this is not a grep. Every `.` in the asset name was a regex
    /// wildcard, so a lookup could return a DIFFERENT file's digest — and that
    /// digest is what gets signed into the layer.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_dot_in_an_asset_name_is_a_dot_and_not_a_wildcard() {
        let text = "\
1111111111111111111111111111111111111111111111111111111111111111  rivet-v0X34.0-x86_64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  rivet-v0.34.0-x86_64.tar.gz
";
        let s = Sums::parse(text).expect("parses");
        // The wildcard match would have taken the FIRST line here.
        assert_eq!(
            s.digest_of("rivet-v0.34.0-x86_64.tar.gz"),
            Some("2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(
            s.digest_of("rivet-v0X34.0-x86_64.tar.gz"),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    /// A name that is a suffix of another must not be satisfied by it: the old
    /// pattern anchored on `[ /]`, so `tool.tar.gz` could be matched by a line
    /// naming `other-tool.tar.gz` only via the separator class — a guard one
    /// character wide.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_name_that_is_a_suffix_of_another_does_not_match_it() {
        let text = "\
3333333333333333333333333333333333333333333333333333333333333333  other-tool.tar.gz
";
        let s = Sums::parse(text).expect("parses");
        assert_eq!(s.digest_of("tool.tar.gz"), None);
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn binary_mode_and_extra_whitespace_are_handled() {
        let text =
            "4444444444444444444444444444444444444444444444444444444444444444   *bin.tar.gz\n";
        let s = Sums::parse(text).expect("parses");
        assert_eq!(
            s.digest_of("bin.tar.gz"),
            Some("4444444444444444444444444444444444444444444444444444444444444444")
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_uppercase_digest_is_normalised_so_comparisons_do_not_depend_on_case() {
        let text = "AAAA111111111111111111111111111111111111111111111111111111111111  a.tar.gz\n";
        let s = Sums::parse(text).expect("parses");
        assert_eq!(
            s.digest_of("a.tar.gz"),
            Some("aaaa111111111111111111111111111111111111111111111111111111111111")
        );
    }

    /// A line the parser cannot read is a digest silently skipped, so it is an
    /// error rather than something to step over.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_malformed_line_is_refused_rather_than_skipped() {
        for bad in [
            "not-a-digest  a.tar.gz\n",
            "abc  a.tar.gz\n",
            "1111111111111111111111111111111111111111111111111111111111111111\n",
            "1111111111111111111111111111111111111111111111111111111111111111  \n",
        ] {
            let err = Sums::parse(bad).expect_err("must refuse");
            assert!(
                matches!(err, SumsError::Malformed { .. }),
                "{bad:?} -> {err:?}"
            );
        }
    }

    /// The line number is the whole value of the message: it is what an
    /// operator opens the file at. An off-by-one sends them to the wrong line
    /// of a file whose entire purpose is being exact.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_malformed_line_is_reported_at_its_own_one_based_number() {
        let text = format!("{REAL}garbage here\n");
        let err = Sums::parse(&text).expect_err("must refuse");
        // REAL has three lines, so the bad one is the fourth, counting from 1.
        assert_eq!(
            err,
            SumsError::Malformed {
                line_no: 4,
                line: "garbage here".into()
            },
            "{err}"
        );
        assert!(err.to_string().contains("line 4"), "{err}");
    }

    /// A name that consists only of markers — `*` (binary mode) or `./` —
    /// names no file once they are stripped. This is the ONLY way to reach the
    /// empty-name branch: `raw.trim()` has already removed trailing
    /// whitespace, so a line that merely ends in spaces fails earlier. Found
    /// by cargo mutants, whose survivors here were pointing at a branch no
    /// test reached rather than at a missing assertion.
    ///
    /// Exercised at line 2 on purpose: at line 1 every plausible arithmetic on
    /// the index looks alike, so the test would pass against a wrong one.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_line_whose_name_is_only_a_marker_is_reported_at_its_own_number() {
        for marker in ["*", "./"] {
            let text = format!(
                "1111111111111111111111111111111111111111111111111111111111111111  a.tar.gz\n\
                 2222222222222222222222222222222222222222222222222222222222222222  {marker}\n"
            );
            let err = Sums::parse(&text).expect_err("must refuse");
            assert!(
                matches!(err, SumsError::Malformed { line_no: 2, .. }),
                "{marker:?} -> {err:?}"
            );
        }
    }

    /// Blank lines are skipped but still counted, or every number after one is
    /// wrong.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn blank_lines_do_not_shift_the_reported_line_number() {
        let err = Sums::parse("\n\nbad\n").expect_err("must refuse");
        assert!(
            matches!(err, SumsError::Malformed { line_no: 3, .. }),
            "{err:?}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_empty_sums_file_is_empty_and_a_populated_one_is_not() {
        assert!(Sums::parse("").expect("parses").is_empty());
        assert!(Sums::parse("\n  \n").expect("parses").is_empty());
        assert!(!Sums::parse(REAL).expect("parses").is_empty());
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn one_name_at_two_digests_is_refused_rather_than_resolved_by_order() {
        let text = "\
1111111111111111111111111111111111111111111111111111111111111111  a.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  ./a.tar.gz
";
        let err = Sums::parse(text).expect_err("must refuse");
        assert!(matches!(err, SumsError::Conflicting { .. }), "{err:?}");
        assert!(err.to_string().contains("coin flip"), "{err}");
    }

    /// The same name listed twice with the SAME digest is redundant, not
    /// contradictory, and must not fail the run.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_duplicate_line_with_an_identical_digest_is_accepted() {
        let text = "\
1111111111111111111111111111111111111111111111111111111111111111  a.tar.gz
1111111111111111111111111111111111111111111111111111111111111111  ./a.tar.gz
";
        let s = Sums::parse(text).expect("parses");
        assert_eq!(s.names().count(), 1);
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_missing_asset_is_an_expected_absence_not_an_error() {
        let s = Sums::parse(REAL).expect("parses");
        assert_eq!(s.digest_of("nothing-like-this.tar.gz"), None);
        assert!(!s.is_empty());
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn pairs_get_the_same_checks_a_parsed_file_gets() {
        let ok = Sums::from_pairs([(
            "a.tar.gz",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )])
        .expect("accepts");
        assert_eq!(
            ok.digest_of("a.tar.gz"),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        // A short or non-hex digest is refused, exactly as in a parsed file.
        assert!(Sums::from_pairs([("a", "abc")]).is_err());
        assert!(Sums::from_pairs([("", "1".repeat(64))]).is_err());
        // Reported at its own 1-based position, and checked at a position past
        // the first: at index 0 every plausible arithmetic looks alike.
        let err = Sums::from_pairs([
            ("a".to_string(), "1".repeat(64)),
            ("b".into(), "nope".into()),
        ])
        .expect_err("refuses");
        assert!(
            matches!(err, SumsError::Malformed { line_no: 2, .. }),
            "{err:?}"
        );
        // And the same name at two digests is still a coin flip.
        let err =
            Sums::from_pairs([("a", "1".repeat(64)), ("a", "2".repeat(64))]).expect_err("refuses");
        assert!(matches!(err, SumsError::Conflicting { .. }), "{err:?}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn blank_lines_are_ignored() {
        let s = Sums::parse(&format!("\n\n{REAL}\n\n")).expect("parses");
        assert_eq!(s.names().count(), 3);
    }
}
