//! Finding the binary inside an extracted release archive (REQ-PRODUCER-002).
//!
//! Release layouts differ per repository — some archives are flat, some carry a
//! versioned subdirectory, some ship docs and completions alongside — so the
//! binary is located by NAME rather than by a fixed path.
//!
//! ## What the shell did
//!
//! ```text
//! bin="$(find "extract/$tool-$platform" -type f -name "$binname" | head -1)"
//! ```
//!
//! Two defects in one line, and both decide which bytes get SIGNED:
//!
//! * `head -1` takes the first result in **filesystem enumeration order**,
//!   which is not deterministic across machines or filesystems. An archive
//!   carrying `bin/rivet` and `share/doc/examples/rivet` deposits whichever
//!   the kernel happened to hand back first — and the same archive can resolve
//!   differently on the next runner.
//! * `-type f` never checks whether the file is executable, so a README named
//!   `rivet` is an equally valid candidate.
//!
//! This module refuses ambiguity instead of resolving it by luck. When two
//! candidates are genuinely indistinguishable the answer is an error naming
//! both, because guessing here means signing bytes nobody chose.

use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
    /// No file of that name anywhere in the archive.
    NotFound { name: String, saw: Vec<String> },
    /// Files of that name exist, but none is executable.
    NoneExecutable { name: String, found: Vec<String> },
    /// Several equally-good executables. Refused rather than guessed.
    Ambiguous { name: String, found: Vec<String> },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractError::NotFound { name, saw } => write!(
                f,
                "the archive contains no file named {name:?}. It contains: {}. \
                 The asset template probably names the wrong archive, or the \
                 release renamed its binary — either way the payload would be \
                 missing from a layer that still signs.",
                preview(saw)
            ),
            ExtractError::NoneExecutable { name, found } => write!(
                f,
                "the archive contains {name:?} but nothing executable: {}. A \
                 non-executable match is documentation or a completion script, \
                 not the tool; depositing it would put a file in the layer that \
                 cannot be dispatched.",
                preview(found)
            ),
            ExtractError::Ambiguous { name, found } => write!(
                f,
                "the archive contains more than one executable {name:?} and \
                 varve will not choose between them: {}. Which one is deposited \
                 decides which bytes get signed, so it is not a guess worth \
                 making — name the path explicitly in the manifest, or fix the \
                 archive.",
                preview(found)
            ),
        }
    }
}

impl std::error::Error for ExtractError {}

fn preview(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(8).map(String::as_str).collect();
    if items.len() > shown.len() {
        format!(
            "{} … and {} more",
            shown.join(", "),
            items.len() - shown.len()
        )
    } else if shown.is_empty() {
        "nothing".to_string()
    } else {
        shown.join(", ")
    }
}

/// One file considered for dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub executable: bool,
}

/// Is this path directly inside a directory called `bin`?
///
/// The one tie-break worth having: every layout that ships more than one file
/// of the same name puts the real tool under `bin/` and the copy somewhere
/// else. Beyond that, refuse.
fn in_bin_dir(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|d| d == "bin")
}

/// Choose the binary to deposit, deterministically or not at all.
///
/// `candidates` is every file found in the extraction; the caller supplies it
/// so this stays a pure function over a listing rather than a directory walk.
pub fn choose_binary(name: &str, candidates: &[Candidate]) -> Result<PathBuf, ExtractError> {
    let named: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.path.file_name().is_some_and(|n| n == name))
        .collect();

    if named.is_empty() {
        let mut saw: Vec<String> = candidates.iter().map(|c| show(&c.path)).collect();
        saw.sort();
        return Err(ExtractError::NotFound {
            name: name.to_string(),
            saw,
        });
    }

    let mut exec: Vec<&Candidate> = named.iter().copied().filter(|c| c.executable).collect();
    if exec.is_empty() {
        let mut found: Vec<String> = named.iter().map(|c| show(&c.path)).collect();
        found.sort();
        return Err(ExtractError::NoneExecutable {
            name: name.to_string(),
            found,
        });
    }

    if exec.len() > 1 {
        let under_bin: Vec<&Candidate> = exec
            .iter()
            .copied()
            .filter(|c| in_bin_dir(&c.path))
            .collect();
        if under_bin.len() == 1 {
            return Ok(under_bin[0].path.clone());
        }
        // Sorted so the error is identical on every machine, which matters
        // when the message is the only record of why a deposit stopped.
        let mut found: Vec<String> = exec.iter().map(|c| show(&c.path)).collect();
        found.sort();
        return Err(ExtractError::Ambiguous {
            name: name.to_string(),
            found,
        });
    }

    Ok(exec.remove(0).path.clone())
}

fn show(p: &Path) -> String {
    // Normalise away a leading `./` so messages compare cleanly.
    let mut comps = p.components().peekable();
    if matches!(comps.peek(), Some(Component::CurDir)) {
        comps.next();
    }
    comps.collect::<PathBuf>().display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(path: &str, executable: bool) -> Candidate {
        Candidate {
            path: PathBuf::from(path),
            executable,
        }
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_single_executable_of_that_name_is_chosen() {
        let got = choose_binary(
            "rivet",
            &[
                c("rivet-v0.34.0/README.md", false),
                c("rivet-v0.34.0/bin/rivet", true),
            ],
        )
        .expect("chooses");
        assert_eq!(got, PathBuf::from("rivet-v0.34.0/bin/rivet"));
    }

    /// Deliberately NOT under `bin/`: a flat archive is a real layout, and a
    /// single candidate must be taken without consulting the tie-break at all.
    /// The `bin/` case cannot distinguish "one executable" from "several, one
    /// of which is under bin" — cargo-mutants found that by widening the
    /// comparison and killing nothing.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_lone_executable_outside_bin_is_still_chosen() {
        let got = choose_binary("wsc", &[c("wsc", true), c("LICENSE", false)]).expect("chooses");
        assert_eq!(got, PathBuf::from("wsc"));
    }

    /// Exactly at the preview cut: eight items are all of them, so nothing is
    /// elided and the message must not claim otherwise.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_listing_exactly_at_the_preview_limit_elides_nothing() {
        let eight: Vec<Candidate> = (0..8).map(|i| c(&format!("d/f{i}"), false)).collect();
        let msg = choose_binary("nope", &eight).unwrap_err().to_string();
        assert!(
            !msg.contains("more"),
            "claimed elision with nothing elided: {msg}"
        );
        let nine: Vec<Candidate> = (0..9).map(|i| c(&format!("d/f{i}"), false)).collect();
        let msg9 = choose_binary("nope", &nine).unwrap_err().to_string();
        assert!(msg9.contains("and 1 more"), "{msg9}");
    }

    /// The shell's `head -1` took whatever the filesystem offered first. Here
    /// the doc copy and the binary are distinguished by `bin/`, which is the
    /// only tie-break real layouts justify.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_doc_copy_beside_the_binary_does_not_win_by_enumeration_order() {
        for order in [
            vec![c("share/doc/examples/rivet", true), c("bin/rivet", true)],
            vec![c("bin/rivet", true), c("share/doc/examples/rivet", true)],
        ] {
            let got = choose_binary("rivet", &order).expect("chooses");
            assert_eq!(
                got,
                PathBuf::from("bin/rivet"),
                "order changed the answer: {order:?}"
            );
        }
    }

    /// Two executables, neither under `bin/`: there is no principled winner and
    /// the choice decides what gets signed. Refuse.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn two_indistinguishable_executables_are_refused_not_guessed() {
        let err = choose_binary("rivet", &[c("a/rivet", true), c("b/rivet", true)])
            .expect_err("must refuse");
        assert_eq!(
            err,
            ExtractError::Ambiguous {
                name: "rivet".into(),
                found: vec!["a/rivet".into(), "b/rivet".into()]
            }
        );
        assert!(
            err.to_string().contains("decides which bytes get signed"),
            "{err}"
        );
    }

    /// And two under `bin/` are still ambiguous — the tie-break narrows, it
    /// does not invent a winner.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn two_executables_both_under_bin_are_still_refused() {
        let err = choose_binary("rivet", &[c("x/bin/rivet", true), c("y/bin/rivet", true)])
            .expect_err("must refuse");
        assert!(matches!(err, ExtractError::Ambiguous { .. }), "{err:?}");
    }

    /// `find -type f` accepted a README. A non-executable match is not the tool.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_non_executable_file_of_the_right_name_is_refused_and_says_why() {
        let err = choose_binary("rivet", &[c("docs/rivet", false)]).expect_err("must refuse");
        assert_eq!(
            err,
            ExtractError::NoneExecutable {
                name: "rivet".into(),
                found: vec!["docs/rivet".into()]
            }
        );
        assert!(err.to_string().contains("cannot be dispatched"), "{err}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_archive_without_the_binary_lists_what_it_did_contain() {
        let err = choose_binary("rivet", &[c("bin/spar", true), c("README.md", false)])
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("bin/spar"), "{msg}");
        assert!(msg.contains("still signs"), "{msg}");
    }

    /// The error is the only record of why a deposit stopped, so it must read
    /// the same on every machine.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_refusal_lists_candidates_in_a_stable_order() {
        let a = choose_binary("t", &[c("z/t", true), c("a/t", true)]).unwrap_err();
        let b = choose_binary("t", &[c("a/t", true), c("z/t", true)]).unwrap_err();
        assert_eq!(a, b);
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_long_listing_is_previewed_rather_than_dumped() {
        let many: Vec<Candidate> = (0..30).map(|i| c(&format!("d/f{i:02}"), false)).collect();
        let msg = choose_binary("nope", &many).unwrap_err().to_string();
        assert!(msg.contains("and 22 more"), "{msg}");
    }

    /// A leading `./` is how `find` reports paths; it must not change identity.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_leading_dot_slash_does_not_change_the_reported_path() {
        let err = choose_binary("t", &[c("./a/t", true), c("b/t", true)]).unwrap_err();
        match err {
            ExtractError::Ambiguous { found, .. } => {
                assert_eq!(found, vec!["a/t".to_string(), "b/t".to_string()])
            }
            other => panic!("{other:?}"),
        }
    }
}
