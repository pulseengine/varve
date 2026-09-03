//! Asking a registry what it already holds (REQ-IMMUTABLE-001 clause 1).
//!
//! ## Why this does not read error messages
//!
//! The first version of this module decided "the tag does not exist" by
//! looking for `not found`, `404`, `manifest_unknown` and friends in oras's
//! output. A clean-room review refuted it in three lines:
//!
//! ```text
//! --repo 127.0.0.1:4040/o/r      -> connection refused -> verdict: publish
//! --repo host.invalid/org/b-404  -> no such host       -> verdict: publish
//! --layer 2026.09.404            -> no such host       -> verdict: publish
//! ```
//!
//! oras echoes the reference and the URL it was given, so the haystack
//! contains operator-supplied text as well as the registry's answer. A port
//! number, a repository path or a layer id containing `404` turned an
//! unreachable registry into "nothing is published here" — the exact failure
//! this module exists to prevent, reached by a route the module's own tests
//! never tried, because every test message I wrote was a realistic error and
//! none of them contained an incidental `404`.
//!
//! (A Go TCP error quotes the local ephemeral port — `read tcp
//! 10.1.0.4:54043->…` — so roughly one connection reset in two hundred would
//! have hit it against the live registry.)
//!
//! So absence is no longer inferred from prose. Two authoritative signals:
//!
//! * `oras manifest fetch --descriptor` **succeeding** is proof the tag exists,
//!   and yields its digest;
//! * `oras repo tags` **succeeding** is an authoritative listing, and a tag
//!   absent from it is genuinely absent.
//!
//! Anything else is "the registry did not answer", which stops the publish.
//! Absence must be *established*, never assumed from a failure whose text we
//! happened to recognise.

use crate::gh::CommandRunner;
use crate::immutable::Existing;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    NotInstalled,
    /// The registry could not answer. NOT the same as answering "nothing".
    Unreachable {
        repo: String,
        detail: String,
    },
    Unparseable {
        detail: String,
    },
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::NotInstalled => write!(
                f,
                "oras is not on PATH. It is how this program asks a registry \
                 what it already holds; without it the immutability check \
                 cannot run, and publishing without that check is how a layer \
                 id comes to name two different sets of bytes."
            ),
            LookupError::Unreachable { repo, detail } => write!(
                f,
                "cannot determine what {repo} already holds: {detail}\n\n\
                 Refusing to publish. This is NOT the same as the registry \
                 holding nothing — an unreachable registry read as an empty one \
                 would republish over a layer that exists, which is the exact \
                 failure this check was added to prevent. Absence has to be \
                 established, not assumed from a failure."
            ),
            LookupError::Unparseable { detail } => write!(
                f,
                "oras answered in a shape this program cannot read: {detail}\n\
                 Refusing to publish rather than guessing what it meant."
            ),
        }
    }
}

impl std::error::Error for LookupError {}

/// `oras manifest fetch --descriptor <repo>:<tag>` — exact, for one tag.
pub fn fetch_descriptor_argv(repo: &str, tag: &str) -> Vec<String> {
    vec![
        "manifest".into(),
        "fetch".into(),
        "--descriptor".into(),
        format!("{repo}:{tag}"),
    ]
}

/// `oras repo tags <repo>` — the authoritative listing.
pub fn tags_argv(repo: &str) -> Vec<String> {
    vec!["repo".into(), "tags".into(), repo.into()]
}

/// The digest from a SUCCESSFUL descriptor fetch.
pub fn parse_descriptor(stdout: &str) -> Result<String, LookupError> {
    let doc: serde_json::Value =
        serde_json::from_str(stdout).map_err(|e| LookupError::Unparseable {
            detail: e.to_string(),
        })?;
    let digest =
        doc.get("digest")
            .and_then(|d| d.as_str())
            .ok_or_else(|| LookupError::Unparseable {
                detail: "the descriptor carries no `digest`".into(),
            })?;
    if digest.trim().is_empty() {
        return Err(LookupError::Unparseable {
            detail: "the descriptor's `digest` is empty".into(),
        });
    }
    Ok(digest.to_string())
}

/// Is `tag` in a SUCCESSFUL listing? One line per tag.
pub fn tag_is_listed(stdout: &str, tag: &str) -> bool {
    stdout.lines().any(|l| l.trim() == tag)
}

/// Ask the registry what it holds for one layer id.
///
/// Never infers absence from an error message. See the module docs.
pub fn lookup<R: CommandRunner>(
    runner: &R,
    repo: &str,
    tag: &str,
) -> Result<Existing, LookupError> {
    let d = runner.run("oras", &fetch_descriptor_argv(repo, tag), &[]);
    if d.code == 127 {
        return Err(LookupError::NotInstalled);
    }
    if d.ok() {
        // The tag exists and we read it. Nothing to interpret.
        return Ok(Existing::At(parse_descriptor(&d.stdout)?));
    }

    // The manifest could not be read. That is not yet an answer about whether
    // the tag exists, so ask for the listing rather than guessing from the
    // failure text.
    let t = runner.run("oras", &tags_argv(repo), &[]);
    if t.code == 127 {
        return Err(LookupError::NotInstalled);
    }
    if !t.ok() {
        return Err(LookupError::Unreachable {
            repo: repo.to_string(),
            detail: format!(
                "neither the manifest nor the tag listing could be read.\n  \
                 manifest: {}\n  listing:  {}",
                d.stderr.trim(),
                t.stderr.trim()
            ),
        });
    }
    if tag_is_listed(&t.stdout, tag) {
        // It IS published; we simply could not read it. Publishing over it is
        // exactly what must not happen.
        return Err(LookupError::Unreachable {
            repo: repo.to_string(),
            detail: format!(
                "the registry lists {tag}, but its manifest could not be read: {}",
                d.stderr.trim()
            ),
        });
    }
    // An authoritative listing that does not contain the tag.
    Ok(Existing::Absent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gh::RunOutput;
    use std::cell::RefCell;

    const D: &str = "sha256:088db18c45da66ae7b8570f5736fc71e777df2c4a48ab2263242bb6eb0e4655b";

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput {
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// Answers `manifest fetch` and `repo tags` separately.
    struct Oras {
        descriptor: RunOutput,
        tags: RunOutput,
        calls: RefCell<Vec<String>>,
    }

    impl CommandRunner for Oras {
        fn run(&self, program: &str, args: &[String], _e: &[(String, String)]) -> RunOutput {
            assert_eq!(program, "oras");
            self.calls.borrow_mut().push(args.join(" "));
            match args.first().map(String::as_str) {
                Some("manifest") => self.descriptor.clone(),
                Some("repo") => self.tags.clone(),
                other => panic!("unexpected argv {other:?}"),
            }
        }
    }

    fn oras(descriptor: RunOutput, tags: RunOutput) -> Oras {
        Oras {
            descriptor,
            tags,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn desc_ok() -> RunOutput {
        out(0, &format!(r#"{{"digest":"{D}","size":1493}}"#), "")
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_readable_tag_yields_its_digest_without_consulting_anything_else() {
        let o = oras(desc_ok(), out(1, "", "should not be called"));
        assert_eq!(
            lookup(&o, "ghcr.io/o/r", "2026.09.0").unwrap(),
            Existing::At(D.into())
        );
        assert_eq!(o.calls.borrow().len(), 1, "{:?}", o.calls.borrow());
    }

    /// Absence is ESTABLISHED by an authoritative listing, never inferred from
    /// the text of a failure.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn absence_comes_from_a_listing_that_does_not_contain_the_tag() {
        let o = oras(
            out(1, "", "Error: ... : not found"),
            out(0, "2026.08.4\n2026.09.0\n", ""),
        );
        assert_eq!(
            lookup(&o, "ghcr.io/o/r", "2099.12.9").unwrap(),
            Existing::Absent
        );
    }

    /// THE refutation that produced this rewrite. Three unreachable registries
    /// whose error text happens to contain `404` — from a port, a repository
    /// path, and a layer id — every one of which the previous implementation
    /// reported as `publish`, exit 0.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn an_incidental_404_in_the_error_text_cannot_produce_absence() {
        for (msg, tag) in [
            (
                r#"Error: Get "https://127.0.0.1:4040/v2/o/r/tags/list": dial tcp 127.0.0.1:4040: connect: connection refused"#,
                "2026.09.0",
            ),
            (
                r#"Error: Get "https://host.invalid/v2/org/build-404/manifests/x": dial tcp: lookup host.invalid: no such host"#,
                "2026.09.0",
            ),
            (
                r#"Error: Get "https://host.invalid/v2/o/r/manifests/2026.09.404": no such host"#,
                "2026.09.404",
            ),
            (
                "read tcp 10.1.0.4:54043->140.82.121.34:443: read: connection reset by peer",
                "2026.09.0",
            ),
        ] {
            // Both calls fail, as they would for an unreachable registry.
            let o = oras(out(1, "", msg), out(1, "", msg));
            let e = lookup(&o, "ghcr.io/o/r", tag).expect_err(msg);
            assert!(
                matches!(e, LookupError::Unreachable { .. }),
                "{msg} -> {e:?}"
            );
        }
    }

    /// A registry that hides a private repository behind a bare 404, with no
    /// denial word anywhere — Harbor and Artifactory do this. The old
    /// substring veto was GHCR-specific and would have published over it.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_repository_we_cannot_see_is_not_reported_as_empty() {
        let o = oras(
            out(1, "", "NAME_UNKNOWN: repository name not known to registry"),
            out(1, "", "NAME_UNKNOWN: repository name not known to registry"),
        );
        let e = lookup(&o, "harbor.example/o/r", "2026.09.0").expect_err("must refuse");
        assert!(matches!(e, LookupError::Unreachable { .. }), "{e:?}");
    }

    /// Listed but unreadable is the worst case to get wrong: the layer is
    /// demonstrably there.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_tag_that_is_listed_but_unreadable_never_reads_as_absent() {
        let o = oras(
            out(1, "", "denied: requested access to the resource is denied"),
            out(0, "2026.09.0\n", ""),
        );
        let e = lookup(&o, "ghcr.io/o/r", "2026.09.0").expect_err("must refuse");
        match &e {
            LookupError::Unreachable { detail, .. } => {
                assert!(detail.contains("lists 2026.09.0"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// A tag listing must match whole lines: `2026.09.1` must not satisfy a
    /// lookup for `2026.09.10`, nor the other way round.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn tag_membership_is_by_whole_line_not_by_substring() {
        let listing = "2026.09.1\n2026.09.10\n";
        assert!(tag_is_listed(listing, "2026.09.1"));
        assert!(tag_is_listed(listing, "2026.09.10"));
        assert!(!tag_is_listed(listing, "2026.09"));
        assert!(!tag_is_listed(listing, "026.09.1"));
        assert!(!tag_is_listed("", "2026.09.1"));
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn an_unreadable_descriptor_refuses_rather_than_reporting_absence() {
        for body in [
            "not json",
            r#"{"size":1}"#,
            r#"{"digest":""}"#,
            r#"{"digest":null}"#,
        ] {
            let o = oras(out(0, body, ""), out(0, "", ""));
            let e = lookup(&o, "ghcr.io/o/r", "x").expect_err(body);
            assert!(
                matches!(e, LookupError::Unparseable { .. }),
                "{body}: {e:?}"
            );
        }
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_missing_oras_is_named_as_such_rather_than_as_a_registry_problem() {
        let o = oras(out(127, "", "not found"), out(127, "", "not found"));
        assert_eq!(
            lookup(&o, "ghcr.io/o/r", "x").expect_err("must fail"),
            LookupError::NotInstalled
        );
        // ...including when only the LISTING is missing it.
        let o = oras(out(1, "", "boom"), out(127, "", "no such file"));
        assert_eq!(
            lookup(&o, "ghcr.io/o/r", "x").expect_err("must fail"),
            LookupError::NotInstalled
        );
    }

    /// A refusal nobody can read is a refusal nobody acts on — and the
    /// "NOT the same as" sentence is the one that stops an operator reaching
    /// for a force flag.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn every_lookup_failure_explains_itself() {
        let un = LookupError::Unreachable {
            repo: "ghcr.io/o/r".into(),
            detail: "no such host".into(),
        }
        .to_string();
        assert!(
            un.contains("ghcr.io/o/r") && un.contains("no such host"),
            "{un}"
        );
        assert!(un.contains("NOT the same as"), "{un}");
        assert!(un.contains("established, not assumed"), "{un}");

        let ni = LookupError::NotInstalled.to_string();
        assert!(ni.contains("oras is not on PATH"), "{ni}");

        let up = LookupError::Unparseable {
            detail: "no `digest`".into(),
        }
        .to_string();
        assert!(
            up.contains("no `digest`") && up.contains("Refusing"),
            "{up}"
        );
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn the_commands_name_the_right_reference() {
        assert_eq!(
            fetch_descriptor_argv("ghcr.io/o/r", "2026.09.1"),
            ["manifest", "fetch", "--descriptor", "ghcr.io/o/r:2026.09.1"]
        );
        assert_eq!(tags_argv("ghcr.io/o/r"), ["repo", "tags", "ghcr.io/o/r"]);
    }
}
