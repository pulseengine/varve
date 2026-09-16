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

/// `oras manifest fetch <repo>:<tag>` — the manifest ITSELF, not its
/// descriptor.
///
/// Distinct from `fetch_descriptor_argv`, which asks only for digest and size.
/// The next-layer derivation needs the manifest body, to find the baseline
/// line-status by its role annotation.
pub fn fetch_manifest_argv(repo: &str, tag: &str) -> Vec<String> {
    vec!["manifest".into(), "fetch".into(), format!("{repo}:{tag}")]
}

/// `oras repo tags <repo>` — the authoritative listing.
/// `oras blob fetch --output <file> <repo>@<digest>` — retrieve a blob the
/// destination registry already holds (REQ-REUSEBLOB-001 clause 1).
///
/// To a FILE, not to stdout. A blob is a whole payload archive, and routing
/// tens of megabytes of binary through a captured stdout invites exactly the
/// truncation-shaped bug this pipeline has been bitten by before.
pub fn blob_fetch_argv(repo: &str, digest: &str, out: &std::path::Path) -> Vec<String> {
    vec![
        "blob".into(),
        "fetch".into(),
        "--output".into(),
        out.display().to_string(),
        format!("{repo}@{}", oci_digest(digest)),
    ]
}

/// An OCI reference digest: `sha256:<hex>`, whether or not the caller already
/// spelled the algorithm.
///
/// varve's proofs carry BARE lowercase hex — `Sums` validates with `is_hex64`
/// and REFUSES a `sha256:`-prefixed line — while an OCI reference requires the
/// algorithm. Passing the bare form to oras fails at REFERENCE PARSING, before
/// any network call:
///
/// ```text
/// invalid reference: invalid digest "2d711642…": invalid checksum digest format
/// ```
///
/// which `fetch_blob` maps to `None`, which the orchestrator maps to a
/// fallback — so carry-forward silently degrades to a full upstream download
/// and blames the registry for it. Found by clean-room verification, after the
/// unit tests all passed: every one supplied a fake keyed on bare hex, so the
/// fakes agreed with the caller and neither agreed with oras.
fn oci_digest(digest: &str) -> String {
    if digest.contains(':') {
        digest.to_string()
    } else {
        format!("sha256:{digest}")
    }
}

/// Fetch a blob by digest, or `None` if it cannot be retrieved.
///
/// Every failure is `None`, deliberately: absent, unreachable, oras missing,
/// truncated. The caller's only correct response to any of them is the same —
/// fall back to upstream (clause 4) — and a Result here would invite a caller
/// to abort a deposit because a cache was pruned. The bytes are NOT trusted:
/// the caller re-hashes them against the digest it asked for (clause 3).
pub fn fetch_blob<R: CommandRunner>(
    runner: &R,
    repo: &str,
    digest: &str,
    out: &std::path::Path,
) -> Option<Vec<u8>> {
    let d = runner.run("oras", &blob_fetch_argv(repo, digest, out), &[]);
    if !d.ok() {
        return None;
    }
    std::fs::read(out).ok()
}

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

/// Every tag in a SUCCESSFUL listing, one per line.
///
/// Blank lines and surrounding whitespace are dropped; nothing else is
/// interpreted. A caller deciding what these tags MEAN — which are layers of a
/// line, which are the index and status tags beside them — does that itself.
pub fn parse_tags(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
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
    /// The reference oras is handed must carry the ALGORITHM. varve's proofs
    /// carry bare hex, oras requires `sha256:<hex>`, and the mismatch fails at
    /// reference parsing — before any network call — so it looks exactly like
    /// a blob that is not there.
    ///
    /// This function had no test at all, which is why the gate missed it: a
    /// mutant can only be killed by a test, and being listed in the mutation
    /// shard is not the same as being covered.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_blob_reference_names_the_digest_algorithm() {
        let out = std::path::Path::new("/tmp/x");
        let bare = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
        let argv = super::blob_fetch_argv("ghcr.io/org/layers", bare, out);
        let reference = argv.last().expect("a reference");
        assert_eq!(
            reference,
            &format!("ghcr.io/org/layers@sha256:{bare}"),
            "a bare digest is rejected by oras as `invalid checksum digest format`, \
             which fetch_blob reports as None and the orchestrator reports as the \
             REGISTRY's fault"
        );
        assert!(
            reference.contains("@sha256:"),
            "the algorithm must be present: {reference}"
        );
    }

    /// Idempotent: a digest that already names its algorithm is not given a
    /// second one. `sha256:sha256:...` is as invalid as the bare form.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn an_already_qualified_digest_is_not_prefixed_twice() {
        let out = std::path::Path::new("/tmp/x");
        let prefixed = "sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
        let argv = super::blob_fetch_argv("ghcr.io/org/layers", prefixed, out);
        let reference = argv.last().unwrap();
        assert_eq!(reference, &format!("ghcr.io/org/layers@{prefixed}"));
        assert_eq!(reference.matches("sha256:").count(), 1, "{reference}");
    }

    /// `fetch_blob` had FIVE surviving mutants — the whole function replaceable
    /// by None, by an empty vec, by arbitrary bytes, and its success check
    /// invertible — because the tests above only covered the argv BUILDER.
    /// The clean-room review said `blob_fetch_argv` AND `fetch_blob` were
    /// untested; the first fix covered one of the two.
    ///
    /// Returning `Some(vec![])` is the one that matters: the caller re-hashes
    /// what it gets, so empty bytes are refused there — but only because that
    /// check exists. A fetch that invents bytes must be caught here too.
    struct FakeOras {
        code: i32,
        writes: Option<Vec<u8>>,
    }

    impl CommandRunner for FakeOras {
        fn run(&self, program: &str, args: &[String], _e: &[(String, String)]) -> RunOutput {
            assert_eq!(program, "oras");
            // Honour --output the way oras does: write the file, then report.
            if let Some(bytes) = &self.writes {
                let i = args.iter().position(|a| a == "--output").expect("--output");
                std::fs::write(&args[i + 1], bytes).unwrap();
            }
            RunOutput {
                code: self.code,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    }

    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_fetched_blob_returns_the_bytes_that_were_written() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("blob");
        let got = super::fetch_blob(
            &FakeOras {
                code: 0,
                writes: Some(b"payload bytes".to_vec()),
            },
            "ghcr.io/org/layers",
            "aa",
            &out,
        );
        assert_eq!(got.as_deref(), Some(b"payload bytes".as_slice()));
    }

    /// oras failed: absent, unauthorised, unreachable. All None, all one
    /// fallback — but None must actually be reached, not assumed.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_failed_fetch_is_none_rather_than_whatever_was_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("blob");
        // A stale file from an earlier run sits exactly where the output goes.
        std::fs::write(&out, b"stale bytes from a previous attempt").unwrap();
        let got = super::fetch_blob(
            &FakeOras {
                code: 1,
                writes: None,
            },
            "ghcr.io/org/layers",
            "aa",
            &out,
        );
        assert_eq!(
            got, None,
            "a failed fetch must not hand back a leftover file — the caller \
             would re-hash it, and a stale blob whose digest happened to match \
             is exactly the substitution carry-forward exists to prevent"
        );
    }

    /// oras missing entirely. Same answer, different world: 127 is
    /// command-not-found, and conflating it with a refusal is a mistake this
    /// pipeline has made before.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_missing_oras_is_a_fallback_not_a_pretend_blob() {
        let dir = tempfile::tempdir().unwrap();
        let got = super::fetch_blob(
            &FakeOras {
                code: 127,
                writes: None,
            },
            "r",
            "aa",
            &dir.path().join("blob"),
        );
        assert_eq!(got, None);
    }

    /// Reported success, no file. Any Some() here would be invented bytes.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_successful_command_that_wrote_nothing_yields_no_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let got = super::fetch_blob(
            &FakeOras {
                code: 0,
                writes: None,
            },
            "r",
            "aa",
            &dir.path().join("never-written"),
        );
        assert_eq!(got, None);
    }

    /// The manifest body, not the descriptor: `--descriptor` returns digest
    /// and size, and the baseline is found by a role annotation inside the
    /// body.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_manifest_fetch_asks_for_the_body_not_the_descriptor() {
        let a = super::fetch_manifest_argv("ghcr.io/o/l", "2026.09.2");
        assert_eq!(a, vec!["manifest", "fetch", "ghcr.io/o/l:2026.09.2"]);
        assert!(!a.iter().any(|x| x == "--descriptor"));
    }

    /// A listing is lines, and only lines. The scanner derives the next layer
    /// id from this, so a blank line read as a tag would become a layer id of
    /// its own.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_tag_listing_is_lines_with_the_blanks_dropped() {
        assert_eq!(
            super::parse_tags("2026.09.1\n2026.09.2\n\n  realm-bootstrap  \n"),
            vec!["2026.09.1", "2026.09.2", "realm-bootstrap"]
        );
        assert!(super::parse_tags("").is_empty());
        assert!(super::parse_tags("   \n\n").is_empty());
    }

    /// The argv shape itself: a blob is a whole payload archive, so it goes to
    /// a FILE. Routing tens of megabytes of binary through captured stdout is
    /// the truncation-shaped bug this pipeline has been bitten by before.
    // rivet: verifies REQ-REUSEBLOB-001
    #[test]
    fn a_blob_is_fetched_to_a_file_not_to_stdout() {
        let out = std::path::Path::new("/tmp/reused/abc");
        let argv = super::blob_fetch_argv("r", "aa", out);
        assert_eq!(argv[0], "blob");
        assert_eq!(argv[1], "fetch");
        assert_eq!(argv[2], "--output");
        assert_eq!(argv[3], "/tmp/reused/abc");
        assert_ne!(argv[3], "-", "not stdout");
    }

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
