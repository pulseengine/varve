//! Asking a registry what it already holds (REQ-IMMUTABLE-001 clause 1).
//!
//! ## The three states, again
//!
//! `oras manifest fetch` answers one of three things, and only the first two
//! are answers:
//!
//! * the tag exists, here is its digest;
//! * the tag does not exist;
//! * I could not tell you.
//!
//! Collapsing the third into the second is what makes this dangerous rather
//! than merely wrong. "Absent" means *publish*, so a registry that is
//! unreachable — an outage, an expired token, a typo'd repository, a network
//! partition — would be read as "nothing is there" and the publisher would
//! republish over a layer that very much exists. That is precisely the
//! `2026.08.4` incident, arrived at by a different route and with a plausible
//! excuse attached.
//!
//! So `lookup` returns `Result<Existing, _>`: absence is a value, and failure
//! is an error that stops the publish.

use crate::gh::{CommandRunner, RunOutput};
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
                 holding nothing — an unreachable registry read as an empty \
                 one would republish over a layer that exists, which is the \
                 exact failure this check was added to prevent."
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

/// `oras manifest fetch --descriptor <repo>:<tag>`
pub fn fetch_descriptor_argv(repo: &str, tag: &str) -> Vec<String> {
    vec![
        "manifest".into(),
        "fetch".into(),
        "--descriptor".into(),
        format!("{repo}:{tag}"),
    ]
}

/// Turn one `oras` invocation into an answer, or into a refusal to answer.
pub fn classify(repo: &str, out: &RunOutput) -> Result<Existing, LookupError> {
    if out.code == 127 {
        return Err(LookupError::NotInstalled);
    }
    if out.ok() {
        let doc: serde_json::Value =
            serde_json::from_str(&out.stdout).map_err(|e| LookupError::Unparseable {
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
        return Ok(Existing::At(digest.to_string()));
    }

    let hay = format!("{} {}", out.stdout, out.stderr).to_lowercase();
    // The ONLY failure that means "nothing is there". Everything else — auth,
    // DNS, TLS, rate limits, a repository that does not exist — is a registry
    // that did not answer, and must not be read as an empty one.
    let absent = hay.contains("not found")
        || hay.contains("manifest_unknown")
        || hay.contains("name_unknown")
        || hay.contains("404");
    // ...except that a 401/403 often ALSO renders as "not found" by design, to
    // avoid leaking whether a private repository exists. Treating that as
    // absent would publish over a layer we simply are not allowed to see.
    let denied = hay.contains("unauthorized")
        || hay.contains("denied")
        || hay.contains("forbidden")
        || hay.contains("401")
        || hay.contains("403");
    if absent && !denied {
        return Ok(Existing::Absent);
    }
    Err(LookupError::Unreachable {
        repo: repo.to_string(),
        detail: out.stderr.trim().to_string(),
    })
}

/// Ask the registry what it holds for one layer id.
pub fn lookup<R: CommandRunner>(
    runner: &R,
    repo: &str,
    tag: &str,
) -> Result<Existing, LookupError> {
    let out = runner.run("oras", &fetch_descriptor_argv(repo, tag), &[]);
    classify(repo, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput {
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    const D: &str = "sha256:088db18c45da66ae7b8570f5736fc71e777df2c4a48ab2263242bb6eb0e4655b";

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_published_tag_yields_its_digest() {
        let json = format!(r#"{{"mediaType":"application/json","digest":"{D}","size":1493}}"#);
        assert_eq!(
            classify("ghcr.io/o/r", &out(0, &json, "")).unwrap(),
            Existing::At(D.into())
        );
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_tag_that_does_not_exist_is_absent() {
        for msg in [
            "Error: ghcr.io/o/r:2026.09.1: not found",
            "MANIFEST_UNKNOWN: manifest unknown",
            "unexpected status code 404",
        ] {
            assert_eq!(
                classify("ghcr.io/o/r", &out(1, "", msg)).unwrap(),
                Existing::Absent,
                "{msg}"
            );
        }
    }

    /// THE dangerous case. "Absent" means publish, so a registry that could not
    /// answer must never produce it — an outage would otherwise become
    /// permission to republish over a live layer.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_registry_that_could_not_answer_is_never_read_as_an_empty_one() {
        for msg in [
            "dial tcp: lookup ghcr.io: no such host",
            "x509: certificate signed by unknown authority",
            "context deadline exceeded",
            "TOOMANYREQUESTS: retry later",
            "unexpected status code 500 Internal Server Error",
        ] {
            let e = classify("ghcr.io/o/r", &out(1, "", msg)).expect_err(msg);
            assert!(matches!(e, LookupError::Unreachable { .. }), "{msg}: {e:?}");
            assert!(
                e.to_string().contains("NOT the same as"),
                "the refusal must say why: {e}"
            );
        }
    }

    /// A private repository answers "not found" to someone who may not see it.
    /// Reading that as absent publishes over a layer we simply cannot look at.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_denial_dressed_up_as_not_found_is_not_absence() {
        for msg in [
            "unauthorized: authentication required",
            "denied: requested access to the resource is denied",
            "GET https://ghcr.io/v2/o/r/manifests/x: 403 Forbidden (not found)",
            "unexpected status code 401 Unauthorized: not found",
        ] {
            let e = classify("ghcr.io/o/r", &out(1, "", msg)).expect_err(msg);
            assert!(matches!(e, LookupError::Unreachable { .. }), "{msg}: {e:?}");
        }
    }

    /// Each denial marker must independently veto absence.
    ///
    /// The previous test paired several markers in one message, so breaking any
    /// single one still left a sibling to catch it — four surviving mutants
    /// said so. A registry that hides a private repository behind "not found"
    /// may use any ONE of these words, and if that word stops counting, the
    /// answer becomes "nothing is published here" and the publisher overwrites
    /// a layer it was merely not allowed to see.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn any_single_denial_marker_is_enough_to_veto_absence() {
        for msg in [
            "unauthorized: not found",
            "denied: not found",
            "forbidden: not found",
            "401: not found",
            "403: not found",
        ] {
            let got = classify("ghcr.io/o/r", &out(1, "", msg));
            assert!(
                matches!(got, Err(LookupError::Unreachable { .. })),
                "{msg} was read as {got:?} — a hidden repository would be overwritten"
            );
        }
    }

    /// A success whose body we cannot read is our problem, and still must not
    /// be reported as absence.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn an_unreadable_descriptor_refuses_rather_than_reporting_absence() {
        for body in [
            "not json at all",
            r#"{"size":1}"#,
            r#"{"digest":""}"#,
            r#"{"digest":null}"#,
        ] {
            let e = classify("ghcr.io/o/r", &out(0, body, "")).expect_err(body);
            assert!(
                matches!(e, LookupError::Unparseable { .. }),
                "{body}: {e:?}"
            );
        }
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_missing_oras_is_named_as_such_rather_than_as_a_registry_problem() {
        let e = classify("ghcr.io/o/r", &out(127, "", "no such file")).expect_err("must fail");
        assert_eq!(e, LookupError::NotInstalled);
        assert!(e.to_string().contains("not on PATH"), "{e}");
    }

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn the_lookup_asks_for_the_descriptor_of_the_right_tag() {
        let argv = fetch_descriptor_argv("ghcr.io/o/r", "2026.09.1");
        assert_eq!(
            argv,
            ["manifest", "fetch", "--descriptor", "ghcr.io/o/r:2026.09.1"]
        );
    }
}
