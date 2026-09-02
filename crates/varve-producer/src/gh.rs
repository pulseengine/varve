//! The seam where this program talks to the outside world
//! (REQ-PRODUCER-002 clause 5).
//!
//! Everything else in this crate is a pure function over data. This module is
//! the one place that shells out — to `gh` for release listings, downloads and
//! attestation verification, and to `cosign` for signature verification. It is
//! deliberately thin, and the parts that decide anything are separated from
//! the parts that execute, so the deciding can be tested without a network.
//!
//! ## The distinction this module exists to preserve
//!
//! The shell ran `if gh attestation verify … 2>/dev/null` and treated any
//! non-zero exit as "not attested". That collapses two different facts:
//!
//! * **no attestation exists** — the release simply does not offer this
//!   mechanism, and the ladder should try the next rung;
//! * **an attestation exists and did not verify** — which is a rejected proof,
//!   and reading it as absence turns a detected failure into a silent
//!   downgrade to something weaker.
//!
//! `AttestationProbe` has three states for exactly this reason, and this is
//! where the third one gets produced. A seam that flattened it here would make
//! the type honest and the program not.

use crate::ingest::AttestationProbe;
use std::fmt;

/// What running a command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutput {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// Executes a command. The real implementation spawns; tests substitute.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> RunOutput;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhError {
    /// The tool is not installed. Named separately because "gh is missing" and
    /// "gh said no" send an operator to completely different places.
    NotInstalled { program: String },
    /// The command ran and failed.
    Failed {
        program: String,
        args: Vec<String>,
        code: i32,
        stderr: String,
    },
    /// The command succeeded and its output was not what we parse.
    Unparseable { program: String, detail: String },
}

impl fmt::Display for GhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GhError::NotInstalled { program } => write!(
                f,
                "{program} is not on PATH. It is one of the external services \
                 this assembler deliberately does not reimplement; install it \
                 rather than working around it."
            ),
            GhError::Failed {
                program,
                args,
                code,
                stderr,
            } => write!(
                f,
                "{program} {} exited {code}: {}",
                args.join(" "),
                stderr.trim()
            ),
            GhError::Unparseable { program, detail } => {
                write!(f, "cannot read {program}'s output: {detail}")
            }
        }
    }
}

impl std::error::Error for GhError {}

/// `gh release view <version> --repo <repo> --json assets`
pub fn release_assets_argv(repo: &str, version: &str) -> Vec<String> {
    vec![
        "release".into(),
        "view".into(),
        version.into(),
        "--repo".into(),
        repo.into(),
        "--json".into(),
        "assets".into(),
    ]
}

/// `gh release download <version> --repo <repo> -p <asset> -D <dir>`
///
/// `--clobber` is deliberately absent: `gh` refusing to overwrite is what
/// caught a repo being verified twice in one deposit, and silencing that
/// refusal is what killed the 2026.08.3 run. Idempotence is the caller's job.
pub fn release_download_argv(repo: &str, version: &str, asset: &str, dir: &str) -> Vec<String> {
    vec![
        "release".into(),
        "download".into(),
        version.into(),
        "--repo".into(),
        repo.into(),
        "-p".into(),
        asset.into(),
        "-D".into(),
        dir.into(),
    ]
}

/// `gh attestation verify <file> --repo <repo> --format json`
pub fn attestation_verify_argv(file: &str, repo: &str) -> Vec<String> {
    vec![
        "attestation".into(),
        "verify".into(),
        file.into(),
        "--repo".into(),
        repo.into(),
        "--format".into(),
        "json".into(),
    ]
}

/// `cosign verify-blob --bundle … --certificate-identity-regexp … --certificate-oidc-issuer …`
///
/// The identity and issuer come from the forge rather than being literals, so
/// an enterprise instance is checked against its own authority.
pub fn cosign_verify_argv(bundle: &str, identity: &str, issuer: &str, sums: &str) -> Vec<String> {
    vec![
        "verify-blob".into(),
        "--bundle".into(),
        bundle.into(),
        "--certificate-identity-regexp".into(),
        identity.into(),
        "--certificate-oidc-issuer".into(),
        issuer.into(),
        sums.into(),
    ]
}

/// Turn `gh attestation verify`'s outcome into the THREE states the ladder
/// needs, rather than the two an exit code offers.
///
/// A release with no attestation and a release whose attestation failed are
/// different facts, and only the first may continue the ladder.
pub fn classify_attestation(out: &RunOutput) -> AttestationProbe {
    if out.ok() {
        return match crate::attestation::parse(&out.stdout) {
            Ok(a) => AttestationProbe::Verified {
                signer: a.signer,
                commit: a.source_commit,
            },
            // Verified by gh but unreadable by us is OUR failure to parse, not
            // upstream's failure to attest — and it must not read as absence.
            Err(e) => AttestationProbe::Rejected(format!(
                "gh verified an attestation this assembler cannot read: {e}"
            )),
        };
    }
    let haystack = format!("{} {}", out.stdout, out.stderr).to_lowercase();
    // GitHub answers "there is no attestation for these bytes" with a 404 on
    // the attestations endpoint. Anything else that fails is a verification
    // that ran and said no.
    let absent = haystack.contains("no attestation")
        || haystack.contains("http 404")
        || haystack.contains("404: not found");
    if absent {
        AttestationProbe::NotAttested
    } else {
        AttestationProbe::Rejected(out.stderr.trim().to_string())
    }
}

/// Assets a release publishes, from `gh release view --json assets`.
pub fn parse_release_assets(stdout: &str) -> Result<Vec<String>, GhError> {
    let doc: serde_json::Value =
        serde_json::from_str(stdout).map_err(|e| GhError::Unparseable {
            program: "gh".into(),
            detail: e.to_string(),
        })?;
    let arr = doc
        .get("assets")
        .and_then(|a| a.as_array())
        .ok_or_else(|| GhError::Unparseable {
            program: "gh".into(),
            detail: "no `assets` array in the release JSON".into(),
        })?;
    let mut names = Vec::with_capacity(arr.len());
    for a in arr {
        let n = a
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| GhError::Unparseable {
                program: "gh".into(),
                detail: "a release asset carries no name".into(),
            })?;
        names.push(n.to_string());
    }
    Ok(names)
}

/// The environment a command needs to reach the right forge.
///
/// `GH_HOST` is what `gh` itself uses; passing it rather than assuming
/// github.com is what makes an enterprise instance reachable at all.
pub fn forge_env(forge: &crate::forge::Forge) -> Vec<(String, String)> {
    if forge.is_public_github() {
        Vec::new()
    } else {
        vec![("GH_HOST".to_string(), forge.host.clone())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge::Forge;

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput {
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    const ATT: &str = r#"[{"verificationResult":{
        "statement":{"subject":[{"name":"a.tar.gz","digest":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}]},
        "signature":{"certificate":{"buildSignerURI":"https://github.com/o/r/.github/workflows/release.yml","sourceRepositoryDigest":"abc"}}}}]"#;

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_verified_attestation_becomes_the_verified_state() {
        let p = classify_attestation(&out(0, ATT, ""));
        assert_eq!(
            p,
            AttestationProbe::Verified {
                signer: "https://github.com/o/r/.github/workflows/release.yml".into(),
                commit: "abc".into()
            }
        );
    }

    /// THE distinction. The shell read every non-zero exit as "not attested",
    /// which turns a rejected proof into a silent downgrade.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_missing_attestation_and_a_failed_one_are_different_states() {
        // GitHub answers "nothing attests these bytes" with a 404.
        for absent in [
            "HTTP 404: Not Found (https://api.github.com/…/attestations/sha256:…)",
            "no attestations found for subject",
            "404: Not Found",
        ] {
            assert_eq!(
                classify_attestation(&out(1, "", absent)),
                AttestationProbe::NotAttested,
                "{absent}"
            );
        }
        // Anything else ran and said no.
        let p = classify_attestation(&out(1, "", "signature verification failed: bad cert chain"));
        assert!(
            matches!(&p, AttestationProbe::Rejected(d) if d.contains("bad cert chain")),
            "{p:?}"
        );
    }

    /// gh says verified, we cannot read what it verified. That is our defect,
    /// and it must not be reported as upstream offering nothing.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unreadable_but_verified_attestation_is_rejected_not_absent() {
        let p = classify_attestation(&out(0, "{not the expected shape}", ""));
        assert!(
            matches!(&p, AttestationProbe::Rejected(d) if d.contains("cannot read")),
            "{p:?}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn release_assets_are_read_from_ghs_json() {
        let names = parse_release_assets(
            r#"{"assets":[{"name":"a.tar.gz","size":1},{"name":"SHA256SUMS.txt","size":2}]}"#,
        )
        .expect("parses");
        assert_eq!(names, vec!["a.tar.gz", "SHA256SUMS.txt"]);
    }

    /// An empty release is a fact, not a parse failure — a repo can tag
    /// without uploading.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_release_with_no_assets_parses_to_an_empty_list() {
        assert_eq!(
            parse_release_assets(r#"{"assets":[]}"#).unwrap(),
            Vec::<String>::new()
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn output_that_is_not_the_expected_json_is_refused_rather_than_read_as_empty() {
        for bad in ["not json", r#"{"other":[]}"#, r#"{"assets":[{"size":1}]}"#] {
            let e = parse_release_assets(bad).expect_err("must refuse");
            assert!(matches!(e, GhError::Unparseable { .. }), "{bad}: {e:?}");
        }
    }

    /// `--clobber` must NOT be here. gh refusing to overwrite is what surfaced
    /// a repo being verified twice in one deposit; silencing it is what killed
    /// the 2026.08.3 run.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_download_command_does_not_silence_ghs_overwrite_refusal() {
        let argv = release_download_argv("o/r", "v1", "a.tar.gz", "/tmp/x");
        assert!(!argv.iter().any(|a| a == "--clobber"), "{argv:?}");
        assert_eq!(argv[0], "release");
        assert!(argv.windows(2).any(|w| w == ["-p", "a.tar.gz"]));
    }

    /// `--repo` is not a convenience here: without it `gh` will accept an
    /// attestation issued by ANY repository for these bytes, which is the
    /// difference between "this release built it" and "someone built it".
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn attestation_verify_is_bound_to_the_repository_that_must_have_built_it() {
        let argv = attestation_verify_argv("a.tar.gz", "o/r");
        assert!(
            argv.windows(2).any(|w| w == ["--repo", "o/r"]),
            "without --repo any repository's attestation would be accepted: {argv:?}"
        );
        assert_eq!(&argv[..3], &["attestation", "verify", "a.tar.gz"]);
        // The JSON is what classify_attestation reads; human output would parse
        // to Rejected and read as a failure that never happened.
        assert!(
            argv.windows(2).any(|w| w == ["--format", "json"]),
            "{argv:?}"
        );
    }

    /// `--json assets` is what makes the output parseable at all; dropping it
    /// gives gh's human table, which parse_release_assets refuses — turning a
    /// present release into an unreadable one.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_release_listing_asks_for_the_machine_readable_form() {
        let argv = release_assets_argv("o/r", "v1.2.3");
        assert_eq!(&argv[..3], &["release", "view", "v1.2.3"]);
        assert!(argv.windows(2).any(|w| w == ["--repo", "o/r"]), "{argv:?}");
        assert!(
            argv.windows(2).any(|w| w == ["--json", "assets"]),
            "{argv:?}"
        );
    }

    /// The identity and issuer are the whole security content of this command;
    /// hardcoding either would check an enterprise release against the wrong
    /// authority.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn cosign_is_told_which_authority_to_trust_rather_than_assuming_one() {
        let f = Forge::enterprise("ghe.example.com");
        let argv = cosign_verify_argv(
            "b.bundle",
            &f.identity_prefix("acme/tool"),
            &f.oidc_issuer,
            "SHA256SUMS.txt",
        );
        let joined = argv.join(" ");
        assert!(
            joined.contains("https://ghe.example.com/acme/tool/"),
            "{joined}"
        );
        assert!(
            joined.contains("https://ghe.example.com/_services/token"),
            "{joined}"
        );
        assert!(!joined.contains("githubusercontent"), "{joined}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_enterprise_forge_reaches_gh_through_the_variable_gh_itself_uses() {
        assert!(forge_env(&Forge::github_com()).is_empty());
        assert_eq!(
            forge_env(&Forge::enterprise("ghe.example.com")),
            vec![("GH_HOST".to_string(), "ghe.example.com".to_string())]
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_missing_tool_reads_differently_from_a_tool_that_said_no() {
        let missing = GhError::NotInstalled {
            program: "gh".into(),
        }
        .to_string();
        assert!(missing.contains("not on PATH"), "{missing}");
        let said_no = GhError::Failed {
            program: "gh".into(),
            args: vec!["release".into()],
            code: 1,
            stderr: "release not found".into(),
        }
        .to_string();
        assert!(
            said_no.contains("exited 1") && said_no.contains("release not found"),
            "{said_no}"
        );
    }
}
