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
    /// A RustSec advisory-db query was asked about something that cannot be
    /// a crate name — refused BEFORE the argv is built, so no caller can
    /// smuggle a path-traversal segment into the request (REQ-ADVISORYWATCH-001
    /// clause 4). `name` carries what was asked for.
    InvalidCrateName { name: String },
    /// Same refusal, for the FILENAME half of a RustSec query.
    InvalidAdvisoryFilename { filename: String },
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
            GhError::InvalidCrateName { name } => write!(
                f,
                "{name:?} is not a crate name this RustSec query will accept — refusing \
                 to build a request that would interpolate it into a URL path"
            ),
            GhError::InvalidAdvisoryFilename { filename } => write!(
                f,
                "{filename:?} is not a RustSec advisory filename this query will accept — \
                 refusing to build a request that would interpolate it into a URL path"
            ),
        }
    }
}

impl std::error::Error for GhError {}

/// `gh release view <version> --repo <repo> --json assets`
/// `gh release view --repo <repo> --json tagName` — what has this upstream most
/// recently published (REQ-SCAN-001)?
///
/// The LATEST release, which is what a scanner asks about, as distinct from
/// `release_assets_argv`, which asks about a named one.
pub fn latest_release_argv(repo: &str) -> Vec<String> {
    vec![
        "release".into(),
        "view".into(),
        "--repo".into(),
        repo.into(),
        "--json".into(),
        "tagName".into(),
    ]
}

/// The tag out of `gh release view --json tagName`.
///
/// An empty or absent tag is an ERROR rather than an empty string. A scanner
/// comparing "" against a pin would report every payload as moved, and an
/// unattended depositor would act on it.
pub fn parse_latest_release(stdout: &str) -> Result<String, GhError> {
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|e| GhError::Unparseable {
        program: "gh".into(),
        detail: format!("release view returned unreadable JSON: {e}"),
    })?;
    match v.get("tagName").and_then(|t| t.as_str()) {
        Some(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        _ => Err(GhError::Unparseable {
            program: "gh".into(),
            detail: "release view returned no tagName — a blank tag compared against \
                     a pin would report every payload as moved"
                .into(),
        }),
    }
}

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

/// `gh api repos/<repo>` — the repository resource, whose `license.spdx_id`
/// carries GitHub's own classification of what the repo declared
/// (REQ-SBOMFIELDS-001 clause 5).
pub fn repo_info_argv(repo: &str) -> Vec<String> {
    vec!["api".into(), format!("repos/{repo}")]
}

/// The repository's DECLARED SPDX license, out of `gh api repos/<repo>`.
///
/// GitHub answers `"license": null` when nothing was detected, and
/// `license.spdx_id == "NOASSERTION"` when it found a LICENSE file it could
/// not classify. Both read as "nothing declared" — never as a license this
/// assembler invents on GitHub's behalf (REQ-SBOMFIELDS-001 clause 6).
pub fn parse_repo_license(stdout: &str) -> Result<Option<String>, GhError> {
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|e| GhError::Unparseable {
        program: "gh".into(),
        detail: format!("repo info returned unreadable JSON: {e}"),
    })?;
    let spdx = v
        .get("license")
        .and_then(|l| l.get("spdx_id"))
        .and_then(|s| s.as_str());
    Ok(match spdx {
        Some(id) if !id.trim().is_empty() && id != "NOASSERTION" => Some(id.trim().to_string()),
        _ => None,
    })
}

/// `gh api --paginate repos/<repo>/security-advisories?state=published&per_page=100`
/// (REQ-ADVISORYWATCH-001 clause 1). `--paginate` so a repo publishing more
/// than one page of advisories is not silently read as having fewer.
pub fn security_advisories_argv(repo: &str) -> Vec<String> {
    vec![
        "api".into(),
        "--paginate".into(),
        format!("repos/{repo}/security-advisories?state=published&per_page=100"),
    ]
}

/// Is `s` a crate name crates.io itself would accept — a letter, then up to
/// 63 more letters, digits, `_` or `-`?
///
/// `krate` ends up interpolated directly into a URL path
/// (`.../crates/<krate>` and `.../crates/<krate>/<filename>`), and its only
/// source is an upstream SBOM's component names — untrusted text a crafted
/// `../../..` could use to steer that request anywhere on the GitHub API.
/// Checked in BYTES, not `char`s: every character this pattern allows is a
/// single ASCII byte, so slicing at index 1 below can never land inside a
/// multi-byte sequence, and anything actually multi-byte fails the
/// `is_ascii_alphabetic` check on its own first byte regardless.
pub fn is_valid_crate_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

/// Is `s` a safe GitHub owner or repository NAME — letters, digits, `-`,
/// `_` or `.`, non-empty, at most 100 bytes, and never `.` or `..` alone
/// (which name no real owner or repo and must not be mistaken for a path
/// traversal segment)?
///
/// Used to validate EACH path segment of an untrusted
/// `https://github.com/<owner>/<repo>/...` URL — a RustSec advisory's own
/// `url` field, which this round's live run showed can point at a PR, a
/// commit or an issue, not only a `/security/advisories/` link — before
/// either segment is interpolated into a second request path. Same
/// reasoning as [`is_valid_crate_name`] above, one more untrusted input
/// source later.
pub fn is_valid_github_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 100 || s == "." || s == ".." {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Is `s` the exact shape of a RustSec advisory filename,
/// `RUSTSEC-YYYY-NNNN.md`?
///
/// `filename` comes from a directory LISTING this program asked for, which
/// is one layer removed from upstream input — but the listing is still
/// untrusted content from a network response, and interpolating it
/// unchecked into a second URL path is the same mistake as `krate` above,
/// one hop later.
pub fn is_valid_rustsec_filename(s: &str) -> bool {
    let four_digits = |t: &str| t.len() == 4 && t.bytes().all(|b| b.is_ascii_digit());
    let Some(rest) = s.strip_prefix("RUSTSEC-") else {
        return false;
    };
    let Some((year, rest)) = rest.split_once('-') else {
        return false;
    };
    let Some(number) = rest.strip_suffix(".md") else {
        return false;
    };
    four_digits(year) && four_digits(number)
}

/// `gh api repos/rustsec/advisory-db/contents/crates/<crate>` — the directory
/// listing for one crate. Always against github.com: the advisory database
/// has one home, independent of which forge this run's OWN releases live on.
///
/// Refuses BEFORE building anything when `krate` is not a shape crates.io
/// itself would issue (REQ-ADVISORYWATCH-001 clause 4) — defense in depth
/// beneath whatever check a caller already ran.
pub fn rustsec_crate_dir_argv(krate: &str) -> Result<Vec<String>, GhError> {
    if !is_valid_crate_name(krate) {
        return Err(GhError::InvalidCrateName {
            name: krate.to_string(),
        });
    }
    Ok(vec![
        "api".into(),
        format!("repos/rustsec/advisory-db/contents/crates/{krate}"),
    ])
}

/// `gh api -H "Accept: application/vnd.github.raw" repos/rustsec/advisory-db/contents/crates/<crate>/<file>`
///
/// The raw media type, so stdout IS the markdown — not a JSON envelope
/// carrying it base64-encoded, which `rustsec_finding` would then have to be
/// taught to unwrap for no reason but this one call site.
///
/// Refuses BEFORE building anything when either half is not the shape it
/// claims to be — same reasoning as [`rustsec_crate_dir_argv`].
pub fn rustsec_advisory_md_argv(krate: &str, filename: &str) -> Result<Vec<String>, GhError> {
    if !is_valid_crate_name(krate) {
        return Err(GhError::InvalidCrateName {
            name: krate.to_string(),
        });
    }
    if !is_valid_rustsec_filename(filename) {
        return Err(GhError::InvalidAdvisoryFilename {
            filename: filename.to_string(),
        });
    }
    Ok(vec![
        "api".into(),
        "-H".into(),
        "Accept: application/vnd.github.raw".into(),
        format!("repos/rustsec/advisory-db/contents/crates/{krate}/{filename}"),
    ])
}

/// Did `gh api` fail because the resource genuinely does not exist?
///
/// Looks for gh's OWN structured error marker, `(HTTP 404)` — not a bare
/// `404`, which [`crate::registry`]'s module docs already catalogue as
/// something a port number, a repository path or a crate name can contain
/// by coincidence. `gh api` prints that exact parenthesised form on a real
/// 404 from the GitHub API, so requiring it is strictly narrower than the
/// bare substring and does not reach for the incidental case.
pub fn is_http_404(stderr: &str) -> bool {
    stderr.contains("(HTTP 404)")
}

/// The `.md` filenames in a RustSec crate directory listing
/// (`gh api repos/rustsec/advisory-db/contents/crates/<crate>`).
///
/// Anything that is not a markdown file (a stray `README` the directory
/// convention does not actually carry, but nothing here assumes it never
/// will) is simply not an advisory and is dropped rather than refused.
pub fn parse_rustsec_dir_listing(stdout: &str) -> Result<Vec<String>, GhError> {
    let v: serde_json::Value = serde_json::from_str(stdout).map_err(|e| GhError::Unparseable {
        program: "gh".into(),
        detail: e.to_string(),
    })?;
    let arr = v.as_array().ok_or_else(|| GhError::Unparseable {
        program: "gh".into(),
        detail: "expected a JSON array of directory entries".into(),
    })?;
    let mut names = Vec::new();
    for entry in arr {
        let name =
            entry
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| GhError::Unparseable {
                    program: "gh".into(),
                    detail: "a directory entry carries no name".into(),
                })?;
        if name.ends_with(".md") {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

/// The environment a command needs to reach the right forge.
///
/// `GH_HOST` is what `gh` itself uses, and it is ALWAYS stated here —
/// including for public GitHub. An empty environment does not mean "target
/// github.com"; it means "inherit whatever `GH_HOST` the calling process
/// already has", and a `GH_HOST` set for an unrelated reason in that
/// process's environment would then silently redirect every probe, sums
/// fetch, SBOM download and advisory query to a different host. Stating the
/// host explicitly is the only way "this call targets forge X" is actually
/// true of the call, rather than true of the forge object and merely hoped
/// of the environment.
pub fn forge_env(forge: &crate::forge::Forge) -> Vec<(String, String)> {
    vec![("GH_HOST".to_string(), forge.host.clone())]
}

/// The environment a RustSec advisory-db query needs: `GH_HOST` pinned to
/// `github.com` explicitly, REGARDLESS of which forge this run's own
/// releases live on and regardless of the calling process's own
/// environment. `rustsec/advisory-db` has one home; stating that is the
/// only way a call that is SUPPOSED to always target github.com actually
/// does, rather than inheriting whatever `GH_HOST` happens to be set.
pub fn rustsec_advisory_db_env() -> Vec<(String, String)> {
    vec![("GH_HOST".to_string(), "github.com".to_string())]
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

    /// `GH_HOST` is ALWAYS passed explicitly, including for public GitHub.
    ///
    /// An empty env here does not mean "no host override" — it means
    /// "inherit whatever `GH_HOST` the calling process already has", which
    /// silently redirects every probe, sums fetch, SBOM download and
    /// advisory query to a different host when the environment happens to
    /// set one. Stating `github.com` explicitly is what makes "this call
    /// targets the public forge" true regardless of the environment it
    /// runs in.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_host_is_always_stated_explicitly_never_inherited() {
        assert_eq!(
            forge_env(&Forge::github_com()),
            vec![("GH_HOST".to_string(), "github.com".to_string())]
        );
        assert_eq!(
            forge_env(&Forge::enterprise("ghe.example.com")),
            vec![("GH_HOST".to_string(), "ghe.example.com".to_string())]
        );
    }

    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_real_spdx_license_is_read_from_the_repo_info() {
        let out = parse_repo_license(r#"{"license":{"spdx_id":"Apache-2.0"}}"#).unwrap();
        assert_eq!(out, Some("Apache-2.0".into()));
    }

    /// GitHub's own "we could not classify this" answer must read as nothing
    /// declared — recording it verbatim would sign a non-license as if it
    /// were one.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn noassertion_and_a_null_license_both_read_as_absent() {
        for stdout in [
            r#"{"license":{"spdx_id":"NOASSERTION"}}"#,
            r#"{"license":null}"#,
            r#"{}"#,
            r#"{"license":{"spdx_id":null}}"#,
        ] {
            assert_eq!(parse_repo_license(stdout).unwrap(), None, "{stdout}");
        }
    }

    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn repo_info_is_asked_for_by_name() {
        assert_eq!(
            repo_info_argv("pulseengine/rivet"),
            vec!["api", "repos/pulseengine/rivet"]
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_security_advisories_query_paginates_and_asks_for_published_only() {
        let argv = security_advisories_argv("bytecodealliance/wasmtime");
        assert_eq!(argv[0], "api");
        assert!(argv.contains(&"--paginate".to_string()), "{argv:?}");
        let path = argv.last().unwrap();
        assert!(
            path.starts_with("repos/bytecodealliance/wasmtime/security-advisories?"),
            "{path}"
        );
        assert!(path.contains("state=published"), "{path}");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_rustsec_queries_name_the_fixed_advisory_db_repository() {
        let dir = rustsec_crate_dir_argv("rustls").expect("a real crate name");
        assert_eq!(
            dir,
            vec!["api", "repos/rustsec/advisory-db/contents/crates/rustls"]
        );
        let md = rustsec_advisory_md_argv("rustls", "RUSTSEC-2026-0346.md")
            .expect("a real crate name and a real filename");
        assert_eq!(
            md,
            vec![
                "api",
                "-H",
                "Accept: application/vnd.github.raw",
                "repos/rustsec/advisory-db/contents/crates/rustls/RUSTSEC-2026-0346.md"
            ]
        );
    }

    /// `krate` and `filename` land directly in a URL path
    /// (`.../crates/<krate>/<filename>`); a component name from an
    /// upstream SBOM or a filename from a directory listing is untrusted
    /// text, and `../../..` steers that request anywhere. The argv
    /// builders refuse BEFORE building anything — defense in depth beneath
    /// whatever check a caller already did.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_argv_builders_refuse_a_crate_name_that_could_steer_the_request() {
        for bad in ["../x", "a/b", "", &"a".repeat(65), "1abc"] {
            assert!(
                matches!(
                    rustsec_crate_dir_argv(bad),
                    Err(GhError::InvalidCrateName { .. })
                ),
                "{bad:?} must be refused"
            );
            assert!(
                matches!(
                    rustsec_advisory_md_argv(bad, "RUSTSEC-2026-0346.md"),
                    Err(GhError::InvalidCrateName { .. })
                ),
                "{bad:?} must be refused as the crate half too"
            );
        }
        for bad in ["../evil.md", "README.md", "RUSTSEC-2026-03466.md", ""] {
            assert!(
                matches!(
                    rustsec_advisory_md_argv("rustls", bad),
                    Err(GhError::InvalidAdvisoryFilename { .. })
                ),
                "{bad:?} must be refused as a filename"
            );
        }
        assert!(rustsec_advisory_md_argv("rustls", "RUSTSEC-2026-0346.md").is_ok());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn crate_name_validation_matches_crates_ios_own_rule() {
        for good in ["rustls", "a", "wasm-tools", "wasm_tools", "A1", "z12345"] {
            assert!(is_valid_crate_name(good), "{good:?} should be valid");
        }
        for bad in [
            "",
            "1abc",
            "-abc",
            "_abc",
            "a/b",
            "../x",
            "a b",
            &"a".repeat(65),
        ] {
            assert!(!is_valid_crate_name(bad), "{bad:?} should be invalid");
        }
        // Exactly 64 characters is the boundary, and must still be valid.
        let max = format!("a{}", "b".repeat(63));
        assert_eq!(max.len(), 64);
        assert!(is_valid_crate_name(&max));
    }

    /// `bytecodealliance`/`wasmtime` are the real owner/repo this round's
    /// alias-severity rule widened to — real GitHub names, with digits,
    /// hyphens and dots all allowed; `.`/`..` alone, and a path-traversal
    /// attempt, are refused.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn github_name_validation_refuses_traversal_and_empty_segments() {
        for good in [
            "bytecodealliance",
            "wasmtime",
            "rust-lang",
            "my_repo.rs",
            "a",
            "123",
        ] {
            assert!(is_valid_github_name(good), "{good:?} should be valid");
        }
        for bad in ["", ".", "..", "../x", "a/b", "a b"] {
            assert!(!is_valid_github_name(bad), "{bad:?} should be invalid");
        }
        assert!(!is_valid_github_name(&"a".repeat(101)));
        assert!(is_valid_github_name(&"a".repeat(100)));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_filename_validation_matches_the_real_shape() {
        for good in ["RUSTSEC-2026-0346.md", "RUSTSEC-0000-0001.md"] {
            assert!(is_valid_rustsec_filename(good), "{good:?} should be valid");
        }
        for bad in [
            "../evil.md",
            "README.md",
            "RUSTSEC-2026-03466.md",
            "RUSTSEC-26-0346.md",
            "RUSTSEC-2026-346.md",
            "rustsec-2026-0346.md",
            "RUSTSEC-2026-0346.MD",
            "RUSTSEC-2026-0346",
            "",
            "RUSTSEC-2026-0346.md/../x",
        ] {
            assert!(!is_valid_rustsec_filename(bad), "{bad:?} should be invalid");
        }
    }

    /// THE guard against registry.rs's own lesson: a bare `404` anywhere in
    /// an error must not be read as absence. `gh api`'s own marker is the
    /// parenthesised `(HTTP 404)`, and only that is matched.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn only_ghs_own_structured_404_marker_is_read_as_absence() {
        assert!(is_http_404("gh: Not Found (HTTP 404)"));
        assert!(!is_http_404(
            "gh: repository build-404 not found: HTTP 403: forbidden"
        ));
        assert!(!is_http_404("connection reset while fetching crate 404"));
        assert!(!is_http_404(""));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_rustsec_directory_listing_keeps_only_markdown_files() {
        let names = parse_rustsec_dir_listing(
            r#"[{"name":"RUSTSEC-2026-0346.md"},{"name":"RUSTSEC-2026-0347.md"},{"name":".gitkeep"}]"#,
        )
        .expect("parses");
        assert_eq!(names, vec!["RUSTSEC-2026-0346.md", "RUSTSEC-2026-0347.md"]);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_empty_rustsec_directory_is_not_an_error() {
        assert_eq!(
            parse_rustsec_dir_listing("[]").unwrap(),
            Vec::<String>::new()
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn unreadable_rustsec_directory_output_is_refused() {
        for bad in ["not json", r#"{"not":"an array"}"#, r#"[{"size":1}]"#] {
            let e = parse_rustsec_dir_listing(bad).expect_err(bad);
            assert!(matches!(e, GhError::Unparseable { .. }), "{bad}: {e:?}");
        }
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

#[cfg(test)]
mod latest_release_tests {
    use super::*;

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_latest_release_query_names_the_repository_and_asks_for_the_tag() {
        let argv = latest_release_argv("pulseengine/meld");
        assert_eq!(
            argv,
            vec![
                "release",
                "view",
                "--repo",
                "pulseengine/meld",
                "--json",
                "tagName"
            ]
        );
    }

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_tag_is_read_out_of_the_json_and_trimmed() {
        assert_eq!(
            parse_latest_release(r#"{"tagName":"v0.55.1"}"#).unwrap(),
            "v0.55.1"
        );
        assert_eq!(
            parse_latest_release("{\"tagName\":\"  v1.0.0\\n\"}").unwrap(),
            "v1.0.0"
        );
    }

    /// A blank or missing tag must be an ERROR, never an empty string. Compared
    /// against a pin, "" reports every payload as moved — and an unattended
    /// depositor would act on that, signing a layer built from a scan that
    /// found nothing.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_blank_tag_is_refused_rather_than_compared() {
        for bad in [
            r#"{"tagName":""}"#,
            r#"{"tagName":"   "}"#,
            r#"{}"#,
            r#"{"tagName":null}"#,
        ] {
            let e = parse_latest_release(bad)
                .expect_err(&format!("{bad} must not yield a comparable tag"));
            assert!(
                e.to_string().contains("every payload as moved"),
                "the refusal must say what a blank tag would cause: {e}"
            );
        }
        parse_latest_release("not json").expect_err("unreadable output is not a tag");
    }
}
