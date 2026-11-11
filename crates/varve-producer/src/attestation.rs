//! Reading a GitHub build attestation (REQ-INGEST-001, REQ-PRODUCER-002).
//!
//! A build attestation binds an artifact to the workflow, repository and
//! source commit that produced it — strictly more than a sums file, which only
//! says "these bytes hash to this". It is what makes a second realm ingestible
//! at all: `bytecodealliance/wasm-tools` publishes no sums and no cosign
//! bundle, and is attested.
//!
//! The in-toto statement carries the sha256 of every asset in the release, so
//! the attestation REPLACES the sums file rather than accompanying it. Those
//! digests are transcribed into the signed layer and inherited by consumers'
//! lockfiles, which is why they go through the same door as a parsed sums file
//! ([`Sums::from_pairs`]) instead of a looser path.
//!
//! ## What the shell did, and what it did with a bad document
//!
//! ```text
//! doc = json.load(open(sys.argv[1]))
//! subjects = doc[0]["verificationResult"]["statement"]["subject"]
//! ```
//!
//! An empty array is an `IndexError`, a renamed field is a `KeyError`, and
//! either surfaces as a Python traceback in the middle of a deposit rather
//! than as something an operator can act on. The empty-subject check also ran
//! *after* the file was written, so a vouching-for-nothing attestation left an
//! empty sums file on disk before the run stopped.

use crate::sums::{Sums, SumsError};
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "verificationResult")]
    verification_result: VerificationResult,
}

#[derive(Debug, Deserialize)]
struct VerificationResult {
    statement: Statement,
    signature: Signature,
}

#[derive(Debug, Deserialize)]
struct Statement {
    #[serde(default)]
    subject: Vec<Subject>,
}

#[derive(Debug, Deserialize)]
struct Subject {
    name: String,
    digest: Digest,
}

#[derive(Debug, Deserialize)]
struct Digest {
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Signature {
    certificate: Certificate,
}

#[derive(Debug, Deserialize)]
struct Certificate {
    #[serde(rename = "buildSignerURI", default)]
    build_signer_uri: Option<String>,
    #[serde(rename = "sourceRepositoryDigest", default)]
    source_repository_digest: Option<String>,
    #[serde(rename = "sourceRepositoryRef", default)]
    source_repository_ref: Option<String>,
}

/// One verified statement: who built it, from which ref and commit, and the
/// subjects (name and digest) it vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// The workflow identity that signed the build (`buildSignerURI`).
    pub signer: String,
    /// The ref the build ran from (`sourceRepositoryRef`, or, where the
    /// certificate omits it, the part of the signer URI after `@`). Empty when
    /// neither says.
    pub source_ref: String,
    /// The source commit the artifact was built from. May be absent in older
    /// attestations; recorded as empty rather than invented.
    pub source_commit: String,
    /// The subjects this statement names.
    pub sums: Sums,
}

/// What `gh attestation verify` established: EVERY statement it returned for
/// the digest (a pull-request build set aside), not the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The signer of the first statement kept. The record of what vouched for
    /// an asset comes from [`Attested::vouching`], not from here.
    pub signer: String,
    /// The source commit of the first statement kept.
    pub source_commit: String,
    /// The statements kept, in the order gh returned them.
    pub statements: Vec<Build>,
    /// The union of every kept statement's subjects: a name at two digests is
    /// refused rather than resolved by order.
    pub sums: Sums,
}

impl Attested {
    /// The statements whose subjects include a subject NAMED `asset`.
    pub fn vouching(&self, asset: &str) -> Vec<&Build> {
        self.statements
            .iter()
            .filter(|s| s.sums.digest_of(asset).is_some())
            .collect()
    }

    /// Fold another verification's statements in (an upstream that attests
    /// each file separately). A name at two digests is refused.
    pub fn merge(&mut self, other: &Attested) -> Result<(), SumsError> {
        self.sums.merge(&other.sums)?;
        for s in &other.statements {
            if !self.statements.contains(s) {
                self.statements.push(s.clone());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    NotJson(String),
    /// `gh` returns an array; an empty one means nothing was verified.
    NoAttestations,
    /// An attestation with no subjects vouches for no bytes.
    NoSubjects,
    /// A subject with no sha256 digest.
    SubjectWithoutDigest {
        name: String,
    },
    /// The signer identity is what "build-provenance" MEANS; without it the
    /// mechanism has nothing to record.
    NoSigner,
    /// A digest that fails the same checks a sums file's would.
    BadDigest(SumsError),
    /// Every statement gh returned was built from a pull request ref.
    PullRequestBuild {
        source_ref: String,
    },
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::NotJson(e) => {
                write!(
                    f,
                    "the attestation document is not the JSON `gh attestation verify --format json` produces: {e}"
                )
            }
            AttestationError::NoAttestations => write!(
                f,
                "the attestation document is an empty list — nothing was \
                 verified. This is not the same as a release having no \
                 attestation, and varve will not read it as such."
            ),
            AttestationError::NoSubjects => write!(
                f,
                "the attestation names no subjects — it vouches for nothing. \
                 Its digests are what would be recorded in the layer, so there \
                 is nothing to record."
            ),
            AttestationError::SubjectWithoutDigest { name } => write!(
                f,
                "attestation subject {name:?} carries no sha256 digest. The \
                 digest is the entire content of the claim; a subject without \
                 one cannot be transcribed into a signed layer."
            ),
            AttestationError::NoSigner => write!(
                f,
                "the attestation carries no buildSignerURI. \"Built by\" with \
                 no identity is not provenance, and recording an empty signer \
                 would be a signed claim that somebody vouched and declined to \
                 say who."
            ),
            AttestationError::BadDigest(e) => write!(f, "{e}"),
            AttestationError::PullRequestBuild { source_ref } => write!(
                f,
                "every attestation for these bytes was built from {source_ref}, a pull \
                 request. A pull-request build is never a release, however well it is \
                 signed, so it vouches for nothing."
            ),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Whether a ref names a pull request build.
fn is_pull_request(r: &str) -> bool {
    r.starts_with("refs/pull/")
}

/// Parse the output of `gh attestation verify --format json`.
///
/// gh returns every attestation from the repository that covers the digest, so
/// all of them are read. A statement built from `refs/pull/*` is set aside
/// (and refused when nothing else remains); a subject name that two kept
/// statements give different digests is refused.
pub fn parse(json: &str) -> Result<Attested, AttestationError> {
    let docs: Vec<Envelope> =
        serde_json::from_str(json).map_err(|e| AttestationError::NotJson(e.to_string()))?;
    if docs.is_empty() {
        return Err(AttestationError::NoAttestations);
    }
    let mut statements: Vec<Build> = Vec::new();
    let mut pull_request: Option<String> = None;
    for doc in docs {
        let cert = doc.verification_result.signature.certificate;
        let signer = cert
            .build_signer_uri
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or(AttestationError::NoSigner)?;
        let source_ref = cert
            .source_repository_ref
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .or_else(|| signer.split_once('@').map(|(_, r)| r.to_string()))
            .unwrap_or_default();
        // Absent rather than invented: older attestations omit it, and an empty
        // string reads as "built from nothing" rather than "not recorded".
        let source_commit = cert
            .source_repository_digest
            .unwrap_or_default()
            .trim()
            .to_string();

        let subjects = doc.verification_result.statement.subject;
        if subjects.is_empty() {
            return Err(AttestationError::NoSubjects);
        }
        let mut pairs = Vec::with_capacity(subjects.len());
        for s in subjects {
            let digest = s
                .digest
                .sha256
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty())
                .ok_or_else(|| AttestationError::SubjectWithoutDigest {
                    name: s.name.clone(),
                })?;
            pairs.push((s.name, digest));
        }
        let sums = Sums::from_pairs(pairs).map_err(AttestationError::BadDigest)?;
        if is_pull_request(&source_ref) {
            pull_request.get_or_insert(source_ref);
            continue;
        }
        statements.push(Build {
            signer,
            source_ref,
            source_commit,
            sums,
        });
    }
    let Some(first) = statements.first() else {
        return Err(AttestationError::PullRequestBuild {
            source_ref: pull_request.unwrap_or_default(),
        });
    };
    let (signer, source_commit) = (first.signer.clone(), first.source_commit.clone());
    let mut union = statements[0].sums.clone();
    for s in &statements[1..] {
        union.merge(&s.sums).map_err(AttestationError::BadDigest)?;
    }
    Ok(Attested {
        signer,
        source_commit,
        statements,
        sums: union,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(subjects: &str, signer: &str, commit: &str) -> String {
        format!(
            r#"[{{"verificationResult":{{
                "statement":{{"subject":[{subjects}]}},
                "signature":{{"certificate":{{
                    "buildSignerURI":"{signer}",
                    "sourceRepositoryDigest":"{commit}"
                }}}}
            }}}}]"#
        )
    }

    const WASM_TOOLS: &str = r#"{"name":"wasm-tools-1.257.1-aarch64-macos.tar.gz","digest":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}"#;

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_real_shaped_attestation_yields_signer_commit_and_digests() {
        let a = parse(&doc(
            WASM_TOOLS,
            "https://github.com/bytecodealliance/wasm-tools/.github/workflows/release.yml",
            "abc123",
        ))
        .expect("parses");
        assert_eq!(
            a.signer,
            "https://github.com/bytecodealliance/wasm-tools/.github/workflows/release.yml"
        );
        assert_eq!(a.source_commit, "abc123");
        assert_eq!(
            a.sums.digest_of("wasm-tools-1.257.1-aarch64-macos.tar.gz"),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    /// `gh` returns a LIST. Empty means nothing verified — the shell indexed
    /// `[0]` and produced a Python traceback mid-deposit.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_empty_attestation_list_is_a_clean_refusal_not_a_crash() {
        let err = parse("[]").expect_err("refuses");
        assert_eq!(err, AttestationError::NoAttestations);
        assert!(err.to_string().contains("not the same as"), "{err}");
    }

    /// The shell wrote the sums file and THEN checked for subjects, leaving an
    /// empty file on disk before stopping.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_attestation_vouching_for_nothing_is_refused_before_anything_is_recorded() {
        let err = parse(&doc("", "https://example/wf", "c")).expect_err("refuses");
        assert_eq!(err, AttestationError::NoSubjects);
    }

    /// "Built by" with no identity is not provenance.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_attestation_without_a_signer_is_refused() {
        for signer in ["", "   "] {
            let err = parse(&doc(WASM_TOOLS, signer, "c")).expect_err("refuses");
            assert_eq!(err, AttestationError::NoSigner, "{signer:?}");
        }
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_subject_without_a_digest_is_refused_naming_it() {
        let err = parse(&doc(
            r#"{"name":"x.tar.gz","digest":{}}"#,
            "https://example/wf",
            "c",
        ))
        .expect_err("refuses");
        assert_eq!(
            err,
            AttestationError::SubjectWithoutDigest {
                name: "x.tar.gz".into()
            }
        );
    }

    /// An attestation-derived digest gets exactly the checks a sums-file digest
    /// gets. Which mechanism vouched must not change how carefully the number
    /// is handled.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_malformed_attestation_digest_is_refused_like_a_malformed_sums_line() {
        let err = parse(&doc(
            r#"{"name":"x.tar.gz","digest":{"sha256":"nope"}}"#,
            "https://example/wf",
            "c",
        ))
        .expect_err("refuses");
        assert!(matches!(err, AttestationError::BadDigest(_)), "{err:?}");
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn one_name_at_two_digests_in_one_attestation_is_refused() {
        let two = format!(
            r#"{{"name":"x","digest":{{"sha256":"{}"}}}},{{"name":"x","digest":{{"sha256":"{}"}}}}"#,
            "1".repeat(64),
            "2".repeat(64)
        );
        let err = parse(&doc(&two, "https://example/wf", "c")).expect_err("refuses");
        assert!(matches!(err, AttestationError::BadDigest(_)), "{err:?}");
    }

    /// Older attestations omit the source commit. Recorded as empty rather
    /// than invented — and the caller renders "built by X from source commit "
    /// rather than claiming a commit that was never asserted.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_missing_source_commit_is_empty_not_fabricated() {
        let json = format!(
            r#"[{{"verificationResult":{{"statement":{{"subject":[{WASM_TOOLS}]}},
               "signature":{{"certificate":{{"buildSignerURI":"https://example/wf"}}}}}}}}]"#
        );
        let a = parse(&json).expect("parses");
        assert_eq!(a.source_commit, "");
    }

    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_document_that_is_not_the_expected_json_is_refused_with_what_was_expected() {
        let err = parse("{\"not\":\"a list\"}").expect_err("refuses");
        assert!(matches!(err, AttestationError::NotJson(_)), "{err:?}");
        assert!(err.to_string().contains("gh attestation verify"), "{err}");
    }

    fn result(subjects: &str, signer: &str, source_ref: &str) -> String {
        format!(
            r#"{{"verificationResult":{{"statement":{{"subject":[{subjects}]}},
               "signature":{{"certificate":{{"buildSignerURI":"{signer}",
               "sourceRepositoryRef":"{source_ref}"}}}}}}}}"#
        )
    }

    /// Every result is read, the pull-request one is set aside, and each kept
    /// statement keeps its own signer and ref.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn every_result_is_read_and_a_pull_request_build_is_set_aside() {
        let a = r#"{"name":"a","digest":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}"#;
        let b = r#"{"name":"b","digest":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222"}}"#;
        let json = format!(
            "[{},{},{}]",
            result(
                a,
                "https://h/o/r/.github/workflows/p.yml@refs/pull/9/merge",
                "refs/pull/9/merge"
            ),
            result(
                a,
                "https://h/o/r/.github/workflows/p.yml@refs/heads/main",
                "refs/heads/main"
            ),
            result(
                b,
                "https://h/o/r/.github/workflows/q.yml@refs/tags/v1",
                "refs/tags/v1"
            ),
        );
        let at = parse(&json).expect("parses");
        assert_eq!(at.statements.len(), 2);
        assert!(at.sums.digest_of("b").is_some() && at.sums.digest_of("a").is_some());
        assert_eq!(at.vouching("a").len(), 1);
        assert_eq!(at.vouching("a")[0].source_ref, "refs/heads/main");
        assert_eq!(at.vouching("b")[0].source_ref, "refs/tags/v1");
        assert!(at.vouching("c").is_empty());
        let only = format!(
            "[{}]",
            result(
                a,
                "https://h/o/r/.github/workflows/p.yml@x",
                "refs/pull/9/merge"
            )
        );
        assert!(matches!(
            parse(&only),
            Err(AttestationError::PullRequestBuild { .. })
        ));
        // The ref is read from the signer URI when the certificate omits it.
        let bare = format!(
            r#"[{{"verificationResult":{{"statement":{{"subject":[{a}]}},
               "signature":{{"certificate":{{"buildSignerURI":"https://h/o/r/.github/workflows/p.yml@refs/pull/3/head"}}}}}}}}]"#
        );
        assert!(matches!(
            parse(&bare),
            Err(AttestationError::PullRequestBuild { .. })
        ));
    }
}
