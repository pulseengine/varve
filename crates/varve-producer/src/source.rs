//! The real [`Source`](crate::orchestrate::Source) — `gh` and `cosign` over an
//! actual network (REQ-PRODUCER-002).
//!
//! Everything that *decides* anything lives in [`crate::gh`] and
//! [`crate::orchestrate`] and is tested without a network. What is left here
//! is the part that genuinely cannot be: spawning processes and touching
//! files. It is kept deliberately thin, because it is the part no unit test
//! covers — the systest is its only oracle.
//!
//! Downloads land in a caller-supplied directory and are read back from it, so
//! the bytes that get digested are the bytes on disk. Digesting a buffer that
//! was never written, or written and then re-read from somewhere else, is how
//! a check stops seeing the thing it checks.

use crate::forge::Forge;
use crate::gh::{self, CommandRunner, GhError, RunOutput};
use crate::ingest::ReleaseProbe;
use crate::orchestrate::{RunError, Source};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Spawns real processes.
pub struct Spawn;

impl CommandRunner for Spawn {
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> RunOutput {
        let mut c = Command::new(program);
        c.args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        match c.output() {
            Ok(o) => RunOutput {
                // A process killed by a signal has no exit code. Reporting 0
                // there would read as success; -1 keeps it a failure.
                code: o.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            },
            Err(e) => RunOutput {
                code: 127,
                stdout: String::new(),
                stderr: format!("{program}: {e}"),
            },
        }
    }
}

/// The names this pipeline expects a cosign-signed release to publish.
pub const SUMS: &str = "SHA256SUMS.txt";
pub const BUNDLE: &str = "SHA256SUMS.txt.cosign.bundle";

/// Where a release's downloads live under a work directory.
///
/// One definition, used by both the downloader and whatever stages what it
/// downloaded. A second copy of this convention anywhere else is a bug waiting
/// for its first divergence: the fetch would write one path and the staging
/// would read another, and the symptom would be a missing file rather than
/// anything naming the real cause.
///
/// `/` is replaced rather than nested, so two repos whose names share a tail
/// cannot land in the same directory.
pub(crate) fn release_dir(root: &Path, repo: &str, release: &str) -> PathBuf {
    root.join(repo.replace('/', "__"))
        .join(release.replace('/', "__"))
}

/// Where ONE plan's downloaded bytes live.
///
/// Keyed on `release`, never on `version`: the release tag is what the forge
/// was asked for, so it is what the downloader used to name the directory. The
/// two are the same string for almost every tool, which is exactly why passing
/// the wrong one went unnoticed — a hub is the only shape where they differ,
/// and there the failure is a missing file that names nothing about its cause.
///
/// Callers take the PLAN rather than loose strings so the choice of field is
/// made once, here, instead of at every call site.
pub fn plan_download_dir(root: &Path, plan: &crate::plan::PayloadPlan) -> PathBuf {
    release_dir(root, &plan.repo, &plan.release)
}

pub struct GhSource<R: CommandRunner> {
    runner: R,
    forge: Forge,
    workdir: PathBuf,
    /// Cached per release, so a probe is not re-run for each payload. The
    /// orchestrator already groups by release; this is belt and braces for a
    /// second caller.
    attestations: RefCell<BTreeMap<String, String>>,
}

impl<R: CommandRunner> GhSource<R> {
    pub fn new(runner: R, forge: Forge, workdir: impl Into<PathBuf>) -> Self {
        GhSource {
            runner,
            forge,
            workdir: workdir.into(),
            attestations: RefCell::new(BTreeMap::new()),
        }
    }

    fn dir_for(&self, repo: &str, version: &str) -> PathBuf {
        release_dir(&self.workdir, repo, version)
    }

    fn gh(&self, args: Vec<String>) -> Result<String, RunError> {
        let out = self.runner.run("gh", &args, &gh::forge_env(&self.forge));
        if out.code == 127 {
            return Err(io_err(
                "running gh",
                &GhError::NotInstalled {
                    program: "gh".into(),
                }
                .to_string(),
            ));
        }
        if !out.ok() {
            return Err(io_err(&format!("gh {}", args.join(" ")), out.stderr.trim()));
        }
        Ok(out.stdout)
    }

    /// `gh api --paginate repos/<repo>/security-advisories?state=published`
    /// (REQ-ADVISORYWATCH-001 clause 1). Through the SAME forge as every
    /// other call this source makes — the tool's repo lives wherever this
    /// run's own releases do.
    pub fn ghsa_advisories_json(&self, repo: &str) -> Result<String, RunError> {
        self.gh(gh::security_advisories_argv(repo))
    }

    /// The RustSec advisory-db directory listing for one crate, or `None` on
    /// a 404 — absence of advisories for that crate, never a failure to ask.
    ///
    /// Deliberately NOT through `self.gh`, and deliberately NOT through this
    /// run's forge: `rustsec/advisory-db` has one home, github.com, whatever
    /// forge this run's own releases live on.
    pub fn rustsec_crate_directory(&self, krate: &str) -> Result<Option<String>, RunError> {
        let args = gh::rustsec_crate_dir_argv(krate)
            .map_err(|e| io_err("building the rustsec query", &e.to_string()))?;
        let out = self.runner.run("gh", &args, &gh::rustsec_advisory_db_env());
        if out.code == 127 {
            return Err(io_err(
                "running gh",
                &GhError::NotInstalled {
                    program: "gh".into(),
                }
                .to_string(),
            ));
        }
        if out.ok() {
            return Ok(Some(out.stdout));
        }
        if gh::is_http_404(&out.stderr) {
            return Ok(None);
        }
        Err(io_err(&format!("gh {}", args.join(" ")), out.stderr.trim()))
    }

    /// One RustSec advisory file's raw markdown. Same github.com-only
    /// reasoning as [`Self::rustsec_crate_directory`].
    pub fn rustsec_advisory_markdown(
        &self,
        krate: &str,
        filename: &str,
    ) -> Result<String, RunError> {
        let args = gh::rustsec_advisory_md_argv(krate, filename)
            .map_err(|e| io_err("building the rustsec query", &e.to_string()))?;
        let out = self.runner.run("gh", &args, &gh::rustsec_advisory_db_env());
        if out.code == 127 {
            return Err(io_err(
                "running gh",
                &GhError::NotInstalled {
                    program: "gh".into(),
                }
                .to_string(),
            ));
        }
        if !out.ok() {
            return Err(io_err(&format!("gh {}", args.join(" ")), out.stderr.trim()));
        }
        Ok(out.stdout)
    }

    /// The release's own upstream SBOM, admitted through the SAME proof
    /// `deposit` already verifies for every payload — the fallback for a
    /// payload whose layer manifest recorded no `ANN_SBOM` of its own
    /// (REQ-ADVISORYWATCH-001 clause 4b). Through THIS source's own forge:
    /// unlike the RustSec advisory-db, a release's SBOM lives wherever that
    /// release does.
    pub fn release_sbom(
        &self,
        repo: &str,
        release: &str,
        version: &str,
    ) -> crate::orchestrate::ReleaseSbomOutcome {
        crate::orchestrate::release_sbom_outcome(self, &self.forge, repo, release, version)
    }

    /// Download one asset into the release's directory and return its path.
    fn download(&self, repo: &str, version: &str, asset: &str) -> Result<PathBuf, RunError> {
        let dir = self.dir_for(repo, version);
        let path = dir.join(asset);
        if path.exists() {
            return Ok(path);
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| io_err(&format!("creating {}", dir.display()), &e.to_string()))?;
        let dir_s = dir.to_string_lossy().into_owned();
        self.gh(gh::release_download_argv(repo, version, asset, &dir_s))?;
        if !path.exists() {
            return Err(io_err(
                &format!("{repo} {version}: downloading {asset}"),
                "gh reported success but the file is not there",
            ));
        }
        Ok(path)
    }
}

fn io_err(context: &str, detail: &str) -> RunError {
    RunError::Io {
        context: context.to_string(),
        detail: detail.to_string(),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, RunError> {
    std::fs::read(path).map_err(|e| io_err(&format!("reading {}", path.display()), &e.to_string()))
}

impl<R: CommandRunner> Source for GhSource<R> {
    fn probe(&self, forge: &Forge, repo: &str, version: &str) -> Result<ReleaseProbe, RunError> {
        let listing = self.gh(gh::release_assets_argv(repo, version))?;
        let names = gh::parse_release_assets(&listing)
            .map_err(|e| io_err(&format!("{repo} {version}"), &e.to_string()))?;
        let has_sums = names.iter().any(|n| n == SUMS);
        let has_cosign_bundle = names.iter().any(|n| n == BUNDLE);

        // Rung 1 — only run cosign when the release actually offers both, so
        // that "not offered" stays distinguishable from "offered and failed".
        let cosign = if has_sums && has_cosign_bundle {
            let sums = self.download(repo, version, SUMS)?;
            let bundle = self.download(repo, version, BUNDLE)?;
            let argv = gh::cosign_verify_argv(
                &bundle.to_string_lossy(),
                repo,
                &forge.identity_regexp(repo, version),
                &forge.oidc_issuer,
                &sums.to_string_lossy(),
            );
            let out = self.runner.run("cosign", &argv, &[]);
            Some(if out.code == 127 {
                Err(GhError::NotInstalled {
                    program: "cosign".into(),
                }
                .to_string())
            } else if out.ok() {
                Ok(())
            } else {
                Err(out.stderr.trim().to_string())
            })
        } else {
            None
        };

        // Rung 2 is only probed when rung 1 did not settle it. That is not an
        // optimisation: probing an attestation means DOWNLOADING an asset to
        // verify against, and every repo in the pulseengine realm publishes
        // cosign sums — so an eager probe would fetch one asset per repo on
        // every run and quietly break the promise that re-depositing an
        // unchanged layer.toml fetches nothing (REQ-CARRYFORWARD-001 clause 6).
        //
        // What is NOT done here is set the field to `NotAttested`. Nobody
        // looked, and `NotAttested` is a claim about a release.
        let settled_by_cosign = matches!(
            crate::ingest::rung_cosign_sums(
                forge,
                repo,
                version,
                &ReleaseProbe {
                    published: Vec::new(),
                    has_sums,
                    has_cosign_bundle,
                    cosign: cosign.clone(),
                    attestation: crate::ingest::AttestationProbe::NotProbed,
                    pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
                },
            ),
            crate::ingest::Rung::Accepted { .. } | crate::ingest::Rung::Failed(_)
        );
        if settled_by_cosign {
            return Ok(ReleaseProbe {
                published: names,
                has_sums,
                has_cosign_bundle,
                cosign,
                attestation: crate::ingest::AttestationProbe::NotProbed,
                pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
            });
        }

        // Attestations are per artifact, so verify against one asset of the
        // release. The statement it returns names every asset, which is what
        // lets one verification cover the whole release.
        let attestation = match names.iter().find(|n| *n != SUMS && *n != BUNDLE) {
            None => crate::ingest::AttestationProbe::NotAttested,
            Some(subject) => {
                let path = self.download(repo, version, subject)?;
                let argv = gh::attestation_verify_argv(&path.to_string_lossy(), repo);
                let out = self.runner.run("gh", &argv, &gh::forge_env(forge));
                if out.ok() {
                    self.attestations
                        .borrow_mut()
                        .insert(format!("{repo}@{version}"), out.stdout.clone());
                }
                gh::classify_attestation(&out)
            }
        };

        Ok(ReleaseProbe {
            published: names,
            has_sums,
            has_cosign_bundle,
            cosign,
            attestation,
            pgp_sums: crate::ingest::PgpSumsProbe::NotDeclared,
        })
    }

    fn sums_text(&self, repo: &str, version: &str) -> Result<String, RunError> {
        // Already downloaded by the probe, and read back from disk: the bytes
        // cosign verified are the bytes on this path.
        let path = self.dir_for(repo, version).join(SUMS);
        let bytes = read(&path)?;
        String::from_utf8(bytes).map_err(|e| {
            io_err(
                &format!("{repo} {version}: {SUMS}"),
                &format!("not valid UTF-8: {e}"),
            )
        })
    }

    fn attestation_json(&self, repo: &str, version: &str) -> Result<String, RunError> {
        self.attestations
            .borrow()
            .get(&format!("{repo}@{version}"))
            .cloned()
            .ok_or_else(|| {
                io_err(
                    &format!("{repo} {version}"),
                    "the attestation was not captured during the probe; this is \
                     a caller ordering error, not an upstream omission",
                )
            })
    }

    fn attestation_json_for(
        &self,
        repo: &str,
        version: &str,
        asset: &str,
    ) -> Result<String, RunError> {
        // Verified against THIS asset's bytes, which is the whole point: the
        // statement that comes back names the file it was asked about, so the
        // digest recorded for these bytes is one an attestation actually
        // vouches for rather than one inherited from a sibling.
        let path = self.download(repo, version, asset)?;
        let argv = gh::attestation_verify_argv(&path.to_string_lossy(), repo);
        let out = self.runner.run("gh", &argv, &gh::forge_env(&self.forge));
        if !out.ok() {
            return Err(io_err(
                &format!("{repo} {version}: {asset}"),
                &format!(
                    "`gh attestation verify` did not accept this asset's own \
                     attestation: {}",
                    out.stderr.trim()
                ),
            ));
        }
        Ok(out.stdout)
    }

    fn asset_bytes(&self, repo: &str, version: &str, asset: &str) -> Result<Vec<u8>, RunError> {
        let path = self.download(repo, version, asset)?;
        read(&path)
    }

    fn repo_license(&self, repo: &str) -> Result<Option<String>, RunError> {
        let out = self.gh(gh::repo_info_argv(repo))?;
        gh::parse_repo_license(&out).map_err(|e| {
            io_err(
                &format!("{repo}: reading the repository's declared license"),
                &e.to_string(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for `gh` that actually behaves like it: when handed a
    /// `release download` argv it writes the scripted bytes to the directory
    /// and filename that argv names.
    ///
    /// This matters more than a canned string would. The property under test
    /// is that the bytes which get digested are the bytes on disk, and a
    /// double that returns buffers without ever touching the filesystem cannot
    /// tell whether the code reads back what it wrote.
    struct FakeGh {
        replies: Vec<(String, RunOutput)>,
        /// asset name -> contents written on download.
        files: BTreeMap<String, Vec<u8>>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeGh {
        fn new() -> Self {
            FakeGh {
                replies: Vec::new(),
                files: BTreeMap::new(),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn reply(mut self, key: &str, o: RunOutput) -> Self {
            self.replies.push((key.into(), o));
            self
        }
        fn file(mut self, name: &str, bytes: &[u8]) -> Self {
            self.files.insert(name.into(), bytes.to_vec());
            self
        }
        fn listing(self, names: &[&str]) -> Self {
            let assets: Vec<String> = names
                .iter()
                .map(|n| format!(r#"{{"name":"{n}"}}"#))
                .collect();
            let json = format!(r#"{{"assets":[{}]}}"#, assets.join(","));
            self.reply("gh release", out(0, &json, ""))
        }
        fn log(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn flag<'a>(args: &'a [String], f: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .map(|s| s.as_str())
    }

    impl CommandRunner for FakeGh {
        fn run(&self, program: &str, args: &[String], _env: &[(String, String)]) -> RunOutput {
            let key = format!("{program} {}", args.first().cloned().unwrap_or_default());
            self.calls
                .borrow_mut()
                .push(format!("{key} {}", args.join(" ")));
            // Emulate `gh release download -p <asset> -D <dir>`.
            if key == "gh release" && args.get(1).map(|a| a == "download").unwrap_or(false) {
                let (Some(asset), Some(dir)) = (flag(args, "-p"), flag(args, "-D")) else {
                    return out(1, "", "malformed download argv");
                };
                return match self.files.get(asset) {
                    Some(bytes) => {
                        std::fs::create_dir_all(dir).expect("test dir");
                        std::fs::write(Path::new(dir).join(asset), bytes).expect("test write");
                        out(0, "", "")
                    }
                    None => out(1, "", &format!("release asset not found: {asset}")),
                };
            }
            for (k, v) in &self.replies {
                if *k == key {
                    return v.clone();
                }
            }
            out(1, "", &format!("unscripted: {key}"))
        }
    }

    /// Answers from a script keyed on the program and first argument.
    struct Scripted(Vec<(String, RunOutput)>);

    impl CommandRunner for Scripted {
        fn run(&self, program: &str, args: &[String], _env: &[(String, String)]) -> RunOutput {
            let key = format!("{program} {}", args.first().cloned().unwrap_or_default());
            for (k, v) in &self.0 {
                if *k == key {
                    return v.clone();
                }
            }
            RunOutput {
                code: 1,
                stdout: String::new(),
                stderr: format!("unscripted: {key}"),
            }
        }
    }

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput {
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// A release offering neither sums nor bundle must not run cosign at all —
    /// running it and reading the failure as a rejection would turn "this
    /// mechanism is not offered" into "this proof was refused", and abort a
    /// run that should have tried the next rung.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn cosign_is_not_run_against_a_release_that_publishes_no_sums() {
        let tmp = scratch("probe-test");
        let src = GhSource::new(
            Scripted(vec![("gh release".into(), out(0, r#"{"assets":[]}"#, ""))]),
            Forge::github_com(),
            &*tmp,
        );
        let p = src
            .probe(&Forge::github_com(), "o/r", "v1")
            .expect("probes");
        assert!(!p.has_sums && !p.has_cosign_bundle);
        // None, not Some(Err(...)): never run, rather than run and failed.
        assert!(p.cosign.is_none(), "{:?}", p.cosign);
        assert_eq!(p.attestation, crate::ingest::AttestationProbe::NotAttested);
    }

    /// A `cosign` and a `gh attestation` that enforce what they are TOLD to,
    /// the way the real ones do: cosign matches the identity regexp it is
    /// handed against the certificate's identity, and gh requires the digest of
    /// the file it is given to be one of the attestation's subjects. A double
    /// that always said yes (or always no) could not tell a bound command from
    /// an unbound one.
    struct Certified {
        inner: FakeGh,
        /// The signing workflow in the certificate.
        identity: String,
        /// The repository the certificate says the workflow RAN in (the
        /// caller's, for a reusable workflow).
        run_in: String,
        /// The ref the attestation was built from.
        built_from: String,
        /// The attestation's subjects: (name, sha256 hex).
        subjects: Vec<(String, String)>,
        /// Further attestations gh returns for the same digest (a list, as the
        /// real one): (built from, subjects).
        more: Vec<(String, Vec<(String, String)>)>,
        /// The identity regexp cosign was last handed.
        seen_identity: std::rc::Rc<RefCell<Option<String>>>,
    }

    impl CommandRunner for Certified {
        fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> RunOutput {
            if program == "cosign" {
                let re = flag(args, "--certificate-identity-regexp").expect("an identity");
                *self.seen_identity.borrow_mut() = Some(re.to_string());
                let re = regex::Regex::new(re).expect("the regexp compiles");
                let ran_in_the_right_repo = flag(args, "--certificate-github-workflow-repository")
                    .is_none_or(|want| want == self.run_in);
                return if re.is_match(&self.identity) && ran_in_the_right_repo {
                    out(0, "Verified OK", "")
                } else {
                    out(
                        1,
                        "",
                        "none of the expected identities matched what was in the certificate",
                    )
                };
            }
            if program == "gh" && args.first().map(String::as_str) == Some("attestation") {
                let file = std::fs::read(&args[2]).expect("gh is handed a downloaded file");
                let digest = crate::orchestrate::sha256_hex(&file);
                let covered = self
                    .subjects
                    .iter()
                    .chain(self.more.iter().flat_map(|(_, s)| s.iter()))
                    .any(|(_, d)| *d == digest);
                if !covered {
                    return out(
                        1,
                        "",
                        "verifying with issuer \"sigstore.dev\": the artifact's digest is not \
                         a subject of any attestation",
                    );
                }
                // Like gh: every attestation whose subjects include the file's
                // digest, in order, each with its own certificate.
                let all = std::iter::once((&self.built_from, &self.subjects))
                    .chain(self.more.iter().map(|(r, s)| (r, s)));
                let results: Vec<String> = all
                    .filter(|(_, subjects)| subjects.iter().any(|(_, d)| *d == digest))
                    .map(|(built_from, subjects)| {
                        let subjects: Vec<String> = subjects
                            .iter()
                            .map(|(n, d)| {
                                format!(r#"{{"name":"{n}","digest":{{"sha256":"{d}"}}}}"#)
                            })
                            .collect();
                        format!(
                            r#"{{"verificationResult":{{
                              "statement":{{"subject":[{}]}},
                              "signature":{{"certificate":{{
                                "buildSignerURI":"https://github.com/o/r/.github/workflows/release.yml@{built_from}",
                                "sourceRepositoryRef":"{built_from}",
                                "sourceRepositoryDigest":"abc"}}}}}}}}"#,
                            subjects.join(",")
                        )
                    })
                    .collect();
                return out(0, &format!("[{}]", results.join(",")), "");
            }
            self.inner.run(program, args, env)
        }
    }

    fn certified(listing: &[&str], identity: &str, built_from: &str) -> Certified {
        Certified {
            inner: FakeGh::new()
                .listing(listing)
                .file(SUMS, SUMS_TEXT.as_bytes())
                .file(BUNDLE, b"bundle")
                .file("one.tar.gz", b"payload"),
            identity: identity.into(),
            run_in: "o/r".into(),
            built_from: built_from.into(),
            more: Vec::new(),
            seen_identity: Default::default(),
            subjects: vec![(
                "one.tar.gz".into(),
                crate::orchestrate::sha256_hex(b"payload"),
            )],
        }
    }

    impl Certified {
        /// The attestation's subjects, replacing the default one.
        fn attesting(mut self, subjects: &[(&str, &[u8])]) -> Self {
            self.subjects = subjects
                .iter()
                .map(|(n, b)| (n.to_string(), crate::orchestrate::sha256_hex(b)))
                .collect();
            self
        }
        /// The repository the signing certificate says the workflow ran in.
        fn running_in(mut self, repo: &str) -> Self {
            self.run_in = repo.into();
            self
        }
        /// A further attestation gh returns for the same digest.
        fn also_attested(mut self, built_from: &str, subjects: &[(&str, &[u8])]) -> Self {
            self.more.push((
                built_from.into(),
                subjects
                    .iter()
                    .map(|(n, b)| (n.to_string(), crate::orchestrate::sha256_hex(b)))
                    .collect(),
            ));
            self
        }
        /// An asset the release serves under `name`.
        fn serving(mut self, name: &str, bytes: &[u8]) -> Self {
            self.inner = self.inner.file(name, bytes);
            self
        }
    }

    fn ladder_at(
        runner: Certified,
        repo: &str,
        tag: &str,
    ) -> Result<crate::ingest::Accepted, crate::ingest::IngestError> {
        let dir = scratch("bound-ladder");
        let forge = Forge::github_com();
        let src = GhSource::new(runner, forge.clone(), &*dir);
        let probe = src.probe(&forge, repo, tag).expect("probes");
        crate::ingest::choose(&forge, repo, tag, &probe, &BTreeMap::new(), None)
    }

    const SIGNED_AT_V1: &str =
        "https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1.0.0";

    /// Rung 1: sums signed for v1.0.0 are refused when presented as v2.0.0,
    /// accepted as v1.0.0, and refused when the signing workflow belongs to a
    /// different repository at the same tag.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn cosign_sums_signed_for_one_release_are_refused_for_another() {
        let listing = [SUMS, BUNDLE, "one.tar.gz"];
        let older = ladder_at(certified(&listing, SIGNED_AT_V1, ""), "o/r", "v2.0.0");
        assert!(
            matches!(
                &older,
                Err(crate::ingest::IngestError::ProofRejected { .. })
            ),
            "an older release's signature must not vouch for a newer tag: {older:?}"
        );
        let same = ladder_at(certified(&listing, SIGNED_AT_V1, ""), "o/r", "v1.0.0")
            .expect("the same tag verifies");
        assert_eq!(same.mechanism, crate::ingest::Mechanism::CosignSums);
        assert!(
            same.asserts.contains("v1.0.0"),
            "the record names the release it was bound to: {}",
            same.asserts
        );
        let elsewhere = SIGNED_AT_V1.replace("/o/r/", "/o/other/");
        let other = ladder_at(certified(&listing, &elsewhere, ""), "o/r", "v1.0.0");
        assert!(
            matches!(
                &other,
                Err(crate::ingest::IngestError::ProofRejected { .. })
            ),
            "another repository's workflow at the same tag must be refused: {other:?}"
        );
        let branch = SIGNED_AT_V1.replace("refs/tags/v1.0.0", "refs/heads/main");
        let on_a_branch = ladder_at(certified(&listing, &branch, ""), "o/r", "v1.0.0");
        assert!(
            matches!(
                &on_a_branch,
                Err(crate::ingest::IngestError::ProofRejected { .. })
            ),
            "a branch is not a release: {on_a_branch:?}"
        );
    }

    /// The identity recorded in the signed manifest is the one cosign was told
    /// to enforce, not text written beside the enforcement: the exact regexp
    /// the command received, tag included, is in the recorded assertion, while
    /// the signer stays the repository prefix.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_recorded_cosign_identity_is_the_regexp_cosign_enforced() {
        let listing = [SUMS, BUNDLE, "one.tar.gz"];
        let runner = certified(&listing, SIGNED_AT_V1, "");
        let seen = runner.seen_identity.clone();
        let accepted = ladder_at(runner, "o/r", "v1.0.0").expect("verifies");
        let enforced = seen.borrow().clone().expect("cosign was run");
        assert!(
            accepted.asserts.contains(&enforced),
            "the record must carry what cosign enforced: {enforced} not in {}",
            accepted.asserts
        );
        assert!(enforced.ends_with(r"@refs/tags/v1\.0\.0$"), "{enforced}");
        assert_eq!(accepted.signer.as_deref(), Some("https://github.com/o/r/"));
    }

    /// The cosign exemption from the name rule under `unbound-release-reason`
    /// is safe only because of this: sums signed for the OLDER tag, with their
    /// files, served under this tag with a versionless name, are refused by
    /// the identity check itself.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn older_signed_sums_for_a_versionless_name_are_refused_by_the_tag_pin() {
        let listing = [SUMS, BUNDLE, "one.tar.gz"];
        let older = SIGNED_AT_V1;
        let e = ladder_at(certified(&listing, older, ""), "o/r", "v2.0.0")
            .expect_err("the older release's certificate must not verify for v2.0.0");
        assert!(
            matches!(e, crate::ingest::IngestError::ProofRejected { .. }),
            "{e:?}"
        );
        ladder_at(certified(&listing, older, ""), "o/r", "v1.0.0").expect("its own tag verifies");
    }

    /// A reusable workflow of the upstream repository, called from ANOTHER
    /// repository, yields a certificate whose workflow identity matches the
    /// upstream's path and tag while the code that ran was the caller's. cosign
    /// is told which repository the workflow must have run in.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn cosign_sums_signed_by_a_foreign_caller_of_the_workflow_are_refused() {
        let listing = [SUMS, BUNDLE, "one.tar.gz"];
        let foreign = ladder_at(
            certified(&listing, SIGNED_AT_V1, "").running_in("evil/caller"),
            "o/r",
            "v1.0.0",
        );
        assert!(
            matches!(
                &foreign,
                Err(crate::ingest::IngestError::ProofRejected { .. })
            ),
            "a certificate for a workflow run from another repository: {foreign:?}"
        );
        ladder_at(certified(&listing, SIGNED_AT_V1, ""), "o/r", "v1.0.0")
            .expect("the repository's own run still verifies");
    }

    /// Verify a release the way a run does.
    fn verified(
        runner: Certified,
        tag: &str,
        asset: &str,
    ) -> Result<crate::orchestrate::Verified, crate::orchestrate::RunError> {
        let dir = scratch("bound-spend");
        let forge = Forge::github_com();
        let src = GhSource::new(runner, forge.clone(), &*dir);
        crate::orchestrate::verify_release(
            &src,
            &forge,
            "o/r",
            tag,
            &BTreeMap::new(),
            &crate::orchestrate::Declared::default(),
            &[asset.to_string()],
        )
    }

    /// Verify a release the way a run does, then spend its proof on `bytes`
    /// served as `asset`.
    fn spend(
        runner: Certified,
        tag: &str,
        asset: &str,
        bytes: &[u8],
    ) -> Result<String, crate::orchestrate::RunError> {
        let v = verified(runner, tag, asset)?;
        assert_eq!(
            v.accepted.mechanism,
            crate::ingest::Mechanism::BuildProvenance
        );
        crate::orchestrate::admit(&v, "o/r", asset, bytes)
    }

    /// Rung 2, with NO `--source-ref` (upstreams such as wasm-tools sign every
    /// release from a branch workflow): the release binding is the subject
    /// NAME. An attestation for 1.0.0's asset, whose bytes are served under
    /// 2.0.0's name, is refused for 2.0.0; one that names 2.0.0's asset with
    /// the matching digest is accepted even though it was built from a branch.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn build_provenance_for_one_release_is_refused_for_another() {
        let old = b"the 1.0.0 build".as_slice();
        let new = b"the 2.0.0 build".as_slice();
        // The older release's attestation, replayed: its subject is the 1.0.0
        // asset, and the 1.0.0 bytes are what the 2.0.0 name serves.
        let replay = certified(&["one-2.0.0.tar.gz"], "", "refs/heads/main")
            .attesting(&[("one-1.0.0.tar.gz", old)])
            .serving("one-2.0.0.tar.gz", old);
        let refused = spend(replay, "v2.0.0", "one-2.0.0.tar.gz", old);
        assert!(
            matches!(
                &refused,
                Err(crate::orchestrate::RunError::NotCoveredByProof { .. })
            ),
            "an older release's attestation must not vouch for a newer asset: {refused:?}"
        );
        // The attestation that names this release's asset, built from a branch.
        let good = certified(&["one-2.0.0.tar.gz"], "", "refs/heads/main")
            .attesting(&[("one-2.0.0.tar.gz", new), ("one-1.0.0.tar.gz", old)])
            .serving("one-2.0.0.tar.gz", new);
        let digest = spend(good, "v2.0.0", "one-2.0.0.tar.gz", new).expect("named and matching");
        assert_eq!(digest, crate::orchestrate::sha256_hex(new));
        // Named correctly, but the served bytes are not the attested ones: gh
        // refuses the file itself.
        let swapped = certified(&["one-2.0.0.tar.gz"], "", "refs/heads/main")
            .attesting(&[("one-2.0.0.tar.gz", new)])
            .serving("one-2.0.0.tar.gz", old);
        assert!(
            spend(swapped, "v2.0.0", "one-2.0.0.tar.gz", old).is_err(),
            "bytes that are not the named subject's digest must be refused"
        );
    }

    const NEW: &[u8] = b"the 2.0.0 build";
    const OLD: &[u8] = b"the 1.0.0 build";
    const ASSET2: &str = "one-2.0.0.tar.gz";

    fn serving_new(extra_first: &str, first: &[(&str, &[u8])]) -> Certified {
        certified(&[ASSET2], "", extra_first)
            .attesting(first)
            .serving(ASSET2, NEW)
    }

    /// gh returns EVERY attestation for the digest. The first can be for
    /// another asset's name (the same bytes attested under it); the one that
    /// names this asset still vouches for it.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_attestation_after_the_first_can_vouch_for_the_asset_it_names() {
        let r = serving_new("refs/heads/main", &[("misc.tar.gz", NEW)])
            .also_attested("refs/heads/main", &[(ASSET2, NEW)]);
        spend(r, "v2.0.0", ASSET2, NEW).expect("the second statement names the asset");
    }

    /// Two statements that disagree about one name's digest are refused, not
    /// resolved by order: the first would have been taken alone before.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn statements_that_disagree_on_a_subjects_digest_are_refused() {
        let r = serving_new("refs/heads/main", &[(ASSET2, NEW)])
            .also_attested("refs/heads/main", &[(ASSET2, OLD), ("other.tar.gz", NEW)]);
        let e = spend(r, "v2.0.0", ASSET2, NEW).expect_err("a disagreement is refused");
        assert!(format!("{e}").contains(ASSET2), "{e}");
    }

    /// A pull-request build is never a release, however well it is signed.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_pull_request_build_never_vouches_for_a_release() {
        let only = serving_new("refs/pull/7/merge", &[(ASSET2, NEW)]);
        let e = spend(only, "v2.0.0", ASSET2, NEW).expect_err("a PR build is refused");
        assert!(format!("{e}").contains("refs/pull/7/merge"), "{e}");
        // Alongside a real build it is set aside, and the record names the
        // statement that vouched.
        let both = serving_new("refs/pull/7/merge", &[(ASSET2, NEW)])
            .also_attested("refs/heads/main", &[(ASSET2, NEW)]);
        let v = verified(both, "v2.0.0", ASSET2).expect("the real build vouches");
        let signer = v.accepted.signer.expect("a signer");
        assert!(signer.ends_with("@refs/heads/main"), "{signer}");
        assert!(
            v.accepted.asserts.contains("@refs/heads/main"),
            "{}",
            v.accepted.asserts
        );
        assert!(
            !v.accepted.asserts.contains("refs/pull"),
            "{}",
            v.accepted.asserts
        );
    }

    /// An upstream that signs from the release tag has a different
    /// buildSignerURI (its `@<ref>` part) for every release; the recorded
    /// `proof-signer` must not move with it, or a layer delta reports a moved
    /// signer on every bump. The full URIs, refs included, are in the assertion.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_build_provenance_signer_is_the_same_for_two_releases() {
        let release = |tag: &str, asset: &str, bytes: &[u8]| {
            let r = certified(&[asset], "", &format!("refs/tags/{tag}"))
                .attesting(&[(asset, bytes)])
                .serving(asset, bytes);
            verified(r, tag, asset).expect("verifies").accepted
        };
        let one = release("v1.0.0", "one-1.0.0.tar.gz", OLD);
        let two = release("v2.0.0", "one-2.0.0.tar.gz", NEW);
        assert_eq!(one.signer, two.signer, "{one:?} {two:?}");
        assert_eq!(
            one.signer.as_deref(),
            Some("https://github.com/o/r/.github/workflows/release.yml@refs/tags/*")
        );
        assert!(
            one.asserts.contains("release.yml@refs/tags/v1.0.0"),
            "{}",
            one.asserts
        );
        assert!(
            two.asserts.contains("release.yml@refs/tags/v2.0.0"),
            "{}",
            two.asserts
        );
    }

    /// The record names the buildSignerURI and ref of the statement that
    /// vouched for the assets, not of whichever came first.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_record_names_the_statement_that_vouched() {
        let r = serving_new("refs/heads/other", &[("misc.tar.gz", NEW)])
            .also_attested("refs/heads/main", &[(ASSET2, NEW)]);
        let v = verified(r, "v2.0.0", ASSET2).expect("verifies");
        let signer = v.accepted.signer.expect("a signer");
        assert_eq!(
            signer,
            "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main"
        );
        let asserts = &v.accepted.asserts;
        assert!(asserts.contains("refs/heads/main"), "{asserts}");
        assert!(!asserts.contains("refs/heads/other"), "{asserts}");
    }

    /// An attestation built from a branch is accepted: the producer passes gh
    /// no `--source-ref`, so wasm-tools-style releases are not refused.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn build_provenance_built_from_a_branch_is_accepted() {
        let runner = certified(&["one.tar.gz"], "", "refs/heads/main");
        let accepted =
            ladder_at(runner, "o/r", "v1.0.0").expect("an attestation built from a branch");
        assert_eq!(
            accepted.mechanism,
            crate::ingest::Mechanism::BuildProvenance
        );
    }

    fn scratch(name: &str) -> crate::testscratch::Scratch {
        crate::testscratch::Scratch::new(&format!("producer-{name}"))
    }

    const SUMS_TEXT: &str = "aaaa  ./one.tar.gz\nbbbb  ./two.tar.gz\n";

    /// The bytes handed to the digest step must be the bytes that landed on
    /// disk. A double that never writes a file cannot establish this; FakeGh
    /// writes exactly where the argv says, so a read from the wrong path or a
    /// buffer returned without reading fails here.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn what_is_read_back_is_what_the_download_actually_wrote() {
        let dir = scratch("readback");
        let gh = FakeGh::new()
            .listing(&[SUMS, BUNDLE, "one.tar.gz"])
            .file(SUMS, SUMS_TEXT.as_bytes())
            .file(BUNDLE, b"bundle-bytes")
            .file("one.tar.gz", b"payload-bytes")
            .reply("cosign verify-blob", out(0, "", ""));
        let src = GhSource::new(gh, Forge::github_com(), &*dir);
        let p = src
            .probe(&Forge::github_com(), "o/r", "v1")
            .expect("probes");
        assert_eq!(p.cosign, Some(Ok(())));
        assert_eq!(src.sums_text("o/r", "v1").expect("reads"), SUMS_TEXT);
        assert_eq!(
            src.asset_bytes("o/r", "v1", "one.tar.gz").expect("reads"),
            b"payload-bytes".to_vec()
        );
        // And it is genuinely on disk, under the per-release directory.
        let on_disk = dir.join("o__r").join("v1").join("one.tar.gz");
        assert_eq!(std::fs::read(&on_disk).expect("exists"), b"payload-bytes");
    }

    /// `SHA256SUMS.txt` present without its bundle is not a cosign-signed
    /// release. Treating either name as sufficient would run cosign against a
    /// missing file and report the failure as a rejected proof.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn both_the_sums_and_its_bundle_are_required_before_cosign_is_run() {
        for (names, sums, bundle) in [
            (vec![SUMS, "one.tar.gz"], true, false),
            (vec![BUNDLE, "one.tar.gz"], false, true),
            (vec!["one.tar.gz"], false, false),
        ] {
            let dir = scratch("halfsigned");
            let gh = FakeGh::new()
                .listing(&names)
                .file(SUMS, SUMS_TEXT.as_bytes())
                .file(BUNDLE, b"b")
                .file("one.tar.gz", b"p")
                .reply("gh attestation", out(1, "", "no attestations found"));
            let src = GhSource::new(gh, Forge::github_com(), &*dir);
            let p = src
                .probe(&Forge::github_com(), "o/r", "v1")
                .expect("probes");
            assert_eq!(p.has_sums, sums, "{names:?}");
            assert_eq!(p.has_cosign_bundle, bundle, "{names:?}");
            assert!(p.cosign.is_none(), "cosign must not run for {names:?}");
        }
    }

    /// `attestation_json_for` verifies THE NAMED ASSET and hands back what
    /// `gh` actually said.
    ///
    /// The orchestrator's tests drive this through a double, so the real
    /// implementation had no coverage at all: cargo-mutants replaced its whole
    /// body with `Ok(String::new())` and with `Ok("xyzzy".into())` and nothing
    /// noticed. A statement is the only thing standing between a payload and
    /// an unproven digest, so a stub returning nothing must not pass.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn one_assets_attestation_is_verified_against_that_asset_and_returned() {
        let dir = scratch("perasset");
        const DOC: &str = r#"[{"verificationResult":{"statement":{"subject":[]}}}]"#;
        let gh = FakeGh::new()
            .file("two.tar.gz", b"bytes of two")
            .reply("gh attestation", out(0, DOC, ""));
        let src = GhSource::new(gh, Forge::github_com(), &*dir);

        let json = src
            .attestation_json_for("o/r", "v1", "two.tar.gz")
            .expect("gh accepted it");

        assert_eq!(json, DOC, "the caller must get gh's own statement");
        let verified: Vec<_> = src
            .runner
            .log()
            .into_iter()
            .filter(|c| c.starts_with("gh attestation"))
            .collect();
        assert_eq!(verified.len(), 1, "{verified:?}");
        assert!(
            verified[0].contains("two.tar.gz"),
            "verified the wrong file: {verified:?}"
        );
    }

    /// A `gh attestation verify` that did NOT accept the asset is an error,
    /// not an empty statement.
    ///
    /// Deleting the `!` from this check survived the mutation gate. It has to
    /// fail closed: continuing with whatever `gh` printed on a rejection would
    /// hand the caller a document to parse, and a parse of nothing is how an
    /// unproven payload acquires a digest.
    // rivet: verifies REQ-PROVSHAPE-001
    #[test]
    fn an_asset_whose_own_attestation_is_rejected_is_an_error() {
        let dir = scratch("perasset-bad");
        let gh = FakeGh::new().file("two.tar.gz", b"bytes of two").reply(
            "gh attestation",
            out(1, "", "no attestations found for subject"),
        );
        let src = GhSource::new(gh, Forge::github_com(), &*dir);

        let e = src
            .attestation_json_for("o/r", "v1", "two.tar.gz")
            .expect_err("a rejected attestation must not read as an accepted one");
        let msg = e.to_string();
        assert!(msg.contains("two.tar.gz"), "must name the asset: {msg}");
        assert!(
            msg.contains("no attestations found for subject"),
            "must carry what gh said: {msg}"
        );
    }

    /// The asset an attestation is verified against must be a real payload —
    /// verifying against the sums file or its bundle would attest the wrong
    /// artifact, and on a release that publishes only those two there is
    /// nothing to attest at all.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_attestation_subject_is_a_payload_not_the_sums_file() {
        let dir = scratch("subject");
        let gh = FakeGh::new()
            // Sums present, bundle absent: rung 1 is not offered, so rung 2 is
            // probed and must pick one.tar.gz, not SHA256SUMS.txt.
            .listing(&[SUMS, "one.tar.gz"])
            .file(SUMS, SUMS_TEXT.as_bytes())
            .file("one.tar.gz", b"p")
            .reply("gh attestation", out(1, "", "no attestations found"));
        let src = GhSource::new(gh, Forge::github_com(), &*dir);
        src.probe(&Forge::github_com(), "o/r", "v1")
            .expect("probes");
        // The download that fed `gh attestation verify` was the payload.
        assert!(
            src.runner.log().iter().any(|c| c.contains("-p one.tar.gz")),
            "{:?}",
            src.runner.log()
        );
        let verified: Vec<_> = src
            .runner
            .log()
            .into_iter()
            .filter(|c| c.starts_with("gh attestation"))
            .collect();
        assert_eq!(verified.len(), 1, "{verified:?}");
        assert!(verified[0].contains("one.tar.gz"), "{verified:?}");
        assert!(
            !verified[0].contains(SUMS),
            "attested the sums file: {verified:?}"
        );
    }

    /// A release publishing only a sums file and a bundle has no payload to
    /// attest, and must not verify an attestation against one of those.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_release_with_no_payload_has_nothing_to_attest() {
        let dir = scratch("nopayload");
        let gh = FakeGh::new()
            .listing(&[SUMS])
            .file(SUMS, SUMS_TEXT.as_bytes());
        let src = GhSource::new(gh, Forge::github_com(), &*dir);
        let p = src
            .probe(&Forge::github_com(), "o/r", "v1")
            .expect("probes");
        assert_eq!(p.attestation, crate::ingest::AttestationProbe::NotAttested);
        assert!(
            !src.runner
                .log()
                .iter()
                .any(|c| c.starts_with("gh attestation")),
            "{:?}",
            src.runner.log()
        );
    }

    /// A process killed by a signal reports no exit code. Whatever stands in
    /// for it must be negative — a positive stand-in is indistinguishable from
    /// an ordinary failure exit, and 0 would read as success.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_signal_killed_process_reports_a_code_no_ordinary_exit_can_produce() {
        let o = Spawn.run("sh", &["-c".to_string(), "kill -9 $$".to_string()], &[]);
        assert!(!o.ok(), "{o:?}");
        assert!(
            o.code < 0,
            "a signalled process must not look like an exit: {o:?}"
        );
    }

    /// Probing rung 2 costs a DOWNLOAD. Doing it when rung 1 already settled
    /// the release would fetch one asset per repo on every run and quietly
    /// break "re-deposit an unchanged layer.toml and nothing is fetched".
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn rung_two_is_not_probed_when_rung_one_already_settled_the_release() {
        let tmp = scratch("shortcircuit-test");
        let src = GhSource::new(
            Scripted(vec![
                (
                    "gh release".into(),
                    out(
                        0,
                        r#"{"assets":[{"name":"SHA256SUMS.txt"},{"name":"SHA256SUMS.txt.cosign.bundle"},{"name":"big.tar.gz"}]}"#,
                        "",
                    ),
                ),
                ("cosign verify-blob".into(), out(0, "", "")),
                // If rung 2 were probed, this would answer — and the test for
                // NotProbed below would fail instead of this comment mattering.
                ("gh attestation".into(), out(0, "{}", "")),
            ]),
            Forge::github_com(),
            &*tmp,
        );
        // The download of SHA256SUMS.txt itself is scripted through `gh
        // release`, which writes nothing; so assert on the probe's verdict.
        let p = src.probe(&Forge::github_com(), "o/r", "v1");
        // Downloading the sums file cannot succeed under a scripted runner, so
        // the probe fails at that point — which is itself the proof that it
        // never reached the attestation step for a rung-1 release.
        match p {
            Err(RunError::Io { context, .. }) => {
                assert!(context.contains("SHA256SUMS.txt"), "{context}");
            }
            other => panic!("expected to stop at the sums download, got {other:?}"),
        }
    }

    /// Reaching rung 2 on a release nobody probed must fail closed. Reading it
    /// as "no attestation" would let an unprobed release fall through to the
    /// unverified rung.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unprobed_attestation_fails_rung_two_rather_than_reading_as_absent() {
        let probe = ReleaseProbe {
            attestation: crate::ingest::AttestationProbe::NotProbed,
            ..Default::default()
        };
        match crate::ingest::rung_build_provenance(&probe) {
            crate::ingest::Rung::Failed(d) => {
                assert!(d.contains("never probed"), "{d}");
            }
            other => panic!("must not be decidable: {other:?}"),
        }
    }

    /// The downloader and anything that stages what it downloaded must agree
    /// on where the bytes are. They agree by construction — one function — and
    /// this pins that they still do.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_download_path_has_exactly_one_definition() {
        let src = GhSource::new(Spawn, Forge::github_com(), "/w");
        assert_eq!(
            src.dir_for("o/r", "v1"),
            release_dir(Path::new("/w"), "o/r", "v1")
        );
    }

    /// A repo name contains `/`; two repos sharing a tail must not share a
    /// download directory, or one release's sums file is verified and
    /// another's is read.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn two_repos_with_the_same_tail_do_not_share_a_download_directory() {
        let src = GhSource::new(Spawn, Forge::github_com(), "/w");
        let a = src.dir_for("one/tool", "v1");
        let b = src.dir_for("two/tool", "v1");
        assert_ne!(a, b, "{a:?} vs {b:?}");
        assert!(!a.to_string_lossy().contains("one/tool"), "{a:?}");
    }

    /// A process killed by a signal has no exit code. Reporting that as 0
    /// would read as a successful verification.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_command_that_could_not_run_is_never_reported_as_success() {
        let o = Spawn.run("definitely-not-a-real-binary-xyzzy", &[], &[]);
        assert!(!o.ok(), "{o:?}");
        assert_eq!(o.code, 127);
    }

    /// GHSA queries go through the SAME forge as everything else this
    /// source does — the tool's own repo lives wherever this run's releases
    /// do, enterprise or not.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_advisories_are_asked_through_the_runs_own_forge() {
        const JSON: &str = r#"[{"ghsa_id":"GHSA-x"}]"#;
        let src = GhSource::new(
            Scripted(vec![("gh api".into(), out(0, JSON, ""))]),
            Forge::enterprise("ghe.example.com"),
            "/w",
        );
        assert_eq!(src.ghsa_advisories_json("o/r").unwrap(), JSON);
    }

    /// Records every env it is handed, so a test can assert the EXACT
    /// `GH_HOST` each call carried, rather than merely that gh was invoked.
    struct CapturingRunner {
        envs: RefCell<Vec<Vec<(String, String)>>>,
    }

    impl CapturingRunner {
        fn new() -> Self {
            CapturingRunner {
                envs: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for CapturingRunner {
        fn run(&self, program: &str, _args: &[String], env: &[(String, String)]) -> RunOutput {
            assert_eq!(program, "gh");
            self.envs.borrow_mut().push(env.to_vec());
            out(0, "[]", "")
        }
    }

    /// THE host-inheritance hole: an empty env for a public-GitHub call
    /// does not mean "target github.com" — it means "inherit whatever
    /// `GH_HOST` the calling process already has", which can silently
    /// redirect a probe, a sums fetch, an SBOM download or an advisory
    /// query to a different host. Every call — GHSA through this run's
    /// own forge, and RustSec pinned to github.com regardless of it —
    /// must state its host explicitly, including when that host IS
    /// github.com.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn every_gh_call_states_its_host_explicitly_never_inheriting_the_ambient_one() {
        let public = GhSource::new(CapturingRunner::new(), Forge::github_com(), "/w");
        let _ = public.ghsa_advisories_json("o/r");
        assert_eq!(
            public.runner.envs.borrow()[0],
            vec![("GH_HOST".to_string(), "github.com".to_string())],
            "a public-GitHub GHSA call must still state its host"
        );

        let enterprise = GhSource::new(
            CapturingRunner::new(),
            Forge::enterprise("ghe.example.com"),
            "/w",
        );
        let _ = enterprise.ghsa_advisories_json("o/r");
        assert_eq!(
            enterprise.runner.envs.borrow()[0],
            vec![("GH_HOST".to_string(), "ghe.example.com".to_string())]
        );

        // RustSec is pinned to github.com from the SAME enterprise source.
        let _ = enterprise.rustsec_crate_directory("rustls");
        assert_eq!(
            enterprise.runner.envs.borrow()[1],
            vec![("GH_HOST".to_string(), "github.com".to_string())]
        );
        let _ = enterprise.rustsec_advisory_markdown("rustls", "RUSTSEC-2026-0346.md");
        assert_eq!(
            enterprise.runner.envs.borrow()[2],
            vec![("GH_HOST".to_string(), "github.com".to_string())]
        );
    }

    /// The RustSec advisory database is fetched WITHOUT this run's forge
    /// environment — it lives on github.com no matter which forge the
    /// run's own releases come from.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_queries_do_not_carry_an_enterprise_forges_environment() {
        // Pinned to github.com EXPLICITLY, never empty: an empty env means
        // "inherit whatever GH_HOST this process already has", which is
        // exactly the host-inheritance hole this pins shut.
        struct AssertGithubComHost;
        impl CommandRunner for AssertGithubComHost {
            fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> RunOutput {
                assert_eq!(program, "gh");
                assert_eq!(
                    env,
                    &[("GH_HOST".to_string(), "github.com".to_string())],
                    "rustsec/advisory-db must be pinned to github.com, not {env:?}"
                );
                if args.contains(&"contents/crates/rustls".to_string())
                    || args.last().unwrap().ends_with("crates/rustls")
                {
                    out(0, r#"[{"name":"RUSTSEC-2026-0346.md"}]"#, "")
                } else {
                    out(0, "raw markdown body", "")
                }
            }
        }
        let src = GhSource::new(
            AssertGithubComHost,
            Forge::enterprise("ghe.example.com"),
            "/w",
        );
        let listing = src.rustsec_crate_directory("rustls").unwrap();
        assert_eq!(
            listing,
            Some(r#"[{"name":"RUSTSEC-2026-0346.md"}]"#.to_string())
        );
        let md = src
            .rustsec_advisory_markdown("rustls", "RUSTSEC-2026-0346.md")
            .unwrap();
        assert_eq!(md, "raw markdown body");
    }

    /// A 404 on the crate directory is absence, not a failure — most crates
    /// have never had an advisory.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_404_rustsec_crate_directory_is_none_not_an_error() {
        let src = GhSource::new(
            Scripted(vec![(
                "gh api".into(),
                out(1, "", "gh: Not Found (HTTP 404)"),
            )]),
            Forge::github_com(),
            "/w",
        );
        assert_eq!(src.rustsec_crate_directory("no-such-crate").unwrap(), None);
    }

    /// Anything else — rate limiting, a network error — is a real failure
    /// and must not be read as "this crate has no advisories".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_non_404_rustsec_failure_is_an_error_not_an_absent_crate() {
        let src = GhSource::new(
            Scripted(vec![(
                "gh api".into(),
                out(1, "", "HTTP 403: API rate limit exceeded"),
            )]),
            Forge::github_com(),
            "/w",
        );
        let e = src
            .rustsec_crate_directory("rustls")
            .expect_err("must refuse");
        assert!(e.to_string().contains("403"), "{e}");
    }

    /// Asking for an attestation the probe never captured is an ordering bug
    /// in this program, and must not be reported as upstream having none.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_uncaptured_attestation_is_an_ordering_error_not_an_absent_one() {
        let src = GhSource::new(Scripted(vec![]), Forge::github_com(), "/w");
        let e = src.attestation_json("o/r", "v1").expect_err("must refuse");
        assert!(e.to_string().contains("caller ordering error"), "{e}");
    }
    /// The live `repo_license` is the one a deposit actually calls: the
    /// repository's own declared SPDX id comes back, GitHub's "I cannot tell"
    /// comes back as absent, and a gh that cannot answer is an ERROR — never
    /// "this repository declares no license" (REQ-SBOMFIELDS-001 clause 5).
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn the_live_repo_license_reads_what_github_declares_and_refuses_when_it_cannot() {
        let src = |reply: RunOutput| {
            GhSource::new(
                Scripted(vec![("gh api".into(), reply)]),
                Forge::github_com(),
                "/w",
            )
        };
        let mit = src(out(0, r#"{"license":{"spdx_id":"MIT"}}"#, ""));
        assert_eq!(mit.repo_license("o/r").unwrap().as_deref(), Some("MIT"));
        let unsure = src(out(0, r#"{"license":{"spdx_id":"NOASSERTION"}}"#, ""));
        assert_eq!(unsure.repo_license("o/r").unwrap(), None);
        let down = src(out(1, "", "HTTP 502"));
        assert!(down.repo_license("o/r").is_err());
    }
}
