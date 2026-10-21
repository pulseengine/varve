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
                &forge.identity_prefix(repo),
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
                &ReleaseProbe {
                    published: Vec::new(),
                    has_sums,
                    has_cosign_bundle,
                    cosign: cosign.clone(),
                    attestation: crate::ingest::AttestationProbe::NotProbed,
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
        let tmp = std::env::temp_dir().join("varve-producer-probe-test");
        let src = GhSource::new(
            Scripted(vec![("gh release".into(), out(0, r#"{"assets":[]}"#, ""))]),
            Forge::github_com(),
            &tmp,
        );
        let p = src
            .probe(&Forge::github_com(), "o/r", "v1")
            .expect("probes");
        assert!(!p.has_sums && !p.has_cosign_bundle);
        // None, not Some(Err(...)): never run, rather than run and failed.
        assert!(p.cosign.is_none(), "{:?}", p.cosign);
        assert_eq!(p.attestation, crate::ingest::AttestationProbe::NotAttested);
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("varve-producer-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        d
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
        let src = GhSource::new(gh, Forge::github_com(), &dir);
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
            let src = GhSource::new(gh, Forge::github_com(), &dir);
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
        let src = GhSource::new(gh, Forge::github_com(), &dir);

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
        let src = GhSource::new(gh, Forge::github_com(), &dir);

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
        let src = GhSource::new(gh, Forge::github_com(), &dir);
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
        let src = GhSource::new(gh, Forge::github_com(), &dir);
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
        let tmp = std::env::temp_dir().join("varve-producer-shortcircuit-test");
        let _ = std::fs::remove_dir_all(&tmp);
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
            &tmp,
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
