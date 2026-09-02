//! Assembling a deposit spec end to end (REQ-PRODUCER-002).
//!
//! plan → verify → stage → describe. This module holds the description step
//! and the wiring; the steps it calls are each tested on their own.
//!
//! ## What this module will not guess
//!
//! Carry-forward asks whether the registry already holds a blob. This program
//! cannot know that without asking the registry, and a default of "yes" would
//! skip a fetch for bytes that are not there — producing a manifest pointing
//! at a digest nothing can serve. So the answer is an INPUT. When it is not
//! supplied, every payload is fetched: slower, and correct.

use crate::binfmt;
use crate::carryforward::PreviousEntry;
use crate::gh::CommandRunner;
use crate::orchestrate::{Resolved, RunError};
use crate::plan::PayloadKind;
use crate::spec::{SourceOut, SpecOut, ToolOut};
use crate::stage;
use std::collections::BTreeMap;
use std::path::Path;

/// Previous entries, keyed by payload name, read from a spec this assembler
/// wrote last time.
pub fn previous_from_spec(text: &str) -> anyhow::Result<BTreeMap<String, PreviousEntry>> {
    // `deny_unknown_fields` is the guard, not a formality. Without it a spec
    // whose sections are named anything else parses cleanly to an empty
    // history — which is indistinguishable from a first run, so every payload
    // is silently re-fetched forever. That is precisely the bug this reader
    // shipped with until a live deposit exposed it.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Prev {
        #[allow(dead_code)]
        layer: String,
        #[allow(dead_code)]
        channel: String,
        #[allow(dead_code)]
        counter: u64,
        #[serde(rename = "include", default)]
        #[allow(dead_code)]
        includes: Vec<toml::Value>,
        // `tool`, not `tools`: SpecOut serialises the field under that name.
        // Reading a key the writer never emits yields an empty history that
        // looks exactly like a first run — every payload re-fetched, silently,
        // for as long as nobody times the job. A live run is what caught it;
        // the unit test below round-trips through the real writer so the two
        // cannot drift apart again.
        #[serde(rename = "tool", default)]
        tools: Vec<PrevTool>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PrevTool {
        #[allow(dead_code)]
        version: String,
        #[allow(dead_code)]
        path: String,
        #[serde(default)]
        #[allow(dead_code)]
        kind: Option<String>,
        name: String,
        platform: Option<String>,
        source: PrevSource,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PrevSource {
        #[serde(rename = "proof", default)]
        #[allow(dead_code)]
        proof: Option<String>,
        #[serde(rename = "proof-signer", default)]
        #[allow(dead_code)]
        proof_signer: Option<String>,
        #[serde(rename = "proof-asserts", default)]
        #[allow(dead_code)]
        proof_asserts: Option<String>,
        repo: String,
        release: String,
        asset: String,
        sha256: String,
    }
    let doc: Prev = toml::from_str(text)?;
    let mut out = BTreeMap::new();
    for t in doc.tools {
        // Keyed the way the plan names payloads: one entry per platform, or a
        // bare name where there is no platform. Keying by name alone would let
        // one platform's record answer for another's.
        let key = match &t.platform {
            Some(p) => format!("{}@{p}", t.name),
            None => t.name.clone(),
        };
        out.insert(
            key,
            PreviousEntry {
                repo: t.source.repo,
                release: t.source.release,
                asset: t.source.asset,
                sha256: t.source.sha256,
            },
        );
    }
    Ok(out)
}

/// The key a payload is remembered under between runs.
pub fn payload_key(name: &str, platform: Option<&str>) -> String {
    match platform {
        Some(p) => format!("{name}@{p}"),
        None => name.to_string(),
    }
}

/// Stage one resolved payload and describe it.
pub fn stage_one<R: CommandRunner>(
    runner: &R,
    r: &Resolved,
    version: &str,
    stage_root: &Path,
    downloads: &Path,
    scratch: &Path,
    binary_name: &str,
) -> anyhow::Result<ToolOut> {
    let rel = stage::staged_path(
        r.plan.kind,
        binary_name,
        version,
        r.plan.platform.as_deref(),
    );
    let dest = stage_root.join(&rel);
    let archive = downloads.join(&r.plan.asset);

    match r.plan.kind {
        PayloadKind::Tarball => {
            let ex = scratch.join(format!(
                "{}-{}",
                r.plan.name,
                r.plan.platform.as_deref().unwrap_or("any")
            ));
            let bin = stage::extract_binary(runner, &r.plan.asset, &archive, &ex, binary_name)?;
            stage::place(&bin, &dest, true)?;
        }
        PayloadKind::RawPerPlatform => stage::place(&archive, &dest, true)?,
        // Never unpacked: the extension IS the payload.
        PayloadKind::Vsix => stage::place(&archive, &dest, false)?,
    }

    // The architecture check reads the staged file, not the archive — what
    // gets deposited is what gets checked. A tool filed under the wrong
    // platform installs cleanly and fails on first use, on someone else's
    // machine.
    if let Some(platform) = r.plan.platform.as_deref()
        && r.plan.kind != PayloadKind::Vsix
    {
        let bytes = std::fs::read(&dest)?;
        binfmt::check_platform(&rel, &bytes, platform)?;
    }

    Ok(ToolOut {
        name: binary_name.to_string(),
        version: version.to_string(),
        platform: r.plan.platform.clone(),
        path: rel,
        kind: match r.plan.kind {
            PayloadKind::Vsix => Some("vsix".to_string()),
            _ => None,
        },
        source: SourceOut {
            repo: r.plan.repo.clone(),
            release: r.plan.version.clone(),
            asset: r.plan.asset.clone(),
            sha256: r.digest.clone(),
            proof: Some(r.accepted.mechanism.as_str().to_string()),
            proof_signer: Some(r.accepted.signer.clone()),
            proof_asserts: Some(r.accepted.asserts.clone()),
        },
    })
}

/// Digests the registry is known to hold, one per line.
///
/// Absent means "we do not know", which is treated as "not present" — every
/// payload is fetched. Treating not-known as present would let a run skip a
/// fetch for bytes nobody has, and publish a manifest pointing at a digest the
/// registry cannot serve.
pub fn parse_present_digests(text: &str) -> std::collections::BTreeSet<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_start_matches("sha256:").to_ascii_lowercase())
        .collect()
}

/// Fold resolved payloads into a spec.
pub fn describe(layer: &str, channel: &str, counter: u64, tools: Vec<ToolOut>) -> SpecOut {
    let mut s = SpecOut::new(layer, channel, counter);
    s.tools = tools;
    s
}

/// Report a payload that was planned but had no build, so an operator sees the
/// gap rather than inferring it from a shorter list.
pub fn omitted(planned: &[crate::plan::PayloadPlan], resolved: &[Resolved]) -> Vec<String> {
    let got: std::collections::BTreeSet<(String, String)> = resolved
        .iter()
        .map(|r| (r.plan.name.clone(), r.plan.asset.clone()))
        .collect();
    planned
        .iter()
        .filter(|p| !got.contains(&(p.name.clone(), p.asset.clone())))
        .map(|p| {
            format!(
                "{} has no {} build — the layer omits it there",
                p.name,
                p.platform.as_deref().unwrap_or("(no platform)")
            )
        })
        .collect()
}

impl From<crate::stage::StageError> for RunError {
    fn from(e: crate::stage::StageError) -> Self {
        RunError::Io {
            context: "staging".into(),
            detail: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::gh::RunOutput;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("varve-deposit-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    /// A minimal ELF header the arch check can read: x86_64 or aarch64.
    fn elf(machine: u16) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        v[4] = 2; // 64-bit
        v[5] = 1; // little-endian
        v[18..20].copy_from_slice(&machine.to_le_bytes());
        v
    }

    struct Unpacker;
    impl CommandRunner for Unpacker {
        fn run(&self, _p: &str, args: &[String], _e: &[(String, String)]) -> RunOutput {
            let dest = args
                .iter()
                .position(|a| a == "-C")
                .and_then(|i| args.get(i + 1))
                .expect("-C");
            let bin = Path::new(dest).join("rivet");
            std::fs::write(&bin, elf(0x3E)).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            RunOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    }

    fn resolved(kind: PayloadKind, asset: &str, platform: Option<&str>) -> Resolved {
        Resolved {
            plan: crate::plan::PayloadPlan {
                name: "rivet".into(),
                repo: "o/r".into(),
                version: "v0.34.0".into(),
                asset: asset.into(),
                platform: platform.map(str::to_string),
                kind,
                unverified_reason: None,
            },
            digest: "d".into(),
            accepted: crate::ingest::Accepted {
                mechanism: crate::ingest::Mechanism::CosignSums,
                signer: "s".into(),
                asserts: "a".into(),
            },
            bytes: None,
            decision: crate::carryforward::Decision::Fetch {
                why: crate::carryforward::FetchReason::NoPrevious,
            },
        }
    }

    /// The architecture check reads the STAGED file, and a payload filed under
    /// the wrong platform installs cleanly and fails on someone else's machine.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_binary_whose_architecture_contradicts_its_platform_is_refused() {
        let root = scratch("archmismatch");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        std::fs::write(dl.join("rivet-linux.tar.gz"), b"archive").unwrap();
        let r = resolved(
            PayloadKind::Tarball,
            "rivet-linux.tar.gz",
            // The archive yields an x86_64 ELF; file it under aarch64.
            Some("aarch64-unknown-linux-gnu"),
        );
        let e = stage_one(
            &Unpacker,
            &r,
            "0.34.0",
            &root,
            &dl,
            &root.join("extract"),
            "rivet",
        )
        .expect_err("must refuse");
        let msg = e.to_string();
        assert!(msg.contains("aarch64") || msg.contains("x86_64"), "{msg}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_matching_binary_is_staged_and_described() {
        let root = scratch("archok");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        std::fs::write(dl.join("rivet-linux.tar.gz"), b"archive").unwrap();
        let r = resolved(
            PayloadKind::Tarball,
            "rivet-linux.tar.gz",
            Some("x86_64-unknown-linux-gnu"),
        );
        let t = stage_one(
            &Unpacker,
            &r,
            "0.34.0",
            &root,
            &dl,
            &root.join("extract"),
            "rivet",
        )
        .expect("stages");
        assert_eq!(t.path, "tools/rivet-x86_64-unknown-linux-gnu");
        assert_eq!(t.kind, None, "a tool must not be labelled a vsix");
        assert!(root.join(&t.path).exists());
        assert_eq!(t.source.proof.as_deref(), Some("cosign-sums"));
    }

    /// A vsix is a zip. Arch-checking one would refuse every extension the
    /// layer carries; the check must apply to binaries and only to binaries.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_vsix_is_labelled_as_one_and_not_arch_checked() {
        let root = scratch("vsix");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        // Zip bytes: an architecture check would reject these outright.
        std::fs::write(dl.join("ext.vsix"), b"PK\x03\x04 not a binary at all").unwrap();
        let mut r = resolved(PayloadKind::Vsix, "ext.vsix", Some("linux-x64"));
        r.plan.name = "ext".into();
        let t = stage_one(
            &Unpacker,
            &r,
            "1.0.0",
            &root,
            &dl,
            &root.join("extract"),
            "ext",
        )
        .expect("a vsix is not arch-checked");
        assert_eq!(
            t.kind.as_deref(),
            Some("vsix"),
            "an extension must be labelled one"
        );
        assert!(
            t.path.starts_with("vsix/") && t.path.ends_with(".vsix"),
            "{}",
            t.path
        );
        assert!(root.join(&t.path).exists());
    }

    /// A raw per-platform asset IS the binary — no unpacking, but still checked.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_raw_per_platform_asset_is_staged_directly_and_still_arch_checked() {
        let root = scratch("raw");
        let dl = root.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        std::fs::write(dl.join("wsc-aarch64"), elf(0xB7)).unwrap();
        let mut r = resolved(
            PayloadKind::RawPerPlatform,
            "wsc-aarch64",
            Some("aarch64-unknown-linux-gnu"),
        );
        r.plan.name = "wsc".into();
        let t = stage_one(
            &Unpacker,
            &r,
            "0.6.0",
            &root,
            &dl,
            &root.join("extract"),
            "wsc",
        )
        .expect("stages");
        assert_eq!(t.path, "tools/wsc-aarch64-unknown-linux-gnu");
        assert_eq!(t.kind, None);

        // And the same asset filed under the wrong platform is refused.
        let mut bad = r.clone();
        bad.plan.platform = Some("x86_64-unknown-linux-gnu".into());
        assert!(
            stage_one(
                &Unpacker,
                &bad,
                "0.6.0",
                &root,
                &dl,
                &root.join("extract"),
                "wsc"
            )
            .is_err(),
            "a raw asset must be arch-checked too"
        );
    }

    fn spec_with_two_platforms() -> String {
        let src = |asset: &str, sha: &str| SourceOut {
            repo: "pulseengine/rivet".into(),
            release: "v0.34.0".into(),
            asset: asset.into(),
            sha256: sha.into(),
            proof: Some("cosign-sums".into()),
            proof_signer: Some("https://github.com/pulseengine/rivet/".into()),
            proof_asserts: Some("signed".into()),
        };
        let tool = |platform: &str, asset: &str, sha: &str| ToolOut {
            name: "rivet".into(),
            version: "0.34.0".into(),
            platform: Some(platform.into()),
            path: format!("tools/rivet-{platform}"),
            kind: None,
            source: src(asset, sha),
        };
        describe(
            "2026.09.1",
            "rolling",
            7,
            vec![
                tool(
                    "x86_64-unknown-linux-gnu",
                    "rivet-v0.34.0-x86_64-unknown-linux-gnu.tar.gz",
                    "aaaa",
                ),
                tool(
                    "aarch64-apple-darwin",
                    "rivet-v0.34.0-aarch64-apple-darwin.tar.gz",
                    "bbbb",
                ),
            ],
        )
        .render()
        .expect("the writer produces a valid spec")
    }

    /// Round-tripped through the REAL writer, deliberately.
    ///
    /// The first version of this test hand-wrote its TOML with `[[tools]]`,
    /// while SpecOut serialises `[[tool]]`. It passed, and the reader silently
    /// returned an empty history for every real spec — which looks exactly
    /// like a first run, so every payload was re-fetched and nothing failed.
    /// A live deposit caught it. A fixture the writer never produces tests the
    /// fixture, not the program.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_spec_this_program_wrote_is_a_spec_this_program_can_read_back() {
        let text = spec_with_two_platforms();
        assert!(
            text.contains("[[tool]]"),
            "the writer changed shape: {text}"
        );
        let prev = previous_from_spec(&text).expect("parses");
        assert_eq!(
            prev.len(),
            2,
            "read {} entries back from {text}",
            prev.len()
        );
        assert_eq!(prev["rivet@x86_64-unknown-linux-gnu"].sha256, "aaaa");
        assert_eq!(prev["rivet@aarch64-apple-darwin"].sha256, "bbbb");
        assert_eq!(prev["rivet@aarch64-apple-darwin"].repo, "pulseengine/rivet");
        assert_eq!(prev["rivet@aarch64-apple-darwin"].release, "v0.34.0");
    }

    /// One layer carries the same tool for four platforms, so a previous-entry
    /// map keyed by name alone would let one platform's record answer for
    /// another's and carry a linux digest forward as a darwin payload.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn previous_entries_are_remembered_per_platform_not_per_tool() {
        let prev = previous_from_spec(&spec_with_two_platforms()).expect("parses");
        assert_ne!(
            prev["rivet@x86_64-unknown-linux-gnu"].sha256,
            prev["rivet@aarch64-apple-darwin"].sha256
        );
    }

    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn a_payload_with_no_platform_is_keyed_by_its_bare_name() {
        assert_eq!(payload_key("ext", None), "ext");
        assert_eq!(payload_key("ext", Some("linux-x64")), "ext@linux-x64");
        assert_ne!(
            payload_key("ext", None),
            payload_key("ext", Some("linux-x64"))
        );
    }

    /// "We do not know what the registry holds" must read as "not present".
    /// The other way round skips a fetch for bytes nobody has, and publishes a
    /// manifest pointing at a digest the registry cannot serve.
    // rivet: verifies REQ-CARRYFORWARD-001
    #[test]
    fn an_unknown_registry_state_means_fetch_rather_than_assume() {
        assert!(parse_present_digests("").is_empty());
        assert!(parse_present_digests("# nothing but a comment\n\n").is_empty());
        let s = parse_present_digests("sha256:AAAA\n bbbb \n# c\n");
        assert!(s.contains("aaaa"), "{s:?}");
        assert!(s.contains("bbbb"), "{s:?}");
        assert_eq!(s.len(), 2, "{s:?}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_previous_spec_that_cannot_be_read_is_an_error_not_an_empty_history() {
        // An empty history silently re-fetches everything, which is safe. A
        // MISREAD history is not: it would answer carry-forward questions with
        // whatever survived the parse.
        assert!(previous_from_spec("this is not toml {{{").is_err());
        // A section this program does not write must be an ERROR, not an
        // empty history: an empty history is indistinguishable from a first
        // run, so the mistake shows up as permanent silent re-fetching rather
        // than as a failure.
        let wrong_name = previous_from_spec(
            "layer = \"x\"\nchannel = \"c\"\ncounter = 1\n[[tools]]\nname = \"x\"\n",
        );
        assert!(
            wrong_name.is_err(),
            "a misnamed section parsed as an empty history"
        );
        // And a spec missing the fields carry-forward needs is an error too.
        assert!(previous_from_spec("layer = \"x\"\n").is_err());
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn planned_payloads_that_had_no_build_are_reported_by_name() {
        let p = |name: &str, plat: &str, asset: &str| crate::plan::PayloadPlan {
            name: name.into(),
            repo: "o/r".into(),
            version: "v1".into(),
            asset: asset.into(),
            platform: Some(plat.into()),
            kind: PayloadKind::Tarball,
            unverified_reason: None,
        };
        let planned = vec![p("loom", "linux", "a"), p("loom", "darwin", "b")];
        let resolved = vec![Resolved {
            plan: planned[0].clone(),
            digest: "d".into(),
            accepted: crate::ingest::Accepted {
                mechanism: crate::ingest::Mechanism::CosignSums,
                signer: "s".into(),
                asserts: "a".into(),
            },
            bytes: None,
            decision: crate::carryforward::Decision::Fetch {
                why: crate::carryforward::FetchReason::NoPrevious,
            },
        }];
        let msgs = omitted(&planned, &resolved);
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        assert!(
            msgs[0].contains("loom") && msgs[0].contains("darwin"),
            "{msgs:?}"
        );
    }
}
