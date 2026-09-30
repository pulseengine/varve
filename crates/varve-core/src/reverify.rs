//! Re-verification of an installed layer (REQ-VERIFY-001) — `varve verify`.
//!
//! The install-time verdict, repeatable forever after: the retained envelope
//! must verify against the trust root, its payload must be byte-identical to
//! the layer.json in the core, and every tool binary must match its digest in
//! the signed manifest. Corruption, tampering, and bit-rot all surface as the
//! same loud failure — and "I cannot check" (no envelope retained) is its own
//! distinct verdict, never silently treated as success.

use crate::install::{ManifestVerifier, VerifyError};
use crate::manifest::{LayerManifest, ManifestError};
use crate::store::{InstalledLayer, Store, StoreError};

/// The file the install pipeline retains alongside `layer.json` so the
/// signature verdict stays reproducible offline.
pub const ENVELOPE_FILE: &str = "layer.dsse.json";

#[derive(Debug, thiserror::Error)]
pub enum ReverifyError {
    #[error(
        "layer {digest} has no retained signature envelope ({ENVELOPE_FILE}) — cannot re-verify \
         its signature; reinstall from a signed source"
    )]
    NoEnvelope { digest: String },
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(
        "retained envelope verifies, but its payload does not match layer.json — the core entry \
         was modified after install"
    )]
    PayloadMismatch,
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("payload '{tool}' is missing from the installed layer")]
    MissingTool { tool: String },
    /// The platform filter matched nothing, so nothing was checked.
    ///
    /// Reported as a REFUSAL because the alternative is that "this layer
    /// carries no payload for your platform" and "every payload of this layer
    /// is intact" are the same answer. A verification that checked nothing is
    /// not a verification, and it is the cheapest thing to arrange: it needs
    /// no altered bytes, only a platform nothing matches (varve#189).
    #[error(
        "verified nothing: layer {layer} carries {available} payload(s), none of them for \
         platform '{platform}'. It carries: {carried}. If this layer was installed for \
         another platform, verify it for that one."
    )]
    NothingToVerify {
        layer: String,
        platform: String,
        available: usize,
        carried: String,
    },
    #[error("payload '{tool}' does not match its signed digest {digest} — its bytes were altered")]
    ToolDigestMismatch { tool: String, digest: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// How to name a payload in a verdict. A layer may hold several versions of one
/// name, so the bare name no longer identifies WHICH payload failed — and a
/// verification tool that cannot say which artifact is wrong has not reported
/// the fault (REQ-STORE-002 clause 4).
fn named(entry: &crate::manifest::ManifestEntry, name: &str) -> String {
    match crate::store::entry_version(entry) {
        Some(version) => format!("{name}@{version}"),
        None => name.to_string(),
    }
}

/// Where `verify` spent its time (REQ-VERIFYSTREAM-001 clause 2).
///
/// Attributed by stage so the NEXT change is chosen from a measurement. The
/// report that started this (varve#141: ~9 s on a layer with a 2 GB SDK) was
/// answered once with a guess about parallelising the hash, and the arithmetic
/// said the hash could not be the cost. This is what settles such a question.
///
/// No `decompress` stage exists because verify does not decompress: a payload
/// is hashed exactly as signed, which is what keeps the digest re-derivable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyTiming {
    /// Verifying the retained DSSE envelope against the trust root.
    pub signature: std::time::Duration,
    /// Reading and parsing `layer.json`, and comparing it with the payload.
    pub manifest: std::time::Duration,
    /// The payloads: read and hash, summed, with the total bytes.
    pub payloads: crate::store::StageTiming,
    /// How many payloads were digested — the denominator for a per-payload rate.
    pub checked: usize,
}

/// Re-verify one installed layer against the trust root. Returns the number
/// of tool binaries checked.
pub fn verify_installed(
    store: &Store,
    layer: &InstalledLayer,
    verifier: &dyn ManifestVerifier,
    platform: &str,
) -> Result<usize, ReverifyError> {
    verify_installed_timed(store, layer, verifier, platform).map(|(checked, _)| checked)
}

/// [`verify_installed`], reporting where the time went.
///
/// The timing rides on the real verification path — the same function every
/// caller uses — because a number measured by a separate copy of the code is a
/// number about the copy.
pub fn verify_installed_timed(
    store: &Store,
    layer: &InstalledLayer,
    verifier: &dyn ManifestVerifier,
    platform: &str,
) -> Result<(usize, VerifyTiming), ReverifyError> {
    let mut timing = VerifyTiming::default();
    let io = |path: &std::path::Path, source: std::io::Error| ReverifyError::Io {
        path: path.display().to_string(),
        source,
    };

    // 1. The retained envelope must exist and verify against the trust root.
    let envelope_path = layer.root.join(ENVELOPE_FILE);
    let envelope = match std::fs::read(&envelope_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReverifyError::NoEnvelope {
                digest: layer.digest.clone(),
            });
        }
        Err(e) => return Err(io(&envelope_path, e)),
    };
    let t = std::time::Instant::now();
    let payload = verifier.verify(&envelope)?;
    timing.signature = t.elapsed();

    // 2. The verified payload must be byte-identical to the stored manifest.
    let t = std::time::Instant::now();
    let manifest_path = layer.root.join("layer.json");
    let stored = std::fs::read(&manifest_path).map_err(|e| io(&manifest_path, e))?;
    if payload != stored {
        return Err(ReverifyError::PayloadMismatch);
    }

    // 3. Every tool the signed manifest names must be present and unaltered.
    let manifest = LayerManifest::parse(&payload)?;
    timing.manifest = t.elapsed();
    let mut checked = 0;
    for entry in &manifest.entries {
        if !crate::platform::entry_matches(
            entry
                .annotations
                .get(crate::platform::ANN_PLATFORM)
                .map(String::as_str),
            platform,
        ) {
            continue;
        }
        // A composed layer is a REFERENCE to another layer's manifest, not a
        // blob laid down here; install skips it and so must re-verification.
        if entry.kind() == Ok(crate::kind::PayloadKind::Layer) {
            continue;
        }
        let Some(tool) = entry.annotations.get("eu.pulseengine.tool") else {
            continue;
        };
        // Locate by ENTRY, not by name: several versions of one name coexist,
        // and each must be checked against its own signed digest
        // (REQ-STORE-002 clause 4).
        let Some(path) = store.entry_path(layer, entry) else {
            return Err(ReverifyError::MissingTool {
                tool: named(entry, tool),
            });
        };
        // Streamed, in bounded memory (REQ-VERIFYSTREAM-001). The bytes are
        // only ever needed to HASH here, so reading a 2 GB SDK whole to do it
        // was a 2 GB allocation per payload for nothing (varve#141).
        let (found, stage) = crate::store::digest_file_timed(&path).map_err(|e| io(&path, e))?;
        timing.payloads.add(stage);
        if found != entry.digest {
            return Err(ReverifyError::ToolDigestMismatch {
                tool: named(entry, tool),
                digest: entry.digest.clone(),
            });
        }
        checked += 1;
    }
    // A platform filter that matched nothing must not read as success.
    // `checked == 0` is only acceptable when the layer genuinely has no
    // payloads at all — a composition-only layer, which install already
    // learned to accept (REQ-COMPOSE-001).
    let payload_entries = manifest
        .entries
        .iter()
        .filter(|e| e.kind() != Ok(crate::kind::PayloadKind::Layer))
        .count();
    if checked == 0 && payload_entries > 0 {
        let mut carried: Vec<&str> = manifest
            .entries
            .iter()
            .filter(|e| e.kind() != Ok(crate::kind::PayloadKind::Layer))
            .map(|e| {
                e.annotations
                    .get(crate::platform::ANN_PLATFORM)
                    .map(String::as_str)
                    .unwrap_or("any")
            })
            .collect();
        carried.sort_unstable();
        carried.dedup();
        return Err(ReverifyError::NothingToVerify {
            layer: layer.layer.to_string(),
            platform: platform.to_string(),
            available: payload_entries,
            carried: carried.join(", "),
        });
    }
    timing.checked = checked;
    Ok((checked, timing))
}

#[cfg(test)]
mod tests {
    /// True when mode 000 does not actually deny a read here (running as root,
    /// or a filesystem that ignores permission bits) — so the unreadable-file
    /// tests cannot hold their premise and must skip rather than fail.
    #[cfg(unix)]
    fn premise_unavailable() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let Ok(dir) = tempfile::tempdir() else {
            return true;
        };
        let probe = dir.path().join("probe");
        if std::fs::write(&probe, b"x").is_err() {
            return true;
        }
        if std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).is_err() {
            return true;
        }
        let readable = std::fs::read(&probe).is_ok();
        let _ = std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o644));
        readable
    }

    use super::*;
    use crate::install::{InstallPolicy, install};
    use crate::manifest::fixtures::manifest_with_tools;
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::MemorySource;
    use crate::store::manifest_digest;
    use crate::verify::{PinnedKeyVerifier, generate_root_keypair, sign_layer_manifest};

    struct Installed {
        _tmp: tempfile::TempDir,
        store: Store,
        layer: InstalledLayer,
        verifier: PinnedKeyVerifier,
    }

    fn installed_layer() -> Installed {
        let (sk, pk) = generate_root_keypair();
        let synth = b"synth-bytes".to_vec();
        let blob_digest = manifest_digest(&synth);
        let payload = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blob_digest)],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&blob_digest, &synth);
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        Installed {
            _tmp: tmp,
            store,
            layer,
            verifier,
        }
    }

    /// A layer installed FOR one platform, as `--platform` produces.
    fn installed_for(install_platform: &str) -> Installed {
        let (sk, pk) = generate_root_keypair();
        let linux = b"wac-linux-bytes".to_vec();
        let mac = b"wac-darwin-bytes".to_vec();
        let (dl, dm) = (manifest_digest(&linux), manifest_digest(&mac));
        let payload = crate::manifest::fixtures::manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("wac", &dl, Some("x86_64-unknown-linux-gnu")),
                ("wac", &dm, Some("aarch64-apple-darwin")),
            ],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&dl, &linux)
            .with_blob(&dm, &mac);
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: install_platform,
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        Installed {
            _tmp: tmp,
            store,
            layer,
            verifier,
        }
    }

    /// A composition-only layer checks zero payloads and that is CORRECT.
    ///
    /// The refusal added for varve#189 keys on `payload_entries > 0`, and a
    /// mutant weakening that to `>= 0` survived: nothing distinguished "this
    /// layer has payloads and none matched" from "this layer has no payloads
    /// at all". The second is a whole supported layer kind — `install`
    /// learned it at REQ-COMPOSE-001 and refusing it here would break every
    /// composition-only pin.
    // rivet: verifies REQ-COMPOSE-001
    #[test]
    fn a_composition_only_layer_verifies_although_it_checks_nothing() {
        let (sk, pk) = generate_root_keypair();
        let payload = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
 "artifactType":"application/vnd.pulseengine.varve.layer.v1+json",
 "annotations":{{"eu.pulseengine.varve.layer":"2026.07.0",
 "eu.pulseengine.varve.line":"2026.07","eu.pulseengine.varve.channel":"qualified",
 "eu.pulseengine.varve.counter":"1",
 "org.opencontainers.image.created":"2026-07-31T09:14:00Z"}},
 "manifests":[{{"digest":"sha256:{d}","size":0,
 "annotations":{{"{k}":"layer","eu.pulseengine.varve.include.realm":"other"}}}}]}}"#,
            d = "0".repeat(64),
            k = crate::kind::ANN_KIND,
        )
        .into_bytes();
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new().with_manifest(envelope.as_bytes());
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "x86_64-unknown-linux-gnu",
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        let checked = verify_installed(&store, &layer, &verifier, "x86_64-unknown-linux-gnu")
            .expect("a composition-only layer must verify, not be refused for checking nothing");
        assert_eq!(checked, 0, "it has no payloads of its own to check");
    }

    /// The refusal has to name the platforms the layer ACTUALLY carries.
    ///
    /// Without this, a mutant inverting the filter that builds that list
    /// survived: the message would have listed the composition edges instead
    /// of the payloads, and an operator would be told to try a platform the
    /// layer has nothing for.
    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn the_refusal_names_the_platforms_the_layer_does_carry() {
        let i = installed_for("x86_64-unknown-linux-gnu");
        let err = verify_installed(
            &i.store,
            &i.layer,
            &i.verifier,
            "riscv64gc-unknown-linux-gnu",
        )
        .unwrap_err();
        let msg = err.to_string();
        for expected in ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"] {
            assert!(
                msg.contains(expected),
                "the refusal does not name {expected}, which this layer carries: {msg}"
            );
        }
        assert!(msg.contains("riscv64gc-unknown-linux-gnu"), "{msg}");
    }

    /// varve#189: a layer installed FOR another platform verifies, and is
    /// not accused of tampering.
    ///
    /// Reported from a Mac installing a Linux toolchain — legitimate, and the
    /// thing `--platform` exists for. `verify` resolved the HOST, matched the
    /// darwin entry, hashed the linux bytes that were actually laid down, and
    /// said "its bytes were altered". The bytes were exactly what was signed;
    /// the platform was the wrong question. Install records which platform it
    /// chose, and verify asks that instead of the host.
    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_layer_installed_for_another_platform_verifies_against_that_platform() {
        let i = installed_for("x86_64-unknown-linux-gnu");
        assert_eq!(
            i.layer.platform.as_deref(),
            Some("x86_64-unknown-linux-gnu"),
            "install did not record the platform it selected payloads for"
        );
        let plat = i.layer.platform.clone().unwrap();
        let checked = verify_installed(&i.store, &i.layer, &i.verifier, &plat)
            .expect("a layer installed for another platform must verify");
        assert_eq!(checked, 1, "the linux payload was not the one checked");
    }

    /// The exact false accusation varve#189 reported, pinned so it cannot
    /// come back: asking about the HOST names bytes that were never there.
    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn asking_the_wrong_platform_is_what_produced_the_false_tamper_claim() {
        let i = installed_for("x86_64-unknown-linux-gnu");
        let out = verify_installed(&i.store, &i.layer, &i.verifier, "aarch64-apple-darwin");
        assert!(
            matches!(out, Err(ReverifyError::MissingTool { .. }))
                || matches!(out, Err(ReverifyError::ToolDigestMismatch { .. })),
            "expected the host-platform question to fail; got {out:?}"
        );
        // …and the recorded platform is what saves the caller from asking it.
        assert_eq!(
            i.layer.platform.as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
    }

    /// Verifying against a platform the layer carries NOTHING for must refuse.
    ///
    /// Found while fixing varve#189. `verify_installed` filters entries by
    /// platform and counts what it checked; nothing anywhere refused a count
    /// of zero, so "this layer has no payload for your platform" and "every
    /// payload of this layer is intact" were the same answer — `Ok`. A
    /// verification that checked nothing is not a verification, and it is the
    /// shape an attacker would pick: it needs no bad bytes, only a platform
    /// nothing matches.
    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn verifying_against_a_platform_the_layer_carries_nothing_for_is_refused() {
        let i = installed_for("x86_64-unknown-linux-gnu");
        let out = verify_installed(
            &i.store,
            &i.layer,
            &i.verifier,
            "riscv64gc-unknown-linux-gnu",
        );
        assert!(
            matches!(out, Err(ReverifyError::NothingToVerify { .. })),
            "verifying a layer for a platform it carries nothing for did not refuse: {out:?}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_freshly_installed_layer_reverifies() {
        let ctx = installed_layer();
        let checked =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap();
        assert_eq!(checked, 1);
    }

    /// A signed layer holding TWO versions of one crate, installed.
    fn installed_two_versions() -> (Installed, Vec<u8>, Vec<u8>) {
        use crate::manifest::fixtures::manifest_with_payloads;
        let (sk, pk) = generate_root_keypair();
        let a = b"serde-1.0.200-crate".to_vec();
        let b = b"serde-1.0.210-crate".to_vec();
        let (da, db) = (manifest_digest(&a), manifest_digest(&b));
        let payload = manifest_with_payloads(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("serde", "1.0.200", "crate", &da),
                ("serde", "1.0.210", "crate", &db),
            ],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&da, &a)
            .with_blob(&db, &b);
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        (
            Installed {
                _tmp: tmp,
                store,
                layer,
                verifier,
            },
            a,
            b,
        )
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn each_version_of_one_name_is_checked_against_its_own_signed_digest() {
        // Clause 4, verification half. `verify_installed` looked payloads up by
        // NAME, so with two versions present it would have hashed one file
        // twice — passing the entry whose bytes happened to land and failing
        // the other, with a verdict that named only "serde" and could not say
        // which. Both are checked here, and tampering with EITHER is caught and
        // named with its version.
        let (ctx, a, b) = installed_two_versions();
        assert_eq!(
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap(),
            2,
            "both versions must be checked, not one file twice"
        );
        // The bytes on disk really are each version's own.
        assert_eq!(
            std::fs::read(ctx.layer.root.join("payloads/serde/1.0.200")).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(ctx.layer.root.join("payloads/serde/1.0.210")).unwrap(),
            b
        );

        for (version, path) in [
            ("1.0.200", "payloads/serde/1.0.200"),
            ("1.0.210", "payloads/serde/1.0.210"),
        ] {
            let (ctx, ..) = installed_two_versions();
            std::fs::write(ctx.layer.root.join(path), b"EVIL").unwrap();
            let err = verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform")
                .unwrap_err();
            assert!(
                matches!(&err, ReverifyError::ToolDigestMismatch { tool, .. }
                    if tool == &format!("serde@{version}")),
                "tampering with {version} must be caught AND named: {err}"
            );
        }

        // A payload that is simply gone is named with its version too — with
        // two versions present, "serde is missing" would not say which.
        let (ctx, ..) = installed_two_versions();
        std::fs::remove_file(ctx.layer.root.join("payloads/serde/1.0.210")).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(&err, ReverifyError::MissingTool { tool } if tool == "serde@1.0.210"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn install_retains_the_envelope_for_offline_reverification() {
        let ctx = installed_layer();
        assert!(
            ctx.layer.root.join(ENVELOPE_FILE).is_file(),
            "install must retain the signature envelope"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn an_altered_tool_binary_is_detected() {
        let ctx = installed_layer();
        std::fs::write(ctx.layer.root.join("bin/synth"), b"EVIL").unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(err, ReverifyError::ToolDigestMismatch { ref tool, .. } if tool == "synth"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn an_altered_manifest_payload_is_detected() {
        let ctx = installed_layer();
        let path = ctx.layer.root.join("layer.json");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b" ");
        std::fs::write(&path, bytes).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(matches!(err, ReverifyError::PayloadMismatch), "got: {err}");
    }

    // rivet: verifies REQ-PROOF-001
    #[cfg(unix)]
    #[test]
    fn an_unreadable_envelope_is_an_io_error_not_a_missing_one() {
        // An envelope that EXISTS but cannot be read is not a layer installed
        // without one. Collapsing the two would report "no retained envelope"
        // for what is really a permissions fault — a verification tool must
        // name the fault it actually hit. (Found by cargo-mutants: the
        // NotFound guard survived being replaced with `true`.)
        // chmod(000) does not stop root, and some filesystems ignore modes, so
        // this case cannot always be exercised. Test the PREMISE directly
        // rather than guessing at uid: if an unreadable file is still readable
        // here, skip. A test that cannot hold its premise should say so, not go
        // red for the wrong reason.
        if premise_unavailable() {
            eprintln!("skipping: this environment does not deny reads on mode 000");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let ctx = installed_layer();
        let path = ctx.layer.root.join(ENVELOPE_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        assert!(
            matches!(err, ReverifyError::Io { .. }),
            "an unreadable envelope must be an Io error, got: {err}"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_missing_envelope_is_its_own_loud_verdict() {
        let ctx = installed_layer();
        std::fs::remove_file(ctx.layer.root.join(ENVELOPE_FILE)).unwrap();
        let err =
            verify_installed(&ctx.store, &ctx.layer, &ctx.verifier, "test-platform").unwrap_err();
        assert!(
            matches!(err, ReverifyError::NoEnvelope { .. }),
            "got: {err}"
        );
    }
}
