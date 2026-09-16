//! The consumer API (REQ-CONSUMERAPI-001) — ask varve a question, get an
//! answer that cannot be misread.
//!
//! Consumers reach varve through its CLI: run a command, read an exit code,
//! parse stderr. jess reported four measured failures of that contract in one
//! repository in one day (varve#130), two of them mistakes this repository
//! made in the same week. Every one was a CONSUMPTION failure — the tools
//! behaved correctly and the contract broke:
//!
//! * a gate shelled out to `objcopy`, which printed a format error and wrote
//!   nothing; the value became the empty string, `[ "" -gt N ]` errors AND
//!   evaluates false, both range tests fell through, and the script printed
//!   `ok` and exited 0 — a green verdict on a file it never parsed;
//! * a tool resolved by name picked a stale binary ahead of the shim, so the
//!   failure said `Unknown command: codegen` — naming the subcommand when the
//!   fault was WHICH BINARY;
//! * `cmd | tail` reports tail's status, and a pipeline's exit code was quoted
//!   as a tool's verdict;
//! * `set -e` aborted a script at the very command whose failure was being
//!   measured, so the assertion never ran.
//!
//! The shape they share is that ABSENCE and FAILURE arrive looking alike. This
//! module's whole job is to make them different types.

use std::path::PathBuf;

use crate::install::ManifestVerifier;
use crate::manifest::LayerManifest;
use crate::store::{InstalledLayer, Store, manifest_digest};

/// This crate's version — so a consumer can record which varve answered.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `manifest-version` of a project pin this crate understands.
///
/// Readable as a VALUE, not only as an error string (REQ-CONSUMERAPI-001
/// clause 5). A consumer built once and run for months can compare this
/// against what it meets and record "I met a pin newer than I know" as a fact,
/// rather than meeting it as a parse failure it has to pattern-match on prose.
pub const PIN_MANIFEST_VERSION: i64 = 1;

/// What varve knows about ONE payload, as distinct facts.
///
/// The variants exist so that "I could not find it" and "I found it and it did
/// not verify" cannot be confused. They are opposite facts: the first says
/// nothing about integrity, the second is an integrity failure. A consumer
/// that folds the second into the first fails OPEN — which is exactly what the
/// shell contract did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadStatus {
    /// Present, and its bytes hash to the digest the SIGNED manifest names.
    /// The only variant that asserts anything about integrity.
    Verified {
        name: String,
        path: PathBuf,
        digest: String,
    },
    /// The signed manifest names no payload of this name in this layer.
    /// Says nothing about integrity — nothing was checked.
    AbsentFromLayer {
        name: String,
        layer: String,
        available: Vec<String>,
    },
    /// The manifest names it, but no entry matches this platform. Distinct
    /// from absence: the payload exists in the layer and not for you, which is
    /// a different thing to tell a user and a different thing to fix.
    NoEntryForPlatform {
        name: String,
        layer: String,
        platform: String,
        platforms: Vec<String>,
    },
    /// The signed manifest names it and the store does not hold it. An
    /// incomplete install, not a tampered one.
    MissingFromStore {
        name: String,
        path: PathBuf,
        digest: String,
    },
    /// PRESENT AND WRONG. The bytes on disk do not hash to the signed digest.
    /// Its own variant, never foldable into absence (clause 2).
    DigestMismatch {
        name: String,
        path: PathBuf,
        signed: String,
        found: String,
    },
    /// The LAYER's authenticity could not be established, so nothing inside it
    /// can be reported as verified. Distinct from a payload-level failure: the
    /// fault is the layer, and every answer about its contents is void.
    LayerNotAuthentic { layer: String, reason: String },
    /// Could not be read to decide. Not absence and not a mismatch — the third
    /// outcome shell scripts collapse into one of the other two.
    Unreadable {
        name: String,
        path: PathBuf,
        reason: String,
    },
}

impl PayloadStatus {
    /// True only for [`PayloadStatus::Verified`].
    ///
    /// Deliberately the ONLY convenience predicate. A `is_ok()` that also
    /// returned true for absence would rebuild the bug this module exists to
    /// prevent, one helper at a time.
    pub fn is_verified(&self) -> bool {
        matches!(self, PayloadStatus::Verified { .. })
    }
}

/// Resolve one payload of an installed layer and verify it, in one call.
///
/// The verifier is a PARAMETER rather than an optional second step
/// (REQ-CONSUMERAPI-001 clause 3). A `verify()` a caller can forget is a
/// protocol that fails open, and "call verify first" is the shell contract
/// wearing types. There is no way to obtain [`PayloadStatus::Verified`]
/// without the trust root having been involved: the envelope is checked
/// against it, the stored manifest must be byte-identical to what it signed,
/// and only then is the payload's own digest compared.
pub fn payload_status(
    store: &Store,
    layer: &InstalledLayer,
    verifier: &dyn ManifestVerifier,
    name: &str,
    platform: &str,
) -> PayloadStatus {
    let not_authentic = |reason: String| PayloadStatus::LayerNotAuthentic {
        layer: layer.layer.to_string(),
        reason,
    };

    // 1. The layer's own authenticity, first. Reading the STORED manifest and
    //    trusting it would let an attacker who can edit `layer.json` and a
    //    payload together produce a self-consistent lie that reports Verified.
    let envelope_path = layer.root.join(crate::reverify::ENVELOPE_FILE);
    let envelope = match std::fs::read(&envelope_path) {
        Ok(bytes) => bytes,
        Err(e) => return not_authentic(format!("{}: {e}", envelope_path.display())),
    };
    let signed = match verifier.verify(&envelope) {
        Ok(payload) => payload,
        Err(e) => return not_authentic(e.to_string()),
    };
    let manifest_path = layer.root.join("layer.json");
    match std::fs::read(&manifest_path) {
        Ok(stored) if stored == signed => {}
        Ok(_) => {
            return not_authentic(
                "the stored manifest is not the one the envelope signed".to_string(),
            );
        }
        Err(e) => return not_authentic(format!("{}: {e}", manifest_path.display())),
    }
    let manifest = match LayerManifest::parse(&signed) {
        Ok(m) => m,
        Err(e) => return not_authentic(e.to_string()),
    };

    // 2. Does the layer name it at all, and for this platform?
    let named: Vec<_> = manifest
        .entries
        .iter()
        .filter(|e| e.annotations.get("eu.pulseengine.tool").map(String::as_str) == Some(name))
        .collect();
    if named.is_empty() {
        let mut available: Vec<String> = manifest
            .entries
            .iter()
            .filter_map(|e| e.annotations.get("eu.pulseengine.tool").cloned())
            .collect();
        available.sort();
        available.dedup();
        return PayloadStatus::AbsentFromLayer {
            name: name.to_string(),
            layer: layer.layer.to_string(),
            available,
        };
    }
    let Some(entry) = named.iter().find(|e| {
        crate::platform::entry_matches(
            e.annotations
                .get(crate::platform::ANN_PLATFORM)
                .map(String::as_str),
            platform,
        )
    }) else {
        let mut platforms: Vec<String> = named
            .iter()
            .filter_map(|e| e.annotations.get(crate::platform::ANN_PLATFORM).cloned())
            .collect();
        platforms.sort();
        platforms.dedup();
        return PayloadStatus::NoEntryForPlatform {
            name: name.to_string(),
            layer: layer.layer.to_string(),
            platform: platform.to_string(),
            platforms,
        };
    };

    // 3. Present for this platform. Now the only question left is integrity.
    let Some(path) = store.entry_path(layer, entry) else {
        return PayloadStatus::MissingFromStore {
            name: name.to_string(),
            path: layer.root.clone(),
            digest: entry.digest.clone(),
        };
    };
    // Any read failure here is Unreadable, with the reason NAMED. There is
    // deliberately no NotFound arm: `entry_path` already returns None unless
    // the file exists, so absence is decided above and a NotFound at this
    // point could only come from the file vanishing between that check and
    // this read. Mutation testing flagged such an arm as untestable, which it
    // was — three surviving mutants on a branch no test could reach. Dead
    // defensive code that cannot be exercised is not caution; it is a place
    // for a defect to hide.
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return PayloadStatus::Unreadable {
                name: name.to_string(),
                path,
                reason: e.to_string(),
            };
        }
    };
    let found = manifest_digest(&bytes);
    if found != entry.digest {
        return PayloadStatus::DigestMismatch {
            name: name.to_string(),
            path,
            signed: entry.digest.clone(),
            found,
        };
    }
    PayloadStatus::Verified {
        name: name.to_string(),
        path,
        digest: entry.digest.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{InstallPolicy, install};
    use crate::manifest::fixtures::manifest_with_tools;
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::MemorySource;
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

    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_present_and_intact_payload_is_verified_against_its_signed_digest() {
        let ctx = installed_layer();
        let got = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        );
        match &got {
            PayloadStatus::Verified { name, path, digest } => {
                assert_eq!(name, "synth");
                assert!(path.exists(), "the verified path must be usable");
                assert_eq!(digest, &manifest_digest(b"synth-bytes"));
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        assert!(got.is_verified());
    }

    /// THE CLAUSE 2 TEST. A tampered payload must report an INTEGRITY FAILURE,
    /// never absence. "I could not find it" and "I found it and it did not
    /// verify" are opposite facts, and a consumer that treats the second as the
    /// first fails OPEN — which is precisely what the shell contract did when
    /// objcopy wrote nothing and the empty string tested false.
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_tampered_payload_is_a_digest_mismatch_and_never_an_absence() {
        let ctx = installed_layer();
        let PayloadStatus::Verified { path, digest, .. } = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        ) else {
            panic!("precondition: the fixture must verify before it is tampered with");
        };
        std::fs::write(&path, b"tampered").unwrap();

        let got = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        );
        match &got {
            PayloadStatus::DigestMismatch {
                signed,
                found,
                name,
                ..
            } => {
                assert_eq!(name, "synth");
                assert_eq!(signed, &digest, "the SIGNED digest is reported verbatim");
                assert_eq!(found, &manifest_digest(b"tampered"));
                assert_ne!(signed, found);
            }
            other => panic!("tampering must not be reported as {other:?}"),
        }
        assert!(!got.is_verified());
        assert!(
            !matches!(got, PayloadStatus::AbsentFromLayer { .. }),
            "an integrity failure reported as absence is the fail-open bug"
        );
    }

    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_name_the_layer_does_not_carry_is_absent_and_says_what_is_there() {
        let ctx = installed_layer();
        match payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "meld",
            "test-platform",
        ) {
            PayloadStatus::AbsentFromLayer {
                name,
                layer,
                available,
            } => {
                assert_eq!(name, "meld");
                assert_eq!(layer, "2026.07.0");
                assert_eq!(
                    available,
                    vec!["synth".to_string()],
                    "absence must name what IS carried, or the consumer's next \
                     question is unanswerable"
                );
            }
            other => panic!("expected AbsentFromLayer, got {other:?}"),
        }
    }

    /// Deleting the payload is an incomplete install, not a tampered one, and
    /// not the same as the layer never naming it.
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_payload_missing_from_the_store_is_distinct_from_one_the_layer_never_named() {
        let ctx = installed_layer();
        let PayloadStatus::Verified { path, .. } = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        ) else {
            panic!("precondition");
        };
        std::fs::remove_file(&path).unwrap();

        let got = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        );
        assert!(
            matches!(got, PayloadStatus::MissingFromStore { .. }),
            "a deleted payload the manifest NAMES is a broken install, not an \
             absence and not tampering — got {got:?}"
        );
    }

    /// True when mode 000 does not actually deny a read here (running as root,
    /// or a filesystem that ignores permission bits) — so the unreadable-file
    /// test cannot hold its premise and must skip rather than fail.
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

    /// "Cannot read it" is not "it is not there", and this module exists to
    /// keep those apart. Mutation testing found the guard that separates them
    /// untested — three surviving mutants on one `ErrorKind::NotFound` match,
    /// any of which would report an unreadable payload as MissingFromStore.
    ///
    /// That is the objcopy failure rebuilt inside the type that was supposed
    /// to prevent it: a permissions fault presented as an absent file, which
    /// sends an operator to reinstall something that is already there while
    /// the real fault goes unnamed.
    #[cfg(unix)]
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn an_unreadable_payload_is_not_reported_as_missing() {
        use std::os::unix::fs::PermissionsExt;
        if premise_unavailable() {
            eprintln!("skipped: mode 000 does not deny reads here");
            return;
        }
        let ctx = installed_layer();
        let PayloadStatus::Verified { path, .. } = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        ) else {
            panic!("precondition: the fixture must verify first");
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let got = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        );
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));

        match &got {
            PayloadStatus::Unreadable { name, reason, .. } => {
                assert_eq!(name, "synth");
                assert!(!reason.is_empty(), "the fault must be NAMED, not implied");
            }
            other => panic!(
                "an unreadable payload must not be reported as {other:?} — a permissions \
                 fault presented as absence is the fail-open confusion this module exists \
                 to prevent"
            ),
        }
        assert!(!got.is_verified());
    }

    /// Clause 3, structurally. There is no second call to forget: the trust
    /// root is a parameter, so a layer whose stored manifest is not the one
    /// the envelope signed cannot report anything as Verified.
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_layer_whose_manifest_was_swapped_can_report_nothing_as_verified() {
        let ctx = installed_layer();
        let manifest_path = ctx.layer.root.join("layer.json");
        let mut doctored = std::fs::read(&manifest_path).unwrap();
        doctored.extend_from_slice(b"\n");
        std::fs::write(&manifest_path, &doctored).unwrap();

        let got = payload_status(
            &ctx.store,
            &ctx.layer,
            &ctx.verifier,
            "synth",
            "test-platform",
        );
        assert!(
            matches!(got, PayloadStatus::LayerNotAuthentic { .. }),
            "a manifest that is not what the envelope signed voids every answer \
             about the layer's contents — got {got:?}"
        );
        assert!(!got.is_verified());
    }

    /// A different root must not be able to certify this layer. Without this,
    /// the verifier parameter could be satisfied by any key and clause 3 would
    /// be decoration.
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_stranger_root_cannot_make_a_payload_verified() {
        let ctx = installed_layer();
        let (_sk, other_pk) = generate_root_keypair();
        let stranger = PinnedKeyVerifier::from_public_key_bytes(&other_pk).unwrap();
        let got = payload_status(&ctx.store, &ctx.layer, &stranger, "synth", "test-platform");
        assert!(
            matches!(got, PayloadStatus::LayerNotAuthentic { .. }),
            "the trust root decides, and a stranger's root decides nothing — got {got:?}"
        );
    }

    /// The variant that says "it exists, and not for you" — a different thing
    /// to tell a user, and a different thing to fix, than "it does not exist".
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn a_payload_built_for_another_platform_is_not_reported_as_absent() {
        use crate::manifest::fixtures::manifest_with_platform_tools;
        let (sk, pk) = generate_root_keypair();
        let blob = b"linux-only-bytes".to_vec();
        let digest = manifest_digest(&blob);
        let payload = manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("meld", &digest, Some("x86_64-unknown-linux-gnu"))],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&digest, &blob);
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
        let outcome = install(
            &pin,
            &source,
            &verifier,
            &store,
            &mut marks,
            &InstallPolicy {
                index: None,
                now: "2026-08-07T00:00:00Z",
                staleness_threshold_days: 90,
                platform: "x86_64-unknown-linux-gnu",
            },
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();

        match payload_status(&store, &layer, &verifier, "meld", "aarch64-apple-darwin") {
            PayloadStatus::NoEntryForPlatform {
                name,
                platform,
                platforms,
                ..
            } => {
                assert_eq!(name, "meld");
                assert_eq!(platform, "aarch64-apple-darwin");
                assert_eq!(
                    platforms,
                    vec!["x86_64-unknown-linux-gnu".to_string()],
                    "it must say which platforms the layer DOES carry"
                );
            }
            other => panic!("expected NoEntryForPlatform, got {other:?}"),
        }
    }

    /// Clause 5: a consumer built once and run for months can record what it
    /// understands as a FACT, rather than meeting a newer pin as a parse error
    /// it has to pattern-match on prose.
    // rivet: verifies REQ-CONSUMERAPI-001
    #[test]
    fn the_crate_states_its_version_and_the_pin_format_it_understands() {
        assert!(!VERSION.is_empty());
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(PIN_MANIFEST_VERSION, 1);
        // And the constant is the one the parser actually enforces, not a
        // second copy that can drift from it.
        let newer = format!(
            "manifest-version = {}\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.07.0\"\n",
            PIN_MANIFEST_VERSION + 1
        );
        assert!(
            Pin::parse(&newer, "varve.toml").is_err(),
            "a pin one version newer than PIN_MANIFEST_VERSION must be refused, or \
             the constant is not describing the parser"
        );
    }
}
