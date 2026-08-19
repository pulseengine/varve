//! The verified install pipeline (REQ-VERIFY-001, REQ-ROLLBACK-001).
//!
//! Order is the security argument, so it is fixed here and tested:
//!
//! 1. fetch manifest bytes (by pin digest if pinned, else by name)
//! 2. **verify the manifest signature** against the trust root
//! 3. parse strictly; cross-check layer name, channel, pinned digest
//! 4. anti-rollback check against the per-line high-water mark
//! 5. fetch each blob; **verify each digest** against the signed manifest
//! 6. lay down in the core
//! 7. only now advance the high-water mark
//!
//! Nothing a source returns reaches the core unverified, and a failed
//! install leaves both the core and the high-water marks untouched. The
//! kill-criterion (REQ-VERIFY-001): running the same bytes through two
//! different sources yields identical verdicts — a source that could
//! influence acceptance has joined the trusted base, and the design is broken.

use crate::layer::LayerId;
use crate::manifest::{LayerManifest, ManifestError};
use crate::pin::Pin;
use crate::rollback::{HighWaterMarks, RollbackError, RollbackVerdict};
use crate::source::{LayerRef, LayerSource, SourceError};
use crate::store::{Store, StoreError, manifest_digest};

/// Signature verification over fetched manifest bytes, against the
/// PulseEngine trust root. Returns the *authenticated payload* (the layer
/// manifest itself) — for DSSE-enveloped transport the fetched bytes and the
/// trusted bytes differ, and everything downstream must use only the latter.
/// Implementations carry the trust root; callers cannot relax it per-source —
/// the pipeline takes exactly one verifier for all sources.
pub trait ManifestVerifier {
    fn verify(&self, fetched_bytes: &[u8]) -> Result<Vec<u8>, VerifyError>;
}

#[derive(Debug, thiserror::Error)]
#[error("manifest signature verification failed: {0}")]
pub struct VerifyError(pub String);

/// A successful install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub digest: String,
    pub layer: LayerId,
    pub counter: u64,
    /// `Some(age_days)` when the accepted layer is older than the staleness
    /// threshold — surfaced, never fatal.
    pub staleness_days: Option<i64>,
    /// The greatest counter the realm's signed index asserts for this line
    /// (REQ-INDEXAUTH-001 clause 4). Reported, NOT enforced: the high-water
    /// mark records what this machine has accepted, and raising it to what
    /// merely EXISTS would refuse a deliberately-pinned older layer the moment
    /// a newer one is published — an availability failure wearing a security
    /// control's clothes, in the one tool whose purpose is frozen toolchains.
    pub index_high_water: Option<u64>,
    /// How many attestations travelled with the layer and were persisted into
    /// its root (REQ-ATTEST-002). Unverified at this point, by design — see
    /// `attestcarry::carry_from_source`; `varve verify` is what checks them.
    pub attestations_carried: usize,
    /// Why carriage was incomplete, when it was. REPORTED, never fatal: a
    /// mirror that dropped an attestation blob must not be able to make a
    /// correctly-signed layer uninstallable, but the loss must not be silent
    /// either — silence is the exact bandersnatch/Verdaccio failure this
    /// requirement exists to surface.
    pub attestation_note: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(transparent)]
    Index(#[from] crate::lineindex::IndexError),
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(
        "source returned manifest {got} where the pin demands {pinned} — refusing (the digest is the artifact)"
    )]
    DigestMismatch { pinned: String, got: String },
    #[error("manifest is for layer {got}, the pin names {pinned} — refusing")]
    LayerMismatch { pinned: String, got: String },
    #[error("manifest is on channel '{got}', the pin selects '{pinned}' — refusing")]
    ChannelMismatch { pinned: String, got: String },
    #[error(
        "rollback refused: layer presents counter {presented} but the {line} line's high-water mark is {high_water} — a stale, validly-signed layer cannot be passed off as current"
    )]
    Rollback {
        line: String,
        presented: u64,
        high_water: u64,
    },
    #[error("blob {digest} fetched for tool '{tool}' does not match its signed digest — refusing")]
    BlobDigestMismatch { tool: String, digest: String },
    #[error("manifest entry {digest} is missing the eu.pulseengine.tool annotation")]
    UnnamedEntry { digest: String },
    #[error(
        "layer {layer} carries no entry for platform {platform} — refusing to install a \
         wrong-architecture toolchain; use --platform only if you know why"
    )]
    NoPlatformEntry { layer: String, platform: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    State(#[from] RollbackError),
}

/// Policy inputs the caller supplies; time is data, not something the
/// pipeline samples.
pub struct InstallPolicy<'a> {
    /// RFC 3339 "now" for the staleness verdict.
    pub now: &'a str,
    pub staleness_threshold_days: u32,
    /// Target platform (a triple) entries must match. Entries without a
    /// platform annotation are platform-independent (REQ-PLATFORM-001).
    pub platform: &'a str,
    /// The realm's line-index obligation (REQ-INDEXAUTH-001). `None` where the
    /// pin names no realm — there is then no root that could have signed an
    /// index, so there is nothing to check.
    pub index: Option<crate::lineindex::IndexPolicy<'a>>,
}

pub fn install(
    pin: &Pin,
    source: &dyn LayerSource,
    verifier: &dyn ManifestVerifier,
    store: &Store,
    marks: &mut HighWaterMarks,
    policy: &InstallPolicy<'_>,
) -> Result<InstallOutcome, InstallError> {
    // 1. Fetch.
    let layer_ref = match &pin.digest {
        Some(digest) => LayerRef::Digest(digest.clone()),
        None => LayerRef::Name(pin.layer.clone()),
    };
    let fetched = source.fetch_manifest(&layer_ref)?;

    // 2. Signature first: nothing else is read from unverified bytes, and no
    // blob is fetched on the strength of an unverified manifest. Only the
    // authenticated payload the verifier returns is used from here on.
    let bytes = verifier.verify(&fetched)?;

    // 3. Strict parse + cross-checks against the pin.
    let manifest = LayerManifest::parse(&bytes)?;
    let digest = manifest_digest(&bytes);
    if let Some(pinned) = &pin.digest
        && &digest != pinned
    {
        return Err(InstallError::DigestMismatch {
            pinned: pinned.clone(),
            got: digest,
        });
    }
    if manifest.layer != pin.layer {
        return Err(InstallError::LayerMismatch {
            pinned: pin.layer.to_string(),
            got: manifest.layer.to_string(),
        });
    }
    let pinned_channel = match pin.channel {
        crate::pin::Channel::Qualified => "qualified",
        crate::pin::Channel::Rolling => "rolling",
    };
    if manifest.channel != pinned_channel {
        return Err(InstallError::ChannelMismatch {
            pinned: pinned_channel.to_string(),
            got: manifest.channel.clone(),
        });
    }

    // 3b. The realm's signed index (REQ-INDEXAUTH-001). Before anti-rollback,
    // because the index can RAISE the mark: a registry that hides the newest
    // layer must not lower the bar this install has to clear. Everything here
    // is verified against the realm's root — the source is the party being
    // constrained and is never asked whether its own listing is honest.
    let line = manifest.layer.line();
    let line_str = line.to_string();
    let index_cache = crate::lineindex::IndexCache::at_root(store.root());
    let mut index_high_water: Option<u64> = None;
    // The verified index and the bytes it came from, held until the install
    // lands: a refused install must not leave a raised index behind, for the
    // same reason it must not burn the high-water mark.
    let mut accepted_index: Option<(crate::lineindex::LineIndex, Vec<u8>)> = None;
    if let Some(index_policy) = &policy.index {
        let envelope = source.fetch_line_index(&line_str)?;
        let served = source.served_layers(&line_str)?;
        // Clause 2 needs something to compare AGAINST, and it is the cache
        // that supplies it. Passing `None` here left the whole
        // presented-older-than-held rule unreachable from the pipeline: it
        // could only ever fire in a test that called `check` itself.
        let cached = index_cache.load(&line_str)?;
        let verified = crate::lineindex::check(
            &line_str,
            envelope.as_deref(),
            served.as_deref(),
            cached.as_ref(),
            index_policy,
        )?;
        index_high_water = verified.as_ref().and_then(|i| i.high_water());
        if let (Some(doc), Some(bytes)) = (verified, envelope) {
            accepted_index = Some((doc, bytes));
        }
    }

    // 4. Anti-rollback, before any blob moves.
    if let RollbackVerdict::Rollback {
        line,
        presented,
        high_water,
    } = marks.check(&manifest)
    {
        return Err(InstallError::Rollback {
            line,
            presented,
            high_water,
        });
    }

    // 5. Fetch blobs; each is accepted only if it matches its signed digest.
    // Platform filtering happens BEFORE any fetch: a foreign entry's blob
    // never even leaves the source (REQ-PLATFORM-001).
    // Name, version and dispatchability travel with the bytes: a payload that
    // is not dispatched by name is laid down under its version too, so two
    // versions of one crate cannot overwrite each other (REQ-STORE-002).
    struct Fetched {
        name: String,
        version: Option<String>,
        dispatchable: bool,
        bytes: Vec<u8>,
    }
    let mut tools: Vec<Fetched> = Vec::new();
    let mut matched = 0usize;
    for entry in &manifest.entries {
        if !crate::platform::entry_matches(
            entry
                .annotations
                .get(crate::platform::ANN_PLATFORM)
                .map(String::as_str),
            policy.platform,
        ) {
            continue;
        }
        // A composed layer is a REFERENCE, not a blob to lay down: its digest
        // names another layer's manifest, which has its own install. Skip it
        // here — install rejected it outright before, so a real composed layer
        // could not be installed at all (REQ-COMPOSE-001).
        if entry.kind() == Ok(crate::kind::PayloadKind::Layer) {
            continue;
        }
        matched += 1;
        let tool = entry
            .annotations
            .get("eu.pulseengine.tool")
            .ok_or_else(|| InstallError::UnnamedEntry {
                digest: entry.digest.clone(),
            })?
            .clone();
        let blob = source.fetch_blob(&entry.digest)?;
        if manifest_digest(&blob) != entry.digest {
            return Err(InstallError::BlobDigestMismatch {
                tool,
                digest: entry.digest.clone(),
            });
        }
        tools.push(Fetched {
            name: tool,
            version: crate::store::entry_version(entry).map(str::to_string),
            dispatchable: crate::store::entry_is_dispatchable(entry),
            bytes: blob,
        });
    }

    // A fully-stamped layer with nothing for this platform fails closed —
    // a wrong-architecture toolchain must not land looking installed.
    if matched == 0 && !manifest.entries.is_empty() {
        return Err(InstallError::NoPlatformEntry {
            layer: manifest.layer.to_string(),
            platform: policy.platform.to_string(),
        });
    }

    // 6. Lay down.
    let payloads: Vec<crate::store::Payload<'_>> = tools
        .iter()
        .map(|t| crate::store::Payload {
            name: t.name.as_str(),
            version: t.version.as_deref(),
            dispatchable: t.dispatchable,
            bytes: t.bytes.as_slice(),
        })
        .collect();
    let stored_digest = store.lay_down_payloads(&bytes, &payloads)?;
    debug_assert_eq!(stored_digest, digest);

    // Retain the signature envelope beside the payload, so `varve verify`
    // can repeat the install-time verdict offline, forever. (When transport
    // was already the bare payload — test doubles — there is nothing to keep.)
    if fetched != bytes
        && let Some(entry) = store.get(&digest)?
    {
        let path = entry.root.join(crate::reverify::ENVELOPE_FILE);
        std::fs::write(&path, &fetched).map_err(|source| StoreError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }

    // 6b. Carry the layer's attestations into its root (REQ-ATTEST-002).
    // Registries publish this evidence and mirrors drop it: bandersnatch and
    // Verdaccio carry none, and every Bazel Central Registry attestation URL
    // points at github.com — so without this an air-gapped consumer receives
    // the bytes and none of the accountability, with no error saying so.
    // Persisting here is also what lets `archive` put it back on the wire.
    let mut attestations_carried = 0usize;
    let mut attestation_note = None;
    if let Some(entry) = store.get(&digest)? {
        match crate::attestcarry::carry_from_source(source, &layer_ref, &entry.root) {
            Ok(n) => attestations_carried = n,
            // Never fatal. The layer's own signature and digests decided the
            // install several steps ago; a third party's evidence being
            // missing, malformed, or unfetchable is evidence ABOUT the
            // evidence, and refusing here would hand a mirror the power to
            // make a perfectly-signed layer uninstallable.
            Err(e) => attestation_note = Some(e.to_string()),
        }
    }

    // 7. Only a fully landed layer advances the high-water mark — or the
    // cached index it was checked against (REQ-INDEXAUTH-001 clause 2).
    marks.advance(&manifest)?;
    if let Some((doc, bytes)) = &accepted_index {
        index_cache.update(&line_str, bytes, doc)?;
    }

    let staleness_days = crate::rollback::staleness_warning(
        &manifest.issued_at,
        policy.now,
        policy.staleness_threshold_days,
    );
    Ok(InstallOutcome {
        digest,
        layer: manifest.layer.clone(),
        counter: manifest.counter,
        staleness_days,
        index_high_water,
        attestations_carried,
        attestation_note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::fixtures::manifest_with_tools;
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::{DirSource, MemorySource};

    struct AcceptAll;
    impl ManifestVerifier for AcceptAll {
        fn verify(&self, fetched: &[u8]) -> Result<Vec<u8>, VerifyError> {
            Ok(fetched.to_vec())
        }
    }

    struct RejectAll;
    impl ManifestVerifier for RejectAll {
        fn verify(&self, _: &[u8]) -> Result<Vec<u8>, VerifyError> {
            Err(VerifyError("untrusted signature (test)".into()))
        }
    }

    fn pin(layer: &str) -> Pin {
        Pin::parse(
            &format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
            ),
            "varve.toml",
        )
        .unwrap()
    }

    fn policy() -> InstallPolicy<'static> {
        InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        }
    }

    /// One layer's worth of test material: manifest bytes + blobs.
    fn july() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let synth = b"july-synth".to_vec();
        let rivet = b"july-rivet".to_vec();
        let blobs = vec![
            (manifest_digest(&synth), synth),
            (manifest_digest(&rivet), rivet),
        ];
        let bytes = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blobs[0].0), ("rivet", &blobs[1].0)],
        );
        (bytes, blobs)
    }

    fn memory_source(manifest: &[u8], blobs: &[(String, Vec<u8>)]) -> MemorySource {
        let mut source = MemorySource::new().with_manifest(manifest);
        for (digest, bytes) in blobs {
            source = source.with_blob(digest, bytes);
        }
        source
    }

    fn setup() -> (tempfile::TempDir, Store, HighWaterMarks) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("varve-root");
        let store = Store::at(&root);
        let marks = HighWaterMarks::load(&root).unwrap();
        (tmp, store, marks)
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn installs_a_verified_layer_end_to_end() {
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        let source = memory_source(&bytes, &blobs);
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        assert_eq!(outcome.layer.to_string(), "2026.07.0");
        assert_eq!(outcome.digest, manifest_digest(&bytes));
        // The layer is resolvable afterwards — install feeds resolution.
        let entry = store.get(&outcome.digest).unwrap().unwrap();
        assert!(store.tool_path(&entry, "synth").is_some());
        assert!(store.tool_path(&entry, "rivet").is_some());
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn installing_two_versions_of_one_crate_lands_both_sets_of_bytes() {
        // Clause 2 through the function that actually runs it. `install`
        // collected (name, bytes) pairs and handed them to a store that wrote
        // `bin/<name>`, so the second serde's bytes landed under the first's
        // name: ONE file, the WRONG contents, and `verify` then failing on the
        // other entry with nothing explaining why.
        use crate::manifest::fixtures::manifest_with_payloads;
        let (_tmp, store, mut marks) = setup();
        let (a, b) = (
            b"serde-1.0.200-crate".to_vec(),
            b"serde-1.0.210-crate".to_vec(),
        );
        let (da, db) = (manifest_digest(&a), manifest_digest(&b));
        let bytes = manifest_with_payloads(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("serde", "1.0.200", "crate", &da),
                ("serde", "1.0.210", "crate", &db),
            ],
        );
        let source = memory_source(&bytes, &[(da, a.clone()), (db, b.clone())]);
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .expect("two versions of one crate is the ordinary shape of a dependency graph");

        let entry = store.get(&outcome.digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(entry.root.join("payloads/serde/1.0.200")).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(entry.root.join("payloads/serde/1.0.210")).unwrap(),
            b,
            "the second version must not have overwritten the first"
        );
        // Nothing landed under the bare name, where one version would have won.
        assert!(!entry.root.join("bin/serde").exists());
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_signed_manifest_whose_entries_share_one_identity_is_refused_not_overwritten() {
        // `deposit` refuses this, but deposit is not the only producer varve
        // installs from: any realm root can sign a manifest, built by any
        // software. If two entries ever reach one path, install must fail
        // LOUDLY — writing one over the other would put the wrong bytes under
        // the right name and make `verify` fail on the innocent entry.
        use crate::manifest::fixtures::manifest_with_payloads;
        let (_tmp, store, mut marks) = setup();
        let (a, b) = (b"first-bytes".to_vec(), b"second-bytes".to_vec());
        let (da, db) = (manifest_digest(&a), manifest_digest(&b));
        let bytes = manifest_with_payloads(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("serde", "1.0.200", "crate", &da),
                ("serde", "1.0.200", "crate", &db),
            ],
        );
        let source = memory_source(&bytes, &[(da, a), (db, b)]);
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .expect_err("one identity, two payloads: the store must refuse");
        assert!(
            matches!(err, InstallError::Store(StoreError::Collision { .. })),
            "got: {err}"
        );
        assert!(store.list().unwrap().is_empty(), "nothing may be laid down");
        assert_eq!(
            marks.mark(&"2026.07".parse().unwrap()),
            None,
            "a refused install must not burn the mark"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn kill_criterion_two_sources_one_verdict() {
        // The same bytes through two different transports must produce
        // identical verdicts — accept AND reject cases.
        let (bytes, blobs) = july();
        let tmp = tempfile::tempdir().unwrap();
        let dir = DirSource::at(tmp.path().join("archive"));
        dir.put(
            &bytes,
            &blobs
                .iter()
                .map(|(d, b)| (d.as_str(), b.as_slice()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mem = memory_source(&bytes, &blobs);

        let run = |source: &dyn LayerSource, verifier: &dyn ManifestVerifier| {
            let (_t, store, mut marks) = setup();
            install(
                &pin("2026.07.0"),
                source,
                verifier,
                &store,
                &mut marks,
                &policy(),
            )
            .map_err(|e| e.to_string())
        };

        let accept_mem = run(&mem, &AcceptAll).unwrap();
        let accept_dir = run(&dir, &AcceptAll).unwrap();
        assert_eq!(accept_mem, accept_dir, "same bytes, same acceptance");

        let reject_mem = run(&mem, &RejectAll).unwrap_err();
        let reject_dir = run(&dir, &RejectAll).unwrap_err();
        assert_eq!(reject_mem, reject_dir, "same bytes, same rejection");
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn an_unverified_manifest_fetches_no_blobs_and_installs_nothing() {
        struct CountingSource {
            inner: MemorySource,
            blob_fetches: std::cell::Cell<usize>,
        }
        impl LayerSource for CountingSource {
            fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
                self.inner.fetch_manifest(layer)
            }
            fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
                self.blob_fetches.set(self.blob_fetches.get() + 1);
                self.inner.fetch_blob(digest)
            }
        }
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        let source = CountingSource {
            inner: memory_source(&bytes, &blobs),
            blob_fetches: std::cell::Cell::new(0),
        };
        let err = install(
            &pin("2026.07.0"),
            &source,
            &RejectAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(matches!(err, InstallError::Verify(_)), "got: {err}");
        assert_eq!(
            source.blob_fetches.get(),
            0,
            "no blob leaves the source before the signature verdict"
        );
        assert!(store.list().unwrap().is_empty(), "nothing laid down");
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_source_that_alters_a_blob_is_caught_by_the_signed_digest() {
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        // Serve the right manifest but tamper with one blob.
        let mut source = MemorySource::new().with_manifest(&bytes);
        source = source.with_blob(&blobs[0].0, b"EVIL");
        source = source.with_blob(&blobs[1].0, &blobs[1].1);
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(err, InstallError::BlobDigestMismatch { .. }),
            "got: {err}"
        );
        assert!(
            store.list().unwrap().is_empty(),
            "tampered layer must not land"
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn a_source_that_answers_a_digest_request_with_other_bytes_is_caught() {
        struct LyingSource(Vec<u8>);
        impl LayerSource for LyingSource {
            fn fetch_manifest(&self, _: &LayerRef) -> Result<Vec<u8>, SourceError> {
                Ok(self.0.clone())
            }
            fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
                Err(SourceError::NotFound(digest.into()))
            }
        }
        let (_tmp, store, mut marks) = setup();
        // Pin a digest that is NOT the digest of what the source returns.
        let (bytes, _) = july();
        let other = manifest_with_tools("2026.07.0", "qualified", 1, "2026-07-31T09:14:00Z", &[]);
        let pinned = manifest_digest(&other);
        let hex = pinned.strip_prefix("sha256:").unwrap();
        let p = Pin::parse(
            &format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ndigest = \"sha256:{hex}\"\n"
            ),
            "varve.toml",
        )
        .unwrap();
        let err = install(
            &p,
            &LyingSource(bytes),
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(err, InstallError::DigestMismatch { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_rolled_back_layer_is_refused_at_install() {
        let (_tmp, store, mut marks) = setup();
        // The line's high-water mark is already at 5.
        let newer = manifest_with_tools("2026.07.2", "qualified", 5, "2026-08-01T00:00:00Z", &[]);
        marks
            .advance(&LayerManifest::parse(&newer).unwrap())
            .unwrap();
        let (bytes, blobs) = july(); // counter 1 < 5
        let source = memory_source(&bytes, &blobs);
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                InstallError::Rollback {
                    presented: 1,
                    high_water: 5,
                    ..
                }
            ),
            "got: {err}"
        );
        assert!(store.list().unwrap().is_empty());
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_failed_install_does_not_advance_the_high_water_mark() {
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        // Source is missing one blob: install fails after the rollback check.
        let source = MemorySource::new()
            .with_manifest(&bytes)
            .with_blob(&blobs[0].0, &blobs[0].1);
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(err, InstallError::Source(SourceError::NotFound(_))),
            "got: {err}"
        );
        let m = LayerManifest::parse(&bytes).unwrap();
        assert_eq!(
            marks.mark(m.layer.line()),
            None,
            "failed install must not burn the mark"
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn staleness_is_surfaced_on_an_accepted_layer() {
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july(); // issued 2026-07-31
        let source = memory_source(&bytes, &blobs);
        let policy = InstallPolicy {
            index: None,
            now: "2026-12-01T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .unwrap();
        assert_eq!(outcome.staleness_days, Some(123));
    }

    // rivet: verifies REQ-PLATFORM-001
    #[test]
    fn install_selects_only_entries_for_the_target_platform() {
        let (_tmp, store, mut marks) = setup();
        let here = b"here-tool".to_vec();
        let there = b"there-tool".to_vec();
        let (d_here, d_there) = (manifest_digest(&here), manifest_digest(&there));
        let bytes = crate::manifest::fixtures::manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("synth", &d_here, Some("test-platform")),
                ("synth", &d_there, Some("other-platform")),
            ],
        );
        // Only the matching blob is served — a correct install never asks
        // for the foreign one.
        let source = MemorySource::new()
            .with_manifest(&bytes)
            .with_blob(&d_here, &here);
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .unwrap();
        let entry = store.get(&outcome.digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(store.tool_path(&entry, "synth").unwrap()).unwrap(),
            here,
            "the host-platform binary landed"
        );
    }

    // rivet: verifies REQ-PLATFORM-001
    #[test]
    fn a_layer_with_nothing_for_the_host_platform_fails_closed() {
        let (_tmp, store, mut marks) = setup();
        let there = b"there-tool".to_vec();
        let d_there = manifest_digest(&there);
        let bytes = crate::manifest::fixtures::manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &d_there, Some("other-platform"))],
        );
        let source = MemorySource::new()
            .with_manifest(&bytes)
            .with_blob(&d_there, &there);
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "test-platform",
        };
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .unwrap_err();
        assert!(
            matches!(err, InstallError::NoPlatformEntry { .. }),
            "got: {err}"
        );
        assert!(store.list().unwrap().is_empty(), "no wrong-arch bytes land");
    }

    // rivet: verifies REQ-PLATFORM-001
    #[test]
    fn unstamped_legacy_entries_install_on_any_platform() {
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july(); // fixtures without platform annotations
        let source = memory_source(&bytes, &blobs);
        let policy = InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: "any-platform-at-all",
        };
        assert!(
            install(
                &pin("2026.07.0"),
                &source,
                &AcceptAll,
                &store,
                &mut marks,
                &policy
            )
            .is_ok()
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn channel_and_layer_mismatches_are_refused() {
        let (_tmp, store, mut marks) = setup();
        // Manifest says rolling; pin says qualified.
        let synth = b"s".to_vec();
        let d = manifest_digest(&synth);
        let bytes = manifest_with_tools(
            "2026.07.0",
            "rolling",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &d)],
        );
        let source = MemorySource::new()
            .with_manifest(&bytes)
            .with_blob(&d, &synth);
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(err, InstallError::ChannelMismatch { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn install_carries_the_attestations_the_source_holds_into_the_installed_layer() {
        // The transport half. Binding shipped in v0.22.0 and reached nobody:
        // an attestation that stays in the producer's CI is not evidence a
        // consumer has. This asserts the evidence lands in the installed layer
        // root — the only place `archive` and `verify` can find it later.
        use crate::attest::{AttestationKind, sign, statement};
        let (sk, pk) = crate::verify::generate_root_keypair();
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        let layer_digest = manifest_digest(&bytes);
        let sbom = b"{\"bomFormat\":\"CycloneDX\"}";
        let st = statement(
            "2026.07.0",
            &layer_digest,
            AttestationKind::Sbom,
            sbom,
            "acme-ci",
        );
        let envelope = sign(&st, &sk, "root-1").unwrap();
        let source = memory_source(&bytes, &blobs).with_attestation(envelope.as_bytes(), sbom);

        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            outcome.attestations_carried, 1,
            "install must report what travelled"
        );
        assert_eq!(outcome.attestation_note, None);

        // …and it is really on disk, verbatim, and still binds offline.
        let entry = store.get(&outcome.digest).unwrap().unwrap();
        let carried = crate::attestcarry::read_persisted(&entry.root, "2026.07.0").unwrap();
        assert_eq!(carried.len(), 1, "the evidence reached the installed layer");
        assert_eq!(
            carried[0].bytes, sbom,
            "the attested bytes are stored VERBATIM — varve transports another party's \
             judgement, it never restates it"
        );
        let reports = crate::attestcarry::report(&carried, &layer_digest, "2026.07.0", &pk);
        assert!(reports[0].binds, "reason: {:?}", reports[0].reason);
        assert_eq!(reports[0].producer, "acme-ci");
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn a_source_that_loses_its_attestations_still_installs_but_says_so() {
        // Deliberate: REPORTING, not refusal. A mirror that drops the evidence
        // must not gain the power to make a correctly-signed layer
        // uninstallable — that would make varve's availability a function of
        // someone else's mirroring. But the loss must not be SILENT either:
        // silence is precisely the bandersnatch/Verdaccio failure this
        // requirement exists to surface.
        struct LosesAttestations(MemorySource);
        impl LayerSource for LosesAttestations {
            fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
                self.0.fetch_manifest(layer)
            }
            fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
                self.0.fetch_blob(digest)
            }
            fn fetch_attestations(
                &self,
                _layer: &LayerRef,
            ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
                Err(SourceError::Transport("the mirror dropped them".into()))
            }
        }
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();
        let outcome = install(
            &pin("2026.07.0"),
            &LosesAttestations(memory_source(&bytes, &blobs)),
            &AcceptAll,
            &store,
            &mut marks,
            &policy(),
        )
        .expect("a layer whose own signature and digests are good is still a good layer");
        assert_eq!(outcome.attestations_carried, 0);
        let note = outcome
            .attestation_note
            .expect("the loss must be reported, never swallowed");
        assert!(note.contains("dropped them"), "note: {note}");
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn install_raises_the_mark_from_the_index_even_when_the_layer_is_hidden() {
        // Clause 4 end to end, through install() — the Uptane property. The
        // registry serves ONLY the old layer and its signature is perfect. The
        // realm's signed index says a newer one exists. Without this, the
        // registry's silence sets the bar, and the hidden layer's counter
        // never constrains anything.
        use crate::lineindex::{IndexPolicy, IndexedLayer, LineIndex};
        let (sk, pk) = crate::verify::generate_root_keypair();
        let (_tmp, store, mut marks) = setup();

        let (bytes, blobs) = july(); // 2026.07.0, counter 1
        let mut source = MemorySource::new().with_manifest(&bytes);
        for (d, b) in &blobs {
            source = source.with_blob(d, b);
        }
        let source = source.with_line_index(
            LineIndex {
                line: "2026.07".into(),
                counter: 1,
                issued_at: "2026-08-07T00:00:00Z".into(),
                layers: vec![
                    IndexedLayer {
                        layer: "2026.07.0".into(),
                        digest: manifest_digest(&bytes),
                        channel: "qualified".into(),
                        counter: 1,
                    },
                    // The layer the registry is not serving.
                    IndexedLayer {
                        layer: "2026.07.9".into(),
                        digest: "sha256:hidden".into(),
                        channel: "qualified".into(),
                        counter: 42,
                    },
                ],
            }
            .sign(&sk, "root-1")
            .unwrap()
            .as_bytes(),
        );

        let policy = InstallPolicy {
            index: Some(IndexPolicy {
                realm: "acme",
                root_public_key: &pk,
                required: true,
            }),
            ..policy()
        };
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .expect("a pinned layer must install even when the line has moved on");

        // The consumer LEARNS what the realm says the line contains, even
        // though the registry never offered it.
        assert_eq!(
            outcome.index_high_water,
            Some(42),
            "the realm's assertion must reach the consumer even when the source \
             withheld the layer it refers to"
        );
        // …and the pinned layer still installed. This assertion is the whole
        // correction: an earlier draft raised the ENFORCEMENT mark to 42, and
        // this very install then failed with `rollback refused: presented 1,
        // high_water 42` — a deliberately-pinned layer made uninstallable by
        // someone else publishing. varve exists to freeze toolchains; a
        // freshness control that unfreezes them is not a fix.
        assert_eq!(outcome.layer.to_string(), "2026.07.0");
        assert_eq!(
            marks.mark(&"2026.07".parse().unwrap()),
            Some(1),
            "the mark records what this machine ACCEPTED, not what exists"
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_replayed_older_index_is_refused_on_the_next_install_not_only_in_theory() {
        // Clause 2 through the pipeline. `check` has always refused a
        // regression against a `cached` document — and install passed `None`
        // for `cached`, so the rule could not fire on any real machine: there
        // was nothing that REMEMBERED. This test installs twice, and the
        // second source replays a superseded index.
        use crate::lineindex::{IndexPolicy, IndexedLayer, LineIndex};
        let (sk, pk) = crate::verify::generate_root_keypair();
        let (_tmp, store, mut marks) = setup();
        let (bytes, blobs) = july();

        let signed_index = |counter: u64| {
            LineIndex {
                line: "2026.07".into(),
                counter,
                issued_at: "2026-08-07T00:00:00Z".into(),
                layers: vec![IndexedLayer {
                    layer: "2026.07.0".into(),
                    digest: manifest_digest(&bytes),
                    channel: "qualified".into(),
                    counter: 1,
                }],
            }
            .sign(&sk, "root-1")
            .unwrap()
        };
        // Counting the blob fetches is what makes this test able to tell WHERE
        // the refusal happened. Without it the test passed with `check` handed
        // `None` for the cached document, because the cache's own write-time
        // regression guard raised the identical error — after the layer had
        // been fetched, laid down, and the mark advanced. Same message, wholly
        // different behaviour, and the version that only compared messages
        // could not see the difference.
        struct CountingSource {
            inner: MemorySource,
            blob_fetches: std::cell::Cell<usize>,
        }
        impl LayerSource for CountingSource {
            fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
                self.inner.fetch_manifest(layer)
            }
            fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
                self.blob_fetches.set(self.blob_fetches.get() + 1);
                self.inner.fetch_blob(digest)
            }
            fn fetch_line_index(&self, line: &str) -> Result<Option<Vec<u8>>, SourceError> {
                self.inner.fetch_line_index(line)
            }
            fn served_layers(&self, line: &str) -> Result<Option<Vec<String>>, SourceError> {
                self.inner.served_layers(line)
            }
        }
        let source_with = |envelope: &str| {
            let mut s = MemorySource::new().with_manifest(&bytes);
            for (d, b) in &blobs {
                s = s.with_blob(d, b);
            }
            CountingSource {
                inner: s.with_line_index(envelope.as_bytes()),
                blob_fetches: std::cell::Cell::new(0),
            }
        };
        let policy = InstallPolicy {
            index: Some(IndexPolicy {
                realm: "acme",
                root_public_key: &pk,
                required: true,
            }),
            ..policy()
        };

        install(
            &pin("2026.07.0"),
            &source_with(&signed_index(9)),
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .expect("the first install accepts index #9");

        // A second source — a stale mirror, or an attacker who kept a copy of
        // a pre-yank index — offers #4. Everything about it verifies.
        let replay = source_with(&signed_index(4));
        let err = install(
            &pin("2026.07.0"),
            &replay,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .expect_err("a superseded index must not be replayable over the held one");
        assert_eq!(
            replay.blob_fetches.get(),
            0,
            "the index check runs BEFORE anything is fetched or laid down — a \
             refusal discovered only when the cache was written would already \
             have installed the layer and advanced the mark"
        );
        assert!(
            matches!(
                err,
                InstallError::Index(crate::lineindex::IndexError::Stale {
                    presented: 4,
                    cached: 9,
                    ..
                })
            ),
            "got: {err}"
        );
        assert!(
            err.to_string().contains('4') && err.to_string().contains('9'),
            "names both counters: {err}"
        );

        // …and the held document is still #9, so a third attempt at the same
        // replay fails the same way rather than sliding down.
        assert_eq!(
            crate::lineindex::IndexCache::at_root(store.root())
                .load("2026.07")
                .unwrap()
                .unwrap()
                .counter,
            9
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn install_refuses_a_source_that_hides_an_indexed_layer() {
        // Clause 3 through install(). Every byte this source serves verifies;
        // the defect is what it withholds.
        use crate::lineindex::{IndexPolicy, IndexedLayer, LineIndex};
        let (sk, pk) = crate::verify::generate_root_keypair();
        let (_tmp, store, mut marks) = setup();

        let (bytes, blobs) = july();
        let mut source = MemorySource::new().with_manifest(&bytes);
        for (d, b) in &blobs {
            source = source.with_blob(d, b);
        }
        // It admits to serving only the old layer, while the realm's index
        // names another.
        let source = source.serving(&["2026.07.0"]).with_line_index(
            LineIndex {
                line: "2026.07".into(),
                counter: 1,
                issued_at: "2026-08-07T00:00:00Z".into(),
                layers: vec![IndexedLayer {
                    layer: "2026.07.5".into(),
                    digest: "sha256:withheld".into(),
                    channel: "qualified".into(),
                    counter: 5,
                }],
            }
            .sign(&sk, "root-1")
            .unwrap()
            .as_bytes(),
        );

        let policy = InstallPolicy {
            index: Some(IndexPolicy {
                realm: "acme",
                root_public_key: &pk,
                required: true,
            }),
            ..policy()
        };
        let err = install(
            &pin("2026.07.0"),
            &source,
            &AcceptAll,
            &store,
            &mut marks,
            &policy,
        )
        .expect_err("a source hiding an indexed layer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("2026.07.5"), "names the hidden layer: {msg}");
        // Nothing was laid down on the strength of a dishonest listing.
        assert!(store.list().unwrap().is_empty(), "no install on a refusal");
    }
}
