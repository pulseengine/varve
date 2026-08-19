//! The archived core (REQ-OFFLINE-001) — the artifact of record.
//!
//! A registry is a cache; retention policies forget. A qualified line must
//! remain reconstructible after every registry has forgotten it, so `varve
//! archive` exports an installed, verified layer as a **directory-shaped OCI
//! image layout** — `oci-layout`, `index.json`, `blobs/sha256/<hex>` — the
//! standard interchange shape (`oras`/`skopeo`-inspectable), with the DSSE
//! signature envelope carried as a blob so verification travels with the
//! evidence. Install from an archive runs the *same* pipeline with the same
//! trust root: where the bytes come from changes, whether they are accepted
//! does not.

use std::path::Path;

use crate::install::VerifyError;
use crate::manifest::LayerManifest;
use crate::reverify::ENVELOPE_FILE;
use crate::source::{LayerRef, LayerSource, SourceError};
use crate::store::{InstalledLayer, Store, StoreError, manifest_digest};

/// artifactType marking the envelope blob in the archive index.
pub const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.pulseengine.varve.signature.v1+json";
/// Annotation on the signature entry naming the manifest digest it signs.
pub const ANN_SIGNS: &str = "eu.pulseengine.varve.signs";

/// The standard OCI tag annotation. Every OCI client reads it to resolve
/// `<layout>:<tag>`; without it a layout can only be addressed by digest, and
/// `oras cp --from-oci-layout ./layout:2026.08.0` — the publish one-liner the
/// deploy docs offer — cannot resolve at all.
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";

/// Annotation on the layer descriptor naming the platform whose payloads a
/// layout carries. `archive` stamps it because an archived core is
/// single-platform by construction (see `export`); `deposit` does not, because
/// a deposit is built from the producer's bytes for every platform at once.
/// Without the stamp a consumer on another platform can only see that a blob is
/// missing, and cannot be told why (varve#80).
pub const ANN_ARCHIVED_FOR: &str = "eu.pulseengine.varve.archived-for";

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("the layer's baseline line-status could not be carried into the archive: {0}")]
    LineStatus(String),
    #[error("io error at {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "layer {digest} has no retained signature envelope — an archive without its signature \
         cannot serve as the artifact of record; reinstall from a signed source first"
    )]
    NoEnvelope { digest: String },
    #[error(
        "payload '{payload}' ({digest}) is named by the layer manifest for platform {platform} but \
         is not present in the installed layer — an archive missing a payload is not the artifact \
         of record; reinstall the layer first"
    )]
    MissingPayload {
        payload: String,
        digest: String,
        platform: String,
    },
    #[error(
        "payload '{payload}' at {path} hashes to {found}, but the signed manifest names {signed} \
         for it — refusing to write a blob under a digest its bytes do not have. Either this core \
         was altered since install, or it was installed for a platform other than {platform} \
         (`varve install --platform`), in which case archive it with the matching \
         `varve archive --platform`."
    )]
    PayloadDigestMismatch {
        payload: String,
        path: String,
        signed: String,
        found: String,
        platform: String,
    },
    #[error(
        "layer {layer} has no payload for platform {platform} in this core — all {omitted} of its \
         payload entries name other platforms ({platforms}). An empty archive is not the artifact \
         of record and would only fail on the far side of the gap: install the layer for \
         {platform}, or archive with the platform this core was installed for."
    )]
    NoPayloadForPlatform {
        layer: String,
        platform: String,
        omitted: usize,
        platforms: String,
    },
    #[error("layer.json in the core is not a valid manifest: {0}")]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error(transparent)]
    Carry(#[from] crate::attestcarry::CarryError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// What an export carried across the gap — and what it could not.
///
/// An archive is SINGLE-PLATFORM by construction: `archive` exports an
/// *installed* layer, and `install` fetches only the payloads of the platform
/// it installed for, so the bytes for any other platform are simply not on this
/// machine. That is not something an operator may discover on the far side of
/// an air gap, so the omission is counted here and printed by the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    /// The platform whose payloads this archive carries — the only one.
    pub platform: String,
    /// Payload blobs written (the manifest and its envelope are not counted).
    pub archived: usize,
    /// Manifest entries left out because they name another platform, counted
    /// per platform — what an operator carrying this media to a mixed site
    /// needs to know BEFORE they travel.
    pub omitted: std::collections::BTreeMap<String, usize>,
}

/// How to name a payload in a verdict: a layer may hold several versions of one
/// name, so the bare name does not identify WHICH payload is at fault.
fn named(entry: &crate::manifest::ManifestEntry, name: &str) -> String {
    match crate::store::entry_version(entry) {
        Some(version) => format!("{name}@{version}"),
        None => name.to_string(),
    }
}

/// Export one installed layer as a directory-shaped OCI image layout, carrying
/// the payloads for `platform` — the platform this core was installed for.
/// Refuses when the layer has no retained envelope: an unsigned archive is
/// not an artifact of record.
pub fn export(
    store: &Store,
    layer: &InstalledLayer,
    dest: &Path,
    platform: &str,
) -> Result<ExportSummary, ArchiveError> {
    let io = |path: &Path, source: std::io::Error| ArchiveError::Io {
        path: path.display().to_string(),
        source,
    };

    // Gather everything first; write nothing until the layer proves whole.
    let manifest_path = layer.root.join("layer.json");
    let payload = std::fs::read(&manifest_path).map_err(|e| io(&manifest_path, e))?;
    let envelope_path = layer.root.join(ENVELOPE_FILE);
    let envelope = match std::fs::read(&envelope_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ArchiveError::NoEnvelope {
                digest: layer.digest.clone(),
            });
        }
        Err(e) => return Err(io(&envelope_path, e)),
    };
    let manifest = LayerManifest::parse(&payload)?;
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut omitted: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in &manifest.entries {
        // A composed layer is a reference to another layer's manifest, not a
        // blob this layer holds.
        if entry.kind() == Ok(crate::kind::PayloadKind::Layer) {
            continue;
        }
        let Some(name) = entry.annotations.get("eu.pulseengine.tool") else {
            continue;
        };
        // Platform-filter exactly as `install` and `verify` do (varve#80). A
        // tool NAME repeats across triples — `kilnd` has one entry per platform
        // — while install lays down only the host's, so archiving every entry
        // read ONE host file once per platform and wrote it under four
        // different digests. Twenty-six of thirty-seven blobs in an archive of
        // varve's own published layer were the host binary filed under some
        // other platform's digest, and `archive` exited 0.
        let entry_platform = entry
            .annotations
            .get(crate::platform::ANN_PLATFORM)
            .map(String::as_str);
        if let Some(other) =
            entry_platform.filter(|p| !crate::platform::entry_matches(Some(p), platform))
        {
            *omitted.entry(other.to_string()).or_default() += 1;
            continue;
        }
        // By ENTRY, not by name: a layer may hold several versions of one name,
        // and each must reach the archive under its own signed digest. Reading
        // `bin/<name>` for both would have put ONE payload's bytes into the
        // archive twice — a layer that cannot be archived whole cannot cross an
        // air gap, which is the whole point (REQ-STORE-002 clause 4).
        let path = store
            .entry_path(layer, entry)
            .ok_or_else(|| ArchiveError::MissingPayload {
                payload: named(entry, name),
                digest: entry.digest.clone(),
                platform: platform.to_string(),
            })?;
        let bytes = std::fs::read(&path).map_err(|e| io(&path, e))?;
        // The invariant that makes this an artifact of RECORD, checked before
        // any of it is written: in a content-addressed layout a blob's NAME is
        // the hash of its bytes, so writing bytes that hash to something else
        // produces a file whose name lies. Platform filtering above is what
        // makes the set right; this is what makes each member of it right, and
        // it is the check whose absence let varve#80 ship — a blob COUNT was
        // correct the whole time.
        let found = manifest_digest(&bytes);
        if found != entry.digest {
            return Err(ArchiveError::PayloadDigestMismatch {
                payload: named(entry, name),
                path: path.display().to_string(),
                signed: entry.digest.clone(),
                found,
                platform: platform.to_string(),
            });
        }
        blobs.push((entry.digest.clone(), bytes));
    }
    // Fail closed on an archive that would carry nothing, the way `install`
    // refuses a layer with no entry for the target platform. The two shapes
    // that reach here are a mistyped `--platform` and a core installed for a
    // different triple, and both otherwise produce a well-formed, signed,
    // completely empty artifact that only fails on the far side of the gap —
    // after the media has been carried there.
    if blobs.is_empty() && !omitted.is_empty() {
        return Err(ArchiveError::NoPayloadForPlatform {
            layer: manifest.layer.to_string(),
            platform: platform.to_string(),
            omitted: omitted.values().sum(),
            platforms: omitted.keys().cloned().collect::<Vec<_>>().join(", "),
        });
    }
    // The attestations that travelled into this layer at install time must
    // travel back out (REQ-ATTEST-002) — otherwise the evidence reaches one
    // machine and dies there, which is the same mirror-boundary loss one hop
    // later. Read BEFORE writing anything: the gather-then-write rule above is
    // what keeps a broken store from producing a half-written artifact of
    // record. A statement whose bytes are gone is an error here, unlike at
    // install: this is our own store, not somebody else's mirror, and an
    // archive is the artifact of record.
    let carried = crate::attestcarry::read_persisted(&layer.root, &manifest.layer.to_string())?;

    write_oci_layout(
        &payload,
        &envelope,
        &blobs,
        &manifest.layer.to_string(),
        &manifest.channel,
        Some(platform),
        dest,
    )
    .map_err(|(path, source)| ArchiveError::Io { path, source })?;
    for c in &carried {
        crate::attestcarry::attach(dest, &c.statement, &c.bytes)?;
    }
    // Carry the line's baseline advisory across the gap (varve#77). Without
    // this, `archive` dropped it: the deposit layout held three manifests and
    // the archive held two, so the AIR-GAPPED consumer — the one the baseline
    // exists for, and the one who cannot ask a registry instead — got a
    // permanently broken `varve status`. The one transport that most needs a
    // yank to arrive was the one discarding it. The attestation carriage added
    // alongside this already did it correctly; line-status was simply never
    // given the same treatment.
    //
    // The bytes are re-attached VERBATIM from the cache and re-verified by the
    // far side against its own trust root. Archiving is a transport, not a
    // place where a signed document is re-shaped.
    // `store.root()`, not `varve_root()`: install writes the cache at the
    // store's own root and `varve status` reads it there, so a realm
    // partition keeps its baseline under `realms/<fingerprint>/state`.
    // Reading from the varve root instead would have found nothing for every
    // realm install — the same drop this fix exists to close, one layer down.
    let cache = crate::linestatus::StatusCache::at_root(store.root());
    if let Some(envelope) = cache
        .envelope_bytes(layer.layer.line())
        .map_err(|e| ArchiveError::LineStatus(e.to_string()))?
    {
        crate::linestatus::attach_to_layout(dest, layer.layer.line(), &envelope)
            .map_err(|e| ArchiveError::LineStatus(e.to_string()))?;
    }
    Ok(ExportSummary {
        platform: platform.to_string(),
        archived: blobs.len(),
        omitted,
    })
}

/// Write the canonical directory-shaped OCI image layout shared by `archive`
/// (exporting an installed layer) and `deposit` (creating one): `oci-layout`,
/// `blobs/sha256/<hex>` for payload + envelope + tools, and an `index.json`
/// referencing the manifest and its signature blob. Errors as (path, io).
///
/// `platform` is `Some` only for an ARCHIVE, which carries one platform's
/// payloads because that is all the archiving machine installed; a `deposit`
/// carries every platform the producer built and passes `None`.
pub(crate) fn write_oci_layout(
    payload: &[u8],
    envelope: &[u8],
    blobs: &[(String, Vec<u8>)],
    layer_name: &str,
    channel: &str,
    platform: Option<&str>,
    dest: &Path,
) -> Result<(), (String, std::io::Error)> {
    let io = |path: &Path, source: std::io::Error| (path.display().to_string(), source);
    let payload_digest = manifest_digest(payload);
    let envelope_digest = manifest_digest(envelope);

    let blob_dir = dest.join("blobs").join("sha256");
    std::fs::create_dir_all(&blob_dir).map_err(|e| io(&blob_dir, e))?;
    let write_blob = |digest: &str, bytes: &[u8]| -> Result<(), (String, std::io::Error)> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        let path = blob_dir.join(hex);
        std::fs::write(&path, bytes).map_err(|e| io(&path, e))
    };
    write_blob(&payload_digest, payload)?;
    write_blob(&envelope_digest, envelope)?;
    for (digest, bytes) in blobs {
        write_blob(digest, bytes)?;
    }

    let marker_path = dest.join("oci-layout");
    std::fs::write(&marker_path, br#"{"imageLayoutVersion":"1.0.0"}"#)
        .map_err(|e| io(&marker_path, e))?;

    let mut index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": payload_digest,
                "size": payload.len(),
                "annotations": {
                    // The standard OCI tag, so `oras cp --from-oci-layout
                    // ./layout:<layer>` and every other client can address
                    // this layout by name rather than by digest alone.
                    REF_NAME: layer_name,
                    "eu.pulseengine.varve.layer": layer_name,
                    "eu.pulseengine.varve.channel": channel,
                }
            },
            {
                "mediaType": "application/json",
                "artifactType": SIGNATURE_ARTIFACT_TYPE,
                "digest": envelope_digest,
                "size": envelope.len(),
                "annotations": { ANN_SIGNS: payload_digest }
            }
        ]
    });
    // Say which platform's payloads are in here, so the far side can be TOLD
    // why a blob is absent rather than left to infer tampering (varve#80).
    if let Some(platform) = platform {
        index["manifests"][0]["annotations"][ANN_ARCHIVED_FOR] =
            serde_json::Value::String(platform.to_string());
    }
    let index_path = dest.join("index.json");
    std::fs::write(
        &index_path,
        serde_json::to_vec_pretty(&index).expect("index serializes"),
    )
    .map_err(|e| io(&index_path, e))?;
    Ok(())
}

/// A `LayerSource` over a directory-shaped OCI image layout — the reading
/// half of REQ-OFFLINE-001. No registry, no network, verification unchanged.
#[derive(Debug)]
pub struct OciLayoutSource {
    root: std::path::PathBuf,
    /// The platform this consumer installs for. Used ONLY to explain an absent
    /// blob; a source has no voice in whether bytes are accepted (DD-003).
    platform: Option<String>,
}

impl OciLayoutSource {
    pub fn at(root: impl Into<std::path::PathBuf>) -> Self {
        OciLayoutSource {
            root: root.into(),
            platform: None,
        }
    }

    /// Name the platform this consumer installs for, so a missing payload can
    /// say WHOSE payload is missing and not merely which digest.
    pub fn for_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    fn blob_path(&self, digest: &str) -> std::path::PathBuf {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.root.join("blobs").join("sha256").join(hex)
    }

    /// The platform this layout was archived for, if it says so. Untrusted
    /// discovery like everything else a source reads: it shapes a message, not
    /// a verdict.
    fn archived_for(&self) -> Option<String> {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.root.join("index.json")).ok()?).ok()?;
        index["manifests"]
            .as_array()?
            .iter()
            .find_map(|e| e["annotations"][ANN_ARCHIVED_FOR].as_str())
            .map(str::to_string)
    }

    /// Why a blob is absent. An archive of one platform, asked for another
    /// platform's payload, is not damaged and not tampered with — and before
    /// varve#80 the far side got `BlobDigestMismatch`, which reads like an
    /// attack when the truth was that our own tool wrote the wrong bytes.
    fn absent(&self, digest: &str) -> SourceError {
        let wanted = self
            .platform
            .clone()
            .unwrap_or_else(crate::platform::host_platform);
        match self.archived_for() {
            Some(archived_for) if archived_for != wanted => SourceError::NoPayloadForPlatform {
                digest: digest.to_string(),
                wanted,
                archived_for,
            },
            _ => SourceError::NotFound(digest.to_string()),
        }
    }
}

impl LayerSource for OciLayoutSource {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        // The archive index tells us which blob is the signed envelope for
        // which manifest digest — untrusted discovery, as always: the
        // returned envelope still has to verify and match the pin.
        let index_path = self.root.join("index.json");
        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&index_path)
                .map_err(|e| SourceError::Transport(format!("{}: {e}", index_path.display())))?,
        )
        .map_err(|e| SourceError::Transport(format!("index.json: {e}")))?;
        let entries = index["manifests"].as_array().cloned().unwrap_or_default();

        // Find candidate manifest digests in the index that match the ref.
        let wanted: Vec<String> = entries
            .iter()
            .filter(|e| e["artifactType"] != SIGNATURE_ARTIFACT_TYPE)
            .filter_map(|e| {
                let digest = e["digest"].as_str()?.to_string();
                match layer {
                    LayerRef::Digest(d) => (&digest == d).then_some(digest),
                    LayerRef::Name(id) => {
                        let name = e["annotations"]["eu.pulseengine.varve.layer"].as_str()?;
                        (name == id.to_string()).then_some(digest)
                    }
                }
            })
            .collect();

        for digest in wanted {
            // Prefer the signed envelope blob; fall back to the bare
            // manifest blob (the pipeline's verifier decides acceptability).
            let envelope = entries.iter().find(|e| {
                e["artifactType"] == SIGNATURE_ARTIFACT_TYPE
                    && e["annotations"][ANN_SIGNS] == *digest
            });
            let blob_digest = envelope
                .and_then(|e| e["digest"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| digest.clone());
            match std::fs::read(self.blob_path(&blob_digest)) {
                Ok(bytes) => return Ok(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(SourceError::Transport(e.to_string())),
            }
        }
        Err(SourceError::NotFound(format!("{layer:?}")))
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        match std::fs::read(self.blob_path(digest)) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(self.absent(digest)),
            Err(e) => Err(SourceError::Transport(e.to_string())),
        }
    }

    fn fetch_line_status(&self, _layer: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
        // The archived layout carries its baseline as a line-status referrer
        // (REQ-STATUS-DIST-001). Untrusted bytes — the caller re-verifies.
        crate::linestatus::read_any_from_layout(&self.root)
            .map_err(|e| SourceError::Transport(e.to_string()))
    }

    fn fetch_line_index(&self, line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        // The realm's signed index rides in the layout as its own referrer
        // (REQ-INDEXAUTH-001), attached by `varve attach-index` beside the
        // baseline status. Untrusted bytes — the caller re-verifies against
        // the realm's root.
        crate::lineindex::read_from_layout(&self.root, line)
            .map_err(|e| SourceError::Transport(e.to_string()))
    }

    // `served_layers` is deliberately left at the trait default (`Ok(None)` —
    // "cannot enumerate"). A layout CAN list its own contents, but its contents
    // are not a listing OF THE LINE: it is a hand-carried subset, usually one
    // layer, exported precisely because someone chose it. Answering
    // `Some(["2026.08.0"])` would make every air-gapped install of a realm with
    // a multi-layer index fail with `Omitted` — a false accusation of tampering
    // against the transport varve exists to serve. Omission is a claim only a
    // party that PURPORTS to list the line can be caught making.

    fn fetch_attestations(
        &self,
        layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        // The same referrer machinery line-status uses (REQ-STATUS-DIST-001),
        // as REQ-ATTEST-002 requires — one shape, not two. Untrusted bytes:
        // the layout is a mirror's output and `verify` re-checks every
        // statement against the trust root.
        let name = match layer {
            LayerRef::Name(id) => id.to_string(),
            LayerRef::Digest(d) => d.clone(),
        };
        crate::attestcarry::read_all(&self.root, &name)
            .map_err(|e| SourceError::Transport(e.to_string()))
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

    /// Install a signed layer into a fresh store; return everything needed
    /// downstream.
    fn installed() -> (
        tempfile::TempDir,
        Store,
        InstalledLayer,
        PinnedKeyVerifier,
        Vec<u8>,
    ) {
        let (sk, pk) = generate_root_keypair();
        let tool = b"synth-bytes".to_vec();
        let blob_digest = manifest_digest(&tool);
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
            .with_blob(&blob_digest, &tool);
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        (tmp, store, layer, verifier, payload)
    }

    /// Every blob in a content-addressed layout must hash to the name it is
    /// filed under. Returns the offenders as (filename, actual digest) — a
    /// blob whose name lies is exactly the corruption of varve#80, and a blob
    /// COUNT stayed correct the whole time it shipped.
    fn blobs_whose_name_lies(dest: &Path) -> Vec<(String, String)> {
        let mut bad = Vec::new();
        for e in std::fs::read_dir(dest.join("blobs/sha256"))
            .unwrap()
            .filter_map(|e| e.ok())
        {
            let name = e.file_name().to_string_lossy().to_string();
            let actual = manifest_digest(&std::fs::read(e.path()).unwrap());
            if actual != format!("sha256:{name}") {
                bad.push((name, actual));
            }
        }
        bad
    }

    /// A signed layer whose ONE tool name repeats across two platforms — the
    /// real shape of the pulseengine layer, where `kilnd` has one entry per
    /// triple — plus a platform-independent payload. Installed for
    /// `platform-a`, so only `platform-a`'s bytes are on this machine.
    #[allow(clippy::type_complexity)]
    fn installed_multi_platform() -> (
        tempfile::TempDir,
        Store,
        InstalledLayer,
        PinnedKeyVerifier,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        use crate::manifest::fixtures::manifest_with_platform_tools;
        let (sk, pk) = generate_root_keypair();
        let kilnd_a = b"kilnd-built-for-platform-a".to_vec();
        let kilnd_b = b"kilnd-built-for-platform-b".to_vec();
        let anyplat = b"a-payload-with-no-platform-claim".to_vec();
        let (da, db, dn) = (
            manifest_digest(&kilnd_a),
            manifest_digest(&kilnd_b),
            manifest_digest(&anyplat),
        );
        let payload = manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("kilnd", &da, Some("platform-a")),
                ("kilnd", &db, Some("platform-b")),
                ("charter", &dn, None),
            ],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        // The SOURCE has every platform's bytes, as a real registry does.
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&da, &kilnd_a)
            .with_blob(&db, &kilnd_b)
            .with_blob(&dn, &anyplat);
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let policy = InstallPolicy {
            platform: "platform-a",
            ..policy()
        };
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy,
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        // The premise: install laid down ONE kilnd, at bin/kilnd — the file
        // both signed entries resolve to by name.
        assert_eq!(
            std::fs::read(layer.root.join("bin/kilnd")).unwrap(),
            kilnd_a
        );
        (tmp, store, layer, verifier, kilnd_a, kilnd_b, anyplat)
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn a_multi_platform_layer_archives_only_this_platforms_payloads() {
        // varve#80. Every archive fixture before this one had ONE platform, and
        // with one platform a tool name does not repeat, so `bin/<name>` was
        // always the right file and every blob was correct. With TWO platforms
        // the same host file was read once per triple and written under each
        // triple's digest: an archive of varve's own published layer held 26
        // blobs whose bytes were not what their names said, and `archive`
        // exited 0 calling it the artifact of record.
        let (tmp, store, layer, _v, kilnd_a, kilnd_b, anyplat) = installed_multi_platform();
        let dest = tmp.path().join("archive");
        let summary = export(&store, &layer, &dest, "platform-a").unwrap();

        // CONTENT against the digest filename, not a count. A count was right
        // while the bytes were wrong — that is how this stayed hidden.
        assert_eq!(
            blobs_whose_name_lies(&dest),
            Vec::<(String, String)>::new(),
            "every blob must hold the bytes its digest names"
        );
        let blob = |digest: &str| dest.join("blobs/sha256").join(&digest[7..]);
        assert_eq!(
            std::fs::read(blob(&manifest_digest(&kilnd_a))).unwrap(),
            kilnd_a
        );
        assert_eq!(
            std::fs::read(blob(&manifest_digest(&anyplat))).unwrap(),
            anyplat,
            "a payload claiming no platform belongs to every archive"
        );
        // platform-b's payload is ABSENT, not present holding platform-a's
        // bytes. Absence is honest; the wrong bytes under the right name are
        // not, and fail as tampering on the far side of the gap.
        assert!(
            !blob(&manifest_digest(&kilnd_b)).exists(),
            "the archive must not invent a payload it does not hold"
        );

        // And the omission is REPORTED, not silent: an operator carrying this
        // media to a mixed site has to learn it before they travel.
        assert_eq!(summary.platform, "platform-a");
        assert_eq!(summary.archived, 2);
        assert_eq!(
            summary.omitted,
            std::collections::BTreeMap::from([("platform-b".to_string(), 1)])
        );

        // The layout says which platform it carries, so the far side can be
        // told why rather than left to infer tampering.
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dest.join("index.json")).unwrap()).unwrap();
        assert_eq!(
            index["manifests"][0]["annotations"][ANN_ARCHIVED_FOR],
            "platform-a"
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn a_multi_platform_archive_reinstalls_and_reverifies_on_its_own_platform() {
        // The round trip that matters: the archive is still a usable artifact
        // of record for the platform it was made on, and every payload in it
        // re-verifies against the signed manifest on the far side.
        let (tmp, store, layer, verifier, kilnd_a, _kb, _kn) = installed_multi_platform();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "platform-a").unwrap();

        let fresh_root = tmp.path().join("fresh");
        let fresh = Store::at(&fresh_root);
        let mut marks = HighWaterMarks::load(&fresh_root).unwrap();
        let policy = InstallPolicy {
            platform: "platform-a",
            ..policy()
        };
        let outcome = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest).for_platform("platform-a"),
            &verifier,
            &fresh,
            &mut marks,
            &policy,
        )
        .unwrap();
        let entry = fresh.get(&outcome.digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(entry.root.join("bin/kilnd")).unwrap(),
            kilnd_a,
            "the far side must get platform-a's kilnd, not platform-b's entry's bytes"
        );
        assert_eq!(
            crate::reverify::verify_installed(&fresh, &entry, &verifier, "platform-a").unwrap(),
            2
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn a_consumer_on_another_platform_is_told_the_archive_carries_none_for_it() {
        // Before varve#80 this consumer got BlobDigestMismatch — it failed
        // closed, which was right, but the message read like tampering when the
        // truth was that our own tool had written the wrong bytes. Nothing is
        // corrupt here and no amount of re-copying the media helps, so the
        // error has to say what actually happened and what to do instead.
        let (tmp, store, layer, verifier, ..) = installed_multi_platform();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "platform-a").unwrap();

        let fresh_root = tmp.path().join("fresh-b");
        let fresh = Store::at(&fresh_root);
        let mut marks = HighWaterMarks::load(&fresh_root).unwrap();
        let policy = InstallPolicy {
            platform: "platform-b",
            ..policy()
        };
        let err = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest).for_platform("platform-b"),
            &verifier,
            &fresh,
            &mut marks,
            &policy,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                crate::install::InstallError::Source(SourceError::NoPayloadForPlatform {
                    wanted,
                    archived_for,
                    ..
                }) if wanted == "platform-b" && archived_for == "platform-a"
            ),
            "a different-platform consumer must be told which platform this \
             archive carries, not accused of tampering: {err}"
        );
        let text = err.to_string();
        assert!(
            text.contains("platform-b") && text.contains("platform-a"),
            "the message must name both the platform asked for and the one \
             carried: {text}"
        );
        assert!(
            fresh.list().unwrap().is_empty(),
            "and nothing lands from a failed install"
        );
    }

    // rivet: verifies REQ-PROOF-001
    #[cfg(unix)]
    #[test]
    fn a_blob_that_exists_but_cannot_be_read_is_a_transport_fault_not_an_absent_payload() {
        // "Absent" now tells a story — which platform this archive carries and
        // what to do instead — so a blob that exists and cannot be read must
        // not borrow it. A permissions fault reported as "this archive carries
        // no payload for X" sends the operator to re-archive on a machine that
        // was never the problem. (cargo-mutants: the NotFound guard survives
        // being replaced with `true`.)
        use std::os::unix::fs::PermissionsExt;
        let (tmp, store, layer, verifier, kilnd_a, ..) = installed_multi_platform();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "platform-a").unwrap();
        let hex = manifest_digest(&kilnd_a)
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        let blob = dest.join("blobs/sha256").join(&hex);
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o000)).unwrap();
        // chmod(000) does not stop root and some filesystems ignore modes, so
        // test the PREMISE rather than guessing at uid: a test that cannot hold
        // its premise should say so, not go red for the wrong reason.
        if std::fs::read(&blob).is_ok() {
            eprintln!("skipping: this environment does not deny reads on mode 000");
            return;
        }
        let fresh_root = tmp.path().join("fresh");
        let fresh = Store::at(&fresh_root);
        let mut marks = HighWaterMarks::load(&fresh_root).unwrap();
        let err = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest).for_platform("platform-a"),
            &verifier,
            &fresh,
            &mut marks,
            &InstallPolicy {
                platform: "platform-a",
                ..policy()
            },
        )
        .unwrap_err();
        let _ = std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o644));
        assert!(
            matches!(
                &err,
                crate::install::InstallError::Source(SourceError::Transport(_))
            ),
            "an unreadable blob must be a transport fault, not an absent one: {err}"
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn a_blob_missing_from_an_archive_of_this_platform_is_not_blamed_on_the_platform() {
        // The other half of the honest-absence rule. A truncated or damaged
        // archive of THIS platform is a real fault the operator must chase —
        // telling them "this archive carries no payload for X, it was archived
        // for X" would be nonsense, and would send them to re-archive on a
        // machine that is already right. (cargo-mutants: the `archived_for !=
        // wanted` guard survived being replaced with `true`.)
        let (tmp, store, layer, verifier, kilnd_a, ..) = installed_multi_platform();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "platform-a").unwrap();
        let hex = manifest_digest(&kilnd_a)
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        std::fs::remove_file(dest.join("blobs/sha256").join(&hex)).unwrap();

        let fresh_root = tmp.path().join("fresh");
        let fresh = Store::at(&fresh_root);
        let mut marks = HighWaterMarks::load(&fresh_root).unwrap();
        let err = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest).for_platform("platform-a"),
            &verifier,
            &fresh,
            &mut marks,
            &InstallPolicy {
                platform: "platform-a",
                ..policy()
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                crate::install::InstallError::Source(SourceError::NotFound(_))
            ),
            "a damaged archive of this platform is not a platform mismatch: {err}"
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn an_archive_that_would_carry_no_payload_at_all_is_refused() {
        // A mistyped `--platform`, or a core installed for another triple,
        // otherwise produces a well-formed, signed, completely EMPTY layout
        // that fails only on the far side of the gap — after the media has been
        // carried there. `install` already refuses a layer with no entry for
        // the target platform; the export side must refuse the mirror image.
        use crate::manifest::fixtures::manifest_with_platform_tools;
        let (sk, pk) = generate_root_keypair();
        let (a, b) = (b"kilnd-a".to_vec(), b"kilnd-b".to_vec());
        let (da, db) = (manifest_digest(&a), manifest_digest(&b));
        let payload = manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[
                ("kilnd", &da, Some("platform-a")),
                ("kilnd", &db, Some("platform-b")),
            ],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&da, &a)
            .with_blob(&db, &b);
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &InstallPolicy {
                platform: "platform-a",
                ..policy()
            },
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        let dest = tmp.path().join("archive");
        let err = export(&store, &layer, &dest, "platfrom-a").unwrap_err();
        assert!(
            matches!(&err, ArchiveError::NoPayloadForPlatform { platform, omitted, .. }
                if platform == "platfrom-a" && *omitted == 2),
            "got: {err}"
        );
        assert!(
            !dest.join("index.json").exists(),
            "and nothing is written: a layout that exists is a layout somebody will carry"
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn a_payload_whose_bytes_do_not_match_its_signed_digest_is_never_archived() {
        // The invariant, standing on its own: `archive` writes a blob only when
        // its bytes hash to the digest the signed manifest names for it. This
        // is the check whose absence let varve#80 exit 0 on a corrupt artifact,
        // and it holds whatever put the wrong bytes there — a foreign-platform
        // payload, bit-rot, or an edit after install.
        let (tmp, store, layer, ..) = installed_multi_platform();
        std::fs::write(layer.root.join("bin/kilnd"), b"NOT-WHAT-WAS-SIGNED").unwrap();
        let err = export(&store, &layer, &tmp.path().join("archive"), "platform-a").unwrap_err();
        assert!(
            matches!(&err, ArchiveError::PayloadDigestMismatch { payload, .. } if payload == "kilnd"),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn export_writes_a_standard_oci_image_layout() {
        // rivet: verifies REQ-LAYOUT-001
        let (tmp, store, layer, _verifier, payload) = installed();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();

        // oci-layout marker file, per the OCI image-layout spec.
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dest.join("oci-layout")).unwrap()).unwrap();
        assert_eq!(marker["imageLayoutVersion"], "1.0.0");

        // Every blob is stored under its own digest, content-addressed.
        let payload_digest = manifest_digest(&payload);
        let hex = payload_digest.strip_prefix("sha256:").unwrap();
        let manifest_blob = dest.join("blobs/sha256").join(hex);
        assert_eq!(std::fs::read(&manifest_blob).unwrap(), payload);

        // The layout is addressable by tag. A ten-persona audit graded the
        // platform engineer's whole job BLOCKED here: `oras cp
        // --from-oci-layout ./layout:2026.08.0` — the one-line publish the
        // docs offered — cannot resolve a layout whose index carries no
        // org.opencontainers.image.ref.name, and every OCI client uses that
        // annotation as the tag.
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dest.join("index.json")).unwrap()).unwrap();
        let tagged = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["annotations"][REF_NAME] == "2026.07.0")
            .expect("the layer manifest must be tagged with the layer id");
        assert_eq!(
            tagged["digest"],
            manifest_digest(&payload).as_str(),
            "the tag must point at the layer manifest, not the envelope"
        );

        // index.json references the manifest and the signature blob.
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dest.join("index.json")).unwrap()).unwrap();
        let entries = index["manifests"].as_array().unwrap();
        assert!(
            entries
                .iter()
                .any(|e| e["digest"] == payload_digest.as_str()),
            "index must reference the layer manifest"
        );
        let signature = entries
            .iter()
            .find(|e| e["artifactType"] == SIGNATURE_ARTIFACT_TYPE)
            .expect("index must reference the signature envelope");
        assert_eq!(signature["annotations"][ANN_SIGNS], payload_digest.as_str());

        // The tool blob is present under its digest.
        let manifest = LayerManifest::parse(&payload).unwrap();
        for entry in &manifest.entries {
            let hex = entry.digest.strip_prefix("sha256:").unwrap();
            assert!(
                dest.join("blobs/sha256").join(hex).is_file(),
                "blob {}",
                entry.digest
            );
        }
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn an_archived_layer_installs_into_a_fresh_core_with_verification_unchanged() {
        let (tmp, store, layer, verifier, payload) = installed();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();

        // Fresh machine: new store, no registry, no network — same verifier.
        let fresh_root = tmp.path().join("fresh");
        let fresh_store = Store::at(&fresh_root);
        let mut fresh_marks = HighWaterMarks::load(&fresh_root).unwrap();
        let source = OciLayoutSource::at(&dest);
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &fresh_store,
            &mut fresh_marks,
            &policy(),
        )
        .unwrap();
        assert_eq!(outcome.digest, manifest_digest(&payload));
        // And the reinstalled layer re-verifies offline, envelope retained.
        let entry = fresh_store.get(&outcome.digest).unwrap().unwrap();
        let checked =
            crate::reverify::verify_installed(&fresh_store, &entry, &verifier, "test-platform")
                .unwrap();
        assert_eq!(checked, 1);
    }

    /// The same signed layer, plus a signed attestation statement carried
    /// beside it — the producer's side of REQ-ATTEST-002.
    #[allow(clippy::type_complexity)]
    fn installed_with_attestation() -> (
        tempfile::TempDir,
        Store,
        InstalledLayer,
        PinnedKeyVerifier,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        use crate::attest::{AttestationKind, sign, statement};
        let (sk, pk) = generate_root_keypair();
        let tool = b"synth-bytes".to_vec();
        let blob_digest = manifest_digest(&tool);
        let payload = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blob_digest)],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let sbom = b"{\"bomFormat\":\"CycloneDX\",\"components\":[]}".to_vec();
        let st = statement(
            "2026.07.0",
            &manifest_digest(&payload),
            AttestationKind::Sbom,
            &sbom,
            "acme-ci",
        );
        let statement_envelope = sign(&st, &sk, "varve-root-1").unwrap().into_bytes();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&blob_digest, &tool)
            .with_attestation(&statement_envelope, &sbom);
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        (tmp, store, layer, verifier, payload, pk.to_vec(), sbom)
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn an_attestation_survives_archive_and_an_offline_install_into_a_fresh_core() {
        // THE requirement, end to end in one process: evidence enters at
        // install, is re-emitted by `archive` as referrer artifacts, crosses to
        // a machine that shares nothing with the first but the pinned root, and
        // is still checkable there with no network. Registries publish this
        // evidence and mirrors drop it — bandersnatch and Verdaccio carry none,
        // and every BCR attestation URL points at github.com — so without this
        // an air-gapped consumer gets the bytes and none of the accountability.
        let (tmp, store, layer, verifier, payload, pk, sbom) = installed_with_attestation();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();

        // The archive carries it as referrer entries, in the layout index.
        let carried = crate::attestcarry::read_all(&dest, "2026.07.0").unwrap();
        assert_eq!(carried.len(), 1, "archive must re-emit the evidence");
        assert_eq!(carried[0].bytes, sbom, "carried verbatim");

        // A fresh core, installing from that archive alone.
        let fresh_root = tmp.path().join("fresh");
        let fresh_store = Store::at(&fresh_root);
        let mut fresh_marks = HighWaterMarks::load(&fresh_root).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest),
            &verifier,
            &fresh_store,
            &mut fresh_marks,
            &policy(),
        )
        .unwrap();
        assert_eq!(outcome.attestations_carried, 1, "it crossed the gap");

        // …and on the far side it STILL BINDS, offline, against the pinned
        // root — which is what `varve verify` reports.
        let entry = fresh_store.get(&outcome.digest).unwrap().unwrap();
        let reports = crate::attestcarry::report_installed(
            &entry.root,
            "2026.07.0",
            &manifest_digest(&payload),
            &pk,
        )
        .unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].binds, "reason: {:?}", reports[0].reason);
        assert_eq!(reports[0].kind, "sbom");
        assert_eq!(reports[0].producer, "acme-ci");
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_yank_survives_archive_and_an_offline_install_into_a_fresh_core() {
        // varve#77. `archive` dropped the line-status: the deposit layout held
        // three manifests and the archive held two, so the AIR-GAPPED consumer
        // — the one who cannot ask a registry instead — got a permanently
        // broken `varve status`. The one transport that most needs a yank to
        // arrive was the one discarding it.
        //
        // The assertion is the YANK, deliberately, not a manifest count: a
        // count passes when the WRONG blob travels, and a yank that does not
        // reach the far side is the whole defect.
        use crate::linestatus::{LineStatus, StatusCache};
        let (sk, pk) = generate_root_keypair();
        let tool = b"synth-bytes".to_vec();
        let blob_digest = manifest_digest(&tool);
        let payload = manifest_with_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &[("synth", &blob_digest)],
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let doc = LineStatus {
            line: "2026.07".into(),
            counter: 3,
            issued_at: "2026-08-07T00:00:00Z".into(),
            support_until: Some("2028-07-31".into()),
            yanked: std::collections::BTreeMap::from([(
                "2026.07.0".to_string(),
                "CVE-2026-0001 in synth".to_string(),
            )]),
            known_problems: Vec::new(),
        };
        let status_envelope = doc.sign(&sk, "varve-root-1").unwrap().into_bytes();
        let source = MemorySource::new()
            .with_manifest(envelope.as_bytes())
            .with_blob(&blob_digest, &tool)
            .with_line_status(&status_envelope);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        let line: crate::layer::Line = "2026.07".parse().unwrap();
        // What `varve install` does next: verify the carried baseline against
        // the trust root and cache it so `status` answers offline.
        let cached = crate::linestatus::cache_baseline_from_source(
            &source,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &line,
            &pk,
            store.root(),
        )
        .unwrap();
        assert_eq!(cached, Some(3), "the near side cached the advisory");
        let layer = store.get(&outcome.digest).unwrap().unwrap();

        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();

        // A fresh core on the far side of the gap: nothing in common with the
        // first but the pinned root and this directory.
        let fresh_root = tmp.path().join("fresh");
        let fresh = Store::at(&fresh_root);
        let mut fresh_marks = HighWaterMarks::load(&fresh_root).unwrap();
        let far = OciLayoutSource::at(&dest);
        install(
            &pin("2026.07.0"),
            &far,
            &verifier,
            &fresh,
            &mut fresh_marks,
            &policy(),
        )
        .unwrap();
        let carried = crate::linestatus::cache_baseline_from_source(
            &far,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &line,
            &pk,
            fresh.root(),
        )
        .unwrap();
        assert_eq!(carried, Some(3), "the advisory crossed the gap");

        // …and on the far side it is READ BACK as a yank, re-verified against
        // that machine's own trust root — which is what `varve status` prints.
        let there = StatusCache::at_root(fresh.root())
            .load(&line, &pk)
            .unwrap()
            .expect("the far side has a cached status document");
        let report = there.report_for(&"2026.07.0".parse().unwrap());
        assert_eq!(
            report.yanked_reason.as_deref(),
            Some("CVE-2026-0001 in synth"),
            "the YANK is what had to arrive, not merely some blob"
        );
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn exporting_a_layer_whose_line_has_no_cached_status_is_not_an_error() {
        // Carrying the baseline must not turn `archive` into a command that
        // demands one. Most lines have no advisory, and an archive of a clean
        // line is still the artifact of record.
        let (tmp, store, layer, _verifier, _payload) = installed();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();
        assert!(
            crate::linestatus::read_any_from_layout(&dest)
                .unwrap()
                .is_none()
        );
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_layer_holding_two_versions_of_one_name_crosses_an_air_gap_intact() {
        // Clause 4. `export` read `bin/<tool>` for every entry, so with two
        // versions of one name it would have read ONE file twice and written it
        // under the OTHER version's digest — an archive that no longer matches
        // its own signed manifest, discovered only on the far side of the air
        // gap. A payload that cannot be archived cannot cross, which is the
        // whole point of the artifact of record.
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
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();

        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();
        // Both blobs are in the archive, each holding ITS OWN bytes — content
        // addressing makes this check exact: a blob written under the wrong
        // digest is a blob whose name lies.
        for (digest, expected) in [(&da, &a), (&db, &b)] {
            let hex = digest.strip_prefix("sha256:").unwrap();
            assert_eq!(
                &std::fs::read(dest.join("blobs/sha256").join(hex)).unwrap(),
                expected,
                "blob {digest} must hold the bytes it is named for"
            );
        }

        // Reinstall on a machine that shares nothing but the pinned root, and
        // re-verify there: both versions, unaltered.
        let fresh_root = tmp.path().join("fresh");
        let fresh = Store::at(&fresh_root);
        let mut fresh_marks = HighWaterMarks::load(&fresh_root).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest),
            &verifier,
            &fresh,
            &mut fresh_marks,
            &policy(),
        )
        .unwrap();
        let entry = fresh.get(&outcome.digest).unwrap().unwrap();
        assert_eq!(
            crate::reverify::verify_installed(&fresh, &entry, &verifier, "test-platform").unwrap(),
            2,
            "both versions survive the round trip and re-verify"
        );
        assert_eq!(
            std::fs::read(entry.root.join("payloads/serde/1.0.200")).unwrap(),
            a
        );
        assert_eq!(
            std::fs::read(entry.root.join("payloads/serde/1.0.210")).unwrap(),
            b
        );
    }

    // rivet: verifies REQ-VERIFY-001
    #[test]
    fn the_archive_source_cannot_relax_acceptance() {
        // Same bytes through the archive path and the memory path: identical
        // verdicts, including rejection by a different trust root.
        let (tmp, store, layer, _verifier, _payload) = installed();
        let dest = tmp.path().join("archive");
        export(&store, &layer, &dest, "test-platform").unwrap();

        let (_, other_pk) = generate_root_keypair();
        let wrong = PinnedKeyVerifier::from_public_key_bytes(&other_pk).unwrap();
        let fresh_root = tmp.path().join("fresh2");
        let fresh_store = Store::at(&fresh_root);
        let mut fresh_marks = HighWaterMarks::load(&fresh_root).unwrap();
        let err = install(
            &pin("2026.07.0"),
            &OciLayoutSource::at(&dest),
            &wrong,
            &fresh_store,
            &mut fresh_marks,
            &policy(),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::install::InstallError::Verify(_)),
            "archive path must reject exactly like any other: {err}"
        );
        assert!(fresh_store.list().unwrap().is_empty());
    }

    // rivet: verifies REQ-OFFLINE-001
    #[test]
    fn export_refuses_a_layer_without_its_envelope() {
        let (tmp, store, layer, _verifier, _payload) = installed();
        std::fs::remove_file(layer.root.join(ENVELOPE_FILE)).unwrap();
        let err = export(&store, &layer, &tmp.path().join("archive"), "test-platform").unwrap_err();
        assert!(matches!(err, ArchiveError::NoEnvelope { .. }), "got: {err}");
    }

    // rivet: verifies REQ-SCOPE-001
    #[test]
    fn export_does_not_mutate_the_core() {
        let (tmp, store, layer, _verifier, _payload) = installed();
        let snapshot = |root: &Path| -> Vec<(String, Vec<u8>)> {
            let mut out = Vec::new();
            let mut stack = vec![root.to_path_buf()];
            while let Some(dir) = stack.pop() {
                for e in std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()) {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
                    }
                }
            }
            out.sort();
            out
        };
        let before = snapshot(store.root());
        export(&store, &layer, &tmp.path().join("archive"), "test-platform").unwrap();
        assert_eq!(before, snapshot(store.root()));
    }
}
