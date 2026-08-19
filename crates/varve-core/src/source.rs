//! Sources — where bytes come from. Pluggable by design; trusted by nobody
//! (DD-003).
//!
//! A source can *obtain* bytes: a manifest by layer name or digest, a blob by
//! digest. It has no voice in whether those bytes are *accepted* — signature
//! and digest verification run against the trust root after every fetch, so
//! swapping the source can change availability, never a verdict. The install
//! pipeline (`crate::install`) enforces this by construction: nothing a
//! `LayerSource` returns reaches the core without passing the same checks.

use crate::layer::LayerId;

/// UNTRUSTED discovery: does `bytes` look like a manifest for `id`, either
/// raw or wrapped in a DSSE envelope? Sources use this to answer name/digest
/// lookups; it grants nothing — the install pipeline re-verifies signature
/// and digest on whatever a source returns.
fn discovery_matches(bytes: &[u8], layer: &LayerRef) -> bool {
    use crate::manifest::LayerManifest;
    let candidate_payloads = || -> Vec<Vec<u8>> {
        let mut out = vec![bytes.to_vec()];
        if let Ok(text) = std::str::from_utf8(bytes)
            && let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text)
            && let Ok(payload) = env.payload_bytes()
        {
            out.push(payload);
        }
        out
    };
    match layer {
        LayerRef::Digest(digest) => candidate_payloads()
            .iter()
            .any(|p| &crate::store::manifest_digest(p) == digest),
        LayerRef::Name(id) => candidate_payloads()
            .iter()
            .any(|p| LayerManifest::parse(p).is_ok_and(|m| &m.layer == id)),
    }
}

/// Reference to a layer a source should produce the manifest for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerRef {
    /// By name — discovery; the returned manifest's own annotations and
    /// digest are then checked against the pin.
    Name(LayerId),
    /// By exact manifest digest (`sha256:<hex>`).
    Digest(String),
}

/// Failures a source may report. `NotFound` is honest absence; everything
/// else is transport trouble. There is deliberately no way for a source to
/// report "trust me" — trust is not its department.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source has no layer matching {0}")]
    NotFound(String),
    /// Absence with a KNOWN cause: the source is an archive of one platform and
    /// the caller wants another. Distinct from `NotFound` because the operator's
    /// next move is different — nothing is corrupt, nothing is missing from the
    /// archive that belongs in it, and no amount of re-copying the media will
    /// help (varve#80).
    #[error(
        "this archive carries no payload for {wanted} — it was archived for {archived_for}, and \
         `varve archive` exports only the payloads the archiving machine installed, so it holds \
         {archived_for} payloads and nothing else (blob {digest} is not in it). Install the layer \
         on a machine running {wanted} and archive it there to carry {wanted} across the gap."
    )]
    NoPayloadForPlatform {
        digest: String,
        wanted: String,
        archived_for: String,
    },
    #[error("source transport error: {0}")]
    Transport(String),
}

/// Where bytes come from. Implementations ship in varve (public registry,
/// archived core, test doubles); the trait is the seam an entitlement
/// plug-in would use — and the reason none of them can influence acceptance.
pub trait LayerSource {
    /// Fetch the manifest bytes for a layer reference.
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError>;
    /// Fetch a blob (a tool binary) by its digest (`sha256:<hex>`).
    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError>;
    /// Fetch the baseline line-status DSSE envelope this source carries
    /// beside the layer, if any (REQ-STATUS-DIST-001). Returns the opaque
    /// envelope bytes — the source is *not* trusted to have verified them;
    /// the caller re-verifies against the trust root before caching. A
    /// source that carries no baseline returns `Ok(None)`, which is not an
    /// error: line-status is updatable evidence, absent on some layers.
    fn fetch_line_status(&self, _layer: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(None)
    }

    /// Fetch the realm's signed line-index envelope for this line, if the
    /// source carries one (REQ-INDEXAUTH-001). Same contract as
    /// `fetch_line_status`: opaque bytes, re-verified by the caller against
    /// the trust root. The source is never trusted to have checked it — it is
    /// precisely the party this document exists to constrain.
    fn fetch_line_index(&self, _line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(None)
    }

    /// Fetch the attestations this source carries beside the layer as
    /// referrer artifacts (REQ-ATTEST-002). Same contract as
    /// `fetch_line_status`: OPAQUE, UNTRUSTED bytes. The source is never
    /// trusted to have verified a statement — it is the party that would
    /// benefit from a forged one — so the caller persists them verbatim and
    /// `varve verify` re-checks each against the trust root.
    ///
    /// A source carrying none returns `Ok(vec![])`, which is not an error: most
    /// layers carry no third-party evidence, and demanding some would make
    /// varve's availability depend on other people's publishing habits.
    fn fetch_attestations(
        &self,
        _layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        Ok(Vec::new())
    }

    /// The layer ids this source is willing to serve for a line. Used to
    /// detect OMISSION against the signed index. A source that cannot
    /// enumerate returns `Ok(None)` — distinct from `Ok(Some(vec![]))`, which
    /// means "I enumerate, and I have nothing", and would flag every indexed
    /// layer as hidden.
    fn served_layers(&self, _line: &str) -> Result<Option<Vec<String>>, SourceError> {
        Ok(None)
    }
}

/// In-memory source — the test double, and the reference for how little a
/// source is trusted to do.
#[derive(Debug, Default)]
pub struct MemorySource {
    manifests: Vec<Vec<u8>>,
    blobs: std::collections::BTreeMap<String, Vec<u8>>,
    line_status: Option<Vec<u8>>,
    line_index: Option<Vec<u8>>,
    served: Option<Vec<String>>,
    attestations: Vec<crate::attestcarry::CarriedAttestation>,
}

impl MemorySource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_manifest(mut self, bytes: &[u8]) -> Self {
        self.manifests.push(bytes.to_vec());
        self
    }

    pub fn with_blob(mut self, digest: &str, bytes: &[u8]) -> Self {
        self.blobs.insert(digest.to_string(), bytes.to_vec());
        self
    }

    /// Attach a baseline line-status envelope the source carries beside the
    /// layer (REQ-STATUS-DIST-001).
    /// Carry a signed line index (REQ-INDEXAUTH-001).
    pub fn with_line_index(mut self, envelope: &[u8]) -> Self {
        self.line_index = Some(envelope.to_vec());
        self
    }

    /// What this source admits to serving. Setting it makes the source
    /// enumerable, which is what lets omission be detected — a source that
    /// never sets it cannot be accused of hiding.
    pub fn serving(mut self, layers: &[&str]) -> Self {
        self.served = Some(layers.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn with_line_status(mut self, envelope: &[u8]) -> Self {
        self.line_status = Some(envelope.to_vec());
        self
    }

    /// Carry an attestation beside the layer (REQ-ATTEST-002). The statement's
    /// digest is derived from the bytes handed over, not declared: a source
    /// that could name its own content addresses would be trusted about
    /// something, and it is trusted about nothing.
    pub fn with_attestation(mut self, statement: &[u8], attested_bytes: &[u8]) -> Self {
        self.attestations
            .push(crate::attestcarry::CarriedAttestation {
                statement_digest: crate::store::manifest_digest(statement),
                statement: statement.to_vec(),
                bytes: attested_bytes.to_vec(),
            });
        self
    }
}

/// Directory-shaped source: `<root>/manifests/sha256-<hex>` and
/// `<root>/blobs/sha256-<hex>`. The reading half of the archived core —
/// and, in tests, the second transport for the two-sources-same-verdict
/// kill-criterion.
#[derive(Debug)]
pub struct DirSource {
    root: std::path::PathBuf,
}

impl DirSource {
    pub fn at(root: impl Into<std::path::PathBuf>) -> Self {
        DirSource { root: root.into() }
    }

    /// Write a manifest + blobs into the directory layout (the producing
    /// side, used by tests and by `archive` later).
    pub fn put(&self, manifest_bytes: &[u8], blobs: &[(&str, &[u8])]) -> std::io::Result<()> {
        let manifests = self.root.join("manifests");
        let blob_dir = self.root.join("blobs");
        std::fs::create_dir_all(&manifests)?;
        std::fs::create_dir_all(&blob_dir)?;
        let digest = crate::store::manifest_digest(manifest_bytes);
        std::fs::write(manifests.join(digest.replace(':', "-")), manifest_bytes)?;
        for (digest, bytes) in blobs {
            std::fs::write(blob_dir.join(digest.replace(':', "-")), bytes)?;
        }
        Ok(())
    }
}

impl LayerSource for DirSource {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        let dir = self.root.join("manifests");
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| SourceError::Transport(format!("{}: {e}", dir.display())))?;
        for entry in entries.filter_map(|e| e.ok()) {
            let bytes =
                std::fs::read(entry.path()).map_err(|e| SourceError::Transport(e.to_string()))?;
            if discovery_matches(&bytes, layer) {
                return Ok(bytes);
            }
        }
        Err(SourceError::NotFound(format!("{layer:?}")))
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        let path = self.root.join("blobs").join(digest.replace(':', "-"));
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(SourceError::NotFound(digest.to_string()))
            }
            Err(e) => Err(SourceError::Transport(e.to_string())),
        }
    }
}

impl LayerSource for MemorySource {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        self.manifests
            .iter()
            .find(|bytes| discovery_matches(bytes, layer))
            .cloned()
            .ok_or_else(|| SourceError::NotFound(format!("{layer:?}")))
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        self.blobs
            .get(digest)
            .cloned()
            .ok_or_else(|| SourceError::NotFound(digest.to_string()))
    }

    fn fetch_line_index(&self, _line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(self.line_index.clone())
    }

    fn served_layers(&self, _line: &str) -> Result<Option<Vec<String>>, SourceError> {
        Ok(self.served.clone())
    }

    fn fetch_line_status(&self, _layer: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
        Ok(self.line_status.clone())
    }

    fn fetch_attestations(
        &self,
        _layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        Ok(self.attestations.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_source_carrying_a_baseline_line_status_yields_it() {
        let envelope = b"an-opaque-dsse-envelope";
        let source = MemorySource::new().with_line_status(envelope);
        let got = source
            .fetch_line_status(&LayerRef::Name("2026.07.0".parse().unwrap()))
            .unwrap();
        assert_eq!(
            got.as_deref(),
            Some(envelope.as_slice()),
            "a source that carries a baseline line-status must hand it back for caching"
        );
    }

    // rivet: verifies REQ-ATTEST-002
    #[test]
    fn a_source_carrying_attestations_hands_over_both_blobs_and_one_without_is_not_an_error() {
        let source = MemorySource::new().with_attestation(b"a-statement-envelope", b"the-evidence");
        let got = source
            .fetch_attestations(&LayerRef::Name("2026.07.0".parse().unwrap()))
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].bytes, b"the-evidence",
            "the attested bytes must travel beside the statement — a claim with nothing to \
             check it against is what crossing the air gap must never produce"
        );
        assert_eq!(
            got[0].statement_digest,
            crate::store::manifest_digest(b"a-statement-envelope"),
            "the digest is derived from the bytes; a source never declares its own address"
        );

        // Absence is emptiness, not failure: most layers carry no third-party
        // evidence, and requiring some would make availability depend on other
        // people's publishing habits.
        assert!(
            MemorySource::new()
                .fetch_attestations(&LayerRef::Name("2026.07.0".parse().unwrap()))
                .unwrap()
                .is_empty()
        );
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_source_without_a_line_status_is_not_an_error() {
        let source = MemorySource::new();
        let got = source
            .fetch_line_status(&LayerRef::Name("2026.07.0".parse().unwrap()))
            .unwrap();
        assert_eq!(
            got, None,
            "an absent line-status is Ok(None), never an error"
        );
    }
}
