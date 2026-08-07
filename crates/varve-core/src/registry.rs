//! The public-registry source (REQ-REGISTRY-001, DD-003).
//!
//! Anonymous pull over the OCI distribution API: token → manifest → blobs.
//! On a registry a layer is one OCI artifact manifest whose `layers[]` are
//! the DSSE envelope, the manifest payload, and the tool blobs, each
//! annotated; the tag is the layer name. Tags are mutable and therefore
//! DISCOVERY ONLY — everything this source returns passes the same pipeline
//! (signature against the trust root, payload digest, per-blob digests,
//! anti-rollback) as every other source. The registry decides availability;
//! it has no voice in acceptance.
//!
//! Pull-only by design: publishing happens in CI with standard tooling
//! (`oras push`), which never joins the client trust path.

use crate::source::{LayerRef, LayerSource, SourceError};

/// artifactType of a layer artifact manifest on a registry.
pub const LAYER_ARTIFACT_TYPE: &str = "application/vnd.pulseengine.varve.layer.v1+json";
/// Annotation marking the envelope entry in `layers[]`.
pub const ANN_ROLE: &str = "eu.pulseengine.varve.role";
pub const ROLE_ENVELOPE: &str = "envelope";
pub const ROLE_PAYLOAD: &str = "payload";

/// An `oci://` reference: registry host + repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRef {
    pub registry: String,
    pub repository: String,
    /// http for the test double, https everywhere real. Never configurable
    /// from a pin — parsed from the explicit `--from` reference only.
    pub scheme: String,
}

impl RegistryRef {
    /// Parse `oci://ghcr.io/org/repo` (https) or `oci+http://host:port/repo`
    /// (test double / air-gapped mirror on a trusted network — acceptance is
    /// unaffected either way; transport privacy is not what the trust model
    /// rests on).
    pub fn parse(reference: &str) -> Result<Self, SourceError> {
        let (scheme, rest) = if let Some(rest) = reference.strip_prefix("oci://") {
            ("https", rest)
        } else if let Some(rest) = reference.strip_prefix("oci+http://") {
            ("http", rest)
        } else {
            return Err(SourceError::Transport(format!(
                "'{reference}' is not an oci:// reference"
            )));
        };
        let (registry, repository) = rest.split_once('/').ok_or_else(|| {
            SourceError::Transport(format!("'{reference}' has no repository path"))
        })?;
        if registry.is_empty() || repository.is_empty() {
            return Err(SourceError::Transport(format!(
                "'{reference}' has an empty registry or repository"
            )));
        }
        Ok(RegistryRef {
            registry: registry.to_string(),
            repository: repository.trim_end_matches('/').to_string(),
            scheme: scheme.to_string(),
        })
    }
}

/// Pull-only OCI distribution client implementing `LayerSource`.
#[derive(Debug)]
pub struct RegistrySource {
    reference: RegistryRef,
    agent: ureq::Agent,
    token: std::cell::RefCell<Option<String>>,
}

impl RegistrySource {
    pub fn new(reference: RegistryRef) -> Self {
        RegistrySource {
            reference,
            agent: ureq::Agent::new_with_defaults(),
            token: std::cell::RefCell::new(None),
        }
    }

    pub fn parse(reference: &str) -> Result<Self, SourceError> {
        Ok(Self::new(RegistryRef::parse(reference)?))
    }

    fn base(&self) -> String {
        format!(
            "{}://{}/v2/{}",
            self.reference.scheme, self.reference.registry, self.reference.repository
        )
    }

    /// Anonymous bearer token (the GHCR dance). 401-less registries (the
    /// test double) work without one.
    fn ensure_token(&self) -> Option<String> {
        if let Some(token) = self.token.borrow().clone() {
            return Some(token);
        }
        let url = format!(
            "{}://{}/token?service={}&scope=repository:{}:pull",
            self.reference.scheme,
            self.reference.registry,
            self.reference.registry,
            self.reference.repository
        );
        let token = self
            .agent
            .get(&url)
            .call()
            .ok()
            .and_then(|mut resp| resp.body_mut().read_to_string().ok())
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .and_then(|json| json["token"].as_str().map(str::to_string));
        *self.token.borrow_mut() = token.clone();
        token
    }

    fn get(&self, url: &str, accept: &str) -> Result<Vec<u8>, SourceError> {
        let mut request = self.agent.get(url).header("Accept", accept);
        if let Some(token) = self.ensure_token() {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        match request.call() {
            Ok(mut resp) => resp
                .body_mut()
                .with_config()
                // Tool binaries are tens of MB; ureq's 10 MiB default would
                // reject them (caught on the first real GHCR pull). 8 GiB is
                // a sanity bound, not a promise — digests still decide.
                .limit(8 * 1024 * 1024 * 1024)
                .read_to_vec()
                .map_err(|e| SourceError::Transport(e.to_string())),
            Err(ureq::Error::StatusCode(404)) => Err(SourceError::NotFound(url.to_string())),
            Err(e) => Err(SourceError::Transport(e.to_string())),
        }
    }

    /// Fetch the OCI artifact manifest for a tag and return the envelope
    /// blob it references. Untrusted discovery: the pipeline re-verifies.
    fn envelope_for_tag(&self, tag: &str) -> Result<Vec<u8>, SourceError> {
        let manifest_bytes = self.get(
            &format!("{}/manifests/{tag}", self.base()),
            "application/vnd.oci.image.manifest.v1+json",
        )?;
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| SourceError::Transport(format!("artifact manifest: {e}")))?;
        let envelope_digest = manifest["layers"]
            .as_array()
            .and_then(|layers| {
                layers
                    .iter()
                    .find(|l| l["annotations"][ANN_ROLE] == ROLE_ENVELOPE)
            })
            .and_then(|l| l["digest"].as_str())
            .ok_or_else(|| {
                SourceError::NotFound(format!("tag {tag} carries no varve envelope layer"))
            })?;
        self.fetch_blob(envelope_digest)
    }

    fn tags(&self) -> Result<Vec<String>, SourceError> {
        let bytes = self.get(&format!("{}/tags/list", self.base()), "application/json")?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| SourceError::Transport(format!("tags/list: {e}")))?;
        Ok(json["tags"]
            .as_array()
            .map(|tags| {
                tags.iter()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }
}

impl LayerSource for RegistrySource {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        match layer {
            LayerRef::Name(id) => self.envelope_for_tag(&id.to_string()),
            LayerRef::Digest(digest) => {
                // A pin's digest names the PAYLOAD, not any registry object;
                // tags are enumerated and each candidate's payload digest
                // compared. Discovery only — verification decides.
                for tag in self.tags()? {
                    if let Ok(envelope) = self.envelope_for_tag(&tag)
                        && let Ok(text) = std::str::from_utf8(&envelope)
                        && let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text)
                        && let Ok(payload) = env.payload_bytes()
                        && &crate::store::manifest_digest(&payload) == digest
                    {
                        return Ok(envelope);
                    }
                }
                Err(SourceError::NotFound(digest.clone()))
            }
        }
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        let bytes = self.get(
            &format!("{}/blobs/{digest}", self.base()),
            "application/octet-stream",
        )?;
        // Transport-level integrity: a registry answering a digest request
        // with other bytes is broken or hostile either way. The pipeline
        // re-checks against the SIGNED digests; this check just fails fast.
        if crate::store::manifest_digest(&bytes) != digest {
            return Err(SourceError::Transport(format!(
                "registry returned wrong bytes for {digest}"
            )));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-REGISTRY-001
    #[test]
    fn oci_references_parse_and_bad_ones_are_refused() {
        let r = RegistryRef::parse("oci://ghcr.io/pulseengine/layers").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "pulseengine/layers");
        assert_eq!(r.scheme, "https");
        let t = RegistryRef::parse("oci+http://127.0.0.1:5000/test/repo").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.registry, "127.0.0.1:5000");
        for bad in [
            "https://ghcr.io/x",
            "oci://",
            "oci://hostonly",
            "oci://host/",
        ] {
            assert!(RegistryRef::parse(bad).is_err(), "{bad} must not parse");
        }
    }
}
