//! The core — the local content-addressed store (REQ-COEXIST-001, DD-006).
//!
//! ```text
//! <root>/core/sha256-<hex>/   # one layer, keyed by its manifest digest
//!   layer.json                # the layer manifest, kept for verify/archive
//!   bin/<tool>                # the tools
//! ```
//!
//! Keyed by manifest digest, so layers coexist by construction: installing
//! August cannot disturb July, and selecting either costs no download.
//! The store is written at lay-down time and read-only ever after — nothing
//! in resolution or listing mutates it (REQ-SCOPE-001's read-only half).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::layer::LayerId;

/// The minimal slice of a layer manifest the store needs: the annotations
/// carrying the layer identity. Everything else is preserved verbatim in
/// `layer.json` for later verification and archiving.
#[derive(Debug, Clone, Deserialize)]
struct ManifestEnvelope {
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

/// One layer present in the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledLayer {
    /// `sha256:<hex>` of the manifest bytes — the store key.
    pub digest: String,
    /// The layer identity from the manifest annotations.
    pub layer: LayerId,
    /// The channel annotation (`qualified` / `rolling`), verbatim.
    pub channel: String,
    /// Root directory of this layer in the core.
    pub root: PathBuf,
}

/// The core store rooted at a directory (defaults to `~/.varve` in the CLI;
/// injectable here so tests and future tools own their roots).
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

/// Store failures. Note what is *absent*: there is no variant for "fell back
/// to another layer" — the API cannot express fallback.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: layer.json is not a valid layer manifest: {reason}")]
    BadManifest { path: String, reason: String },
}

impl Store {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lay a layer down in the core from its manifest bytes and tool
    /// binaries. Returns the manifest digest (`sha256:<hex>`) — the store key.
    ///
    /// This is the write path shared by the future installer and by tests;
    /// nothing else writes to the core.
    pub fn lay_down(
        &self,
        manifest_bytes: &[u8],
        tools: &[(&str, &[u8])],
    ) -> Result<String, StoreError> {
        let digest = manifest_digest(manifest_bytes);
        let entry = self.core_dir().join(digest.replace(':', "-"));
        let io = |path: &Path, source: std::io::Error| StoreError::Io {
            path: path.display().to_string(),
            source,
        };
        let bin = entry.join("bin");
        std::fs::create_dir_all(&bin).map_err(|e| io(&bin, e))?;
        let manifest_path = entry.join("layer.json");
        std::fs::write(&manifest_path, manifest_bytes).map_err(|e| io(&manifest_path, e))?;
        for (name, bytes) in tools {
            let path = bin.join(name);
            std::fs::write(&path, bytes).map_err(|e| io(&path, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| io(&path, e))?;
            }
        }
        Ok(digest)
    }

    /// Every layer present in the core, in stable (digest) order.
    pub fn list(&self) -> Result<Vec<InstalledLayer>, StoreError> {
        let core = self.core_dir();
        if !core.exists() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = std::fs::read_dir(&core)
            .map_err(|e| StoreError::Io {
                path: core.display().to_string(),
                source: e,
            })?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("sha256-"))
            .collect();
        names.sort();
        names
            .into_iter()
            .map(|name| self.read_entry(&name.replacen('-', ":", 1)))
            .collect()
    }

    /// Look up a layer by manifest digest (`sha256:<hex>`).
    pub fn get(&self, digest: &str) -> Result<Option<InstalledLayer>, StoreError> {
        let entry = self.core_dir().join(digest.replace(':', "-"));
        if !entry.join("layer.json").is_file() {
            return Ok(None);
        }
        self.read_entry(digest).map(Some)
    }

    /// Path of one tool's binary within an installed layer, if present.
    pub fn tool_path(&self, layer: &InstalledLayer, tool: &str) -> Option<PathBuf> {
        let path = layer.root.join("bin").join(tool);
        path.is_file().then_some(path)
    }

    fn core_dir(&self) -> PathBuf {
        self.root.join("core")
    }

    fn read_entry(&self, digest: &str) -> Result<InstalledLayer, StoreError> {
        let root = self.core_dir().join(digest.replace(':', "-"));
        let manifest_path = root.join("layer.json");
        let bad = |reason: String| StoreError::BadManifest {
            path: manifest_path.display().to_string(),
            reason,
        };
        let bytes = std::fs::read(&manifest_path).map_err(|source| StoreError::Io {
            path: manifest_path.display().to_string(),
            source,
        })?;
        let envelope: ManifestEnvelope =
            serde_json::from_slice(&bytes).map_err(|e| bad(e.to_string()))?;
        let layer_str = envelope
            .annotations
            .get("eu.pulseengine.varve.layer")
            .ok_or_else(|| bad("missing eu.pulseengine.varve.layer annotation".into()))?;
        let layer: LayerId = layer_str
            .parse()
            .map_err(|e: crate::layer::LayerIdError| bad(e.to_string()))?;
        let channel = envelope
            .annotations
            .get("eu.pulseengine.varve.channel")
            .cloned()
            .unwrap_or_default();
        Ok(InstalledLayer {
            digest: digest.to_string(),
            layer,
            channel,
            root,
        })
    }
}

/// Compute the store key for manifest bytes: `sha256:<hex>`.
pub fn manifest_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// A minimal, valid layer manifest for tests.
    pub fn manifest(layer: &str, channel: &str) -> Vec<u8> {
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}",
    "eu.pulseengine.varve.channel": "{channel}"
  }},
  "manifests": []
}}"#
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path().join("varve-root"));
        (tmp, store)
    }

    // rivet: verifies REQ-COEXIST-001
    #[test]
    fn two_layers_coexist_and_are_independently_addressable() {
        let (_tmp, store) = store();
        let july = fixtures::manifest("2026.07.0", "qualified");
        let august = fixtures::manifest("2026.08.0", "qualified");
        let d_july = store.lay_down(&july, &[("synth", b"july-synth")]).unwrap();
        let d_august = store
            .lay_down(&august, &[("synth", b"august-synth")])
            .unwrap();
        assert_ne!(d_july, d_august);

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);

        let july_entry = store.get(&d_july).unwrap().unwrap();
        let august_entry = store.get(&d_august).unwrap().unwrap();
        assert_eq!(july_entry.layer.to_string(), "2026.07.0");
        assert_eq!(august_entry.layer.to_string(), "2026.08.0");

        // The same tool name resolves to different bytes per layer — the
        // wohl-on-July-while-relay-on-August afternoon, on one machine.
        let july_synth = store.tool_path(&july_entry, "synth").unwrap();
        let august_synth = store.tool_path(&august_entry, "synth").unwrap();
        assert_eq!(std::fs::read(july_synth).unwrap(), b"july-synth");
        assert_eq!(std::fs::read(august_synth).unwrap(), b"august-synth");
    }

    // rivet: verifies REQ-COEXIST-001
    #[test]
    fn store_key_is_the_manifest_digest() {
        let (_tmp, store) = store();
        let bytes = fixtures::manifest("2026.07.0", "qualified");
        let digest = store.lay_down(&bytes, &[]).unwrap();
        assert_eq!(digest, manifest_digest(&bytes));
        let entry = store.get(&digest).unwrap().unwrap();
        assert!(
            entry
                .root
                .ends_with(format!("core/{}", digest.replace(':', "-"))),
            "entry rooted at digest-keyed dir, got {}",
            entry.root.display()
        );
        // layer.json preserved verbatim for verify/archive.
        assert_eq!(std::fs::read(entry.root.join("layer.json")).unwrap(), bytes);
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn missing_layer_is_none_not_an_invention() {
        let (_tmp, store) = store();
        assert_eq!(
            store
                .get("sha256:0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            None
        );
        assert_eq!(store.list().unwrap(), vec![]);
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn missing_tool_in_an_installed_layer_is_none() {
        let (_tmp, store) = store();
        let bytes = fixtures::manifest("2026.07.0", "qualified");
        let digest = store.lay_down(&bytes, &[("rivet", b"r")]).unwrap();
        let entry = store.get(&digest).unwrap().unwrap();
        assert!(store.tool_path(&entry, "rivet").is_some());
        assert_eq!(store.tool_path(&entry, "synth"), None);
    }
}
