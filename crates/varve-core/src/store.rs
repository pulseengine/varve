//! The core — the local content-addressed store (REQ-COEXIST-001, DD-006).
//!
//! ```text
//! <root>/core/sha256-<hex>/          # one layer, keyed by its manifest digest
//!   layer.json                       # the layer manifest, kept for verify/archive
//!   bin/<tool>                       # the tools — dispatched by name
//!   payloads/<name>/<version>        # everything else — held by name AND version
//! ```
//!
//! The split is REQ-STORE-002. A tool is dispatched by name (`varve which`,
//! `varve run`, the argv[0] shims), so a name must resolve to exactly one
//! binary and `bin/<name>` is right. A crate, a WIT package, an SDK or a wasm
//! component is not dispatched at all, and a dependency graph ordinarily holds
//! several versions of one name — laying those down by name alone made the
//! second entry silently overwrite the first's bytes.
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
use crate::manifest::ManifestEntry;

/// The directory holding non-dispatchable payloads, keyed by name AND version.
pub const PAYLOAD_DIR: &str = "payloads";

/// One payload to lay down. What it *is* decides where it lands: a dispatchable
/// payload is placed by name, everything else by name and version.
#[derive(Debug, Clone, Copy)]
pub struct Payload<'a> {
    pub name: &'a str,
    /// The version from the signed manifest. Absent only for pre-kind layers
    /// and for tools, which are not keyed by version.
    pub version: Option<&'a str>,
    /// Dispatched by name — see `PayloadKind::is_dispatchable`.
    pub dispatchable: bool,
    pub bytes: &'a [u8],
}

impl<'a> Payload<'a> {
    /// A dispatchable tool binary: `bin/<name>`, the original layout.
    pub fn tool(name: &'a str, bytes: &'a [u8]) -> Self {
        Payload {
            name,
            version: None,
            dispatchable: true,
            bytes,
        }
    }
}

/// Is this manifest entry dispatched by name (REQ-STORE-002 clause 1)?
///
/// An entry with no kind annotation is a `tool` (pre-kind layers), so it is.
/// An entry whose kind THIS build does not recognise is not: varve cannot
/// dispatch what it cannot classify, and placing an unknown kind by name alone
/// is exactly the overwrite this requirement exists to prevent — a newer
/// varve's versioned kind must not collapse onto one path here.
pub fn entry_is_dispatchable(entry: &ManifestEntry) -> bool {
    matches!(entry.kind(), Ok(kind) if kind.is_dispatchable())
}

/// The version a manifest entry declares, if any.
pub fn entry_version(entry: &ManifestEntry) -> Option<&str> {
    entry
        .annotations
        .get("eu.pulseengine.tool.version")
        .map(String::as_str)
}

/// Refuse a name or version that is not a single, safe path component. These
/// strings come out of a signed manifest, but "signed" means "attributable",
/// not "benign": a realm root signing `../../evil` must not be able to place
/// bytes outside the layer it is laying down.
fn safe_component(what: &'static str, value: &str) -> Result<(), StoreError> {
    let bad = |why: &str| {
        Err(StoreError::UnsafeComponent {
            what,
            value: value.to_string(),
            why: why.to_string(),
        })
    };
    if value.is_empty() {
        return bad("empty");
    }
    if value == "." || value == ".." {
        return bad("a relative path element");
    }
    if let Some(c) = value
        .chars()
        .find(|c| matches!(c, '/' | '\\' | '\0') || c.is_control())
    {
        return bad(&format!("contains {c:?}"));
    }
    Ok(())
}

/// Where a payload lives inside a layer root, relative to it (clause 2).
///
/// Dispatchable → `bin/<name>`, unchanged and byte-compatible with every layer
/// installed before this requirement. Non-dispatchable with a version →
/// `payloads/<name>/<version>`, so `serde@1.0.200` and `serde@1.0.210` are two
/// files, not one file written twice. A non-dispatchable payload with NO
/// version keeps the legacy `bin/<name>` place — that is what a pre-kind layer
/// looks like on disk, and the collision guard in `lay_down` still refuses to
/// let two of them land on one path.
pub fn payload_rel_path(
    dispatchable: bool,
    name: &str,
    version: Option<&str>,
) -> Result<PathBuf, StoreError> {
    safe_component("payload name", name)?;
    match (dispatchable, version) {
        (false, Some(version)) => {
            safe_component("payload version", version)?;
            Ok(PathBuf::from(PAYLOAD_DIR).join(name).join(version))
        }
        _ => Ok(PathBuf::from("bin").join(name)),
    }
}

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
    #[error("{what} {value:?} is not a usable path component ({why}) — refusing to lay it down")]
    UnsafeComponent {
        what: &'static str,
        value: String,
        why: String,
    },
    #[error(
        "two payloads of this layer both claim {path} ('{first}' and '{second}') — refusing to \
         lay one down over the other. A layer may hold several versions of one name, but each \
         must be a distinct payload; two entries with one identity would mean the wrong bytes \
         land under the right name."
    )]
    Collision {
        path: String,
        first: String,
        second: String,
    },
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
    /// The dispatchable-only convenience over [`Store::lay_down_payloads`],
    /// which is the single writer.
    pub fn lay_down(
        &self,
        manifest_bytes: &[u8],
        tools: &[(&str, &[u8])],
    ) -> Result<String, StoreError> {
        let payloads: Vec<Payload<'_>> = tools
            .iter()
            .map(|(name, bytes)| Payload::tool(name, bytes))
            .collect();
        self.lay_down_payloads(manifest_bytes, &payloads)
    }

    /// Lay a layer down in the core from its manifest bytes and its payloads.
    /// Returns the manifest digest (`sha256:<hex>`) — the store key.
    ///
    /// This is the write path shared by the installer and by tests; nothing
    /// else writes to the core. Two payloads that would land on ONE path are
    /// refused (`StoreError::Collision`) rather than written in turn: relaxing
    /// the deposit-time identity check without this would turn a clean error
    /// into silent data loss — the second entry's bytes under the first's name,
    /// with verification then failing on the *other* entry and nothing
    /// explaining why (REQ-STORE-002).
    pub fn lay_down_payloads(
        &self,
        manifest_bytes: &[u8],
        payloads: &[Payload<'_>],
    ) -> Result<String, StoreError> {
        let digest = manifest_digest(manifest_bytes);
        let entry = self.core_dir().join(digest.replace(':', "-"));
        let io = |path: &Path, source: std::io::Error| StoreError::Io {
            path: path.display().to_string(),
            source,
        };

        // Resolve every destination BEFORE writing anything: an unusable name
        // or a collision must leave the core untouched, not half-written.
        let mut placed: BTreeMap<PathBuf, String> = BTreeMap::new();
        let mut plan: Vec<(PathBuf, &Payload<'_>)> = Vec::new();
        for payload in payloads {
            let rel = payload_rel_path(payload.dispatchable, payload.name, payload.version)?;
            let who = match payload.version {
                Some(v) => format!("{}@{v}", payload.name),
                None => payload.name.to_string(),
            };
            if let Some(first) = placed.get(&rel) {
                return Err(StoreError::Collision {
                    path: rel.display().to_string(),
                    first: first.clone(),
                    second: who,
                });
            }
            placed.insert(rel.clone(), who);
            plan.push((rel, payload));
        }

        let bin = entry.join("bin");
        std::fs::create_dir_all(&bin).map_err(|e| io(&bin, e))?;
        let manifest_path = entry.join("layer.json");
        std::fs::write(&manifest_path, manifest_bytes).map_err(|e| io(&manifest_path, e))?;
        for (rel, payload) in plan {
            let path = entry.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
            }
            std::fs::write(&path, payload.bytes).map_err(|e| io(&path, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Only what is dispatched gets the execute bit. A `.crate`
                // tarball or a WIT package is data varve hands to another tool.
                let mode = if payload.dispatchable { 0o755 } else { 0o644 };
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
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
    /// The varve root this store lives under: itself, or the parent of a realm
    /// partition (`<root>/realms/<fingerprint>`).
    pub fn varve_root(&self) -> std::path::PathBuf {
        let root = self.root();
        if root
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|n| n == "realms")
        {
            root.parent()
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| root.to_path_buf())
        } else {
            root.to_path_buf()
        }
    }

    /// Find a layer by digest in ANY partition under this varve root — the
    /// top-level core or any realm's. A digest is content-addressed, so where
    /// it happens to live does not change what it is; a cross-realm composition
    /// include is installed under the INCLUDED realm's fingerprint, not the
    /// including project's, and looking only in one partition reported it as
    /// missing while `list` showed it installed (REQ-STORE-001).
    ///
    /// Locating a layer is not accepting it: the caller still verifies it
    /// against the trust root of the realm that vouches for it.
    pub fn find_anywhere(
        &self,
        digest: &str,
    ) -> Result<Option<(Store, InstalledLayer)>, StoreError> {
        if let Some(entry) = self.get(digest)? {
            return Ok(Some((self.clone(), entry)));
        }
        let root = self.varve_root();
        // The top-level core, then every realm partition, in a stable order.
        let mut candidates = vec![Store::at(&root)];
        if let Ok(rd) = std::fs::read_dir(root.join("realms")) {
            let mut parts: Vec<std::path::PathBuf> =
                rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            parts.sort();
            candidates.extend(parts.into_iter().map(Store::at));
        }
        for candidate in candidates {
            if candidate.root() == self.root() {
                continue;
            }
            if let Some(entry) = candidate.get(digest)? {
                return Ok(Some((candidate, entry)));
            }
        }
        Ok(None)
    }

    pub fn get(&self, digest: &str) -> Result<Option<InstalledLayer>, StoreError> {
        let entry = self.core_dir().join(digest.replace(':', "-"));
        if !entry.join("layer.json").is_file() {
            return Ok(None);
        }
        self.read_entry(digest).map(Some)
    }

    /// Path of one tool's binary within an installed layer, if present.
    /// Dispatch is by name, so this takes a bare name — see `entry_path` for
    /// payloads that are held rather than dispatched.
    pub fn tool_path(&self, layer: &InstalledLayer, tool: &str) -> Option<PathBuf> {
        let path = layer.root.join("bin").join(tool);
        path.is_file().then_some(path)
    }

    /// Path of the bytes one MANIFEST ENTRY refers to within an installed
    /// layer, if present. This is the read side of `lay_down_payloads`, and
    /// every consumer of a layer's bytes (`verify`, `archive`, the export
    /// adapters) goes through it so the two cannot drift.
    ///
    /// Backward compatibility: a layer installed BEFORE REQ-STORE-002 holds its
    /// crates at `bin/<name>`, so a versioned payload that is not at its
    /// versioned path falls back there. Such a layer can hold only one version
    /// per name — the old deposit check made sure of it — so the fallback is
    /// unambiguous.
    pub fn entry_path(&self, layer: &InstalledLayer, entry: &ManifestEntry) -> Option<PathBuf> {
        let name = entry.annotations.get("eu.pulseengine.tool")?;
        let dispatchable = entry_is_dispatchable(entry);
        let rel = payload_rel_path(dispatchable, name, entry_version(entry)).ok()?;
        let path = layer.root.join(rel);
        if path.is_file() {
            return Some(path);
        }
        (!dispatchable)
            .then(|| layer.root.join("bin").join(name))
            .filter(|legacy| legacy.is_file())
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

    /// A layer from before channel annotations existed. The resolver's channel
    /// guard must exempt it: a pre-channel layer states no channel, so it
    /// contradicts no pin.
    pub fn manifest_without_channel(layer: &str) -> Vec<u8> {
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{layer}"
  }},
  "manifests": []
}}"#
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod partition_tests {
    use super::*;

    // rivet: verifies REQ-STORE-001
    #[test]
    fn a_layer_is_found_in_any_partition_under_the_same_root() {
        // A cross-realm composition include lives under the INCLUDED realm's
        // fingerprint, not the including project's. Looking in one partition
        // reported it missing while `list` showed it installed — `verify`,
        // `which` and `run` disagreed with `list`, and the corrective advice
        // failed (REQ-STORE-001).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mine = Store::at(root.join("realms").join("aaaa"));
        let theirs = Store::at(root.join("realms").join("bbbb"));
        let digest = theirs
            .lay_down(
                &fixtures::manifest("2026.08.0", "qualified"),
                &[("btool", b"b")],
            )
            .unwrap();

        // My own partition does not have it…
        assert!(mine.get(&digest).unwrap().is_none());
        // …but it is installed under this varve root, and locating it says so.
        let (owner, entry) = mine.find_anywhere(&digest).unwrap().expect("found");
        assert_eq!(entry.digest, digest);
        assert_eq!(owner.root(), theirs.root(), "found in the owning partition");
        // The tool resolves through the partition that actually holds it.
        assert!(owner.tool_path(&entry, "btool").is_some());
    }

    // rivet: verifies REQ-STORE-001
    #[test]
    fn the_varve_root_is_recovered_from_a_realm_partition() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(
            Store::at(root.join("realms").join("ffff")).varve_root(),
            root.to_path_buf()
        );
        // A non-partition store is its own root.
        assert_eq!(Store::at(root).varve_root(), root.to_path_buf());
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

    /// A manifest entry as a signed layer carries it.
    fn entry(name: &str, version: Option<&str>, kind: Option<&str>) -> ManifestEntry {
        let mut annotations = BTreeMap::new();
        annotations.insert("eu.pulseengine.tool".to_string(), name.to_string());
        if let Some(v) = version {
            annotations.insert("eu.pulseengine.tool.version".to_string(), v.to_string());
        }
        if let Some(k) = kind {
            annotations.insert(crate::kind::ANN_KIND.to_string(), k.to_string());
        }
        ManifestEntry {
            digest: manifest_digest(name.as_bytes()),
            annotations,
        }
    }

    fn held<'a>(name: &'a str, version: &'a str, bytes: &'a [u8]) -> Payload<'a> {
        Payload {
            name,
            version: Some(version),
            dispatchable: false,
            bytes,
        }
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn two_versions_of_one_name_are_two_files_neither_overwriting_the_other() {
        // Clause 2. `lay_down` wrote every payload to `bin/<name>`, so relaxing
        // the deposit check alone would have made the second serde silently
        // overwrite the first: the WRONG BYTES land under the right name, and
        // verification then fails on the OTHER entry with nothing explaining
        // why. A clean error turned into silent data loss.
        let (_tmp, store) = store();
        let manifest = fixtures::manifest("2026.08.0", "qualified");
        let digest = store
            .lay_down_payloads(
                &manifest,
                &[
                    held("serde", "1.0.200", b"serde-200-bytes"),
                    held("serde", "1.0.210", b"serde-210-bytes"),
                ],
            )
            .unwrap();
        let layer = store.get(&digest).unwrap().unwrap();

        // Each version is its OWN file, holding its OWN bytes.
        let two_hundred = layer.root.join("payloads/serde/1.0.200");
        let two_ten = layer.root.join("payloads/serde/1.0.210");
        assert_eq!(std::fs::read(&two_hundred).unwrap(), b"serde-200-bytes");
        assert_eq!(std::fs::read(&two_ten).unwrap(), b"serde-210-bytes");
        // …and nothing landed under the bare name, where one would have won.
        assert!(!layer.root.join("bin/serde").exists());

        // Both are reachable FROM THEIR MANIFEST ENTRIES — the lookup every
        // consumer uses, so `verify`, `archive` and `export-cargo` each see the
        // version they asked for rather than whichever landed last.
        assert_eq!(
            store.entry_path(&layer, &entry("serde", Some("1.0.200"), Some("crate"))),
            Some(two_hundred)
        );
        assert_eq!(
            store.entry_path(&layer, &entry("serde", Some("1.0.210"), Some("crate"))),
            Some(two_ten)
        );
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn two_payloads_claiming_one_path_are_refused_before_anything_is_written() {
        // The guard that makes the relaxation safe. deposit refuses two tools
        // under one name, but deposit is not the only producer: install accepts
        // ANY manifest a realm root signed, including one built by other
        // software. If two entries ever reach one path, the store must say so
        // loudly rather than write one over the other.
        let (_tmp, store) = store();
        let manifest = fixtures::manifest("2026.08.0", "qualified");
        let err = store
            .lay_down_payloads(
                &manifest,
                &[
                    Payload::tool("synth", b"first-bytes"),
                    Payload::tool("synth", b"second-bytes"),
                ],
            )
            .unwrap_err();
        assert!(
            matches!(&err, StoreError::Collision { path, .. } if path.contains("synth")),
            "got: {err}"
        );
        // And the core is untouched: destinations are resolved before any byte
        // is written, so a colliding layer never half-lands.
        assert!(store.list().unwrap().is_empty(), "nothing may be laid down");

        // The same collision through the versionless legacy placement.
        let err = store
            .lay_down_payloads(
                &manifest,
                &[
                    Payload {
                        name: "wit-pkg",
                        version: None,
                        dispatchable: false,
                        bytes: b"a",
                    },
                    Payload {
                        name: "wit-pkg",
                        version: None,
                        dispatchable: false,
                        bytes: b"b",
                    },
                ],
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Collision { .. }), "got: {err}");
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_name_or_version_that_escapes_the_layer_is_refused() {
        // The names now compose a PATH, and they come out of a manifest.
        // "Signed" means attributable, not benign: a realm root must not be
        // able to place bytes outside the layer it is laying down.
        let (_tmp, store) = store();
        let manifest = fixtures::manifest("2026.08.0", "qualified");
        for (name, version) in [
            ("../../escape", Some("1.0.0")),
            ("serde", Some("../../escape")),
            ("a/b", Some("1.0.0")),
            ("..", Some("1.0.0")),
            ("", Some("1.0.0")),
            ("serde", Some("")),
        ] {
            let err = store
                .lay_down_payloads(&manifest, &[held(name, version.unwrap(), b"x")])
                .unwrap_err();
            assert!(
                matches!(err, StoreError::UnsafeComponent { .. }),
                "{name:?}@{version:?} must be refused, got: {err}"
            );
        }
        assert!(store.list().unwrap().is_empty());
        // The escape did not happen by any other route either.
        assert!(!store.root().join("escape").exists());
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_layer_installed_before_this_change_still_resolves_its_crate() {
        // Backward compatibility, stated as a test rather than a hope: a layer
        // laid down by an older varve holds its crate at `bin/<name>`, and
        // `verify`/`archive`/`export-cargo` must still find it there. Such a
        // layer can hold only ONE version per name — the old deposit check made
        // sure of it — so the fallback is unambiguous.
        let (_tmp, store) = store();
        let manifest = fixtures::manifest("2026.08.0", "qualified");
        let digest = store
            .lay_down(&manifest, &[("legacy-crate", b"old-layout-bytes")])
            .unwrap();
        let layer = store.get(&digest).unwrap().unwrap();
        let path = store
            .entry_path(&layer, &entry("legacy-crate", Some("0.1.0"), Some("crate")))
            .expect("a pre-REQ-STORE-002 layer must keep resolving");
        assert_eq!(std::fs::read(path).unwrap(), b"old-layout-bytes");
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_tool_keeps_bin_and_a_held_payload_never_borrows_it() {
        // Dispatch is by name, so `bin/<name>` is not merely retained for
        // compatibility — it is the contract `varve which`, `varve run` and the
        // argv[0] shims resolve through. A held payload must never satisfy a
        // dispatch lookup by landing there.
        let (_tmp, store) = store();
        let manifest = fixtures::manifest("2026.08.0", "qualified");
        let digest = store
            .lay_down_payloads(
                &manifest,
                &[
                    Payload::tool("synth", b"synth-binary"),
                    held("serde", "1.0.200", b"serde-crate"),
                ],
            )
            .unwrap();
        let layer = store.get(&digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(store.tool_path(&layer, "synth").unwrap()).unwrap(),
            b"synth-binary"
        );
        assert_eq!(store.tool_path(&layer, "serde"), None, "not dispatchable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(layer.root.join("bin/synth")), 0o755);
            assert_eq!(
                mode(layer.root.join("payloads/serde/1.0.200")),
                0o644,
                "a .crate tarball is data, not something to execute"
            );
        }
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn an_unrecognised_kind_is_held_by_version_never_dispatched_by_name() {
        // A layer deposited by a NEWER varve carries kinds this build has never
        // heard of, and installs and verifies normally (DD-003, kind.rs). If an
        // unknown kind were placed by name alone, two versions of it would
        // overwrite each other — the very loss this requirement forbids, one
        // release later.
        let e = entry("future", Some("2.0.0"), Some("quantum-blob"));
        assert!(!entry_is_dispatchable(&e));
        assert_eq!(
            payload_rel_path(false, "future", Some("2.0.0")).unwrap(),
            PathBuf::from("payloads/future/2.0.0")
        );
        // …while an entry with NO kind annotation is a tool, as pre-kind
        // layers require.
        assert!(entry_is_dispatchable(&entry("synth", Some("0.45.0"), None)));
        assert_eq!(
            payload_rel_path(true, "synth", Some("0.45.0")).unwrap(),
            PathBuf::from("bin/synth")
        );
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
