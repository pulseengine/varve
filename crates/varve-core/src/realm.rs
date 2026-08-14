//! Realms (REQ-REALM-001) — the pin names its trust universe.
//!
//! A machine can serve several *independent* toolchain universes — different
//! organizations, different trust roots, different registries — in parallel.
//! A realm binds a name to (registry, trust root); the pin references the
//! name; a committed `varve-realms.toml` (discovered by the same walk-up as
//! the pin, so trust travels with the code) carries the definitions.
//!
//! Isolation is by construction, not convention: every piece of per-realm
//! state lives under an effective root namespaced by the TRUST-ROOT
//! FINGERPRINT — two realms cannot cross-talk even with identical layer
//! names and counters, and a realm's layers can only ever verify against
//! that realm's root. When a pin names a realm, the realm is authoritative:
//! the ambient environment cannot substitute a different trust root.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The realms file name, discovered by walking up from the working
/// directory (it may sit beside the pin or above it).
pub const REALMS_FILE: &str = "varve-realms.toml";

/// A resolved realm: everything needed to fetch and verify its layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Realm {
    pub name: String,
    pub registry: String,
    /// Raw ed25519 root public key bytes.
    pub trust_root: Vec<u8>,
}

impl Realm {
    /// Short fingerprint of the trust root — the store namespace. Sixteen
    /// hex chars of sha256(pubkey): collision-safe for a namespace while
    /// staying readable in paths.
    pub fn fingerprint(&self) -> String {
        crate::store::manifest_digest(&self.trust_root)
            .strip_prefix("sha256:")
            .expect("digest shape")[..16]
            .to_string()
    }

    /// The per-realm effective root under which core/state/status live.
    pub fn effective_root(&self, varve_root: &Path) -> PathBuf {
        varve_root.join("realms").join(self.fingerprint())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RealmError {
    #[error(
        "no {REALMS_FILE} found walking up from {start} — the pin names realm '{realm}' but no realm definitions exist; commit a {REALMS_FILE} defining it"
    )]
    NoRealmsFile { start: String, realm: String },
    #[error("{path}: not a valid realms file: {reason}")]
    Parse { path: String, reason: String },
    #[error(
        "realm '{realm}' is not defined in {path} — defined realms: {defined:?}. Fix the pin or add the realm."
    )]
    Undefined {
        realm: String,
        path: String,
        defined: Vec<String>,
    },
    #[error("realm '{realm}' in {path}: {reason}")]
    BadDefinition {
        realm: String,
        path: String,
        reason: String,
    },
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRealmsFile {
    #[serde(default)]
    realm: BTreeMap<String, RawRealm>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRealm {
    registry: String,
    /// Inline hex-encoded ed25519 public key…
    #[serde(rename = "trust-root", default)]
    trust_root: Option<String>,
    /// …or a key file, relative to the realms file.
    #[serde(rename = "trust-root-file", default)]
    trust_root_file: Option<String>,
}

/// Find the realms file by walking up from `start`.
pub fn find_realms_file(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(REALMS_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Every realm name the discovered realms file defines. Used to label store
/// partitions by realm rather than by trust-root fingerprint — a fingerprint is
/// unambiguous but tells a human nothing.
pub fn realm_names(start: &Path) -> Result<Vec<String>, RealmError> {
    let Some(path) = find_realms_file(start) else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(&path).map_err(|source| RealmError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let file: RawRealmsFile = toml::from_str(&text).map_err(|e| RealmError::Parse {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(file.realm.into_keys().collect())
}

/// Load one realm by name from the realms file discovered from `start`.
pub fn resolve_realm(start: &Path, name: &str) -> Result<Realm, RealmError> {
    let Some(path) = find_realms_file(start) else {
        return Err(RealmError::NoRealmsFile {
            start: start.display().to_string(),
            realm: name.to_string(),
        });
    };
    let text = std::fs::read_to_string(&path).map_err(|source| RealmError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let raw: RawRealmsFile = toml::from_str(&text).map_err(|e| RealmError::Parse {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let Some(def) = raw.realm.get(name) else {
        return Err(RealmError::Undefined {
            realm: name.to_string(),
            path: path.display().to_string(),
            defined: raw.realm.keys().cloned().collect(),
        });
    };
    let bad = |reason: String| RealmError::BadDefinition {
        realm: name.to_string(),
        path: path.display().to_string(),
        reason,
    };
    let hex_key = match (&def.trust_root, &def.trust_root_file) {
        (Some(_), Some(_)) => {
            return Err(bad(
                "both trust-root and trust-root-file given — pick one".into()
            ));
        }
        (Some(inline), None) => inline.trim().to_string(),
        (None, Some(file)) => {
            let key_path = path.parent().unwrap_or(Path::new(".")).join(file);
            std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    bad(format!(
                        "cannot read trust-root-file {}: {e}",
                        key_path.display()
                    ))
                })?
                .trim()
                .to_string()
        }
        (None, None) => return Err(bad("no trust-root or trust-root-file".into())),
    };
    if hex_key.len() != 64 || !hex_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad(
            "trust root is not a 64-hex-char ed25519 public key".into()
        ));
    }
    let trust_root = (0..hex_key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_key[i..i + 2], 16).expect("checked hex"))
        .collect();
    Ok(Realm {
        name: name.to_string(),
        registry: def.registry.clone(),
        trust_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realms_dir(content: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(REALMS_FILE), content).unwrap();
        tmp
    }

    // rivet: verifies REQ-STORE-001
    #[test]
    fn every_defined_realm_is_named() {
        // `list` labels store partitions by realm name rather than by
        // trust-root fingerprint, which is unambiguous but tells a human
        // nothing. Mutation testing found this helper replaceable by an empty
        // vec with nothing noticing: the CLI test that covers it cannot kill
        // mutants, because the gate runs `--workspace --lib`.
        let dir = realms_dir(TWO_REALMS);
        let mut names = realm_names(dir.path()).unwrap();
        names.sort();
        assert_eq!(names, ["acme", "pulseengine"], "both realms named");

        // No realms file is not an error — a project may define none.
        let empty = tempfile::tempdir().unwrap();
        assert!(realm_names(empty.path()).unwrap().is_empty());

        // A malformed file IS an error: labelling must not paper over a file
        // the user believes is being read.
        let bad = realms_dir("this is not toml {{{");
        assert!(realm_names(bad.path()).is_err());
    }

    const TWO_REALMS: &str = r#"
[realm.pulseengine]
registry = "oci://ghcr.io/pulseengine/varve/layers"
trust-root = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[realm.acme]
registry = "oci://ghcr.io/acme/layers"
trust-root = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;

    // rivet: verifies REQ-REALM-001
    #[test]
    fn realms_resolve_by_name_with_walk_up_discovery() {
        let tmp = realms_dir(TWO_REALMS);
        let deep = tmp.path().join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        let realm = resolve_realm(&deep, "acme").unwrap();
        assert_eq!(realm.registry, "oci://ghcr.io/acme/layers");
        assert_eq!(realm.trust_root, vec![0xbb; 32]);
    }

    // rivet: verifies REQ-REALM-001
    #[test]
    fn different_roots_mean_different_namespaces() {
        let tmp = realms_dir(TWO_REALMS);
        let pe = resolve_realm(tmp.path(), "pulseengine").unwrap();
        let acme = resolve_realm(tmp.path(), "acme").unwrap();
        assert_ne!(pe.fingerprint(), acme.fingerprint());
        let root = Path::new("/var/root");
        assert_ne!(pe.effective_root(root), acme.effective_root(root));
        assert!(pe.effective_root(root).starts_with("/var/root/realms"));
    }

    // rivet: verifies REQ-REALM-001
    #[test]
    fn an_undefined_realm_fails_closed_naming_what_exists() {
        let tmp = realms_dir(TWO_REALMS);
        let err = resolve_realm(tmp.path(), "evil-corp").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("evil-corp") && msg.contains("pulseengine") && msg.contains("acme"));
    }

    // rivet: verifies REQ-REALM-001
    #[test]
    fn a_missing_realms_file_fails_closed_with_guidance() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_realm(tmp.path(), "pulseengine").unwrap_err();
        assert!(err.to_string().contains(REALMS_FILE));
    }

    // rivet: verifies REQ-REALM-001
    #[test]
    fn trust_root_file_is_read_relative_to_the_realms_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("keys")).unwrap();
        std::fs::write(tmp.path().join("keys/root.pub"), "cc".repeat(32)).unwrap();
        std::fs::write(
            tmp.path().join(REALMS_FILE),
            "[realm.filekey]\nregistry = \"oci://r/x\"\ntrust-root-file = \"keys/root.pub\"\n",
        )
        .unwrap();
        let realm = resolve_realm(tmp.path(), "filekey").unwrap();
        assert_eq!(realm.trust_root, vec![0xcc; 32]);
    }

    // rivet: verifies REQ-REALM-001
    #[test]
    fn malformed_definitions_are_refused() {
        for (name, body) in [
            ("nokey", "[realm.nokey]\nregistry = \"oci://r/x\"\n"),
            (
                "badkey",
                "[realm.badkey]\nregistry = \"oci://r/x\"\ntrust-root = \"zz\"\n",
            ),
            // Wrong-length but PURE-HEX: length and charset must each
            // reject independently.
            (
                "shorthex",
                "[realm.shorthex]\nregistry = \"oci://r/x\"\ntrust-root = \"cccccccccccccccccccccccccccccccc\"\n",
            ),
            (
                "bothkeys",
                "[realm.bothkeys]\nregistry = \"oci://r/x\"\ntrust-root = \"aa\"\ntrust-root-file = \"f\"\n",
            ),
        ] {
            let tmp = realms_dir(body);
            assert!(
                resolve_realm(tmp.path(), name).is_err(),
                "{name} must refuse"
            );
        }
    }
}
