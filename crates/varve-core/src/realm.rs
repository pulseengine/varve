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
    /// The realm's primary source. Kept as the first element of `sources` too,
    /// so existing callers that read `registry` keep working unchanged
    /// (REQ-MIRROR-001 clause 5).
    pub registry: String,
    /// Every source, in the realm's stated order of preference, primary first.
    ///
    /// Ordered, not raced: an operator must be able to predict which source
    /// served them, and a run that picked differently each time would make an
    /// incident unreproducible.
    pub sources: Vec<String>,
    /// Raw ed25519 root public key bytes.
    pub trust_root: Vec<u8>,
    /// The realm asserts that it publishes a signed line index
    /// (REQ-INDEXAUTH-001 clause 5). Where true, a missing index is an ERROR
    /// rather than a silent fall back to the registry's unauthenticated
    /// listing — otherwise an attacker need only delete the index to disable
    /// the check. Defaults to false so every existing realm keeps working:
    /// failing closed by default would break all of them at once.
    pub signed_index: bool,
    /// Roots this realm has RETIRED (REQ-ROTATE-002).
    ///
    /// Documentation, never authority. Nothing verifies against these — they
    /// exist so that a signature failure can be EXPLAINED rather than merely
    /// reported, because nothing otherwise distinguishes "signed by a root
    /// this realm retired last week" from "signed by a stranger", and the
    /// consumer cannot deduce which.
    ///
    /// This is not a rotation mechanism and must not be read as one. varve
    /// still has no succession: nothing signs "this new root replaces the old
    /// one", and no consumer would check such a statement. See
    /// `varve docs threat-model`.
    pub retired_roots: Vec<RetiredRoot>,
}

/// A root a realm used to sign with and has since retired (REQ-ROTATE-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredRoot {
    /// Raw ed25519 public key bytes of the retired root. Held so a failing
    /// signature can be ATTRIBUTED to it; never handed to a verifier.
    pub key: Vec<u8>,
    /// The date it was retired, as the realm states it.
    pub retired: String,
    /// The last layer it signed, when the realm says. Turns "your pin does
    /// not verify" into "layers up to this one used the old root".
    pub last_layer: Option<String>,
}

impl RetiredRoot {
    /// The key as the realms file writes it — for messages, so a human can
    /// match it against what they have.
    pub fn hex(&self) -> String {
        self.key.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The store partition this root's layers were installed under — computed
    /// exactly as `Realm::fingerprint`, because it must name the SAME
    /// directory a consumer already has on disk.
    pub fn fingerprint(&self) -> String {
        crate::store::manifest_digest(&self.key)
            .strip_prefix("sha256:")
            .expect("digest shape")[..16]
            .to_string()
    }
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

    /// A human label for a store-partition fingerprint, if this realm
    /// explains it (REQ-ROTATE-002 clause 5).
    ///
    /// `Some(name)` for the live partition. For one a retired root left
    /// behind, the name plus when it was retired — otherwise `varve list`
    /// shows a bare hex string and the consumer's first symptom, their tools
    /// apparently vanishing, has no stated cause. `None` when this realm has
    /// nothing to say about the fingerprint, so an unrelated partition is
    /// never misattributed to it.
    pub fn partition_label(&self, fingerprint: &str) -> Option<String> {
        if self.fingerprint() == fingerprint {
            return Some(self.name.clone());
        }
        self.retired_roots
            .iter()
            .find(|r| r.fingerprint() == fingerprint)
            .map(|r| {
                format!(
                    "{} (retired root, {} — layers here do not verify against the realm's \
                     current root)",
                    self.name, r.retired
                )
            })
    }

    /// If `envelope` verifies against a root this realm has RETIRED, an
    /// explanation naming it (REQ-ROTATE-002 clause 3). `None` otherwise.
    ///
    /// This NEVER changes a verdict. The caller has already decided the
    /// signature does not verify against the live root and is rejecting; this
    /// only says why the bytes look the way they do. A retired root is
    /// documentation, not authority — if this function's result ever gated
    /// acceptance, a rotation would become a way to keep honouring the key you
    /// rotated away from.
    ///
    /// It matters that an UNKNOWN signer returns `None`. If every unverifiable
    /// signature got the sympathetic "that root was retired" message, the
    /// diagnostic would tell an operator a rotation happened while they were
    /// in fact being attacked — worse than the bare error it replaces.
    pub fn explain_retired_signature(&self, envelope: &[u8], payload_type: &str) -> Option<String> {
        let retired = self
            .retired_roots
            .iter()
            .find(|r| crate::verify::dsse_verify_typed(envelope, payload_type, &r.key).is_ok())?;

        let live: String = self.trust_root.iter().map(|b| format!("{b:02x}")).collect();
        let mut why = format!(
            "this signature verifies against a root the realm '{}' RETIRED on {} ({}), \
             not against its current trust-root ({live}).",
            self.name,
            retired.retired,
            retired.hex(),
        );
        if let Some(last) = &retired.last_layer {
            why.push_str(&format!(
                " Layers up to and including {last} were signed by the retired root."
            ));
        }
        why.push_str(
            " This is not a forgery and not a mistake on your part: the realm changed its \
             root. Move your pin to a layer signed by the current root — the old layers \
             are not recoverable under the new root, by design.",
        );
        Some(why)
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
    #[error("io error at {path}")]
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
    /// Additional sources, tried in order after `registry`, when it cannot be
    /// reached (REQ-MIRROR-001).
    ///
    /// Safe by construction: a layer is accepted because its manifest verifies
    /// against this realm's trust root, so a mirror is transport and not
    /// authority. A tampered mirror fails the signature check and a truncated
    /// one fails the digest check — a second source widens availability, never
    /// the trust surface.
    #[serde(default)]
    mirrors: Vec<String>,
    /// Inline hex-encoded ed25519 public key…
    #[serde(rename = "trust-root", default)]
    trust_root: Option<String>,
    /// …or a key file, relative to the realms file.
    #[serde(rename = "trust-root-file", default)]
    trust_root_file: Option<String>,
    /// `signed-index = true` — this realm publishes a signed line index and
    /// consumers must not accept an unauthenticated listing for it.
    #[serde(rename = "signed-index", default)]
    signed_index: bool,
    /// Roots this realm has retired (REQ-ROTATE-002). Diagnostic only.
    #[serde(rename = "retired-roots", default)]
    retired_roots: Vec<RawRetiredRoot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetiredRoot {
    key: String,
    retired: String,
    #[serde(rename = "last-layer", default)]
    last_layer: Option<String>,
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
    // Retired roots are parsed with the SAME strictness as the live one: a
    // malformed key here would produce a diagnostic naming nonsense, and a
    // diagnostic nobody can act on is worse than the bare error it replaced.
    let mut retired_roots = Vec::with_capacity(def.retired_roots.len());
    for raw in &def.retired_roots {
        let hex = raw.key.trim().to_ascii_lowercase();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad(format!(
                "retired root {:?} is not a 64-hex-char ed25519 public key",
                raw.key
            )));
        }
        let key: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("checked hex"))
            .collect();
        // The live root listed as retired. No legitimate use, and precisely
        // the mistake a half-finished rotation makes: update one field, paste
        // the same value into the other. Refused rather than tolerated,
        // because the realms file is the one place a rotation is written down
        // twice and the two copies disagreeing is the whole failure mode.
        if key == trust_root {
            return Err(bad(format!(
                "the realm's live trust-root {hex} is also listed in retired-roots — \
                 a root cannot be both current and retired; remove it from one"
            )));
        }
        retired_roots.push(RetiredRoot {
            key,
            retired: raw.retired.clone(),
            last_layer: raw.last_layer.clone(),
        });
    }

    Ok(Realm {
        name: name.to_string(),
        registry: def.registry.clone(),
        sources: std::iter::once(def.registry.clone())
            .chain(def.mirrors.iter().cloned())
            .collect(),
        trust_root,
        signed_index: def.signed_index,
        retired_roots,
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

    const NEW: &str = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0";
    const OLD: &str = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973";

    fn realm_with_retired(retired: &str) -> String {
        format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{NEW}\"\n\
             retired-roots = [{retired}]\n"
        )
    }

    /// A realm can say which roots it has retired, so a signature failure can
    /// be explained instead of merely reported.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_realm_can_declare_the_roots_it_has_retired() {
        let dir = realms_dir(&realm_with_retired(&format!(
            "{{ key = \"{OLD}\", retired = \"2026-09-07\", last-layer = \"2026.09.1\" }}"
        )));
        let realm = resolve_realm(dir.path(), "r").unwrap();
        assert_eq!(realm.retired_roots.len(), 1);
        let r = &realm.retired_roots[0];
        assert_eq!(r.hex(), OLD);
        assert_eq!(r.retired, "2026-09-07");
        assert_eq!(r.last_layer.as_deref(), Some("2026.09.1"));
        assert_ne!(
            r.key, realm.trust_root,
            "a retired root is not the live one"
        );
    }

    /// THE LINE THIS MUST NOT CROSS. A retired root is documentation, not
    /// authority. If declaring one ever widened what verifies, this feature
    /// would be far worse than the confusing error it replaces — it would turn
    /// a rotation into a way to keep accepting the key you rotated away from.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_retired_root_is_never_a_key_anything_verifies_against() {
        let dir = realms_dir(&realm_with_retired(&format!(
            "{{ key = \"{OLD}\", retired = \"2026-09-07\" }}"
        )));
        let realm = resolve_realm(dir.path(), "r").unwrap();

        // The ONLY key the realm offers a verifier is the live root.
        let live: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&NEW[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(realm.trust_root, live);
        // And the store partition is the live root's, so declaring a retired
        // root cannot silently reunite a consumer with the old partition.
        let expected = Realm {
            retired_roots: Vec::new(),
            ..realm.clone()
        };
        assert_eq!(
            realm.fingerprint(),
            expected.fingerprint(),
            "retired roots must not change the store namespace"
        );
    }

    /// Listing the live root as retired has no legitimate use and is exactly
    /// the mistake a half-finished rotation makes — updating one field and
    /// pasting the same value into the other.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn declaring_the_live_root_as_retired_is_refused() {
        let dir = realms_dir(&realm_with_retired(&format!(
            "{{ key = \"{NEW}\", retired = \"2026-09-07\" }}"
        )));
        let err = resolve_realm(dir.path(), "r").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("retired") && msg.contains("trust-root"),
            "the error must say the live root is listed as retired, got: {msg}"
        );
    }

    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_retired_root_that_is_not_a_key_is_refused() {
        let dir = realms_dir(&realm_with_retired(
            "{ key = \"not-a-key\", retired = \"2026-09-07\" }",
        ));
        let err = resolve_realm(dir.path(), "r").unwrap_err().to_string();
        assert!(
            err.contains("64-hex"),
            "a malformed retired root must be refused like a malformed live one, got: {err}"
        );
    }

    /// Clause 6: every realms file written before this feature keeps working,
    /// unchanged, with no retired roots.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_realm_file_without_retired_roots_is_unchanged() {
        let dir = realms_dir(&format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{NEW}\"\n"
        ));
        let realm = resolve_realm(dir.path(), "r").unwrap();
        assert!(realm.retired_roots.is_empty());
    }

    /// Clause 5. "My tools vanished" is the symptom a consumer notices before
    /// any error message, because the store partitions by root fingerprint and
    /// the old partition is no longer named by any realm — so `varve list`
    /// shows it as a bare hex string. Naming it costs nothing and turns a
    /// mystery into a fact.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_partition_left_behind_by_a_retired_root_is_named_as_such() {
        use crate::verify::generate_root_keypair;
        let (_old_sk, old_pk) = generate_root_keypair();
        let (_new_sk, new_pk) = generate_root_keypair();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let dir = realms_dir(&format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n\
             retired-roots = [{{ key = \"{}\", retired = \"2026-09-07\" }}]\n",
            hex(&new_pk),
            hex(&old_pk)
        ));
        let realm = resolve_realm(dir.path(), "r").unwrap();

        // The live partition is named plainly.
        assert_eq!(
            realm.partition_label(&realm.fingerprint()).as_deref(),
            Some("r")
        );

        // The partition the retired root left behind is named AND dated, so a
        // human can tell it apart from the live one at a glance.
        let old_fp = realm.retired_roots[0].fingerprint();
        assert_ne!(old_fp, realm.fingerprint());
        let label = realm
            .partition_label(&old_fp)
            .expect("a retired root's partition must be recognised");
        assert!(label.contains('r'), "names the realm: {label}");
        assert!(label.contains("retired"), "says it is retired: {label}");
        assert!(label.contains("2026-09-07"), "says when: {label}");

        // An unrelated partition stays unrecognised rather than being
        // misattributed to this realm.
        assert_eq!(realm.partition_label("0123456789abcdef"), None);
    }

    /// Clause 3. The whole point: a consumer whose pin was signed by the
    /// retired root gets told WHICH root, WHEN it was retired, what replaced
    /// it, and what to do — instead of "No valid signatures", which is
    /// indistinguishable from a forgery by a stranger.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_signature_from_a_retired_root_is_attributed_not_merely_rejected() {
        use crate::verify::generate_root_keypair;
        let (old_sk, old_pk) = generate_root_keypair();
        let (_new_sk, new_pk) = generate_root_keypair();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        let dir = realms_dir(&format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n\
             retired-roots = [{{ key = \"{}\", retired = \"2026-09-07\", \
             last-layer = \"2026.09.1\" }}]\n",
            hex(&new_pk),
            hex(&old_pk)
        ));
        let realm = resolve_realm(dir.path(), "r").unwrap();

        // Something the OLD root signed — a layer deposited before rotation.
        let envelope = crate::verify::dsse_sign_typed(b"{}", "application/x.test", &old_sk, "k")
            .expect("sign with the retired root");

        let why = realm
            .explain_retired_signature(envelope.as_bytes(), "application/x.test")
            .expect("a signature from a declared retired root must be attributed");
        assert!(why.contains("2026-09-07"), "must say WHEN: {why}");
        assert!(
            why.contains(&hex(&old_pk)),
            "must name the retired root: {why}"
        );
        assert!(
            why.contains("2026.09.1"),
            "must say which layers used it: {why}"
        );
        assert!(
            why.to_lowercase().contains("pin"),
            "must say the fix is to move the pin: {why}"
        );
    }

    /// A forgery by a stranger must stay a forgery. If any unverifiable
    /// signature got the sympathetic "this realm retired that root" message,
    /// the diagnostic would be actively misleading — telling an operator a
    /// rotation happened when they are being attacked.
    // rivet: verifies REQ-ROTATE-002
    #[test]
    fn a_signature_from_an_unknown_key_is_not_blamed_on_a_rotation() {
        use crate::verify::generate_root_keypair;
        let (_old_sk, old_pk) = generate_root_keypair();
        let (_new_sk, new_pk) = generate_root_keypair();
        let (stranger_sk, _stranger_pk) = generate_root_keypair();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();

        let dir = realms_dir(&format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n\
             retired-roots = [{{ key = \"{}\", retired = \"2026-09-07\" }}]\n",
            hex(&new_pk),
            hex(&old_pk)
        ));
        let realm = resolve_realm(dir.path(), "r").unwrap();
        let envelope =
            crate::verify::dsse_sign_typed(b"{}", "application/x.test", &stranger_sk, "k")
                .expect("sign with a stranger key");
        assert!(
            realm
                .explain_retired_signature(envelope.as_bytes(), "application/x.test")
                .is_none(),
            "an unknown signer must not be explained away as a rotation"
        );
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

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_realm_declares_whether_it_publishes_a_signed_index() {
        // Clause 5. Failing closed by default would break every realm that
        // exists; failing open with no way to opt in would let an attacker
        // disable the check by deleting the index. The realm decides, which is
        // where every other trust question is already settled.
        let tmp = realms_dir(
            r#"
[realm.declaring]
registry     = "oci://example.test/layers"
trust-root   = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"
signed-index = true

[realm.silent]
registry   = "oci://example.test/other"
trust-root = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"
"#,
        );
        assert!(
            resolve_realm(tmp.path(), "declaring").unwrap().signed_index,
            "a realm that declares an index must be recorded as declaring it"
        );
        assert!(
            !resolve_realm(tmp.path(), "silent").unwrap().signed_index,
            "the default must be false, or every existing realm breaks at once"
        );
    }
}

#[cfg(test)]
mod mirror_tests {
    use super::*;

    fn parse(text: &str, name: &str) -> Realm {
        let dir = std::env::temp_dir().join(format!("varve-realm-mirror-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        std::fs::write(dir.join(REALMS_FILE), text).expect("write");
        resolve_realm(&dir, name).expect("parses")
    }

    /// Clause 5. Every realms file in existence names one registry and no
    /// mirrors; all of them must keep working with no edit.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_realm_naming_one_registry_still_works_and_has_one_source() {
        let r = parse(
            "[realm.solo]\nregistry = \"oci://ghcr.io/o/r\"\n\
             trust-root = \"7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0\"\n",
            "solo",
        );
        assert_eq!(r.registry, "oci://ghcr.io/o/r");
        assert_eq!(r.sources, vec!["oci://ghcr.io/o/r".to_string()]);
    }

    /// Clause 1 and the ordering in clause 2: primary first, then the stated
    /// mirrors in the order written.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn mirrors_follow_the_primary_in_the_order_they_are_written() {
        let r = parse(
            "[realm.many]\nregistry = \"oci://primary\"\n\
             mirrors = [\"oci://second\", \"oci://third\"]\n\
             trust-root = \"7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0\"\n",
            "many",
        );
        assert_eq!(
            r.sources,
            vec![
                "oci://primary".to_string(),
                "oci://second".to_string(),
                "oci://third".to_string()
            ]
        );
        // `registry` still names the primary, so nothing that reads it changes.
        assert_eq!(r.registry, "oci://primary");
    }

    /// The trust root is per REALM, not per source. A mirrors list cannot
    /// introduce a second authority — that is what makes mirroring safe here
    /// rather than a trust decision.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn mirrors_cannot_carry_a_trust_root_of_their_own() {
        let dir = std::env::temp_dir().join("varve-realm-mirror-root");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        std::fs::write(
            dir.join(REALMS_FILE),
            "[realm.x]\nregistry = \"oci://a\"\n\
             mirrors = [{ registry = \"oci://b\", trust-root = \"dead\" }]\n\
             trust-root = \"7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0\"\n",
        )
        .expect("write");
        assert!(
            resolve_realm(&dir, "x").is_err(),
            "a mirror must not be able to declare its own trust root"
        );
    }
}

#[cfg(test)]
mod shipped_realm_agrees_with_shipped_key {
    use super::*;

    /// The repository ships the rolling root TWICE: as key material in
    /// `trust-roots/rolling.pub` (uploaded as a release asset, and used by
    /// `deposit-layer.yml` as `VARVE_TRUST_ROOT`) and as a fingerprint in
    /// `varve-realms.toml` (downloaded by consumers, and authoritative over
    /// the environment). Nothing compared them.
    ///
    /// A rotation touches both, and the half-done rotation is silent in a
    /// specific and bad way: CI deposits a layer signed against the key file
    /// and it verifies, because the same file is used on both sides — while
    /// every consumer resolving the realm rejects that layer with "No valid
    /// signatures". The break appears downstream, in someone else's repo,
    /// after the release ships.
    ///
    /// A sibling test in `varve`'s docs module pins the DOCUMENTED key to
    /// `rolling.pub`. This pins the SHIPPED realm to it. Together the three
    /// copies cannot drift apart.
    // rivet: verifies REQ-ROTATE-001
    #[test]
    fn the_committed_realms_file_names_the_committed_key() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/varve-core is two levels below the repo root")
            .to_path_buf();

        let key_file = repo_root.join("trust-roots/rolling.pub");
        let shipped_key = std::fs::read_to_string(&key_file)
            .expect("trust-roots/rolling.pub is committed")
            .trim()
            .to_ascii_lowercase();
        assert_eq!(
            shipped_key.len(),
            64,
            "{} must hold one 64-hex ed25519 public key",
            key_file.display()
        );

        // The real parser on the real file: whatever a consumer would load.
        let realm = resolve_realm(&repo_root, "pulseengine")
            .expect("this repository commits varve-realms.toml with realm 'pulseengine'");

        let named_root = realm
            .trust_root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        assert_eq!(
            named_root, shipped_key,
            "varve-realms.toml names a rolling root that is NOT the key in \
             trust-roots/rolling.pub. A layer signed with the key file will be \
             REJECTED by every consumer that resolves the realm. Rotate both, \
             or neither."
        );
    }
}
