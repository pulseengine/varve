//! Key roles: which key may sign WHAT (REQ-KEYROLES-001, DD-041).
//!
//! A flat realm root signs layer manifests, line-status, line-index and
//! attestations alike, so nothing says which of those a key was ever meant to
//! do. In a realm that declares roles, the root signs only a DELEGATION naming
//! role keys, and every other signature is judged against the keys delegated to
//! the role its document belongs to.
//!
//! The role claim is the AUTHENTICATED DSSE payloadType mapped through the fixed
//! table in [`role_for`]. There is no new payload field (published envelopes
//! stay byte-identical, and a role cannot be stripped from a signature) and the
//! envelope's `keyid` is never used: it is an unauthenticated hint, so each
//! authorised key is TRIED and none is selected by name.
//!
//! A realm that declares no roles runs [`Mode::RootOnly`], which is the
//! pre-existing verifier through the one code path
//! ([`crate::verify::dsse_verify_typed`] is a wrapper over it). A delegation is
//! never consulted there: a document that names role keys is inert unless the
//! consumer's own trust material opted into roles.

use std::collections::BTreeSet;

use serde::Deserialize;
use wsc::dsse::{DsseEnvelope, Ed25519DsseVerifier};

use crate::attest;
use crate::install::VerifyError;
use crate::lineindex::LINE_INDEX_PAYLOAD_TYPE;
use crate::linestatus::LINE_STATUS_PAYLOAD_TYPE;
use crate::selfverify::RELEASE_SUMS_PAYLOAD_TYPE;
use crate::verify::{LAYER_PAYLOAD_TYPE, verify_with};

/// The authenticated payload type of a delegation: the one document the root
/// signs in a roles realm.
pub const DELEGATION_PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.delegation.v1+json";

/// What a signature is entitled to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Offline; signs only a delegation.
    Root,
    /// Layer manifests, attestations, release sums (the depositor's).
    Layer,
    /// Line-status (incl. advisories) and line-index (a human merge's).
    Status,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Root => "ROOT",
            Role::Layer => "LAYER",
            Role::Status => "STATUS",
        }
    }
}

/// The fixed payloadType -> role table. Unknown types have no role and are
/// refused in a roles realm.
pub fn role_for(payload_type: &str) -> Option<Role> {
    if payload_type == LAYER_PAYLOAD_TYPE
        || payload_type == attest::PAYLOAD_TYPE
        || payload_type == RELEASE_SUMS_PAYLOAD_TYPE
    {
        Some(Role::Layer)
    } else if payload_type == LINE_STATUS_PAYLOAD_TYPE || payload_type == LINE_INDEX_PAYLOAD_TYPE {
        Some(Role::Status)
    } else if payload_type == DELEGATION_PAYLOAD_TYPE {
        Some(Role::Root)
    } else {
        None
    }
}

/// What a payload type is called in an error message.
fn doc_name(payload_type: &str) -> &'static str {
    if payload_type == LAYER_PAYLOAD_TYPE {
        "layer manifest"
    } else if payload_type == attest::PAYLOAD_TYPE {
        "attestation"
    } else if payload_type == RELEASE_SUMS_PAYLOAD_TYPE {
        "release sums document"
    } else if payload_type == LINE_STATUS_PAYLOAD_TYPE {
        "line-status"
    } else if payload_type == LINE_INDEX_PAYLOAD_TYPE {
        "line-index"
    } else {
        "delegation"
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key: String,
    // An unauthenticated hint; never used to select or trust a key when
    // VERIFYING. A producer reads it only to default its own `--key-id`.
    #[serde(default)]
    keyid: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRole {
    threshold: u64,
    keys: Vec<RawKey>,
}

// A struct, not a map, so a repeated role name is a parse error rather than a
// silent last-one-wins, and `root` (or anything else) is an unknown role.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoles {
    layer: Option<RawRole>,
    status: Option<RawRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDelegation {
    #[serde(rename = "realm-root")]
    realm_root: String,
    counter: u64,
    #[serde(rename = "issued-at")]
    issued_at: String,
    roles: RawRoles,
}

/// The keys one role is delegated, and how many distinct ones must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleKeys {
    threshold: usize,
    keys: Vec<Vec<u8>>,
    // Parallel to `keys`: the delegation's unauthenticated key-id hints.
    hints: Vec<Option<String>>,
}

/// A verified delegation: the root, offline, naming who may sign for which role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    realm_root: Vec<u8>,
    counter: u64,
    issued_at: String,
    layer: Option<RoleKeys>,
    status: Option<RoleKeys>,
}

fn decode_key(hex_key: &str, what: &str) -> Result<Vec<u8>, VerifyError> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| VerifyError(format!("delegation {what} is not hex: {e}")))?;
    Ed25519DsseVerifier::from_bytes(&bytes).map_err(|e| {
        VerifyError(format!(
            "delegation {what} is not a valid ed25519 public key: {e}"
        ))
    })?;
    Ok(bytes)
}

fn check_role(
    role: Role,
    raw: RawRole,
    root: &[u8],
    seen: &mut Vec<Vec<u8>>,
) -> Result<RoleKeys, VerifyError> {
    let name = role.name();
    if raw.keys.is_empty() {
        return Err(VerifyError(format!("delegation role {name} has no keys")));
    }
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let hints: Vec<Option<String>> = raw.keys.iter().map(|k| k.keyid.clone()).collect();
    for k in &raw.keys {
        let key = decode_key(&k.key, &format!("{name} key"))?;
        if key == root {
            return Err(VerifyError(format!(
                "delegation lists the realm root as a {name} key; the root signs only delegations"
            )));
        }
        if keys.contains(&key) {
            return Err(VerifyError(format!(
                "delegation lists a {name} key twice; a duplicate would not be a second signer"
            )));
        }
        if seen.contains(&key) {
            return Err(VerifyError(format!(
                "delegation lists a {name} key that is also in another role; one key, one role"
            )));
        }
        keys.push(key);
    }
    let n = keys.len() as u64;
    if raw.threshold < 1 || raw.threshold > n {
        return Err(VerifyError(format!(
            "delegation role {name} has threshold {} for {n} keys; it must be 1..={n}",
            raw.threshold
        )));
    }
    seen.extend(keys.iter().cloned());
    Ok(RoleKeys {
        threshold: raw.threshold as usize,
        keys,
        hints,
    })
}

impl Delegation {
    /// Verify a delegation envelope against the pinned root and check it:
    /// signed by the root and nobody else, naming the pinned root as its realm
    /// (so another realm's delegation cannot be replayed here).
    pub fn from_envelope(envelope: &[u8], pinned_root: &[u8]) -> Result<Self, VerifyError> {
        let payload =
            RealmTrust::root_only(pinned_root)?.verify_bytes(envelope, DELEGATION_PAYLOAD_TYPE)?;
        let raw: RawDelegation = serde_json::from_slice(&payload)
            .map_err(|e| VerifyError(format!("delegation document is invalid: {e}")))?;
        let realm_root = decode_key(&raw.realm_root, "realm-root")?;
        if realm_root != pinned_root {
            return Err(VerifyError(
                "delegation names a different realm root than the one pinned; refusing a \
                 delegation replayed from another realm"
                    .into(),
            ));
        }
        if raw.roles.layer.is_none() && raw.roles.status.is_none() {
            return Err(VerifyError("delegation names no roles".into()));
        }
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let layer = raw
            .roles
            .layer
            .map(|r| check_role(Role::Layer, r, &realm_root, &mut seen))
            .transpose()?;
        let status = raw
            .roles
            .status
            .map(|r| check_role(Role::Status, r, &realm_root, &mut seen))
            .transpose()?;
        Ok(Delegation {
            realm_root,
            counter: raw.counter,
            issued_at: raw.issued_at,
            layer,
            status,
        })
    }

    /// Verify a delegation envelope against the root IT NAMES, for a PRODUCER
    /// that holds a delegation file and no pinned root. This proves only that
    /// the document is internally consistent (signed by the root it claims, no
    /// other signer); it authenticates nothing a consumer may rely on. Consumers
    /// pin the root and use [`Delegation::from_envelope`].
    pub fn from_producer_envelope(envelope: &[u8]) -> Result<Self, VerifyError> {
        let text = std::str::from_utf8(envelope)
            .map_err(|_| VerifyError("delegation is not UTF-8 DSSE JSON".into()))?;
        let env = DsseEnvelope::from_json(text)
            .map_err(|e| VerifyError(format!("delegation is not a DSSE envelope: {e}")))?;
        let payload = env
            .payload_bytes()
            .map_err(|e| VerifyError(format!("delegation payload is not decodable: {e}")))?;
        let raw: RawDelegation = serde_json::from_slice(&payload)
            .map_err(|e| VerifyError(format!("delegation document is invalid: {e}")))?;
        let root = decode_key(&raw.realm_root, "realm-root")?;
        Self::from_envelope(envelope, &root)
    }

    /// Sign a delegation document with the realm root's signer: the ROOT
    /// role's one act. The document must name this very key as its realm root,
    /// and the result is read back through [`Delegation::from_envelope`], so a
    /// delegation that a consumer would refuse is never written.
    pub fn sign(
        document: &[u8],
        root_signer: &dyn crate::verify::RealmSigner,
    ) -> Result<String, VerifyError> {
        let raw: RawDelegation = serde_json::from_slice(document)
            .map_err(|e| VerifyError(format!("delegation document is invalid: {e}")))?;
        let named = decode_key(&raw.realm_root, "realm-root")?;
        if named != root_signer.public_key() {
            return Err(VerifyError(
                "the delegation names a different realm-root than the signing key; only the \
                 realm root signs its delegation"
                    .into(),
            ));
        }
        let envelope =
            crate::verify::dsse_sign_with(document, DELEGATION_PAYLOAD_TYPE, root_signer)?;
        Self::from_envelope(envelope.as_bytes(), &named)?;
        Ok(envelope)
    }

    /// May the holder of `public` sign as `role`? `Ok` carries the delegation's
    /// key-id hint for that key, to default a producer's `--key-id`. The
    /// refusal is for a PRODUCER, before it signs: the verifier would refuse the
    /// result anyway, but only after a signature nobody can use exists.
    pub fn authorise_signer(
        &self,
        role: Role,
        public: &[u8],
    ) -> Result<Option<String>, VerifyError> {
        if public == self.realm_root.as_slice() {
            return Err(VerifyError(
                "this key is the realm root; in a roles realm the root signs only delegations"
                    .into(),
            ));
        }
        if let Some(rk) = self.keys_for(role)
            && let Some(i) = rk.keys.iter().position(|k| k == public)
        {
            return Ok(rk.hints[i].clone());
        }
        for other in [Role::Layer, Role::Status] {
            if other != role
                && self
                    .keys_for(other)
                    .is_some_and(|rk| rk.keys.iter().any(|k| k == public))
            {
                return Err(VerifyError(format!(
                    "this key is delegated to the {} role, not {}; refusing to sign out of role",
                    other.name(),
                    role.name()
                )));
            }
        }
        Err(VerifyError(format!(
            "this key is not delegated to the {} role by this delegation",
            role.name()
        )))
    }

    /// The monotonic counter a later change enforces anti-rollback with. Nothing
    /// here persists or compares against history.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    /// Whether this delegation supersedes `other` (strictly higher counter).
    pub fn newer_than(&self, other: &Delegation) -> bool {
        self.counter > other.counter
    }

    fn keys_for(&self, role: Role) -> Option<&RoleKeys> {
        match role {
            Role::Layer => self.layer.as_ref(),
            Role::Status => self.status.as_ref(),
            Role::Root => None,
        }
    }
}

/// How a realm's signatures are judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// One flat root signs everything: exactly the verifier that predates roles.
    RootOnly,
    /// The root only delegates; role keys sign the rest.
    Roles(Delegation),
}

/// A realm's pinned trust: the root and how its signatures are judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmTrust {
    root: Vec<u8>,
    mode: Mode,
}

/// Verify a one-signature envelope under one public key.
fn verifies_under(single: &DsseEnvelope, key: &[u8]) -> Option<Vec<u8>> {
    let verifier = Ed25519DsseVerifier::from_bytes(key).ok()?;
    single.verify_all(&verifier).ok()
}

impl RealmTrust {
    /// A realm that declares no roles; delegations are never consulted.
    pub fn root_only(root: &[u8]) -> Result<Self, VerifyError> {
        Ed25519DsseVerifier::from_bytes(root)
            .map_err(|e| VerifyError(format!("invalid trust-root public key: {e}")))?;
        Ok(RealmTrust {
            root: root.to_vec(),
            mode: Mode::RootOnly,
        })
    }

    /// A realm that declares roles, through a delegation already verified
    /// against this same root.
    pub fn with_roles(root: &[u8], delegation: Delegation) -> Result<Self, VerifyError> {
        Ed25519DsseVerifier::from_bytes(root)
            .map_err(|e| VerifyError(format!("invalid trust-root public key: {e}")))?;
        if delegation.realm_root != root {
            return Err(VerifyError(
                "delegation belongs to a different realm root".into(),
            ));
        }
        Ok(RealmTrust {
            root: root.to_vec(),
            mode: Mode::Roles(delegation),
        })
    }

    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    pub fn root(&self) -> &[u8] {
        &self.root
    }

    pub fn verify(
        &self,
        envelope: &str,
        expected_payload_type: &str,
    ) -> Result<Vec<u8>, VerifyError> {
        self.verify_bytes(envelope.as_bytes(), expected_payload_type)
    }

    /// The one verification path. Returns the authenticated payload.
    pub fn verify_bytes(
        &self,
        envelope: &[u8],
        expected_payload_type: &str,
    ) -> Result<Vec<u8>, VerifyError> {
        match &self.mode {
            Mode::RootOnly => {
                let verifier = Ed25519DsseVerifier::from_bytes(&self.root)
                    .map_err(|e| VerifyError(format!("invalid trust-root public key: {e}")))?;
                verify_with(&verifier, envelope, expected_payload_type)
            }
            Mode::Roles(d) => self.verify_roles(d, envelope, expected_payload_type),
        }
    }

    fn verify_roles(
        &self,
        d: &Delegation,
        envelope: &[u8],
        expected: &str,
    ) -> Result<Vec<u8>, VerifyError> {
        let text = std::str::from_utf8(envelope)
            .map_err(|_| VerifyError("fetched bytes are not UTF-8 DSSE JSON".into()))?;
        let env = DsseEnvelope::from_json(text)
            .map_err(|e| VerifyError(format!("not a DSSE envelope: {e}")))?;
        if env.payload_type != expected {
            return Err(VerifyError(format!(
                "envelope payload type is '{}', expected '{expected}' — refusing to accept a \
                 signed document as something it is not",
                env.payload_type
            )));
        }
        let role = role_for(expected).ok_or_else(|| {
            VerifyError(format!(
                "payload type '{expected}' belongs to no role of this realm; refusing it"
            ))
        })?;
        let (threshold, authorised): (usize, Vec<Vec<u8>>) = match role {
            Role::Root => (1, vec![self.root.clone()]),
            _ => match d.keys_for(role) {
                Some(rk) => (rk.threshold, rk.keys.clone()),
                None => {
                    return Err(VerifyError(format!(
                        "this realm's delegation names no {} keys; refusing the document",
                        role.name()
                    )));
                }
            },
        };
        if env.signatures.is_empty() {
            return Err(VerifyError("envelope carries no signature".into()));
        }
        let mut signers: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut payload = Vec::new();
        for sig in &env.signatures {
            let single = DsseEnvelope {
                payload: env.payload.clone(),
                payload_type: env.payload_type.clone(),
                signatures: vec![sig.clone()],
            };
            // Never by keyid: try each key authorised for THIS role.
            let hit = authorised
                .iter()
                .find_map(|k| verifies_under(&single, k).map(|p| (k.clone(), p)));
            if let Some((key, p)) = hit {
                signers.insert(key);
                payload = p;
                continue;
            }
            // Every signature must verify (verify_all strictness). Say why not,
            // as specifically as we can.
            if role != Role::Root && verifies_under(&single, &self.root).is_some() {
                return Err(VerifyError(format!(
                    "signed by this realm's ROOT key; in a roles realm the root signs only a \
                     delegation, and a {} must be signed by a {} key",
                    doc_name(expected),
                    role.name()
                )));
            }
            for other in [Role::Layer, Role::Status] {
                if other == role {
                    continue;
                }
                let theirs = d.keys_for(other).into_iter().flat_map(|rk| rk.keys.iter());
                for k in theirs {
                    if verifies_under(&single, k).is_some() {
                        return Err(VerifyError(format!(
                            "signed by this realm's {} key; a {} must be signed by a {} key",
                            other.name(),
                            doc_name(expected),
                            role.name()
                        )));
                    }
                }
            }
            return Err(VerifyError(format!(
                "signature does not verify under any {} key of this realm",
                role.name()
            )));
        }
        if signers.len() < threshold {
            return Err(VerifyError(format!(
                "{} distinct {} signer(s); the delegation requires {threshold}",
                signers.len(),
                role.name()
            )));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{dsse_sign_typed, dsse_verify_typed, generate_root_keypair};
    use proptest::prelude::*;
    use serde_json::json;
    use wsc::dsse::Ed25519DsseSigner;

    struct Key {
        sk: Vec<u8>,
        pk: Vec<u8>,
    }

    fn key() -> Key {
        let (sk, pk) = generate_root_keypair();
        Key { sk, pk }
    }

    fn sign(k: &Key, ty: &str, payload: &[u8], keyid: &str) -> String {
        dsse_sign_typed(payload, ty, &k.sk, keyid).unwrap()
    }

    /// One envelope carrying a signature from each key, in order.
    fn sign_many(keys: &[(&Key, &str)], ty: &str, payload: &[u8]) -> String {
        let mut env = DsseEnvelope::unsigned(payload, ty);
        for (k, id) in keys {
            let s = Ed25519DsseSigner::from_bytes(&k.sk, Some((*id).to_string())).unwrap();
            env.add_signature(&s).unwrap();
        }
        env.to_json().unwrap()
    }

    fn hexk(k: &Key) -> String {
        hex::encode(&k.pk)
    }

    struct Realm {
        root: Key,
        layer: Key,
        layer2: Key,
        status: Key,
    }

    fn realm() -> Realm {
        Realm {
            root: key(),
            layer: key(),
            layer2: key(),
            status: key(),
        }
    }

    fn delegation_doc(r: &Realm) -> serde_json::Value {
        json!({
            "realm-root": hexk(&r.root),
            "counter": 7,
            "issued-at": "2026-11-05T00:00:00Z",
            "roles": {
                "layer": {"threshold": 1, "keys": [{"key": hexk(&r.layer), "keyid": "layer-1"}]},
                "status": {"threshold": 1, "keys": [{"key": hexk(&r.status), "keyid": "status-1"}]},
            }
        })
    }

    fn sign_deleg(signer: &Key, doc: &serde_json::Value) -> String {
        sign(
            signer,
            DELEGATION_PAYLOAD_TYPE,
            doc.to_string().as_bytes(),
            "root",
        )
    }

    fn parse(r: &Realm, doc: &serde_json::Value) -> Result<Delegation, VerifyError> {
        Delegation::from_envelope(sign_deleg(&r.root, doc).as_bytes(), &r.root.pk)
    }

    fn roles_trust(r: &Realm) -> RealmTrust {
        let d = parse(r, &delegation_doc(r)).unwrap();
        RealmTrust::with_roles(&r.root.pk, d).unwrap()
    }

    fn err(r: Result<Vec<u8>, VerifyError>) -> String {
        r.expect_err("must be refused").0
    }

    const LAYER_TYPES: [&str; 3] = [
        LAYER_PAYLOAD_TYPE,
        attest::PAYLOAD_TYPE,
        RELEASE_SUMS_PAYLOAD_TYPE,
    ];
    const STATUS_TYPES: [&str; 2] = [LINE_STATUS_PAYLOAD_TYPE, LINE_INDEX_PAYLOAD_TYPE];

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn role_table_is_fixed() {
        for t in LAYER_TYPES {
            assert_eq!(role_for(t), Some(Role::Layer), "{t}");
        }
        for t in STATUS_TYPES {
            assert_eq!(role_for(t), Some(Role::Status), "{t}");
        }
        assert_eq!(role_for(DELEGATION_PAYLOAD_TYPE), Some(Role::Root));
        assert_eq!(
            role_for("application/vnd.pulseengine.varve.layer.v2+json"),
            None
        );
        assert_eq!(role_for(""), None);
        // The table reads the constants rather than copying them.
        assert_eq!(
            DELEGATION_PAYLOAD_TYPE,
            "application/vnd.pulseengine.varve.delegation.v1+json"
        );
    }

    #[test]
    fn errors_name_the_document_by_its_own_name() {
        assert_eq!(doc_name(LAYER_PAYLOAD_TYPE), "layer manifest");
        assert_eq!(doc_name(attest::PAYLOAD_TYPE), "attestation");
        assert_eq!(doc_name(RELEASE_SUMS_PAYLOAD_TYPE), "release sums document");
        assert_eq!(doc_name(LINE_STATUS_PAYLOAD_TYPE), "line-status");
        assert_eq!(doc_name(LINE_INDEX_PAYLOAD_TYPE), "line-index");
        assert_eq!(doc_name(DELEGATION_PAYLOAD_TYPE), "delegation");
    }

    fn signer_of(k: &Key) -> crate::verify::FileSigner {
        crate::verify::FileSigner::new(&k.sk, "k").unwrap()
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_producer_signs_a_delegation_that_round_trips() {
        let r = realm();
        let doc = delegation_doc(&r).to_string();
        let env = Delegation::sign(doc.as_bytes(), &signer_of(&r.root)).unwrap();
        let by_pin = Delegation::from_envelope(env.as_bytes(), &r.root.pk).unwrap();
        let by_name = Delegation::from_producer_envelope(env.as_bytes()).unwrap();
        assert_eq!(by_pin, by_name);
        assert_eq!(by_pin.counter(), 7);
        // Not the root's key: refused before any envelope exists.
        let m = Delegation::sign(doc.as_bytes(), &signer_of(&r.layer))
            .unwrap_err()
            .0;
        assert!(m.contains("different realm-root"), "{m}");
        // A document a consumer would refuse is not signed.
        let mut bad = delegation_doc(&r);
        bad["counter"] = json!("seven");
        assert!(Delegation::sign(bad.to_string().as_bytes(), &signer_of(&r.root)).is_err());
        let mut empty = delegation_doc(&r);
        empty["roles"] = json!({});
        assert!(
            Delegation::sign(empty.to_string().as_bytes(), &signer_of(&r.root))
                .unwrap_err()
                .0
                .contains("no roles")
        );
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_producer_envelope_signed_by_someone_else_is_refused() {
        let r = realm();
        let doc = delegation_doc(&r);
        // Signed by a role key, though it names the root: the claimed root
        // does not verify it.
        let e = sign_deleg(&r.layer, &doc);
        assert!(Delegation::from_producer_envelope(e.as_bytes()).is_err());
        assert!(Delegation::from_producer_envelope(b"not json").is_err());
        assert!(Delegation::from_producer_envelope(&[0xff, 0xfe]).is_err());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_signer_is_authorised_for_its_own_role_only() {
        let r = realm();
        let d = parse(&r, &delegation_doc(&r)).unwrap();
        // The right role: allowed, and the delegation's key-id hint comes back.
        assert_eq!(
            d.authorise_signer(Role::Layer, &r.layer.pk).unwrap(),
            Some("layer-1".to_string())
        );
        assert_eq!(
            d.authorise_signer(Role::Status, &r.status.pk).unwrap(),
            Some("status-1".to_string())
        );
        // The wrong role is named for what the key IS.
        let m = d.authorise_signer(Role::Status, &r.layer.pk).unwrap_err().0;
        assert!(m.contains("delegated to the LAYER role, not STATUS"), "{m}");
        let m = d.authorise_signer(Role::Layer, &r.status.pk).unwrap_err().0;
        assert!(m.contains("delegated to the STATUS role, not LAYER"), "{m}");
        // The root, for any role, and a stranger.
        for role in [Role::Layer, Role::Status] {
            let m = d.authorise_signer(role, &r.root.pk).unwrap_err().0;
            assert!(m.contains("this key is the realm root"), "{m}");
            let m = d.authorise_signer(role, &key().pk).unwrap_err().0;
            assert!(m.contains("not delegated to the"), "{m}");
        }
        // An entry with no hint gives none.
        let mut doc = delegation_doc(&r);
        doc["roles"]["layer"]["keys"][0] = json!({"key": hexk(&r.layer)});
        let d = parse(&r, &doc).unwrap();
        assert_eq!(d.authorise_signer(Role::Layer, &r.layer.pk).unwrap(), None);
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_second_key_hint_is_matched_by_position() {
        let r = realm();
        let mut doc = delegation_doc(&r);
        doc["roles"]["layer"]["keys"] = json!([
            {"key": hexk(&r.layer), "keyid": "layer-1"},
            {"key": hexk(&r.layer2), "keyid": "layer-2"},
        ]);
        let d = parse(&r, &doc).unwrap();
        assert_eq!(
            d.authorise_signer(Role::Layer, &r.layer2.pk).unwrap(),
            Some("layer-2".to_string())
        );
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_accepts_each_role_for_its_documents() {
        let r = realm();
        let t = roles_trust(&r);
        for ty in LAYER_TYPES {
            let e = sign(&r.layer, ty, b"payload", "x");
            assert_eq!(t.verify(&e, ty).unwrap(), b"payload", "{ty}");
        }
        for ty in STATUS_TYPES {
            let e = sign(&r.status, ty, b"payload", "x");
            assert_eq!(t.verify(&e, ty).unwrap(), b"payload", "{ty}");
        }
        let d = sign_deleg(&r.root, &delegation_doc(&r));
        assert!(t.verify(&d, DELEGATION_PAYLOAD_TYPE).is_ok());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_refuses_a_signature_out_of_role() {
        let r = realm();
        let t = roles_trust(&r);
        for ty in STATUS_TYPES {
            let e = sign(&r.layer, ty, b"p", "x");
            let m = err(t.verify(&e, ty));
            assert!(
                m.contains("signed by this realm's LAYER key") && m.contains("STATUS key"),
                "{m}"
            );
        }
        for ty in LAYER_TYPES {
            let e = sign(&r.status, ty, b"p", "x");
            let m = err(t.verify(&e, ty));
            assert!(
                m.contains("signed by this realm's STATUS key") && m.contains("LAYER key"),
                "{m}"
            );
        }
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_refuses_the_root_signing_anything_but_a_delegation() {
        let r = realm();
        let t = roles_trust(&r);
        for ty in LAYER_TYPES.iter().chain(STATUS_TYPES.iter()) {
            let e = sign(&r.root, ty, b"p", "x");
            let m = err(t.verify(&e, ty));
            assert!(m.contains("signed by this realm's ROOT key"), "{m}");
        }
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_refuses_a_delegation_signed_by_a_role_key() {
        let r = realm();
        let t = roles_trust(&r);
        let e = sign_deleg(&r.layer, &delegation_doc(&r));
        let m = err(t.verify(&e, DELEGATION_PAYLOAD_TYPE));
        assert!(m.contains("signed by this realm's LAYER key"), "{m}");
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_refuses_a_mixed_envelope_and_a_stranger() {
        let r = realm();
        let t = roles_trust(&r);
        // A valid LAYER signature does not launder a STATUS one, either way.
        let e = sign_many(
            &[(&r.layer, "a"), (&r.status, "b")],
            LAYER_PAYLOAD_TYPE,
            b"p",
        );
        assert!(err(t.verify(&e, LAYER_PAYLOAD_TYPE)).contains("STATUS key"));
        let e = sign_many(
            &[(&r.status, "b"), (&r.layer, "a")],
            LAYER_PAYLOAD_TYPE,
            b"p",
        );
        assert!(err(t.verify(&e, LAYER_PAYLOAD_TYPE)).contains("STATUS key"));
        // A stranger, alone or beside a valid signer.
        let s = key();
        let e = sign(&s, LAYER_PAYLOAD_TYPE, b"p", "layer-1");
        assert!(
            err(t.verify(&e, LAYER_PAYLOAD_TYPE)).contains("does not verify under any LAYER key")
        );
        let e = sign_many(&[(&r.layer, "a"), (&s, "b")], LAYER_PAYLOAD_TYPE, b"p");
        assert!(
            err(t.verify(&e, LAYER_PAYLOAD_TYPE)).contains("does not verify under any LAYER key")
        );
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_lying_keyid_neither_helps_nor_hurts() {
        let r = realm();
        let t = roles_trust(&r);
        // Signed by LAYER, naming STATUS: refused as a line-status.
        let e = sign(&r.layer, LINE_STATUS_PAYLOAD_TYPE, b"p", "status-1");
        assert!(err(t.verify(&e, LINE_STATUS_PAYLOAD_TYPE)).contains("LAYER key"));
        // Signed by the right key under a wrong name: still accepted.
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "status-1");
        assert!(t.verify(&e, LAYER_PAYLOAD_TYPE).is_ok());
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "");
        assert!(t.verify(&e, LAYER_PAYLOAD_TYPE).is_ok());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn roles_realm_refuses_unknown_types_wrong_types_and_garbage() {
        let r = realm();
        let t = roles_trust(&r);
        let unk = "application/x-something-else";
        let e = sign(&r.layer, unk, b"p", "x");
        assert!(err(t.verify(&e, unk)).contains("belongs to no role"));
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "x");
        assert!(err(t.verify(&e, LINE_STATUS_PAYLOAD_TYPE)).contains("payload type is"));
        assert!(err(t.verify("not json", LAYER_PAYLOAD_TYPE)).contains("not a DSSE envelope"));
        assert!(err(t.verify_bytes(&[0xff, 0xfe], LAYER_PAYLOAD_TYPE)).contains("UTF-8"));
        let unsigned = DsseEnvelope::unsigned(b"p", LAYER_PAYLOAD_TYPE)
            .to_json()
            .unwrap();
        assert!(err(t.verify(&unsigned, LAYER_PAYLOAD_TYPE)).contains("no signature"));
        // Tampered payload under a valid signature.
        let mut env =
            DsseEnvelope::from_json(&sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "x")).unwrap();
        env.payload = DsseEnvelope::unsigned(b"q", LAYER_PAYLOAD_TYPE).payload;
        assert!(
            t.verify(&env.to_json().unwrap(), LAYER_PAYLOAD_TYPE)
                .is_err()
        );
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn a_role_with_no_delegated_keys_accepts_nothing() {
        let r = realm();
        let mut doc = delegation_doc(&r);
        doc["roles"].as_object_mut().unwrap().remove("status");
        let t = RealmTrust::with_roles(&r.root.pk, parse(&r, &doc).unwrap()).unwrap();
        let e = sign(&r.status, LINE_STATUS_PAYLOAD_TYPE, b"p", "x");
        assert!(err(t.verify(&e, LINE_STATUS_PAYLOAD_TYPE)).contains("names no STATUS keys"));
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "x");
        assert!(t.verify(&e, LAYER_PAYLOAD_TYPE).is_ok());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn threshold_two_needs_two_distinct_keys() {
        let r = realm();
        let mut doc = delegation_doc(&r);
        doc["roles"]["layer"] = json!({"threshold": 2, "keys": [
            {"key": hexk(&r.layer)}, {"key": hexk(&r.layer2), "keyid": "l2"}]});
        let t = RealmTrust::with_roles(&r.root.pk, parse(&r, &doc).unwrap()).unwrap();
        let ty = LAYER_PAYLOAD_TYPE;
        let two = sign_many(&[(&r.layer, "a"), (&r.layer2, "b")], ty, b"p");
        assert_eq!(t.verify(&two, ty).unwrap(), b"p");
        let one = sign(&r.layer, ty, b"p", "a");
        assert!(err(t.verify(&one, ty)).contains("1 distinct LAYER signer(s)"));
        let same_twice = sign_many(&[(&r.layer, "a"), (&r.layer, "b")], ty, b"p");
        assert!(err(t.verify(&same_twice, ty)).contains("1 distinct LAYER signer(s)"));
        // Two signers where one is a stranger is still refused.
        let s = key();
        let bad = sign_many(&[(&r.layer, "a"), (&s, "b")], ty, b"p");
        assert!(t.verify(&bad, ty).is_err());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn delegation_parses_and_exposes_its_counter() {
        let r = realm();
        let d = parse(&r, &delegation_doc(&r)).unwrap();
        assert_eq!(d.counter(), 7);
        assert_eq!(d.issued_at(), "2026-11-05T00:00:00Z");
        let mut doc = delegation_doc(&r);
        doc["counter"] = json!(8);
        let d8 = parse(&r, &doc).unwrap();
        assert!(d8.newer_than(&d));
        assert!(!d.newer_than(&d8));
        assert!(!d.newer_than(&d), "equal is not newer");
        // A role's accessor path.
        assert!(d.keys_for(Role::Root).is_none());
        assert_eq!(d.keys_for(Role::Layer).unwrap().threshold, 1);
        // Uppercase hex is the same key.
        let mut doc = delegation_doc(&r);
        doc["roles"]["layer"]["keys"][0]["key"] = json!(hexk(&r.layer).to_uppercase());
        assert_eq!(parse(&r, &doc).unwrap().layer, d.layer);
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn delegation_refusals() {
        let r = realm();
        let other = key();
        let refuse = |mutate: &dyn Fn(&mut serde_json::Value), needle: &str| {
            let mut doc = delegation_doc(&r);
            mutate(&mut doc);
            let m = parse(&r, &doc).expect_err(needle).0;
            assert!(m.contains(needle), "wanted '{needle}' in '{m}'");
        };
        // unknown role name, including the root
        refuse(
            &|d| d["roles"]["admin"] = json!({"threshold": 1, "keys": []}),
            "unknown field",
        );
        refuse(
            &|d| d["roles"]["root"] = json!({"threshold": 1, "keys": [{"key": hexk(&other)}]}),
            "unknown field",
        );
        // cross-realm replay
        refuse(
            &|d| d["realm-root"] = json!(hexk(&other)),
            "different realm root",
        );
        // a key in two roles
        let lk = hexk(&r.layer);
        refuse(
            &|d| d["roles"]["status"]["keys"] = json!([{"key": lk}]),
            "also in another role",
        );
        // the root in a role
        let rk = hexk(&r.root);
        refuse(
            &|d| d["roles"]["layer"]["keys"] = json!([{"key": rk}]),
            "realm root as a LAYER key",
        );
        refuse(
            &|d| d["roles"]["status"]["keys"] = json!([{"key": rk}]),
            "realm root as a STATUS key",
        );
        // empty role
        refuse(
            &|d| d["roles"]["layer"]["keys"] = json!([]),
            "role LAYER has no keys",
        );
        refuse(
            &|d| d["roles"]["status"]["keys"] = json!([]),
            "role STATUS has no keys",
        );
        // threshold bounds
        refuse(
            &|d| d["roles"]["layer"]["threshold"] = json!(0),
            "threshold 0 for 1 keys",
        );
        refuse(
            &|d| d["roles"]["layer"]["threshold"] = json!(2),
            "threshold 2 for 1 keys",
        );
        // duplicate key within a role
        refuse(
            &|d| d["roles"]["layer"]["keys"] = json!([{"key": lk}, {"key": lk}]),
            "LAYER key twice",
        );
        // no roles at all, malformed key, malformed documents
        refuse(&|d| d["roles"] = json!({}), "names no roles");
        refuse(
            &|d| d["roles"]["layer"]["keys"] = json!([{"key": "zz"}]),
            "not hex",
        );
        refuse(
            &|d| d["roles"]["layer"]["keys"] = json!([{"key": "abcd"}]),
            "not a valid ed25519",
        );
        refuse(&|d| d["extra"] = json!(1), "unknown field");
        refuse(
            &|d| d["roles"]["layer"]["extra"] = json!(1),
            "unknown field",
        );
        refuse(
            &|d| d["roles"]["layer"]["keys"][0]["extra"] = json!(1),
            "unknown field",
        );
        refuse(
            &|d| {
                d.as_object_mut().unwrap().remove("counter");
            },
            "missing field",
        );
        // threshold n == keys is fine
        let mut doc = delegation_doc(&r);
        doc["roles"]["layer"]["threshold"] = json!(1);
        assert!(parse(&r, &doc).is_ok());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn delegation_must_be_signed_by_the_root_alone() {
        let r = realm();
        let doc = delegation_doc(&r);
        let by = |k: &Key| Delegation::from_envelope(sign_deleg(k, &doc).as_bytes(), &r.root.pk);
        assert!(by(&r.layer).is_err());
        assert!(by(&r.status).is_err());
        assert!(by(&key()).is_err());
        assert!(by(&r.root).is_ok());
        // The root plus anyone else is refused (verify_all strictness).
        let e = sign_many(
            &[(&r.root, "r"), (&r.layer, "l")],
            DELEGATION_PAYLOAD_TYPE,
            doc.to_string().as_bytes(),
        );
        assert!(Delegation::from_envelope(e.as_bytes(), &r.root.pk).is_err());
        // Wrong payload type: a layer manifest cannot be passed off as a delegation.
        let e = sign(&r.root, LAYER_PAYLOAD_TYPE, doc.to_string().as_bytes(), "r");
        assert!(Delegation::from_envelope(e.as_bytes(), &r.root.pk).is_err());
    }

    #[test]
    fn with_roles_refuses_a_delegation_of_another_realm() {
        let r = realm();
        let d = parse(&r, &delegation_doc(&r)).unwrap();
        assert!(RealmTrust::with_roles(&key().pk, d.clone()).is_err());
        assert!(RealmTrust::with_roles(b"short", d).is_err());
        assert!(RealmTrust::root_only(b"short").is_err());
        let t = roles_trust(&r);
        assert_eq!(t.root(), &r.root.pk[..]);
        assert!(matches!(t.mode(), Mode::Roles(_)));
        assert_eq!(
            *RealmTrust::root_only(&r.root.pk).unwrap().mode(),
            Mode::RootOnly
        );
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn root_only_realm_behaves_as_before() {
        let r = realm();
        let t = RealmTrust::root_only(&r.root.pk).unwrap();
        for ty in LAYER_TYPES.iter().chain(STATUS_TYPES.iter()) {
            let e = sign(&r.root, ty, b"p", "x");
            assert_eq!(t.verify(&e, ty).unwrap(), b"p");
            assert_eq!(
                dsse_verify_typed(e.as_bytes(), ty, &r.root.pk).unwrap(),
                b"p"
            );
        }
        // An unknown type is verified by the flat root exactly as it always was.
        let e = sign(&r.root, "application/x-anything", b"p", "x");
        assert!(t.verify(&e, "application/x-anything").is_ok());
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "x");
        assert!(t.verify(&e, LAYER_PAYLOAD_TYPE).is_err());
    }

    // rivet: partially-verifies REQ-KEYROLES-001
    #[test]
    fn negative_control_root_only_never_consults_a_delegation() {
        let r = realm();
        // A valid root-signed delegation exists and names the LAYER key...
        let deleg = sign_deleg(&r.root, &delegation_doc(&r));
        assert!(Delegation::from_envelope(deleg.as_bytes(), &r.root.pk).is_ok());
        // ...but a RootOnly trust, handed a LAYER-key signature, still refuses.
        let t = RealmTrust::root_only(&r.root.pk).unwrap();
        let e = sign(&r.layer, LAYER_PAYLOAD_TYPE, b"p", "layer-1");
        assert!(t.verify(&e, LAYER_PAYLOAD_TYPE).is_err());
        assert!(dsse_verify_typed(e.as_bytes(), LAYER_PAYLOAD_TYPE, &r.root.pk).is_err());
        // The same trust that roles mode accepts, the flat one does not.
        assert!(roles_trust(&r).verify(&e, LAYER_PAYLOAD_TYPE).is_ok());
    }

    /// The verifier that predates `RealmTrust`, reproduced as the oracle.
    fn old_verify_with(root: &[u8], envelope: &[u8], expected: &str) -> Result<Vec<u8>, String> {
        let verifier = Ed25519DsseVerifier::from_bytes(root)
            .map_err(|e| format!("invalid trust-root public key: {e}"))?;
        let text = std::str::from_utf8(envelope)
            .map_err(|_| "fetched bytes are not UTF-8 DSSE JSON".to_string())?;
        let envelope =
            DsseEnvelope::from_json(text).map_err(|e| format!("not a DSSE envelope: {e}"))?;
        if envelope.payload_type != expected {
            return Err(format!(
                "envelope payload type is '{}', expected '{expected}' — refusing to \
                 accept a signed document as something it is not",
                envelope.payload_type
            ));
        }
        envelope
            .verify_all(&verifier)
            .map_err(|e| format!("signature does not verify against the trust root: {e}"))
    }

    proptest! {
        // Clause 4: a realm with no roles is the old verifier, byte for byte,
        // on valid, mis-signed, mis-typed and mutated envelopes alike.
        // rivet: partially-verifies REQ-KEYROLES-001
        #[test]
        fn root_only_equals_the_old_verifier(
            payload in prop::collection::vec(any::<u8>(), 0..64),
            signer_is_root in any::<bool>(),
            second_signer in any::<bool>(),
            sign_type in 0usize..3,
            expect_type in 0usize..3,
            mutate in prop::option::of((0usize..4096, any::<u8>(), any::<bool>())),
        ) {
            let types = [LAYER_PAYLOAD_TYPE, LINE_STATUS_PAYLOAD_TYPE, "x/other"];
            let root = key();
            let other = key();
            let signer = if signer_is_root { &root } else { &other };
            let mut keys: Vec<(&Key, &str)> = vec![(signer, "k")];
            if second_signer {
                keys.push((&other, "k2"));
            }
            let mut text = sign_many(&keys, types[sign_type], &payload);
            if let Some((at, byte, truncate)) = mutate {
                let mut b = text.into_bytes();
                let i = at % b.len();
                if truncate { b.truncate(i); } else { b[i] = byte; }
                text = String::from_utf8_lossy(&b).into_owned();
            }
            let expected = types[expect_type];
            let new = RealmTrust::root_only(&root.pk).unwrap().verify(&text, expected);
            let old = old_verify_with(&root.pk, text.as_bytes(), expected);
            prop_assert_eq!(new.map_err(|e| e.0), old);
        }
    }
}
