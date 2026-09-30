//! A digest list covered by a detached PGP signature (REQ-SIGNEDSUMS-001, DD-034).
//!
//! `upstream-sums` is the right rung for a bare `SHA256SUMS.txt`: the bytes are
//! the bytes that list names, and nothing about who produced them, because the
//! same host serves both. It is the WRONG rung for a list somebody signed. This
//! module is the mechanism that tells the two apart — it verifies a detached
//! OpenPGP signature over a digest list against a key the CALLER supplies, and
//! reports the identity that vouched so the rung can name it.
//!
//! The key arrives here as bytes and is never fetched. Where those bytes come
//! from is the realm's problem (clause 3, DD-023): a key discovered beside the
//! artifact it vouches for is not a proof, and a keyserver lookup at deposit
//! time makes the network an authority. This module cannot reach the network and
//! must not grow the ability.
//!
//! # Why `pgp` (rPGP) 0.20 and not `sequoia-openpgp`
//!
//! Measured 2026-09-30, not recalled.
//!
//! `sequoia-openpgp` 2.4.1 is disqualified twice, either of which alone is
//! enough:
//!
//! * **Licence.** `cargo metadata` reports `LGPL-2.0-or-later`. `deny.toml`'s
//!   allow-list is Apache-2.0/MIT/BSD/ISC/Zlib/MPL-2.0/Unicode-3.0/CDLA — LGPL
//!   is not on it, and a static musl binary is precisely the relinking case the
//!   LGPL is written about. Adding it means either changing what this project
//!   is willing to ship or carrying an exception nobody wants to defend.
//! * **C dependency.** Its default backend is `crypto-nettle`, i.e.
//!   `nettle-sys` → libnettle + libhogweed + GMP through `pkg-config`,
//!   `bindgen` and `cc`. That is a C toolchain in the crate every varve
//!   consumer links, and it is the same cost `lzma-rs` was chosen to avoid
//!   (see this crate's Cargo.toml). Its pure-Rust alternative is gated behind
//!   feature flags Sequoia named `allow-experimental-crypto` and
//!   `allow-variable-time-crypto`; a flag whose name is a warning is a warning.
//!
//! `pgp` 0.20.0 (the rPGP project) is `MIT OR Apache-2.0`, and measured with
//! `cargo tree -e build` it has **zero build dependencies** — no `cc`, no
//! `-sys` crate, nothing to cross-compile. With `default-features = false` its
//! tree is 181 crates, all pure Rust; the RustCrypto stack it uses
//! (`rsa`, `sha2`, `ed25519-dalek`, …) is already most of what this workspace
//! links. It has been audited (Radically Open Security 2024-12, ETH Zurich
//! 2024-03) and is the OpenPGP implementation under Delta Chat and the `rpm`
//! crate. `default-features = false` drops the `bzip2` default, which only
//! matters for compressed *messages* and never for a detached signature; the
//! real Rust artifacts below verify without it.
//!
//! **Binary size, measured both ways, because one of the numbers lies.** Adding
//! this module to the release `varve` binary costs 24 KiB today (7 268 528
//! bytes with it, 7 243 552 without) — small only because nothing calls it yet
//! and the linker drops what it cannot reach. Do not quote that number.
//! Linking an actual verification costs **2.27 MiB** of release binary,
//! measured by building one probe crate twice, once calling `verify` and once
//! not (2 760 224 vs 435 488 bytes). That is what wiring this into `ingest`
//! will add — roughly a third of the current binary — and it is the real price
//! of speaking OpenPGP at all.
//!
//! **The cost we are taking on, stated plainly.** `pgp` pulls `rsa` 0.9, which
//! carries RUSTSEC-2023-0071 (Marvin attack) with no fixed version — verified
//! by running `cargo deny check advisories` on this workspace, which FAILS.
//! The advisory is about non-constant-time RSA *private-key* operations leaking
//! the key to an attacker who can time them. This module performs public-key
//! verification only; no OpenPGP secret key ever exists in this process, so
//! there is no secret for the side channel to leak. That reasoning is a
//! judgement, not a fact about the crate, so it belongs in `deny.toml` as an
//! explicit `[advisories] ignore` with this rationale — NOT silently. Until
//! that entry exists, this crate's advisory gate is red, and that is correct
//! behaviour from the gate.
//!
//! # What this module checks, and why each check is here
//!
//! `pgp` is deliberately a low-level library: its README says it implements
//! OpenPGP layers 1–3 and explicitly not layer 4 (expiry, revocation, key
//! flags). Everything below is policy this module owns, confirmed by reading
//! rPGP 0.20.0's source rather than assuming:
//!
//! * **Binary-document signatures only.** `src/composed/signature.rs` documents
//!   that a `DetachedSignature` "is either of type Binary or Text" but its
//!   parser (`fn next`, same file) accepts any signature packet, so the
//!   doc-comment is not a check. It matters: a Text signature hashes the
//!   line-ending-NORMALISED form, so one signature covers both the LF and the
//!   CRLF spelling of the same file. Measured — see
//!   `a_text_signature_covers_two_different_byte_strings`. A digest list must
//!   be byte-exact or the digests in it are not the digests that were vouched
//!   for.
//! * **A 256-bit digest floor.** rPGP's `check_signature_hash_strength`
//!   (`src/packet/signature/types.rs:437`) only enforces a floor when the
//!   public-key algorithm `is_pqc()`. An RSA signature over a SHA-1 hash
//!   verifies happily. SHA-1 is collision-broken, and a digest list is exactly
//!   the kind of structured, attacker-influenceable text a chosen-prefix
//!   collision targets.
//! * **The certificate's own signatures must verify, and it must carry no
//!   revocation.** The pinned key is trusted custody, not trusted bytes: the
//!   realistic failure is an operator re-pinning an upstream key export that
//!   now carries the upstream's own revocation certificate. Refusing it is the
//!   difference between "we noticed" and "we kept verifying with a dead key".
//! * **Subkeys are candidates too.** Rust signs with its PRIMARY key —
//!   measured: issuer `85ab96e6fa1be5fe`, which is the primary, and
//!   `SignedPublicKey`'s own `VerifyingKey` impl only ever tries the primary.
//!   Most other modern keys sign with a signing subkey, and clause 2 says this
//!   mechanism is general, not "Rust". So every bound key in the certificate is
//!   a candidate.
//!
//! # What this module deliberately does NOT check
//!
//! **Key expiry.** rPGP does not check it and neither does this module, and
//! that is a decision rather than an oversight. Deciding whether a key has
//! expired needs a clock, and every clock available at verification time is
//! either absent (air-gapped), wrong, or supplied by the thing being verified:
//! a signature's creation timestamp lives in the hashed area, so it is signed —
//! by the key whose validity is the question. An expiry check built on either
//! would be an invariant enforced by the attacker. The realm's pin is the
//! custody boundary; a key that should no longer be trusted is a key that
//! should no longer be pinned. If this is ever wanted, it needs the same
//! trusted-time story as anti-rollback, not a `SystemTime::now()`.
//!
//! **Key flags.** A certificate may mark a key as not-for-signing. This module
//! does not consult those flags; a signature that verifies under a key in the
//! pinned certificate is accepted. Worth revisiting if a pinned certificate
//! ever carries an encryption-only subkey an attacker could confuse it with.
//!
//! # The measured artifact
//!
//! `static.rust-lang.org/dist/channel-rust-stable.toml` (898 637 bytes on
//! 2026-09-03) with `channel-rust-stable.toml.asc` (801 bytes), verified
//! against `static.rust-lang.org/rust-key.gpg.ascii`: one v4 RSA signature,
//! type 0x00 (binary), SHA-512, issuer key id `85ab96e6fa1be5fe`, primary
//! fingerprint `108f66205eaeb0aaa8dd5e1c85ab96e6fa1be5fe`. Cross-checked
//! against `gpg --verify` before any of this code existed. All three files are
//! vendored under `tests/fixtures/pgpsums/` (the manifest gzipped, 80 KB
//! instead of 898 KB) so the end-to-end path is exercised against the real
//! artifact and not a toy.

use std::collections::BTreeMap;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::packet::SignatureType;
use pgp::types::KeyDetails;

/// The only `manifest-version` of the Rust channel manifest this parser claims
/// to understand. A later version is a different document; reading it under
/// these assumptions would be inventing digests.
pub const RUST_CHANNEL_MANIFEST_VERSION: &str = "2";

/// The smallest signature digest this module will accept, in bits. SHA-1 (160)
/// and everything below it is refused; the Rust manifest is signed with
/// SHA-512.
pub const MIN_SIGNATURE_DIGEST_BITS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum PgpSumsError {
    #[error("the supplied public key is not readable OpenPGP, armored or binary: {0}")]
    KeyUnreadable(String),
    #[error("the supplied certificate's own bindings do not verify: {0}")]
    KeyBindingsBroken(String),
    #[error(
        "the supplied certificate carries {count} revocation signature(s) — a revoked key vouches for nothing"
    )]
    KeyRevoked { count: usize },
    #[error("the detached signature is not readable OpenPGP, armored or binary: {0}")]
    SignatureUnreadable(String),
    #[error("the detached signature file carries no signature packet")]
    SignatureEmpty,
    #[error(
        "signature {index} is of type {found}, and a digest list may only be covered by a \
         binary-document signature (0x00) — a text signature covers the line-ending-normalised \
         form, so it does not bind the bytes"
    )]
    NotBinarySignature { index: usize, found: String },
    #[error(
        "signature {index} hashes with {hash} ({bits} bits), below the {floor}-bit floor this \
         module requires"
    )]
    WeakDigest {
        index: usize,
        hash: String,
        bits: usize,
        floor: usize,
    },
    #[error(
        "no signature verifies against the supplied key {fingerprint}: tried {signatures} \
         signature(s) against {keys} key(s) in the certificate — last failure: {last}"
    )]
    DoesNotVerify {
        fingerprint: String,
        signatures: usize,
        keys: usize,
        last: String,
    },
    #[error("the channel manifest is not UTF-8 text")]
    ManifestNotText,
    #[error("the channel manifest is not readable TOML: {0}")]
    ManifestUnreadable(String),
    #[error(
        "the channel manifest declares manifest-version '{found}', and this parser only \
         understands '{RUST_CHANNEL_MANIFEST_VERSION}'"
    )]
    ManifestVersion { found: String },
    #[error("{at}: names a url but carries no sha256 — a NAMED asset without a digest is refused")]
    DigestMissing { at: String },
    #[error("{at}: carries a sha256 but no url — a digest with nothing to apply it to is refused")]
    UrlMissing { at: String },
    #[error("{at}: sha256 '{found}' is not 64 hex characters")]
    DigestMalformed { at: String, found: String },
}

/// Who vouched for a digest list. Clause 1: this identity travels in the signed
/// annotation exactly as a cosign certificate identity does, so `inspect` and
/// `diff` can report it without re-doing the crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VouchedBy {
    /// Lowercase hex fingerprint of the certificate's primary key. This is the
    /// stable name of the identity.
    pub primary_fingerprint: String,
    /// Lowercase hex fingerprint of the key that actually produced the
    /// signature — the primary, or one of its bound subkeys. Kept separate
    /// because "which key signed" is a different fact from "whose key is it",
    /// and collapsing them is how subkey compromise goes unnoticed.
    pub signing_fingerprint: String,
    /// The certificate's user IDs, in certificate order, lossily decoded. Human
    /// labels only — the fingerprint is the identity.
    pub user_ids: Vec<String>,
}

impl VouchedBy {
    /// The one-line form for `ANN_PROOF_SIGNER`. The fingerprint leads because
    /// it is the part that is cryptographically meaningful; a user ID is a
    /// self-asserted string.
    pub fn signer_annotation(&self) -> String {
        match self.user_ids.first() {
            Some(uid) => format!("openpgp:{} ({uid})", self.primary_fingerprint),
            None => format!("openpgp:{}", self.primary_fingerprint),
        }
    }
}

/// Verify a detached OpenPGP signature over a digest list against a supplied
/// public key.
///
/// `public_key` may be an ASCII-armored certificate (`-----BEGIN PGP PUBLIC KEY
/// BLOCK-----`) or the same certificate in binary packet form; likewise
/// `detached_signature` may be armored or binary. Both are auto-detected, so a
/// realm may pin whichever form its custody process produces — and both forms
/// are tested.
///
/// Returns who vouched. **There is no third outcome**: this never warns, never
/// downgrades, and never reports a weaker rung (clause 5). A digest list whose
/// signature does not verify is evidence of a problem, not an unsigned list.
pub fn verify_detached_signature(
    digest_list: &[u8],
    detached_signature: &[u8],
    public_key: &[u8],
) -> Result<VouchedBy, PgpSumsError> {
    let cert = read_certificate(public_key)?;
    let signatures = read_signatures(detached_signature)?;

    // Every key in the certificate is a candidate. rPGP's own `VerifyingKey`
    // impl for `SignedPublicKey` tries the primary and stops, which is right
    // for Rust (measured: it signs with the primary) and wrong for the general
    // upstream clause 2 promises to serve.
    let mut candidates: Vec<(&dyn VerifyCandidate, String)> =
        vec![(&cert.primary_key, hex_fingerprint(&cert.primary_key))];
    for subkey in &cert.public_subkeys {
        candidates.push((&subkey.key, hex_fingerprint(&subkey.key)));
    }

    let primary_fingerprint = hex_fingerprint(&cert.primary_key);
    let mut last = String::from("no candidate key was tried");

    for (index, signature) in signatures.iter().enumerate() {
        check_signature_shape(index, signature)?;
        for (key, fingerprint) in &candidates {
            match key.try_verify(signature, digest_list) {
                Ok(()) => {
                    return Ok(VouchedBy {
                        primary_fingerprint,
                        signing_fingerprint: fingerprint.clone(),
                        user_ids: cert
                            .details
                            .users
                            .iter()
                            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
                            .collect(),
                    });
                }
                Err(e) => last = e,
            }
        }
    }

    Err(PgpSumsError::DoesNotVerify {
        fingerprint: primary_fingerprint,
        signatures: signatures.len(),
        keys: candidates.len(),
        last,
    })
}

/// One `(url, sha256)` pair the channel manifest vouches for, with the package
/// and target it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEntry {
    /// The package name (`rustc`, `cargo`, `rust-std`, …) or, for the
    /// `[artifacts]` tables, the artifact kind (`installer-msi`, `source-code`).
    pub package: String,
    /// The target triple, or `*` for the target-independent source tarballs.
    pub target: String,
    pub url: String,
    /// Lowercase hex, 64 characters. Normalised here so a caller never has to
    /// wonder about case.
    pub sha256: String,
    pub form: EntryForm,
}

/// Which of the manifest's THREE digest spellings an entry came from. They are
/// not interchangeable and the difference is not cosmetic: `[pkg.…]` tables
/// carry `hash`/`xz_hash` for two compressions of the same content, while
/// `[[artifacts.…]]` tables carry `hash-sha256` for a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryForm {
    /// `[pkg.<name>.target.<triple>]` → `url` + `hash` (a `.tar.gz`).
    Tarball,
    /// `[pkg.<name>.target.<triple>]` → `xz_url` + `xz_hash` (a `.tar.xz`).
    TarballXz,
    /// `[[artifacts.<kind>.target.<triple>]]` → `url` + `hash-sha256`.
    Artifact,
}

/// A parsed Rust channel manifest: the release it names and every digest it
/// vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustChannel {
    /// The manifest's `date`, which is the channel's identity — `1.98.1` is not
    /// enough to name a build, but `2026-09-03` is.
    pub date: String,
    pub entries: Vec<ChannelEntry>,
}

/// Parse a Rust channel manifest (`channel-rust-<channel>.toml`) into the list
/// of `(package, target, url, sha256)` it vouches for.
///
/// This refuses rather than skips. A target the manifest marks unavailable
/// carries no url and no digest and yields no entry — that is the manifest
/// saying nothing, which is different from the manifest saying something
/// incomplete. A table that NAMES a url and omits the digest (or the reverse)
/// is refused, because silently dropping it would turn a broken manifest into a
/// shorter valid one (varve#217).
pub fn parse_rust_channel(manifest: &[u8]) -> Result<RustChannel, PgpSumsError> {
    let text = std::str::from_utf8(manifest).map_err(|_| PgpSumsError::ManifestNotText)?;
    let raw: RawChannel =
        toml::from_str(text).map_err(|e| PgpSumsError::ManifestUnreadable(e.to_string()))?;

    if raw.manifest_version != RUST_CHANNEL_MANIFEST_VERSION {
        return Err(PgpSumsError::ManifestVersion {
            found: raw.manifest_version,
        });
    }

    let mut entries = Vec::new();
    for (package, pkg) in &raw.pkg {
        for (target, spec) in &pkg.target {
            let at = format!("pkg.{package}.target.{target}");
            pair(
                &at,
                &spec.url,
                &spec.hash,
                package,
                target,
                EntryForm::Tarball,
                &mut entries,
            )?;
            pair(
                &format!("{at} (xz)"),
                &spec.xz_url,
                &spec.xz_hash,
                package,
                target,
                EntryForm::TarballXz,
                &mut entries,
            )?;
        }
    }
    for (kind, artifact) in &raw.artifacts {
        for (target, list) in &artifact.target {
            for (n, item) in list.iter().enumerate() {
                let at = format!("artifacts.{kind}.target.{target}[{n}]");
                entries.push(ChannelEntry {
                    package: kind.clone(),
                    target: target.clone(),
                    url: item.url.clone(),
                    sha256: normalise_sha256(&at, &item.hash_sha256)?,
                    form: EntryForm::Artifact,
                });
            }
        }
    }

    Ok(RustChannel {
        date: raw.date,
        entries,
    })
}

/// Verify the signature FIRST, then parse — the only way to reach the entries.
///
/// The shape is the point. An entry list is a set of digests varve would then
/// treat as authoritative, and "verify, then use" is an ordering a caller can
/// get wrong. Here they cannot: `RustChannel` is unreachable without a
/// `VouchedBy`, so there is no code path on which an unverified manifest
/// becomes a list of trusted digests.
pub fn verify_and_parse_rust_channel(
    manifest: &[u8],
    detached_signature: &[u8],
    public_key: &[u8],
) -> Result<(VouchedBy, RustChannel), PgpSumsError> {
    let vouched = verify_detached_signature(manifest, detached_signature, public_key)?;
    let channel = parse_rust_channel(manifest)?;
    Ok((vouched, channel))
}

// ---------------------------------------------------------------- internals

/// A key the signature may have been made by. Exists so the primary key and a
/// subkey — two unrelated rPGP types — can share one candidate loop.
trait VerifyCandidate {
    fn try_verify(&self, signature: &DetachedSignature, data: &[u8]) -> Result<(), String>;
    fn fingerprint_hex(&self) -> String;
}

impl VerifyCandidate for pgp::packet::PublicKey {
    fn try_verify(&self, signature: &DetachedSignature, data: &[u8]) -> Result<(), String> {
        signature.verify(self, data).map_err(|e| e.to_string())
    }
    fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint().as_bytes())
    }
}

impl VerifyCandidate for pgp::packet::PublicSubkey {
    fn try_verify(&self, signature: &DetachedSignature, data: &[u8]) -> Result<(), String> {
        signature.verify(self, data).map_err(|e| e.to_string())
    }
    fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint().as_bytes())
    }
}

fn hex_fingerprint(key: &impl VerifyCandidate) -> String {
    key.fingerprint_hex()
}

fn read_certificate(public_key: &[u8]) -> Result<SignedPublicKey, PgpSumsError> {
    // `from_reader_single` sniffs armor vs binary, so a realm may pin either.
    let (cert, _headers) = SignedPublicKey::from_reader_single(public_key)
        .map_err(|e| PgpSumsError::KeyUnreadable(e.to_string()))?;
    cert.verify_bindings()
        .map_err(|e| PgpSumsError::KeyBindingsBroken(e.to_string()))?;
    let revocations = cert.details.revocation_signatures.len();
    if revocations > 0 {
        return Err(PgpSumsError::KeyRevoked { count: revocations });
    }
    Ok(cert)
}

fn read_signatures(detached: &[u8]) -> Result<Vec<DetachedSignature>, PgpSumsError> {
    let (iter, _headers) = DetachedSignature::from_reader_many(detached)
        .map_err(|e| PgpSumsError::SignatureUnreadable(e.to_string()))?;
    let signatures = iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PgpSumsError::SignatureUnreadable(e.to_string()))?;
    if signatures.is_empty() {
        return Err(PgpSumsError::SignatureEmpty);
    }
    Ok(signatures)
}

/// Refuse anything that is not a binary-document signature over a digest of at
/// least [`MIN_SIGNATURE_DIGEST_BITS`]. Both are checked BEFORE the crypto runs,
/// so a weak-hash signature is reported as weak rather than as "did not
/// verify" — the two are different findings and an operator needs to know which.
fn check_signature_shape(index: usize, signature: &DetachedSignature) -> Result<(), PgpSumsError> {
    match signature.signature.typ() {
        Some(SignatureType::Binary) => {}
        other => {
            return Err(PgpSumsError::NotBinarySignature {
                index,
                found: match other {
                    Some(t) => format!("{t:?}"),
                    None => "unknown (unsupported signature version)".to_string(),
                },
            });
        }
    }
    let hash = signature
        .signature
        .hash_alg()
        .ok_or_else(|| PgpSumsError::WeakDigest {
            index,
            hash: "unknown".to_string(),
            bits: 0,
            floor: MIN_SIGNATURE_DIGEST_BITS,
        })?;
    let bits = hash.digest_size().unwrap_or(0) * 8;
    if bits < MIN_SIGNATURE_DIGEST_BITS {
        return Err(PgpSumsError::WeakDigest {
            index,
            hash: format!("{hash:?}"),
            bits,
            floor: MIN_SIGNATURE_DIGEST_BITS,
        });
    }
    Ok(())
}

/// Both halves of one `(url, digest)` pair, or neither. The `(Some, None)` and
/// `(None, Some)` cases are the ones that matter: a table that names half a
/// pair is a broken table, and dropping it quietly would turn a broken manifest
/// into a shorter valid one.
fn pair(
    at: &str,
    url: &Option<String>,
    hash: &Option<String>,
    package: &str,
    target: &str,
    form: EntryForm,
    out: &mut Vec<ChannelEntry>,
) -> Result<(), PgpSumsError> {
    match (url, hash) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(PgpSumsError::DigestMissing { at: at.to_string() }),
        (None, Some(_)) => Err(PgpSumsError::UrlMissing { at: at.to_string() }),
        (Some(url), Some(hash)) => {
            out.push(ChannelEntry {
                package: package.to_string(),
                target: target.to_string(),
                url: url.clone(),
                sha256: normalise_sha256(at, hash)?,
                form,
            });
            Ok(())
        }
    }
}

/// Hex case is not semantic, so accept either and hand callers one spelling;
/// anything that is not 64 hex characters is refused rather than repaired.
fn normalise_sha256(at: &str, found: &str) -> Result<String, PgpSumsError> {
    let malformed = || PgpSumsError::DigestMalformed {
        at: at.to_string(),
        found: found.to_string(),
    };
    if found.len() != 64 || !found.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    Ok(found.to_ascii_lowercase())
}

#[derive(serde::Deserialize)]
struct RawChannel {
    #[serde(rename = "manifest-version")]
    manifest_version: String,
    date: String,
    #[serde(default)]
    pkg: BTreeMap<String, RawPkg>,
    #[serde(default)]
    artifacts: BTreeMap<String, RawArtifactKind>,
}

#[derive(serde::Deserialize)]
struct RawPkg {
    #[serde(default)]
    target: BTreeMap<String, RawTarget>,
}

#[derive(serde::Deserialize)]
struct RawTarget {
    url: Option<String>,
    hash: Option<String>,
    xz_url: Option<String>,
    xz_hash: Option<String>,
}

#[derive(serde::Deserialize)]
struct RawArtifactKind {
    #[serde(default)]
    target: BTreeMap<String, Vec<RawArtifact>>,
}

#[derive(serde::Deserialize)]
struct RawArtifact {
    url: String,
    #[serde(rename = "hash-sha256")]
    hash_sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder};
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::packet::{SignatureConfig, Subpacket, SubpacketData};
    use pgp::ser::Serialize as _;
    use pgp::types::{Password, Timestamp};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // ---------------------------------------------------------------- fixtures
    //
    // SCOPE OF THESE FIXTURES, stated so nobody cites them for more than they
    // are: the three files under tests/fixtures/pgpsums/ are the REAL artifacts
    // fetched from static.rust-lang.org on 2026-09-30 — the release key, the
    // stable channel manifest dated 2026-09-03, and its detached signature. The
    // manifest is stored gzipped (80 KB instead of 898 KB); `rust_manifest`
    // asserts its decompressed length and digest, so a re-gzip of different
    // content cannot pass unnoticed. They exercise ONE upstream, ONE signature
    // and ONE algorithm pair (RSA-4096 / SHA-512). Everything about text
    // signatures, weak digests, revocation, subkey signing and wrong keys is
    // tested against keys generated below, because no upstream publishes the
    // signatures a verifier must refuse.

    const RUST_KEY_ASC: &[u8] = include_bytes!("../tests/fixtures/pgpsums/rust-release-key.asc");
    const RUST_SIG_ASC: &[u8] =
        include_bytes!("../tests/fixtures/pgpsums/channel-rust-stable-2026-09-03.toml.asc");
    const RUST_MANIFEST_GZ: &[u8] =
        include_bytes!("../tests/fixtures/pgpsums/channel-rust-stable-2026-09-03.toml.gz");

    /// Measured with `wc -c` and `shasum -a 256` on the file as downloaded,
    /// before it was compressed.
    const RUST_MANIFEST_LEN: usize = 898_637;
    const RUST_MANIFEST_SHA256: &str =
        "a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e";
    const RUST_PRIMARY_FPR: &str = "108f66205eaeb0aaa8dd5e1c85ab96e6fa1be5fe";

    fn rust_manifest() -> Vec<u8> {
        use std::io::Read as _;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(RUST_MANIFEST_GZ)
            .read_to_end(&mut out)
            .expect("fixture is not valid gzip");
        // Fails if someone re-compresses a DIFFERENT manifest into the fixture
        // path: every assertion below about counts and dates would then be
        // measuring something nobody looked at.
        assert_eq!(out.len(), RUST_MANIFEST_LEN, "fixture length drifted");
        assert_eq!(
            varve_core::store::manifest_digest(&out),
            format!("sha256:{RUST_MANIFEST_SHA256}"),
            "fixture digest drifted"
        );
        out
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x5164_5645)
    }

    /// Seed derived from the user ID so that two differently-named test keys
    /// are genuinely two different keys. Seeding every generation from one
    /// constant produced two IDENTICAL keypairs and quietly turned the
    /// broken-bindings test into a test of nothing, which is exactly the
    /// failure shape a negative control exists to catch.
    fn rng_for(uid: &str) -> ChaCha20Rng {
        let mut seed = 0xcbf2_9ce4_8422_2325u64;
        for b in uid.bytes() {
            seed ^= u64::from(b);
            seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
        }
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// A certificate whose PRIMARY key signs — the shape Rust uses.
    fn generated_key(uid: &str) -> (SignedSecretKey, Vec<u8>) {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .primary_user_id(uid.to_string())
            .build()
            .unwrap();
        let secret = params.generate(rng_for(uid)).unwrap();
        let public: SignedPublicKey = secret.clone().into();
        let armored = public.to_armored_bytes(Default::default()).unwrap();
        (secret, armored)
    }

    /// A certificate whose signing SUBKEY signs — the shape most non-Rust
    /// upstreams use.
    fn generated_key_with_signing_subkey(uid: &str) -> (SignedSecretKey, Vec<u8>) {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .primary_user_id(uid.to_string())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let secret = params.generate(rng_for(uid)).unwrap();
        let public: SignedPublicKey = secret.clone().into();
        let armored = public.to_armored_bytes(Default::default()).unwrap();
        (secret, armored)
    }

    fn sign_binary(secret: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
        DetachedSignature::sign_binary_data(
            rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .unwrap()
        .to_armored_bytes(Default::default())
        .unwrap()
    }

    const SUMS: &[u8] =
        b"3b1f0e4b1b2c0d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6  tool.tar.gz\n";

    // ------------------------------------------------- the real Rust artifact

    /// Fails if `verify_detached_signature` feeds the wrong bytes to the
    /// verifier, refuses armored input, mis-selects the signing key, or gets
    /// the binary-type or digest-floor gates backwards. This is the only test
    /// that runs the whole path over the artifact REQ-SIGNEDSUMS-001 was
    /// written from.
    #[test]
    fn the_real_rust_channel_signature_verifies_against_the_real_rust_key() {
        let vouched =
            verify_detached_signature(&rust_manifest(), RUST_SIG_ASC, RUST_KEY_ASC).unwrap();
        assert_eq!(vouched.primary_fingerprint, RUST_PRIMARY_FPR);
        // Measured with `gpg --list-packets`: Rust signs with the PRIMARY key,
        // not with either of its two subkeys.
        assert_eq!(vouched.signing_fingerprint, RUST_PRIMARY_FPR);
        assert_eq!(
            vouched.user_ids,
            vec!["Rust Language (Tag and Release Signing Key) <rust-key@rust-lang.org>"]
        );
        assert_eq!(
            vouched.signer_annotation(),
            format!(
                "openpgp:{RUST_PRIMARY_FPR} (Rust Language (Tag and Release Signing Key) \
                 <rust-key@rust-lang.org>)"
            )
        );
    }

    /// Clause 5. Fails if a byte-level difference in the digest list is ever
    /// answered with anything but an error — the exact shape a tampered digest
    /// list has.
    #[test]
    fn one_flipped_byte_in_the_digest_list_is_refused() {
        let mut manifest = rust_manifest();
        // Flip a character inside a real sha256 value, which is the mutation an
        // attacker actually wants.
        let needle = b"hash = \"";
        let at = manifest
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap()
            + needle.len();
        manifest[at] = if manifest[at] == b'a' { b'b' } else { b'a' };
        let err = verify_detached_signature(&manifest, RUST_SIG_ASC, RUST_KEY_ASC).unwrap_err();
        assert!(
            matches!(err, PgpSumsError::DoesNotVerify { .. }),
            "expected a refusal, got {err}"
        );
    }

    /// Fails if a truncated download is treated as a shorter valid list.
    #[test]
    fn a_truncated_digest_list_is_refused() {
        let manifest = rust_manifest();
        let err =
            verify_detached_signature(&manifest[..manifest.len() - 1], RUST_SIG_ASC, RUST_KEY_ASC)
                .unwrap_err();
        assert!(matches!(err, PgpSumsError::DoesNotVerify { .. }), "{err}");
    }

    /// Fails if the verifier ever accepts a signature it did not match to the
    /// supplied key — the whole point of pinning one.
    #[test]
    fn the_rust_signature_does_not_verify_against_some_other_key() {
        let (_, other_key) = generated_key("someone else <nobody@example.invalid>");
        let err =
            verify_detached_signature(&rust_manifest(), RUST_SIG_ASC, &other_key).unwrap_err();
        assert!(matches!(err, PgpSumsError::DoesNotVerify { .. }), "{err}");
    }

    // ------------------------------------------------------- input encodings

    /// Both encodings are accepted, so both are tested (the realm decides which
    /// form its custody process pins). Fails if `read_certificate` or
    /// `read_signatures` is narrowed to one encoding.
    #[test]
    fn a_binary_key_and_a_binary_signature_are_accepted_as_well_as_armored() {
        let manifest = rust_manifest();
        let (cert, _) = SignedPublicKey::from_reader_single(RUST_KEY_ASC).unwrap();
        let mut key_binary = Vec::new();
        cert.to_writer(&mut key_binary).unwrap();
        let (sig, _) = DetachedSignature::from_reader_single(RUST_SIG_ASC).unwrap();
        let mut sig_binary = Vec::new();
        sig.to_writer(&mut sig_binary).unwrap();

        for (key, signature, label) in [
            (
                RUST_KEY_ASC.to_vec(),
                RUST_SIG_ASC.to_vec(),
                "armored/armored",
            ),
            (key_binary.clone(), RUST_SIG_ASC.to_vec(), "binary/armored"),
            (RUST_KEY_ASC.to_vec(), sig_binary.clone(), "armored/binary"),
            (key_binary, sig_binary, "binary/binary"),
        ] {
            let vouched = verify_detached_signature(&manifest, &signature, &key)
                .unwrap_or_else(|e| panic!("{label} should verify: {e}"));
            assert_eq!(vouched.primary_fingerprint, RUST_PRIMARY_FPR, "{label}");
        }
    }

    /// Fails if a non-OpenPGP blob is allowed to reach the verifier, where it
    /// would produce a confusing crypto error instead of "this is not a key".
    #[test]
    fn a_non_openpgp_blob_is_refused_as_a_key_and_as_a_signature() {
        let junk = b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            verify_detached_signature(SUMS, RUST_SIG_ASC, junk).unwrap_err(),
            PgpSumsError::KeyUnreadable(_)
        ));
        assert!(matches!(
            verify_detached_signature(SUMS, junk, RUST_KEY_ASC).unwrap_err(),
            PgpSumsError::SignatureUnreadable(_) | PgpSumsError::SignatureEmpty
        ));
    }

    /// Fails if an empty `.asc` — a download that produced nothing — is read as
    /// "no signature failed to verify".
    #[test]
    fn an_empty_signature_file_is_refused() {
        // A zero-byte file never reaches the packet layer — rPGP rejects it as
        // "empty input" …
        assert!(matches!(
            verify_detached_signature(SUMS, b"", RUST_KEY_ASC).unwrap_err(),
            PgpSumsError::SignatureUnreadable(_)
        ));
        // … whereas a well-formed armor block with no packets inside parses
        // cleanly and yields nothing. That is the case `SignatureEmpty` is for,
        // and it is why `read_signatures` cannot simply trust the parser: an
        // empty candidate list would otherwise fall straight through the
        // verification loop and out the bottom.
        let armored_but_empty =
            b"-----BEGIN PGP SIGNATURE-----\n\n=twTO\n-----END PGP SIGNATURE-----\n";
        assert!(matches!(
            verify_detached_signature(SUMS, armored_but_empty, RUST_KEY_ASC).unwrap_err(),
            PgpSumsError::SignatureEmpty
        ));
    }

    // --------------------------------------------------------- signature type

    /// The measurement that justifies refusing text signatures: ONE text
    /// signature covers TWO different byte strings, because the hash is taken
    /// over the line-ending-normalised form. If this test ever goes red, rPGP
    /// changed its normalisation and `NotBinarySignature` should be
    /// re-justified rather than kept out of habit.
    #[test]
    fn a_text_signature_covers_two_different_byte_strings() {
        let (secret, _) = generated_key("t <t@example.invalid>");
        let lf = b"aa  x\n";
        let crlf = b"aa  x\r\n";
        let public: SignedPublicKey = secret.clone().into();
        let text = DetachedSignature::sign_text_data(
            rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &lf[..],
        )
        .unwrap();
        assert!(text.verify(&public.primary_key, lf).is_ok());
        assert!(
            text.verify(&public.primary_key, crlf).is_ok(),
            "a text signature that did NOT cover the CRLF spelling would remove the reason to \
             refuse text signatures"
        );
        // A binary signature does not have this property.
        let binary = DetachedSignature::sign_binary_data(
            rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &lf[..],
        )
        .unwrap();
        assert!(binary.verify(&public.primary_key, crlf).is_err());
    }

    /// Fails if `check_signature_shape` stops refusing text signatures. rPGP's
    /// own parser does not enforce this — its doc-comment claims it and its
    /// code does not — so removing this check would otherwise be silent.
    #[test]
    fn a_text_type_signature_over_a_digest_list_is_refused() {
        let (secret, key) = generated_key("t <t@example.invalid>");
        let signature = DetachedSignature::sign_text_data(
            rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            SUMS,
        )
        .unwrap()
        .to_armored_bytes(Default::default())
        .unwrap();
        let err = verify_detached_signature(SUMS, &signature, &key).unwrap_err();
        assert!(
            matches!(&err, PgpSumsError::NotBinarySignature { found, .. } if found == "Text"),
            "expected a type refusal, got {err}"
        );
    }

    // ------------------------------------------------------------ hash floor

    /// rPGP's `check_signature_hash_strength` only gates PQC algorithms, so a
    /// SHA-1 signature reaches the verifier untouched. This test rewrites the
    /// hash-algorithm octet of a real signature packet (v4 body layout:
    /// version, type, pub-alg, hash-alg) so the signature parses as SHA-1 while
    /// its crypto is nonsense. That is the discriminating part: the error must
    /// be `WeakDigest`, not `DoesNotVerify`. Fails if the floor is removed, or
    /// if it is moved to AFTER the crypto, where it could no longer tell an
    /// operator which problem they have.
    #[test]
    fn a_signature_hashed_below_the_floor_is_refused_before_the_crypto_runs() {
        let (secret, key) = generated_key("t <t@example.invalid>");
        let signature = DetachedSignature::sign_binary_data(
            rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            SUMS,
        )
        .unwrap();
        let mut bytes = Vec::new();
        signature.to_writer(&mut bytes).unwrap();
        assert_eq!(bytes[0], 0xc2, "new-format signature packet header");
        assert!(bytes[1] < 192, "one-octet packet length");
        assert_eq!(bytes[2], 4, "v4 signature");
        bytes[2 + 3] = 2; // HashAlgorithm::Sha1

        let err = verify_detached_signature(SUMS, &bytes, &key).unwrap_err();
        match err {
            PgpSumsError::WeakDigest { bits, floor, .. } => {
                assert_eq!(bits, 160);
                assert_eq!(floor, MIN_SIGNATURE_DIGEST_BITS);
            }
            other => panic!("expected WeakDigest, got {other}"),
        }
    }

    /// Fails if the floor is set so high the real artifact stops verifying —
    /// the other direction of the same knob. Rust signs with SHA-512.
    #[test]
    fn the_hash_floor_admits_the_algorithm_rust_actually_uses() {
        let (sig, _) = DetachedSignature::from_reader_single(RUST_SIG_ASC).unwrap();
        assert_eq!(sig.signature.hash_alg(), Some(HashAlgorithm::Sha512));
        check_signature_shape(0, &sig).unwrap();
    }

    // ---------------------------------------------------------- key hygiene

    /// Fails if `read_certificate` stops looking at revocation signatures. The
    /// case is an operator re-pinning an upstream key export AFTER the upstream
    /// revoked it: every old signature still verifies cryptographically, and
    /// without this check varve would keep accepting them.
    #[test]
    fn a_certificate_that_carries_its_own_revocation_vouches_for_nothing() {
        let (secret, live) = generated_key("t <t@example.invalid>");
        let mut config = SignatureConfig::v4(
            SignatureType::KeyRevocation,
            PublicKeyAlgorithm::Ed25519,
            HashAlgorithm::Sha256,
        );
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                Timestamp::try_from(std::time::SystemTime::now()).unwrap(),
            ))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerKeyId(
                secret.primary_key.legacy_key_id(),
            ))
            .unwrap(),
        ];
        let revocation = config
            .sign_key(
                &secret.primary_key,
                &Password::empty(),
                &secret.primary_key.public_key(),
            )
            .unwrap();

        let mut public: SignedPublicKey = secret.clone().into();
        public.details.revocation_signatures.push(revocation);
        let revoked = public.to_armored_bytes(Default::default()).unwrap();

        let signature = sign_binary(&secret, SUMS);
        // The same signature verifies against the un-revoked export …
        verify_detached_signature(SUMS, &signature, &live).unwrap();
        // … and is refused once the certificate carries its revocation.
        let err = verify_detached_signature(SUMS, &signature, &revoked).unwrap_err();
        assert!(
            matches!(err, PgpSumsError::KeyRevoked { count: 1 }),
            "expected KeyRevoked, got {err}"
        );
    }

    /// Fails if `verify_bindings` is dropped. The certificate is a blob even
    /// when its custody is good; a user ID or subkey spliced in by someone who
    /// could edit the pinned file must not be read as part of the identity this
    /// module reports.
    #[test]
    fn a_certificate_whose_bindings_do_not_verify_is_refused() {
        let (a, _) = generated_key("a <a@example.invalid>");
        let (b, _) = generated_key("b <b@example.invalid>");
        let mut spliced: SignedPublicKey = a.clone().into();
        let victim: SignedPublicKey = b.into();
        assert_ne!(
            spliced.primary_key.fingerprint(),
            victim.primary_key.fingerprint(),
            "the two test certificates must be different keys, or this test proves nothing"
        );
        // B's user ID together with its self-signature, hung off A's primary
        // key: that self-signature was made by B and cannot verify under A.
        spliced.details.users = victim.details.users;
        let armored = spliced.to_armored_bytes(Default::default()).unwrap();
        let signature = sign_binary(&a, SUMS);
        let err = verify_detached_signature(SUMS, &signature, &armored).unwrap_err();
        assert!(
            matches!(err, PgpSumsError::KeyBindingsBroken(_)),
            "expected KeyBindingsBroken, got {err}"
        );
    }

    // -------------------------------------------------------------- subkeys

    /// Clause 2: the mechanism is general, not "Rust". Rust signs with its
    /// primary, so without this test the subkey branch of the candidate loop is
    /// dead code nothing would notice breaking — and most non-Rust upstreams
    /// sign with a subkey. Fails if the candidate loop stops after the primary
    /// key, which is exactly what rPGP's own `VerifyingKey for SignedPublicKey`
    /// does.
    #[test]
    fn a_signature_made_by_a_bound_signing_subkey_verifies_and_is_named() {
        let (secret, key) = generated_key_with_signing_subkey("s <s@example.invalid>");
        let subkey = secret
            .secret_subkeys
            .first()
            .expect("generated certificate should carry a subkey");
        let signature = DetachedSignature::sign_binary_data(
            rng(),
            &subkey.key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            SUMS,
        )
        .unwrap()
        .to_armored_bytes(Default::default())
        .unwrap();

        let vouched = verify_detached_signature(SUMS, &signature, &key).unwrap();
        let primary = hex::encode(secret.primary_key.public_key().fingerprint().as_bytes());
        let sub = hex::encode(subkey.key.public_key().fingerprint().as_bytes());
        assert_eq!(vouched.primary_fingerprint, primary);
        assert_eq!(
            vouched.signing_fingerprint, sub,
            "the subkey that signed must be reported separately from the identity that owns it"
        );
        assert_ne!(vouched.primary_fingerprint, vouched.signing_fingerprint);
    }

    // ------------------------------------------------------ manifest parsing

    /// Counts measured against the fixture with an independent TOML reader
    /// before this parser existed: 22 packages, 917 (package, target) pairs of
    /// which 601 are available, each contributing BOTH a .tar.gz and a .tar.xz
    /// entry, plus 11 `[[artifacts]]` entries. Fails if the parser starts
    /// dropping a shape — most likely `xz_*` or the `hash-sha256` spelling,
    /// neither of which REQ-SIGNEDSUMS-001 mentions.
    #[test]
    fn the_real_channel_manifest_yields_every_digest_it_carries() {
        let channel = parse_rust_channel(&rust_manifest()).unwrap();
        assert_eq!(channel.date, "2026-09-03");
        assert_eq!(channel.entries.len(), 601 * 2 + 11);

        let gz = channel
            .entries
            .iter()
            .filter(|e| e.form == EntryForm::Tarball)
            .count();
        let xz = channel
            .entries
            .iter()
            .filter(|e| e.form == EntryForm::TarballXz)
            .count();
        let artifacts: Vec<_> = channel
            .entries
            .iter()
            .filter(|e| e.form == EntryForm::Artifact)
            .collect();
        assert_eq!((gz, xz, artifacts.len()), (601, 601, 11));

        let packages: std::collections::BTreeSet<_> =
            channel.entries.iter().map(|e| e.package.as_str()).collect();
        assert!(packages.contains("rustc"));
        assert!(packages.contains("cargo"));
        assert!(packages.contains("rust-std"));
        // The artifact tables are keyed by artifact KIND, not by package name.
        assert!(packages.contains("installer-msi"));
        assert!(packages.contains("source-code"));

        for e in &channel.entries {
            assert_eq!(e.sha256.len(), 64, "{e:?}");
            assert!(e.sha256.bytes().all(|b| b.is_ascii_hexdigit()), "{e:?}");
            assert_eq!(e.sha256, e.sha256.to_ascii_lowercase(), "{e:?}");
            assert!(e.url.starts_with("https://"), "{e:?}");
        }

        // Spot checks read out of the manifest by eye.
        let rust_linux = channel
            .entries
            .iter()
            .find(|e| {
                e.package == "rust"
                    && e.target == "x86_64-unknown-linux-gnu"
                    && e.form == EntryForm::Tarball
            })
            .unwrap();
        assert_eq!(
            rust_linux.sha256,
            "24ba1338a2d35c5a3247936546429e163fa674d726102af18bdf624582c57aea"
        );
        assert_eq!(
            rust_linux.url,
            "https://static.rust-lang.org/dist/2026-09-03/rust-1.98.1-x86_64-unknown-linux-gnu.tar.gz"
        );
        // The source tarball is target-independent and uses the OTHER digest
        // key name.
        let src = artifacts
            .iter()
            .find(|e| e.package == "source-code" && e.url.ends_with("-src.tar.xz"))
            .unwrap();
        assert_eq!(src.target, "*");
        assert_eq!(
            src.sha256,
            "be1816e7f6c40abb90245ad6e024bed2a7e88d7dda4561e4d5470207df616b9f"
        );
    }

    /// Fails if a target the manifest marks unavailable starts contributing an
    /// entry, which would mean inventing a url or a digest.
    #[test]
    fn an_unavailable_target_contributes_no_entry() {
        let channel = parse_rust_channel(
            br#"
manifest-version = "2"
date = "2026-09-03"
[pkg.tool.target.gone]
available = false
[pkg.tool.target.here]
available = true
url = "https://example.invalid/a.tar.gz"
hash = "AA11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
"#,
        )
        .unwrap();
        assert_eq!(channel.entries.len(), 1);
        assert_eq!(channel.entries[0].target, "here");
        // Hex case is not semantic; the parser normalises rather than refuses.
        assert_eq!(
            channel.entries[0].sha256,
            "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
        );
    }

    /// varve#217's rule applied here. Fails if a url without a digest is
    /// skipped instead of refused — a broken manifest would silently become a
    /// shorter valid one.
    #[test]
    fn a_named_url_with_no_digest_is_refused_not_skipped() {
        let err = parse_rust_channel(
            br#"
manifest-version = "2"
date = "2026-09-03"
[pkg.tool.target.here]
available = true
url = "https://example.invalid/a.tar.gz"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(&err, PgpSumsError::DigestMissing { at } if at == "pkg.tool.target.here"),
            "{err}"
        );
    }

    /// The mirror case: a digest with nothing to apply it to is equally a
    /// broken table. Fails if only one direction of the pair is checked.
    #[test]
    fn a_digest_with_no_url_is_refused() {
        let err = parse_rust_channel(
            br#"
manifest-version = "2"
date = "2026-09-03"
[pkg.tool.target.here]
available = true
xz_hash = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(&err, PgpSumsError::UrlMissing { at } if at == "pkg.tool.target.here (xz)"),
            "{err}"
        );
    }

    /// Fails if a digest that is not 64 hex characters is passed through to a
    /// caller that would compare it against a real one and never match — or
    /// worse, truncate it somewhere downstream.
    #[test]
    fn a_digest_that_is_not_64_hex_characters_is_refused() {
        for bad in ["abc", &"z".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            let src = format!(
                "manifest-version = \"2\"\ndate = \"d\"\n[pkg.t.target.x]\nurl = \"u\"\nhash = \
                 \"{bad}\"\n"
            );
            let err = parse_rust_channel(src.as_bytes()).unwrap_err();
            assert!(
                matches!(err, PgpSumsError::DigestMalformed { .. }),
                "{bad} should be refused, got {err}"
            );
        }
    }

    /// Fails if the parser starts reading a manifest format it was not written
    /// against. A future `manifest-version = "3"` may spell digests
    /// differently; guessing would produce digests nobody published.
    #[test]
    fn a_manifest_version_this_parser_does_not_know_is_refused() {
        let err = parse_rust_channel(b"manifest-version = \"3\"\ndate = \"d\"\n").unwrap_err();
        assert!(
            matches!(&err, PgpSumsError::ManifestVersion { found } if found == "3"),
            "{err}"
        );
    }

    /// Fails if a non-UTF-8 or non-TOML body produces a panic or an empty
    /// channel rather than an error.
    #[test]
    fn a_body_that_is_not_utf8_toml_is_refused() {
        assert!(matches!(
            parse_rust_channel(&[0xff, 0xfe, 0x00]).unwrap_err(),
            PgpSumsError::ManifestNotText
        ));
        assert!(matches!(
            parse_rust_channel(b"this is not toml {{{").unwrap_err(),
            PgpSumsError::ManifestUnreadable(_)
        ));
    }

    // -------------------------------------------------------- the two, together

    /// Clause 5 as a structural property rather than a convention: there is no
    /// way to obtain a `RustChannel` from `verify_and_parse_rust_channel`
    /// without a `VouchedBy`. Fails if that function is ever changed to return
    /// entries alongside a warning, which is the downgrade the clause forbids.
    #[test]
    fn entries_are_unreachable_when_the_signature_does_not_verify() {
        let (_, other) = generated_key("nobody <nobody@example.invalid>");
        let err =
            verify_and_parse_rust_channel(&rust_manifest(), RUST_SIG_ASC, &other).unwrap_err();
        assert!(matches!(err, PgpSumsError::DoesNotVerify { .. }), "{err}");

        let (vouched, channel) =
            verify_and_parse_rust_channel(&rust_manifest(), RUST_SIG_ASC, RUST_KEY_ASC).unwrap();
        assert_eq!(vouched.primary_fingerprint, RUST_PRIMARY_FPR);
        assert_eq!(channel.entries.len(), 601 * 2 + 11);
    }
}
