//! Signing-key material (REQ-KEYGEN-001).
//!
//! A ten-persona documentation audit found the extender path was not merely
//! undocumented but CLOSED: nothing in varve emitted the public half of a
//! signing key, so the 64-hex `trust-root` that `varve-realms.toml` demands was
//! unobtainable. One persona held a working key, signed a layer with it, and
//! tried six derivations plus offline DSSE-PAE verification across six message
//! encodings — none matched. Four of five blocked personas were blocked here.
//! Everything needed to run a second realm existed except the one function that
//! prints a public key.
//!
//! The format, stated once so nobody has to reverse-engineer it again: a varve
//! signing key is **64 bytes, hex-encoded (128 characters)** — a 32-byte
//! ed25519 seed followed by its 32-byte public key. The trust root a consumer
//! pins is that second half alone, 32 bytes as 64 hex characters.
//!
//! Because the public half travels inside the secret file, it can DISAGREE with
//! the seed. A key like that signs happily and produces layers no trust root
//! can ever verify, which is exactly what varve was doing with 64 bytes of
//! random entropy. `check_keypair` exists so the produce side can refuse that
//! before signing rather than after publishing.

/// Bytes in a varve signing key: seed ‖ public.
pub const SECRET_LEN: usize = 64;
/// Bytes in the public half — what a realm pins as `trust-root`.
pub const PUBLIC_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(
        "{path} holds {got} hex character(s); a varve signing key is {want} — a 32-byte \
         ed25519 seed followed by its 32-byte public key. Mint one with `varve keygen`."
    )]
    WrongLength {
        path: String,
        got: usize,
        want: usize,
    },
    #[error("{path} is not hex: {reason}")]
    NotHex { path: String, reason: String },
    #[error(
        "{path} is not a consistent keypair: the public half it carries is not the one its \
         seed derives. Signing with it produces layers NO trust root can verify. Mint a \
         fresh key with `varve keygen`."
    )]
    Mismatched { path: String },
}

/// Mint a signing key. Returns `(secret_hex, public_hex)` — the secret is what
/// `deposit --key` reads, the public is what a realm pins as `trust-root`.
pub fn generate() -> (String, String) {
    let (sk, pk) = crate::verify::generate_root_keypair();
    (hex_encode(&sk), hex_encode(&pk))
}

/// The public half of a signing key, in the exact form `trust-root` accepts.
/// Validates length, encoding, and — crucially — that the carried public half
/// actually belongs to the seed.
pub fn public_from_secret(secret_hex: &str, path: &str) -> Result<String, KeyError> {
    let bytes = decode_secret(secret_hex, path)?;
    check_derived(&bytes, path)?;
    Ok(hex_encode(&bytes[32..]))
}

/// Refuse a key that cannot produce verifiable signatures, BEFORE it signs
/// anything. Returns the decoded 64 bytes on success.
pub fn check_keypair(secret_hex: &str, path: &str) -> Result<Vec<u8>, KeyError> {
    let bytes = decode_secret(secret_hex, path)?;
    check_derived(&bytes, path)?;
    Ok(bytes)
}

fn decode_secret(secret_hex: &str, path: &str) -> Result<Vec<u8>, KeyError> {
    let trimmed = secret_hex.trim();
    if trimmed.len() != SECRET_LEN * 2 {
        return Err(KeyError::WrongLength {
            path: path.to_string(),
            got: trimmed.len(),
            want: SECRET_LEN * 2,
        });
    }
    hex_decode(trimmed).map_err(|reason| KeyError::NotHex {
        path: path.to_string(),
        reason,
    })
}

/// The carried public half must actually verify what the seed signs. This is a
/// ROUND TRIP rather than a structural derivation: sign a probe and verify it
/// with the embedded public key. It tests the property that matters — "does
/// signing with this key produce something a consumer can verify" — instead of
/// a proxy for it, and it is the same mechanism `deposit` uses to check the
/// envelope it just wrote.
fn check_derived(bytes: &[u8], path: &str) -> Result<(), KeyError> {
    let mismatched = || KeyError::Mismatched {
        path: path.to_string(),
    };
    let probe = br#"{"varve":"keypair-probe"}"#;
    let envelope = crate::verify::dsse_sign_typed(probe, PROBE_TYPE, bytes, "probe")
        .map_err(|_| mismatched())?;
    let verified = crate::verify::dsse_verify_typed(envelope.as_bytes(), PROBE_TYPE, &bytes[32..])
        .map_err(|_| mismatched())?;
    if verified != probe {
        return Err(mismatched());
    }
    Ok(())
}

/// Payload type for the keypair-consistency probe. Distinct from every real
/// document type, so a probe envelope can never be mistaken for one.
const PROBE_TYPE: &str = "application/vnd.pulseengine.varve.keypair-probe.v1+json";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-KEYGEN-001
    #[test]
    fn a_minted_key_yields_the_public_half_a_realm_pins() {
        let (secret, public) = generate();
        assert_eq!(secret.len(), SECRET_LEN * 2, "128 hex characters");
        assert_eq!(public.len(), PUBLIC_LEN * 2, "64 hex characters");
        // The route that did not exist: secret file -> the trust-root value.
        assert_eq!(public_from_secret(&secret, "k").unwrap(), public);
        // …and it is the shape realms already demand.
        assert!(public.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // rivet: verifies REQ-KEYGEN-001
    #[test]
    fn a_key_that_signs_unverifiably_is_refused_before_it_signs() {
        // 64 bytes of entropy: varve accepted this and emitted signed layers no
        // trust root on earth could verify, exit 0. This is that case.
        let entropy = "ab".repeat(SECRET_LEN);
        match check_keypair(&entropy, "random.key") {
            Err(KeyError::Mismatched { .. }) => {}
            other => panic!("entropy must be refused as a keypair, got {other:?}"),
        }
        // A real key with its public half corrupted is the same fault.
        let (secret, _) = generate();
        let mut bad = secret.clone();
        bad.replace_range(64..66, if &secret[64..66] == "aa" { "bb" } else { "aa" });
        assert!(matches!(
            check_keypair(&bad, "tampered.key"),
            Err(KeyError::Mismatched { .. })
        ));
        // The good one still passes.
        assert!(check_keypair(&secret, "good.key").is_ok());
    }

    // rivet: verifies REQ-KEYGEN-001
    #[test]
    fn the_wrong_length_says_what_it_wanted() {
        // The old error said "Ed25519 signature function error" and gave the
        // same text for every wrong length. A 32-byte ed25519 secret — which
        // the --key help text described — is the likeliest mistake.
        let thirty_two = "ab".repeat(32);
        let err = check_keypair(&thirty_two, "root.key").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("64"), "must name what it got: {msg}");
        assert!(msg.contains("128"), "must name what it needs: {msg}");
        assert!(msg.contains("varve keygen"), "must carry its fix: {msg}");
    }

    // rivet: verifies REQ-KEYGEN-001
    #[test]
    fn non_hex_is_its_own_error_not_a_length_complaint() {
        let not_hex = "z".repeat(SECRET_LEN * 2);
        assert!(matches!(
            check_keypair(&not_hex, "k"),
            Err(KeyError::NotHex { .. })
        ));
    }

    // rivet: verifies REQ-KEYGEN-001
    #[test]
    fn a_minted_key_actually_signs_and_verifies_end_to_end() {
        // The property that matters: a key varve mints must produce a layer the
        // public half it printed can verify. Anything less and keygen is a
        // formatting exercise.
        let (secret, public) = generate();
        let sk = check_keypair(&secret, "k").unwrap();
        let payload = crate::manifest::fixtures::manifest_with_tools(
            "2026.08.0",
            "qualified",
            1,
            "2026-08-01T00:00:00Z",
            &[("synth", "sha256:aa")],
        );
        let envelope = crate::verify::sign_layer_manifest(&payload, &sk, "test-root").unwrap();
        let pk = hex_decode(&public).unwrap();
        let back = crate::verify::dsse_verify_typed(
            envelope.as_bytes(),
            crate::verify::LAYER_PAYLOAD_TYPE,
            &pk,
        )
        .unwrap();
        assert_eq!(
            back, payload,
            "the minted key round-trips through a real layer"
        );
    }
}
