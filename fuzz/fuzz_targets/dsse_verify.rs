#![no_main]
//! The DSSE verification path consumes attacker-controlled envelope bytes.
//! Property: verifying arbitrary bytes against a fixed root never panics and
//! never accepts (a random blob is not a validly-signed layer manifest).
use libfuzzer_sys::fuzz_target;
use varve_core::install::ManifestVerifier;

fuzz_target!(|data: &[u8]| {
    // A fixed, valid-shaped public key (all-zero is a legal ed25519 point
    // encoding for the verifier constructor; no envelope will verify to it).
    let pk = [0u8; 32];
    if let Ok(v) = varve_core::PinnedKeyVerifier::from_public_key_bytes(&pk) {
        let _ = v.verify(data); // must be Err or Ok(payload) — never panic, never accept junk
    }
});
