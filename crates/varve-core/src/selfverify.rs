//! Self-verification (REQ-SELF-001, DD-009) — the tool that gates the
//! toolchain clears its own gate.
//!
//! varve releases carry a varve-native signature: a DSSE envelope over the
//! release's SHA256SUMS.txt, signed with the same root key deposits use.
//! `varve self-verify` checks a candidate archive against that envelope with
//! the pinned trust root, fully offline, failing closed — including when the
//! envelope is absent, because "unsigned" is a verdict, not a shrug.

use crate::install::VerifyError;
use crate::store::manifest_digest;
use crate::verify::{dsse_sign_typed, dsse_verify_typed};

/// The authenticated payload type for release checksum envelopes.
pub const RELEASE_SUMS_PAYLOAD_TYPE: &str =
    "application/vnd.pulseengine.varve.release-sums.v1+json";

#[derive(Debug, thiserror::Error)]
pub enum SelfVerifyError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("SHA256SUMS payload is not UTF-8 text")]
    NotText,
    #[error("'{name}' has no entry in the signed SHA256SUMS — refusing to trust it")]
    NoEntry { name: String },
    #[error(
        "'{name}' does not match its signed digest — expected {expected}, the file hashes to {actual}"
    )]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

/// Verify one release file against the signed sums envelope. Returns the
/// verified digest on success.
pub fn verify_release_file(
    file_name: &str,
    file_bytes: &[u8],
    sums_envelope: &[u8],
    root_public_key: &[u8],
) -> Result<String, SelfVerifyError> {
    let payload = dsse_verify_typed(sums_envelope, RELEASE_SUMS_PAYLOAD_TYPE, root_public_key)?;
    let text = std::str::from_utf8(&payload).map_err(|_| SelfVerifyError::NotText)?;
    // sha256sum format: "<hex>  <name>" (name possibly ./-prefixed).
    let expected = text
        .lines()
        .filter_map(|line| {
            let (hex, name) = line.split_once("  ")?;
            let name = name.trim().trim_start_matches("./");
            (name == file_name).then(|| hex.trim().to_string())
        })
        .next()
        .ok_or_else(|| SelfVerifyError::NoEntry {
            name: file_name.to_string(),
        })?;
    let actual = manifest_digest(file_bytes);
    let actual_hex = actual
        .strip_prefix("sha256:")
        .expect("digest shape")
        .to_string();
    if actual_hex != expected {
        return Err(SelfVerifyError::DigestMismatch {
            name: file_name.to_string(),
            expected,
            actual: actual_hex,
        });
    }
    Ok(actual)
}

/// Sign a SHA256SUMS.txt into the release envelope (the CI side).
pub fn sign_release_sums(
    sums: &[u8],
    secret_key: &[u8],
    key_id: &str,
) -> Result<String, VerifyError> {
    dsse_sign_typed(sums, RELEASE_SUMS_PAYLOAD_TYPE, secret_key, key_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::generate_root_keypair;

    fn fixture() -> (Vec<u8>, String, Vec<u8>, Vec<u8>) {
        let (sk, pk) = generate_root_keypair();
        let archive = b"pretend-tarball-bytes".to_vec();
        let digest = manifest_digest(&archive);
        let hex = digest.strip_prefix("sha256:").unwrap();
        let sums = format!(
            "{hex}  ./varve-v9.9.9-aarch64-apple-darwin.tar.gz\n\
             0000000000000000000000000000000000000000000000000000000000000000  ./other.txt\n"
        );
        let envelope = sign_release_sums(sums.as_bytes(), &sk, "varve-root-1").unwrap();
        (archive, envelope, pk, sk)
    }

    // rivet: verifies REQ-SELF-001
    #[test]
    fn a_release_archive_verifies_against_the_signed_sums() {
        let (archive, envelope, pk, _) = fixture();
        let digest = verify_release_file(
            "varve-v9.9.9-aarch64-apple-darwin.tar.gz",
            &archive,
            envelope.as_bytes(),
            &pk,
        )
        .unwrap();
        assert!(digest.starts_with("sha256:"));
    }

    // rivet: verifies REQ-SELF-001
    #[test]
    fn a_tampered_archive_is_refused() {
        let (mut archive, envelope, pk, _) = fixture();
        archive.push(b'!');
        let err = verify_release_file(
            "varve-v9.9.9-aarch64-apple-darwin.tar.gz",
            &archive,
            envelope.as_bytes(),
            &pk,
        )
        .unwrap_err();
        assert!(
            matches!(err, SelfVerifyError::DigestMismatch { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-SELF-001
    #[test]
    fn a_file_outside_the_signed_sums_is_refused() {
        let (archive, envelope, pk, _) = fixture();
        let err =
            verify_release_file("sneaky.tar.gz", &archive, envelope.as_bytes(), &pk).unwrap_err();
        assert!(matches!(err, SelfVerifyError::NoEntry { .. }), "got: {err}");
    }

    // rivet: verifies REQ-SELF-001
    #[test]
    fn sums_signed_by_an_untrusted_key_are_refused() {
        let (archive, _, _, _) = fixture();
        let (other_sk, other_pk) = generate_root_keypair();
        let _ = other_pk;
        let digest = manifest_digest(&archive);
        let hex = digest.strip_prefix("sha256:").unwrap();
        let sums = format!("{hex}  ./x.tar.gz\n");
        let impostor = sign_release_sums(sums.as_bytes(), &other_sk, "evil").unwrap();
        let (_, _, pk, _) = fixture();
        assert!(
            verify_release_file("x.tar.gz", &archive, impostor.as_bytes(), &pk).is_err(),
            "impostor sums must not verify"
        );
    }

    // rivet: verifies REQ-SELF-001
    #[test]
    fn a_layer_manifest_envelope_cannot_pose_as_release_sums() {
        let (archive, _, pk, sk) = fixture();
        let not_sums = crate::verify::sign_layer_manifest(b"{}", &sk, "k");
        // sign_layer_manifest refuses nothing here — it signs any payload —
        // but its payload TYPE differs, so verification must refuse it.
        let envelope = not_sums.unwrap();
        let err = verify_release_file("x.tar.gz", &archive, envelope.as_bytes(), &pk).unwrap_err();
        assert!(err.to_string().contains("payload type"), "got: {err}");
    }
}
