//! Where varve's HTTPS trust comes from (REQ-OSTRUST-001).
//!
//! Every HTTPS client varve builds — the registry client and both self-update
//! agents — verifies servers through the operating system's trust store, via
//! ureq's `platform-verifier` feature (`rustls-platform-verifier`). Before
//! v0.49.0 they used ureq's default, a Mozilla root set compiled into the
//! binary (`webpki-roots`): every CA distrust then needed a varve release to
//! reach anyone, and a site's own CA could not be added without rebuilding.
//!
//! There is deliberately no bundled fallback. A host with no usable CA store
//! fails the fetch with an error that names the cause and the fix
//! ([`describe`]), rather than quietly trusting a root set nobody on that host
//! chose. What the verifier reads, by platform:
//!
//! * macOS: the Security framework (keychains and their trust settings).
//! * Windows: the CryptoAPI certificate store.
//! * Linux and other non-Apple Unix: `rustls-native-certs`, which reads the
//!   distribution's bundle (`/etc/ssl/certs`, ...) — or, when `SSL_CERT_FILE`
//!   and/or `SSL_CERT_DIR` is set, ONLY those locations. If that yields no
//!   certificate the verifier refuses to build with "No CA certificates were
//!   loaded from the system", which [`describe`] turns into the fix.

use ureq::tls::{RootCerts, TlsConfig};

/// The text `rustls-platform-verifier` (0.7, `verification/others.rs`) fails
/// with when the system store yields no certificate at all. Matched as text
/// because it arrives as a `rustls::Error::General`; the Linux-only test
/// below drives the real verifier into it, so a changed upstream wording
/// fails a test rather than silently dropping the fix from the message.
const NO_SYSTEM_ROOTS: &str = "No CA certificates were loaded from the system";

/// What varve adds to that failure. It names the cause and both fixes, and
/// it only ever follows the error above, which only the non-Apple Unix path
/// produces — where `SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured.
pub(crate) const NO_CA_STORE_FIX: &str = "this host has no usable CA certificate store, and \
     varve carries no bundled fallback: install the system CA bundle (the `ca-certificates` \
     package), or point SSL_CERT_FILE at a PEM bundle (or SSL_CERT_DIR at a directory of them)";

/// The TLS configuration every varve HTTPS client uses: the OS trust store.
pub(crate) fn os_trust() -> TlsConfig {
    TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build()
}

/// A transport error as varve reports it: ureq's own text, plus the fix when
/// the cause is a missing CA store.
pub(crate) fn describe(error: &ureq::Error) -> String {
    let text = error.to_string();
    if text.contains(NO_SYSTEM_ROOTS) {
        format!("{text} — {NO_CA_STORE_FIX}")
    } else {
        text
    }
}

/// An in-process HTTPS server whose certificate chains to a CA generated for
/// this test run — a CA that is in no OS store and in no bundle.
#[cfg(test)]
pub(crate) mod test_server {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    pub(crate) struct TestServer {
        /// `https://127.0.0.1:<port>`
        pub(crate) base: String,
        /// The generated CA, DER.
        pub(crate) ca_der: Vec<u8>,
    }

    /// Start the server. It answers every request with `200 ok` and lives
    /// until the test process exits.
    pub(crate) fn start() -> TestServer {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "varve REQ-OSTRUST-001 test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            )
            .unwrap();
        let config = Arc::new(config);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = config.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let Ok(conn) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    let mut tls = BufReader::new(rustls::StreamOwned::new(conn, stream));
                    // A refused handshake surfaces here as a read error.
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match tls.read_line(&mut line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) if line == "\r\n" => break,
                            Ok(_) => {}
                        }
                    }
                    let tls = tls.get_mut();
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        TestServer {
            base: format!("https://127.0.0.1:{port}"),
            ca_der: ca.der().to_vec(),
        }
    }

    /// The generated CA as ureq's root set — trusting it and nothing else.
    pub(crate) fn only(ca_der: &[u8]) -> ureq::tls::TlsConfig {
        ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::new_with_certs(&[
                ureq::tls::Certificate::from_der(ca_der).to_owned(),
            ]))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-OSTRUST-001
    #[test]
    fn varve_trusts_the_os_store_and_nothing_bundled() {
        assert!(
            matches!(os_trust().root_certs(), RootCerts::PlatformVerifier),
            "trust must come from the OS store, not a root set compiled into varve: {:?}",
            os_trust().root_certs()
        );
    }

    // rivet: verifies REQ-OSTRUST-001
    #[test]
    fn a_missing_ca_store_is_reported_with_its_fix() {
        let error = ureq::Error::Rustls(rustls::Error::General(NO_SYSTEM_ROOTS.to_string()));
        let text = describe(&error);
        assert!(text.starts_with(&error.to_string()), "{text}");
        for needle in ["ca-certificates", "SSL_CERT_FILE", "no bundled fallback"] {
            assert!(text.contains(needle), "missing {needle:?}: {text}");
        }
    }

    // rivet: verifies REQ-OSTRUST-001
    #[test]
    fn other_transport_errors_are_reported_unchanged() {
        let error = ureq::Error::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert_eq!(describe(&error), error.to_string());
        assert!(!describe(&error).contains("ca-certificates"));
    }

    /// The child half of the test below: meaningful only when the parent has
    /// pointed `SSL_CERT_FILE` at an empty file, so it is ignored on its own.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by a_host_without_a_ca_store_fails_with_the_fix in a child process"]
    fn child_no_ca_store() {
        let server = test_server::start();
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder().tls_config(os_trust()).build(),
        );
        let error = agent.get(&server.base).call().unwrap_err();
        let text = describe(&error);
        assert!(text.contains(NO_SYSTEM_ROOTS), "{text}");
        assert!(text.contains(NO_CA_STORE_FIX), "{text}");
        println!("OSTRUST-CHILD-ERROR: {text}");
    }

    /// Measured, not assumed: on Linux, a store that yields no certificate
    /// (here `SSL_CERT_FILE` naming an empty file, which rustls-native-certs
    /// then reads INSTEAD of the system bundle) makes the real verifier
    /// refuse, and varve's message carries the fix.
    // rivet: verifies REQ-OSTRUST-001
    #[cfg(target_os = "linux")]
    #[test]
    fn a_host_without_a_ca_store_fails_with_the_fix() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tls::tests::child_no_ca_store",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SSL_CERT_FILE", &empty)
            .env_remove("SSL_CERT_DIR")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("OSTRUST-CHILD-ERROR:"),
            "child failed or did not run.\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
