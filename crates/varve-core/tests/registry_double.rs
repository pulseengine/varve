//! REQ-REGISTRY-001 integration against an in-process OCI registry double.
//!
//! The double implements exactly the distribution surface the client uses —
//! token, manifest-by-tag, blob-by-digest, tags/list — over a real TCP
//! socket, so the client's HTTP path is exercised for real. The double is a
//! SOURCE, and sources are untrusted: the accompanying tests prove the same
//! bytes produce the same verdicts as every other transport, and that a
//! wrong trust root rejects identically through the registry.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

use varve_core::{
    DirSource, HighWaterMarks, InstallPolicy, LayerSource, Pin, PinnedKeyVerifier, Store, install,
    manifest_digest,
};

/// One deposited layer's registry-side content.
struct RegistryContent {
    /// tag → OCI artifact manifest JSON bytes
    manifests: BTreeMap<String, Vec<u8>>,
    /// digest → blob bytes
    blobs: BTreeMap<String, Vec<u8>>,
}

fn oci_artifact_manifest(
    envelope: &[u8],
    payload_digest: &str,
    tools: &[(&str, &[u8])],
) -> Vec<u8> {
    let envelope_digest = manifest_digest(envelope);
    let mut layers = vec![serde_json::json!({
        "mediaType": "application/json",
        "digest": envelope_digest,
        "size": envelope.len(),
        "annotations": { "eu.pulseengine.varve.role": "envelope" }
    })];
    layers.push(serde_json::json!({
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "digest": payload_digest,
        "size": 0,
        "annotations": { "eu.pulseengine.varve.role": "payload" }
    }));
    for (digest, bytes) in tools {
        layers.push(serde_json::json!({
            "mediaType": "application/octet-stream",
            "digest": digest,
            "size": bytes.len(),
        }));
    }
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
        "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2 },
        "layers": layers,
    }))
    .unwrap()
}

/// Serve the minimal OCI distribution surface on an ephemeral port.
fn serve(content: RegistryContent) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let content = Arc::new(content);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let content = Arc::clone(&content);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                // Drain headers.
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok() {
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    header.clear();
                }
                let mut stream = stream;
                let respond = |stream: &mut std::net::TcpStream, status: &str, body: &[u8]| {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                };
                if path.starts_with("/token") {
                    respond(
                        &mut stream,
                        "200 OK",
                        br#"{"token":"anonymous-test-token"}"#,
                    );
                } else if let Some(tag) = path.strip_prefix("/v2/test/layers/manifests/") {
                    match content.manifests.get(tag) {
                        Some(bytes) => respond(&mut stream, "200 OK", bytes),
                        None => respond(&mut stream, "404 Not Found", b"{}"),
                    }
                } else if let Some(digest) = path.strip_prefix("/v2/test/layers/blobs/") {
                    match content.blobs.get(digest) {
                        Some(bytes) => respond(&mut stream, "200 OK", bytes),
                        None => respond(&mut stream, "404 Not Found", b"{}"),
                    }
                } else if path == "/v2/test/layers/tags/list" {
                    let tags: Vec<&String> = content.manifests.keys().collect();
                    let body = serde_json::to_vec(
                        &serde_json::json!({"name": "test/layers", "tags": tags}),
                    )
                    .unwrap();
                    respond(&mut stream, "200 OK", &body);
                } else {
                    respond(&mut stream, "404 Not Found", b"{}");
                }
            });
        }
    });
    format!("oci+http://{addr}/test/layers")
}

struct Fixture {
    reference: String,
    archive: std::path::PathBuf,
    payload_digest: String,
    pk: Vec<u8>,
    _tmp: tempfile::TempDir,
}

/// Deposit a signed layer, publish it into BOTH transports: the registry
/// double and a directory archive.
fn published_layer() -> Fixture {
    let (sk, pk) = varve_core::generate_root_keypair();
    let tool = b"registry-synth".to_vec();
    let tool_digest = manifest_digest(&tool);
    let host = varve_core::host_platform();
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "2026.08.0",
    "eu.pulseengine.varve.line": "2026.08",
    "eu.pulseengine.varve.channel": "rolling",
    "eu.pulseengine.varve.counter": "1",
    "org.opencontainers.image.created": "2026-08-07T00:00:00Z"
  }},
  "manifests": [
    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{tool_digest}",
      "size": 0,
      "annotations": {{ "eu.pulseengine.tool": "synth", "eu.pulseengine.platform": "{host}" }}
    }}
  ]
}}"#
    )
    .into_bytes();
    let payload_digest = manifest_digest(&payload);
    let envelope = varve_core::sign_layer_manifest(&payload, &sk, "test-root").unwrap();

    let mut blobs = BTreeMap::new();
    blobs.insert(
        manifest_digest(envelope.as_bytes()),
        envelope.as_bytes().to_vec(),
    );
    blobs.insert(payload_digest.clone(), payload.clone());
    blobs.insert(tool_digest.clone(), tool.clone());
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "2026.08.0".to_string(),
        oci_artifact_manifest(
            envelope.as_bytes(),
            &payload_digest,
            &[(&tool_digest, &tool)],
        ),
    );
    let reference = serve(RegistryContent { manifests, blobs });

    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("archive");
    DirSource::at(&archive)
        .put(
            envelope.as_bytes(),
            &[(tool_digest.as_str(), tool.as_slice())],
        )
        .unwrap();
    Fixture {
        reference,
        archive,
        payload_digest,
        pk,
        _tmp: tmp,
    }
}

fn rolling_pin(extra: &str) -> Pin {
    Pin::parse(
        &format!("manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n{extra}"),
        "varve.toml",
    )
    .unwrap()
}

fn run_install(
    fixture: &Fixture,
    source: &dyn LayerSource,
    pk: &[u8],
    pin: &Pin,
) -> Result<varve_core::InstallOutcome, String> {
    let _ = fixture;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(pk).unwrap();
    let policy = InstallPolicy {
        now: "2026-08-07T00:00:00Z",
        staleness_threshold_days: 90,
        platform: &varve_core::host_platform(),
    };
    install(pin, source, &verifier, &store, &mut marks, &policy).map_err(|e| e.to_string())
}

// rivet: verifies REQ-REGISTRY-001
#[test]
fn a_layer_installs_by_name_from_the_registry() {
    let fixture = published_layer();
    let source = varve_core::RegistrySource::parse(&fixture.reference).unwrap();
    let outcome = run_install(&fixture, &source, &fixture.pk, &rolling_pin("")).unwrap();
    assert_eq!(outcome.layer.to_string(), "2026.08.0");
    assert_eq!(outcome.digest, fixture.payload_digest);
}

// rivet: verifies REQ-REGISTRY-001
#[test]
fn a_digest_pin_resolves_through_tag_enumeration() {
    let fixture = published_layer();
    let source = varve_core::RegistrySource::parse(&fixture.reference).unwrap();
    let hex = fixture.payload_digest.strip_prefix("sha256:").unwrap();
    let pin = rolling_pin(&format!("digest = \"sha256:{hex}\"\n"));
    let outcome = run_install(&fixture, &source, &fixture.pk, &pin).unwrap();
    assert_eq!(outcome.digest, fixture.payload_digest);
}

// rivet: verifies REQ-REGISTRY-001
#[test]
fn kill_criterion_registry_and_archive_agree_on_accept_and_reject() {
    let fixture = published_layer();
    let registry = varve_core::RegistrySource::parse(&fixture.reference).unwrap();
    let archive = DirSource::at(&fixture.archive);

    // Accept: identical outcomes through both transports.
    let via_registry = run_install(&fixture, &registry, &fixture.pk, &rolling_pin("")).unwrap();
    let via_archive = run_install(&fixture, &archive, &fixture.pk, &rolling_pin("")).unwrap();
    assert_eq!(via_registry, via_archive);

    // Reject: a wrong trust root refuses identically through both.
    let (_, wrong_pk) = varve_core::generate_root_keypair();
    let reject_registry =
        run_install(&fixture, &registry, &wrong_pk, &rolling_pin("")).unwrap_err();
    let reject_archive = run_install(&fixture, &archive, &wrong_pk, &rolling_pin("")).unwrap_err();
    assert_eq!(reject_registry, reject_archive);
    assert!(reject_registry.contains("signature"), "{reject_registry}");
}

// rivet: verifies REQ-REGISTRY-001
#[test]
fn an_unknown_tag_is_not_found_never_invented() {
    let fixture = published_layer();
    let source = varve_core::RegistrySource::parse(&fixture.reference).unwrap();
    let pin = Pin::parse(
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.12.0\"\n",
        "varve.toml",
    )
    .unwrap();
    let err = run_install(&fixture, &source, &fixture.pk, &pin).unwrap_err();
    assert!(
        err.contains("no layer matching")
            || err.contains("NotFound")
            || err.contains("404")
            || err.contains("Name"),
        "{err}"
    );
}

// rivet: verifies REQ-REGISTRY-001
#[test]
fn blobs_larger_than_ten_mib_pull_cleanly() {
    // Real toolchain binaries are tens of MB; the transport must not cap
    // response bodies (caught live: ureq's 10 MiB default rejected a 31 MB
    // tool blob on the first real GHCR pull).
    let (sk, pk) = varve_core::generate_root_keypair();
    let tool: Vec<u8> = (0..12_000_000u32).map(|i| (i % 251) as u8).collect();
    let tool_digest = manifest_digest(&tool);
    let host = varve_core::host_platform();
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "2026.09.0",
    "eu.pulseengine.varve.line": "2026.09",
    "eu.pulseengine.varve.channel": "rolling",
    "eu.pulseengine.varve.counter": "1",
    "org.opencontainers.image.created": "2026-08-07T00:00:00Z"
  }},
  "manifests": [
    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{tool_digest}",
      "size": 12000000,
      "annotations": {{ "eu.pulseengine.tool": "bigtool", "eu.pulseengine.platform": "{host}" }}
    }}
  ]
}}"#
    )
    .into_bytes();
    let payload_digest = manifest_digest(&payload);
    let envelope = varve_core::sign_layer_manifest(&payload, &sk, "test-root").unwrap();

    let mut blobs = BTreeMap::new();
    blobs.insert(
        manifest_digest(envelope.as_bytes()),
        envelope.as_bytes().to_vec(),
    );
    blobs.insert(payload_digest.clone(), payload.clone());
    blobs.insert(tool_digest.clone(), tool);
    let mut manifests = BTreeMap::new();
    manifests.insert(
        "2026.09.0".to_string(),
        oci_artifact_manifest(envelope.as_bytes(), &payload_digest, &[]),
    );
    let reference = serve(RegistryContent { manifests, blobs });

    let source = varve_core::RegistrySource::parse(&reference).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
    let policy = InstallPolicy {
        now: "2026-08-07T00:00:00Z",
        staleness_threshold_days: 90,
        platform: &varve_core::host_platform(),
    };
    let pin = Pin::parse(
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.09.0\"\n",
        "varve.toml",
    )
    .unwrap();
    let outcome = install(&pin, &source, &verifier, &store, &mut marks, &policy).unwrap();
    assert_eq!(outcome.digest, payload_digest);
}
