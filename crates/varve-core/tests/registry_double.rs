//! REQ-REGISTRY-001 / REQ-REGISTRY-002 integration against an in-process OCI
//! registry double.
//!
//! The double implements exactly the distribution surface the client uses —
//! challenge, token realm, manifest-by-tag, blob-by-digest, paginated
//! tags/list, blob redirect — over a real TCP socket, so the client's HTTP
//! path is exercised for real. The double is a SOURCE, and sources are
//! untrusted: the accompanying tests prove the same bytes produce the same
//! verdicts as every other transport, and that a wrong trust root rejects
//! identically through the registry.
//!
//! For REQ-REGISTRY-002 the double also plays the parts of a registry that is
//! NOT ghcr.io: it demands a token from a realm at a path nobody would guess,
//! rejects a wrong credential, hands out one tag per page, insists on the
//! Docker manifest media type, and redirects blobs to a second server on a
//! different port that records whether the client leaked its Authorization.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

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
    oci_artifact_manifest_with(envelope, payload_digest, tools, &[])
}

/// `attestations` is (statement_digest, statement_len, bytes_digest, bytes_len).
fn oci_artifact_manifest_with(
    envelope: &[u8],
    payload_digest: &str,
    tools: &[(&str, &[u8])],
    attestations: &[(String, usize, String, usize)],
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
    for (st_digest, st_len, b_digest, b_len) in attestations {
        layers.push(serde_json::json!({
            "mediaType": "application/json",
            "digest": st_digest,
            "size": st_len,
            "annotations": { "eu.pulseengine.varve.role": "attestation-statement" }
        }));
        layers.push(serde_json::json!({
            "mediaType": "application/octet-stream",
            "digest": b_digest,
            "size": b_len,
            "annotations": {
                "eu.pulseengine.varve.role": "attestation-bytes",
                "eu.pulseengine.varve.attests": st_digest
            }
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

/// What the double should do beyond the happy path. Every field here is a
/// behaviour a spec-compliant registry is allowed to have and GHCR does not,
/// which is precisely the gap REQ-REGISTRY-002 closes.
#[derive(Clone, Default)]
struct DoubleOptions {
    /// Demand `Authorization: Bearer <token>` on `/v2/`, answering anything
    /// else with 401 + a `WWW-Authenticate` challenge naming this double's
    /// own realm.
    require_token: Option<String>,
    /// Where the challenge points. Deliberately NOT `/token`: a client that
    /// guesses the path instead of reading the challenge cannot reach it.
    token_realm_path: String,
    /// The exact `Authorization` the token realm accepts. `None` grants
    /// anonymously.
    expect_basic: Option<String>,
    /// The token the realm hands out. When it differs from `require_token`
    /// the client is issued a token the API then refuses — a real case
    /// (a token minted for a repository the account may not pull).
    grant_token: Option<String>,
    /// Serve `tags/list` this many tags at a time, with `Link: rel="next"`.
    tags_page_size: Option<usize>,
    /// Always claim there is another page — a broken or hostile registry.
    tags_endless: bool,
    /// Redirect blob requests to this base (`http://host:port`).
    blob_redirect_to: Option<String>,
    /// Refuse a manifest request whose `Accept` omits the Docker media type.
    require_docker_accept: bool,
}

/// One request the double saw, as far as these tests care.
#[derive(Clone, Debug)]
struct Observed {
    path: String,
    authorization: Option<String>,
    accept: Option<String>,
}

struct Double {
    reference: String,
    /// `http://host:port` — what a redirect Location is built from.
    base: String,
    observed: Arc<Mutex<Vec<Observed>>>,
}

impl Double {
    fn saw(&self) -> Vec<Observed> {
        self.observed.lock().unwrap().clone()
    }
}

const DOCKER_MANIFEST_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// Serve the minimal OCI distribution surface on an ephemeral port.
fn serve(content: RegistryContent) -> String {
    serve_with(content, DoubleOptions::default()).reference
}

fn serve_with(content: RegistryContent, options: DoubleOptions) -> Double {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let content = Arc::new(content);
    let observed: Arc<Mutex<Vec<Observed>>> = Arc::new(Mutex::new(Vec::new()));
    let mut options = options;
    if options.token_realm_path.is_empty() {
        // Nothing a client could guess from the registry host alone.
        options.token_realm_path = "/auth/v1/oauth2/token".to_string();
    }
    let options = Arc::new(options);
    let log = Arc::clone(&observed);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let content = Arc::clone(&content);
            let options = Arc::clone(&options);
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut authorization = None;
                let mut accept = None;
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok() {
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        match name.trim().to_ascii_lowercase().as_str() {
                            "authorization" => authorization = Some(value.trim().to_string()),
                            "accept" => accept = Some(value.trim().to_string()),
                            _ => {}
                        }
                    }
                    header.clear();
                }
                log.lock().unwrap().push(Observed {
                    path: target.clone(),
                    authorization: authorization.clone(),
                    accept: accept.clone(),
                });

                let (path, query) = match target.split_once('?') {
                    Some((p, q)) => (p.to_string(), q.to_string()),
                    None => (target.clone(), String::new()),
                };
                let mut stream = stream;

                if path == options.token_realm_path {
                    match &options.expect_basic {
                        Some(expected) if authorization.as_deref() != Some(expected.as_str()) => {
                            respond(
                                &mut stream,
                                "401 Unauthorized",
                                &[],
                                br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#,
                            );
                        }
                        _ => {
                            let token = options
                                .grant_token
                                .clone()
                                .or_else(|| options.require_token.clone())
                                .unwrap_or_else(|| "anonymous-test-token".to_string());
                            respond(
                                &mut stream,
                                "200 OK",
                                &[],
                                format!(r#"{{"token":"{token}"}}"#).as_bytes(),
                            );
                        }
                    }
                    return;
                }

                if let Some(required) = &options.require_token
                    && path.starts_with("/v2/")
                    && authorization.as_deref() != Some(format!("Bearer {required}").as_str())
                {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        &[(
                            "WWW-Authenticate",
                            format!(
                                r#"Bearer realm="http://{addr}{}",service="{addr}",scope="repository:test/layers:pull""#,
                                options.token_realm_path
                            ),
                        )],
                        br#"{"errors":[{"code":"UNAUTHORIZED"}]}"#,
                    );
                    return;
                }

                if let Some(tag) = path.strip_prefix("/v2/test/layers/manifests/") {
                    if options.require_docker_accept
                        && !accept
                            .as_deref()
                            .unwrap_or("")
                            .contains(DOCKER_MANIFEST_TYPE)
                    {
                        respond(&mut stream, "406 Not Acceptable", &[], b"{}");
                        return;
                    }
                    match content.manifests.get(tag) {
                        Some(bytes) => respond(&mut stream, "200 OK", &[], bytes),
                        None => respond(&mut stream, "404 Not Found", &[], b"{}"),
                    }
                } else if let Some(digest) = path.strip_prefix("/v2/test/layers/blobs/") {
                    if let Some(base) = &options.blob_redirect_to {
                        // What a real registry does: hand the client off to a
                        // storage host on a different origin.
                        respond(
                            &mut stream,
                            "302 Found",
                            &[("Location", format!("{base}/v2/test/layers/blobs/{digest}"))],
                            b"",
                        );
                        return;
                    }
                    match content.blobs.get(digest) {
                        Some(bytes) => respond(&mut stream, "200 OK", &[], bytes),
                        None => respond(&mut stream, "404 Not Found", &[], b"{}"),
                    }
                } else if path == "/v2/test/layers/tags/list" {
                    let all: Vec<String> = content.manifests.keys().cloned().collect();
                    let start = match query_param(&query, "last") {
                        Some(last) => all.iter().position(|t| *t == last).map_or(0, |i| i + 1),
                        None => 0,
                    };
                    let page_size = options.tags_page_size.unwrap_or(all.len().max(1));
                    let page: Vec<String> =
                        all.iter().skip(start).take(page_size).cloned().collect();
                    let body = serde_json::to_vec(
                        &serde_json::json!({"name": "test/layers", "tags": page}),
                    )
                    .unwrap();
                    let more = options.tags_endless || start + page.len() < all.len();
                    let mut headers = Vec::new();
                    if more {
                        // `last` advances on a real page; on an endless one it
                        // does not have to, and the client must still stop.
                        let last = page.last().cloned().unwrap_or_else(|| "x".to_string());
                        headers.push((
                            "Link",
                            format!(
                                "</v2/test/layers/tags/list?n={page_size}&last={last}>; rel=\"next\""
                            ),
                        ));
                    }
                    respond(&mut stream, "200 OK", &headers, &body);
                } else {
                    respond(&mut stream, "404 Not Found", &[], b"{}");
                }
            });
        }
    });
    Double {
        reference: format!("oci+http://{addr}/test/layers"),
        base: format!("http://{addr}"),
        observed,
    }
}

/// A signed layer's registry-side content, ready to serve. Returns the
/// content, the payload digest a pin would name, and the trust root.
fn layer_content(tag: &str) -> (RegistryContent, String, Vec<u8>) {
    let (sk, pk) = varve_core::generate_root_keypair();
    let tool = b"registry-synth".to_vec();
    let tool_digest = manifest_digest(&tool);
    let host = varve_core::host_platform();
    let line = tag.rsplit_once('.').map_or(tag, |(line, _)| line);
    let payload = format!(
        r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{tag}",
    "eu.pulseengine.varve.line": "{line}",
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
        tag.to_string(),
        oci_artifact_manifest(
            envelope.as_bytes(),
            &payload_digest,
            &[(&tool_digest, &tool)],
        ),
    );
    (RegistryContent { manifests, blobs }, payload_digest, pk)
}

/// Standard base64, written out here so the expected `Authorization` value is
/// computed independently of the implementation under test.
fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
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
    install_source(source, pk, pin)
}

fn install_source(
    source: &dyn LayerSource,
    pk: &[u8],
    pin: &Pin,
) -> Result<varve_core::InstallOutcome, String> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(pk).unwrap();
    let policy = InstallPolicy {
        index: None,
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
        index: None,
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

// rivet: verifies REQ-ATTEST-002
#[test]
fn an_oci_install_carries_the_attestations_the_registry_publishes() {
    // The clause that was NOT implemented when the rest of carriage shipped:
    // an `oci://` install carried nothing, so a consumer pulling from a
    // registry got the bytes and none of the evidence about them — the exact
    // mirror-boundary loss the requirement exists to close, reproduced by
    // varve's own most-used transport.
    use varve_core::attest::{AttestationKind, sign, statement};
    use varve_core::source::{LayerRef, LayerSource};

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

    // Two attestations, because one would not catch a reader that returns the
    // first match — the shape line-status uses and attestations must not.
    let mut blobs = BTreeMap::new();
    let mut refs = Vec::new();
    for (kind, bytes) in [
        (AttestationKind::Sbom, b"sbom-evidence".to_vec()),
        (AttestationKind::Provenance, b"slsa-evidence".to_vec()),
    ] {
        let st = statement("2026.08.0", &payload_digest, kind, &bytes, "acme-ci");
        let env = sign(&st, &sk, "test-root").unwrap();
        let st_digest = manifest_digest(env.as_bytes());
        let b_digest = manifest_digest(&bytes);
        refs.push((st_digest.clone(), env.len(), b_digest.clone(), bytes.len()));
        blobs.insert(st_digest, env.into_bytes());
        blobs.insert(b_digest, bytes);
    }

    blobs.insert(
        manifest_digest(envelope.as_bytes()),
        envelope.as_bytes().to_vec(),
    );
    blobs.insert(payload_digest.clone(), payload.clone());
    blobs.insert(tool_digest.clone(), tool.clone());

    let mut manifests = BTreeMap::new();
    manifests.insert(
        "2026.08.0".to_string(),
        oci_artifact_manifest_with(
            envelope.as_bytes(),
            &payload_digest,
            &[(tool_digest.as_str(), tool.as_slice())],
            &refs,
        ),
    );
    let reference = serve(RegistryContent { manifests, blobs });

    let source = varve_core::registry::RegistrySource::new(
        varve_core::registry::RegistryRef::parse(&reference).unwrap(),
    );
    let carried = source
        .fetch_attestations(&LayerRef::Name("2026.08.0".parse().unwrap()))
        .expect("the registry publishes them, so the source must surface them");
    assert_eq!(carried.len(), 2, "both attestations, not just the first");

    // …and each still BINDS to this layer once re-verified against the root.
    // The registry is not trusted to have checked anything.
    let reports = varve_core::attestcarry::report(&carried, &payload_digest, "2026.08.0", &pk);
    assert!(
        reports.iter().all(|r| r.binds),
        "every carried attestation must bind: {reports:?}"
    );
    let mut kinds: Vec<&str> = reports.iter().map(|r| r.kind.as_str()).collect();
    kinds.sort();
    assert_eq!(kinds, vec!["provenance", "sbom"]);

    // A digest pin reaches the same evidence via the tag scan.
    let by_digest = source
        .fetch_attestations(&LayerRef::Digest(payload_digest.clone()))
        .unwrap();
    assert_eq!(
        by_digest.len(),
        2,
        "a digest pin must not lose the evidence"
    );
}

// ═══════════════════════ REQ-REGISTRY-002 ═══════════════════════
// varve speaks the OCI distribution spec, not one registry's dialect. Each
// test below puts the double into a shape a spec-compliant registry is
// allowed to have and GHCR does not.

// rivet: verifies REQ-REGISTRY-002
#[test]
fn the_token_comes_from_the_realm_the_challenge_names_not_a_guessed_path() {
    // The double's realm is /auth/v1/oauth2/token. A client that hardcodes
    // `/token?service=…` — what varve shipped — reaches nothing here, which
    // is what it also does against Artifactory, Harbor, ECR and GitLab.
    let (content, payload_digest, pk) = layer_content("2026.08.0");
    let double = serve_with(
        content,
        DoubleOptions {
            require_token: Some("granted-by-the-realm".to_string()),
            expect_basic: Some(format!("Basic {}", base64(b"alice:s3cr3t"))),
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&double.reference)
        .unwrap()
        .with_credential("alice", "s3cr3t");
    let outcome = install_source(&source, &pk, &rolling_pin("")).unwrap();
    assert_eq!(outcome.digest, payload_digest);

    let saw = double.saw();
    let token_request = saw
        .iter()
        .find(|o| o.path.starts_with("/auth/v1/oauth2/token"))
        .unwrap_or_else(|| panic!("the realm the challenge named was never asked: {saw:?}"));
    assert!(
        !saw.iter().any(|o| o.path.starts_with("/token")),
        "no path may be guessed: {saw:?}"
    );
    // The credential goes to the TOKEN endpoint as Basic…
    assert!(
        token_request
            .authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Basic ")),
        "the token endpoint must receive Basic: {token_request:?}"
    );
    // …and the registry API sees only the bearer token it issued.
    assert!(
        saw.iter().any(|o| o.path.starts_with("/v2/")
            && o.authorization.as_deref() == Some("Bearer granted-by-the-realm")),
        "the API must be called with the issued token: {saw:?}"
    );
    assert!(
        !saw.iter().any(|o| o.path.starts_with("/v2/")
            && o.authorization
                .as_deref()
                .is_some_and(|a| a.starts_with("Basic"))),
        "the credential must never be sent to the registry API: {saw:?}"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn a_refused_pull_says_whether_varve_had_no_credential_or_a_bad_one() {
    let secret = "not-the-password-4711";
    let options = || DoubleOptions {
        require_token: Some("granted".to_string()),
        expect_basic: Some(format!("Basic {}", base64(b"alice:s3cr3t"))),
        ..Default::default()
    };

    // Nothing offered. The old client turned this 401 into `None` and the
    // user saw a confusing downstream error instead of "log in".
    let (content, _, pk) = layer_content("2026.08.0");
    let double = serve_with(content, options());
    let source = varve_core::RegistrySource::parse(&double.reference).unwrap();
    let err = install_source(&source, &pk, &rolling_pin("")).unwrap_err();
    assert!(err.contains("offered no credential"), "{err}");
    assert!(err.contains("VARVE_REGISTRY_AUTH"), "{err}");
    assert!(!err.contains("rejected it"), "{err}");

    // Offered and refused — a different problem with a different fix.
    let (content, _, pk) = layer_content("2026.08.0");
    let double = serve_with(content, options());
    let source = varve_core::RegistrySource::parse(&double.reference)
        .unwrap()
        .with_credential("alice", secret);
    let err = install_source(&source, &pk, &rolling_pin("")).unwrap_err();
    assert!(err.contains("rejected it"), "{err}");
    assert!(!err.contains("offered no credential"), "{err}");
    assert!(
        !err.contains(secret),
        "the secret must never reach an error message: {err}"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn a_digest_pin_survives_a_paginated_tag_list() {
    // varve#70. Three tags served one per page; the one that matches is on
    // the last page. A client that reads only the first page answers "no such
    // layer" — indistinguishable from the layer never having been published.
    let (mut content, payload_digest, pk) = layer_content("2026.08.0");
    content
        .manifests
        .insert("0001-decoy".to_string(), b"{}".to_vec());
    content
        .manifests
        .insert("0002-decoy".to_string(), b"{}".to_vec());
    let double = serve_with(
        content,
        DoubleOptions {
            tags_page_size: Some(1),
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&double.reference).unwrap();
    let hex = payload_digest.strip_prefix("sha256:").unwrap();
    let pin = rolling_pin(&format!("digest = \"sha256:{hex}\"\n"));
    let outcome = install_source(&source, &pk, &pin).unwrap();
    assert_eq!(outcome.digest, payload_digest);

    let pages = double
        .saw()
        .iter()
        .filter(|o| o.path.starts_with("/v2/test/layers/tags/list"))
        .count();
    assert!(
        pages >= 3,
        "the client must follow Link rel=next to the end; it asked for {pages} page(s)"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn an_endless_tag_list_stops_with_an_error_rather_than_looping_or_truncating() {
    // A broken or hostile registry that never stops offering `rel="next"`
    // must stop the client. The stop is an ERROR: answering from a partial
    // tag list is the failure this whole clause exists to prevent.
    let (content, payload_digest, pk) = layer_content("2026.08.0");
    let double = serve_with(
        content,
        DoubleOptions {
            tags_page_size: Some(1),
            tags_endless: true,
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&double.reference).unwrap();
    let hex = payload_digest.strip_prefix("sha256:").unwrap();
    let pin = rolling_pin(&format!("digest = \"sha256:{hex}\"\n"));
    let err = install_source(&source, &pk, &pin).unwrap_err();
    assert!(
        err.contains("pages"),
        "the bound must be reported, not silently applied: {err}"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn a_registry_serving_the_docker_manifest_media_type_is_reachable() {
    // This double answers 406 unless the Docker schema-2 type is offered —
    // which is what a registry serving only that type effectively does.
    let (content, payload_digest, pk) = layer_content("2026.08.0");
    let double = serve_with(
        content,
        DoubleOptions {
            require_docker_accept: true,
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&double.reference).unwrap();
    let outcome = install_source(&source, &pk, &rolling_pin("")).unwrap();
    assert_eq!(outcome.digest, payload_digest);

    assert!(
        double.saw().iter().any(|o| o.path.contains("/manifests/")
            && o.accept
                .as_deref()
                .is_some_and(|a| a.contains("application/vnd.oci.image.manifest.v1+json"))),
        "the OCI type must still be offered alongside the Docker one"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn a_blob_redirect_to_another_host_does_not_carry_the_authorization_header() {
    // The empirical test of what ureq does with headers on redirect: the CDN
    // is a SECOND server on a DIFFERENT port, and it records every header it
    // is sent. If the client leaks the credential cross-origin, it shows up
    // here.
    let (content, payload_digest, pk) = layer_content("2026.08.0");
    let cdn = serve_with(
        RegistryContent {
            manifests: BTreeMap::new(),
            blobs: content.blobs,
        },
        DoubleOptions::default(),
    );
    let registry = serve_with(
        RegistryContent {
            manifests: content.manifests,
            blobs: BTreeMap::new(),
        },
        DoubleOptions {
            require_token: Some("granted".to_string()),
            blob_redirect_to: Some(cdn.base.clone()),
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&registry.reference).unwrap();
    let outcome = install_source(&source, &pk, &rolling_pin("")).unwrap();
    assert_eq!(outcome.digest, payload_digest);

    let registry_saw = registry.saw();
    assert!(
        registry_saw.iter().any(|o| o.path.starts_with("/v2/")
            && o.authorization
                .as_deref()
                .is_some_and(|a| a.starts_with("Bearer "))),
        "the registry must have been called WITH a token, or this test proves nothing: \
         {registry_saw:?}"
    );
    let cdn_saw = cdn.saw();
    assert!(
        !cdn_saw.is_empty(),
        "the CDN must have served the redirected blobs"
    );
    assert!(
        cdn_saw.iter().all(|o| o.authorization.is_none()),
        "the credential must not cross a redirect to another host: {cdn_saw:?}"
    );
}

// rivet: verifies REQ-REGISTRY-002
#[test]
fn a_token_the_api_still_refuses_is_reported_rather_than_swallowed() {
    // The realm mints a token and the API refuses it anyway — what a
    // registry does when the account may reach the token endpoint but not
    // this repository. The old client turned the second 401 into `None` too.
    let (content, _, pk) = layer_content("2026.08.0");
    let double = serve_with(
        content,
        DoubleOptions {
            require_token: Some("the-token-that-works".to_string()),
            grant_token: Some("a-token-for-somebody-else".to_string()),
            ..Default::default()
        },
    );
    let source = varve_core::RegistrySource::parse(&double.reference)
        .unwrap()
        .with_credential("alice", "s3cr3t");
    let err = install_source(&source, &pk, &rolling_pin("")).unwrap_err();
    assert!(
        err.contains("refused access"),
        "a 401 that survives the token exchange must be raised, not swallowed: {err}"
    );
    assert!(err.contains("rejected it"), "{err}");
    assert!(
        !err.contains("s3cr3t"),
        "the secret must never reach an error message: {err}"
    );
}

// ─────────────────── REQ-INDEXAUTH-001 over real HTTP ───────────────────
//
// The signed line index has to work against the party it constrains: a
// registry, over the wire, answering `/tags/list` and serving the index under
// its own per-line tag. A mock that returns canned bytes cannot show that the
// index is reachable at all, and reachability is exactly what was missing —
// every source but the in-memory double inherited a `fetch_line_index` that
// returned `Ok(None)`, so the whole requirement was switched off in the field.

/// An artifact manifest carrying nothing but the line-index envelope, under
/// the `line-index-<line>` tag.
fn oci_index_manifest(envelope: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.pulseengine.varve.line-index.v1+json",
        "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2 },
        "layers": [ {
            "mediaType": "application/json",
            "digest": manifest_digest(envelope),
            "size": envelope.len(),
            "annotations": { "eu.pulseengine.varve.role": "line-index" }
        } ],
    }))
    .unwrap()
}

struct IndexedRegistry {
    reference: String,
    pk: Vec<u8>,
}

/// Publish `served` layers of the 2026.08 line under one root, plus (unless
/// `publish_index` is false) a signed index naming `indexed` — each entry as
/// (layer, counter). An indexed layer that is not served is one the registry
/// is HIDING, which is the whole point.
fn indexed_registry(
    served: &[&str],
    indexed: &[(&str, u64)],
    publish_index: bool,
) -> IndexedRegistry {
    let (sk, pk) = varve_core::generate_root_keypair();
    let host = varve_core::host_platform();
    let mut blobs = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut digests: BTreeMap<String, String> = BTreeMap::new();

    for tag in served {
        let tool = format!("tool-for-{tag}").into_bytes();
        let tool_digest = manifest_digest(&tool);
        let line = tag.rsplit_once('.').map_or(*tag, |(line, _)| line);
        let payload = format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {{
    "eu.pulseengine.varve.layer": "{tag}",
    "eu.pulseengine.varve.line": "{line}",
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
        blobs.insert(
            manifest_digest(envelope.as_bytes()),
            envelope.as_bytes().to_vec(),
        );
        blobs.insert(payload_digest.clone(), payload.clone());
        blobs.insert(tool_digest.clone(), tool.clone());
        manifests.insert(
            (*tag).to_string(),
            oci_artifact_manifest(
                envelope.as_bytes(),
                &payload_digest,
                &[(&tool_digest, &tool)],
            ),
        );
        digests.insert((*tag).to_string(), payload_digest);
    }

    if publish_index {
        let doc = varve_core::LineIndex {
            line: "2026.08".into(),
            counter: 1,
            issued_at: "2026-08-07T00:00:00Z".into(),
            layers: indexed
                .iter()
                .map(|(layer, counter)| varve_core::IndexedLayer {
                    layer: (*layer).to_string(),
                    digest: digests
                        .get(*layer)
                        .cloned()
                        // A layer the registry does not serve still has a
                        // digest in the index — that is what makes the
                        // refusal actionable.
                        .unwrap_or_else(|| "sha256:withheld".to_string()),
                    channel: "rolling".into(),
                    counter: *counter,
                })
                .collect(),
        };
        let envelope = doc.sign(&sk, "test-root").unwrap();
        blobs.insert(
            manifest_digest(envelope.as_bytes()),
            envelope.as_bytes().to_vec(),
        );
        manifests.insert(
            varve_core::lineindex::index_tag("2026.08"),
            oci_index_manifest(envelope.as_bytes()),
        );
    }

    IndexedRegistry {
        reference: serve(RegistryContent { manifests, blobs }),
        pk,
    }
}

fn install_with_index(
    source: &dyn LayerSource,
    pk: &[u8],
    required: bool,
) -> Result<varve_core::InstallOutcome, String> {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let store = Store::at(&root);
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(pk).unwrap();
    let policy = InstallPolicy {
        index: Some(varve_core::IndexPolicy {
            realm: "acme",
            root_public_key: pk,
            required,
        }),
        now: "2026-08-07T00:00:00Z",
        staleness_threshold_days: 90,
        platform: &varve_core::host_platform(),
    };
    install(
        &rolling_pin(""),
        source,
        &verifier,
        &store,
        &mut marks,
        &policy,
    )
    .map_err(|e| e.to_string())
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn a_registry_serves_its_realms_signed_index_and_the_consumer_learns_the_line() {
    // Clauses 1 and 4 over HTTP. The registry serves 2026.08.0 and nothing
    // else; the realm's index says the line also holds 2026.08.9 at counter
    // 42. The pinned layer installs, and the consumer is TOLD what the realm
    // says exists — the thing a registry's silence would otherwise hide.
    let fx = indexed_registry(
        &["2026.08.0", "2026.08.9"],
        &[("2026.08.0", 1), ("2026.08.9", 42)],
        true,
    );
    let source = varve_core::RegistrySource::parse(&fx.reference).unwrap();
    let outcome = install_with_index(&source, &fx.pk, true).unwrap();
    assert_eq!(outcome.layer.to_string(), "2026.08.0");
    assert_eq!(
        outcome.index_high_water,
        Some(42),
        "the realm's greatest counter must reach the consumer through a real \
         registry, not merely through the in-memory double"
    );
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn a_registry_that_hides_an_indexed_layer_is_refused_over_the_wire() {
    // Clause 3, the attack the requirement exists for, against the party it
    // constrains. Every byte this registry serves verifies perfectly; the
    // defect is the tag it does not list.
    let fx = indexed_registry(&["2026.08.0"], &[("2026.08.0", 1), ("2026.08.5", 5)], true);
    let source = varve_core::RegistrySource::parse(&fx.reference).unwrap();
    let err = install_with_index(&source, &fx.pk, true)
        .expect_err("a registry hiding a layer the signed index names must be refused");
    assert!(err.contains("2026.08.5"), "names the hidden layer: {err}");
    assert!(
        err.contains("still verifies"),
        "says why per-artifact verification did not catch it: {err}"
    );

    // The same registry, with the index naming only what it serves, installs.
    // Without this the test would pass on a client that refuses everything.
    let ok = indexed_registry(&["2026.08.0"], &[("2026.08.0", 1)], true);
    let source = varve_core::RegistrySource::parse(&ok.reference).unwrap();
    assert!(install_with_index(&source, &ok.pk, true).is_ok());
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn a_registry_cannot_switch_the_check_off_by_answering_404_for_the_index() {
    // Clause 5. Deleting one tag must not disable the control for a realm that
    // declared it publishes an index — otherwise the check is advisory and the
    // cheapest attack is a DELETE.
    let fx = indexed_registry(&["2026.08.0"], &[], false);
    let source = varve_core::RegistrySource::parse(&fx.reference).unwrap();
    let err = install_with_index(&source, &fx.pk, true)
        .expect_err("a declaring realm must not fall back to the raw tag list");
    assert!(err.contains("acme"), "names the realm: {err}");
    assert!(err.contains("will not fall back"), "{err}");

    // A realm that never declared one installs from the very same registry —
    // the default must not break every realm in existence.
    assert!(install_with_index(&source, &fx.pk, false).is_ok());
}

// rivet: verifies REQ-INDEXAUTH-001
#[test]
fn the_index_tag_is_not_reported_as_a_layer_of_the_line() {
    // `served_layers` is the registry's answer to "what do you serve for this
    // line", and it is built from `/tags/list` — which also contains the index
    // artifact's own tag. Counting that as a layer would let an index that
    // named `line-index-2026.08` satisfy itself, and would put a non-layer in
    // every listing this check is measured against.
    let fx = indexed_registry(&["2026.08.0"], &[("2026.08.0", 1)], true);
    let source = varve_core::RegistrySource::parse(&fx.reference).unwrap();
    let served = source
        .served_layers("2026.08")
        .unwrap()
        .expect("a registry CAN enumerate — `None` would switch omission detection off");
    assert_eq!(served, vec!["2026.08.0".to_string()]);
    // …and another line's listing is empty rather than borrowed from this one.
    assert_eq!(source.served_layers("2026.09").unwrap(), Some(Vec::new()));
}
