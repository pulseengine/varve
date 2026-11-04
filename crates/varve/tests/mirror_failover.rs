//! REQ-MIRROR-002 end to end: a realm's declared mirrors are really used.
//!
//! The binary is spawned against loopback OCI registries. "Unreachable" is a
//! port nothing listens on, so the primary fails the way a real outage does
//! (connection refused), not by a stub.

use assert_cmd::Command;
use std::io::{BufRead, BufReader, Write};

/// Where nothing listens: connection refused, immediately.
const DEAD: &str = "oci+http://127.0.0.1:1/inc/layers";

const LAYER: &str = "2026.10.0";

struct Served {
    registry: String,
    root_hex: String,
    /// Digest of the signed layer payload.
    digest: String,
    /// Count of connections the server accepted, so a test can prove which
    /// source was actually asked.
    hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Every request received, request line and headers, verbatim.
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// What one loopback registry serves.
struct Spec<'a> {
    sk: &'a [u8],
    pk: &'a [u8],
    counter: u64,
    /// A tool the layer carries: (bytes the layer SIGNS, bytes the server
    /// SERVES for that digest).
    tool: Option<(Vec<u8>, Vec<u8>)>,
    /// Hang up on the tool's blob request: the source dies after its manifest.
    drop_tool_blob: bool,
}

/// An OCI registry on a loopback port serving one layer signed by a fresh
/// root. Two calls serve the same layer name signed by DIFFERENT roots.
fn serve_layer() -> Served {
    let (sk, pk) = varve_core::generate_root_keypair();
    serve_layer_signed(&sk, &pk, 1)
}

/// The same, signed by a GIVEN root and at a given anti-rollback counter, so
/// two servers can be genuine under one realm root while differing in what
/// they serve.
fn serve_layer_signed(sk: &[u8], pk: &[u8], counter: u64) -> Served {
    serve_spec(Spec {
        sk,
        pk,
        counter,
        tool: None,
        drop_tool_blob: false,
    })
}

fn serve_spec(spec: Spec<'_>) -> Served {
    let Spec {
        sk,
        pk,
        counter,
        tool,
        drop_tool_blob,
    } = spec;
    let entries = match &tool {
        Some((signed, _)) => format!(
            r#"{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":0,"annotations":{{"eu.pulseengine.tool":"probe","eu.pulseengine.platform":"{}"}}}}"#,
            varve_core::manifest_digest(signed),
            varve_core::host_platform()
        ),
        None => String::new(),
    };
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{LAYER}","eu.pulseengine.varve.line":"2026.10","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"{counter}","org.opencontainers.image.created":"2026-09-24T00:00:00Z"}},"manifests":[{entries}]}}"#
    );
    let digest = varve_core::manifest_digest(payload.as_bytes());
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), sk, "test-root").unwrap();
    let env_digest = varve_core::manifest_digest(envelope.as_bytes());
    let mut blobs = std::collections::BTreeMap::new();
    blobs.insert(env_digest.clone(), envelope.into_bytes());
    let mut tool_digest = String::new();
    if let Some((signed, served)) = &tool {
        tool_digest = varve_core::manifest_digest(signed);
        blobs.insert(tool_digest.clone(), served.clone());
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{
            "mediaType": "application/json", "digest": env_digest, "size": 0,
            "annotations": { "eu.pulseengine.varve.role": "envelope" }
        }],
    }))
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = hits.clone();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
            let path = target.split('?').next().unwrap_or("");
            let mut seen = line.clone();
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok() && header != "\r\n" && !header.is_empty() {
                seen.push_str(&header);
                header.clear();
            }
            recorded.lock().unwrap().push(seen);
            if drop_tool_blob && path.ends_with(&tool_digest) && !tool_digest.is_empty() {
                continue; // hang up without a response
            }
            let (status, body): (&str, Vec<u8>) = if path == "/v2/inc/layers/tags/list" {
                (
                    "200 OK",
                    format!(r#"{{"name":"inc/layers","tags":["{LAYER}"]}}"#).into_bytes(),
                )
            } else if path == format!("/v2/inc/layers/manifests/{LAYER}") {
                ("200 OK", manifest.clone())
            } else if let Some(d) = path.strip_prefix("/v2/inc/layers/blobs/") {
                match blobs.get(d) {
                    Some(b) => ("200 OK", b.clone()),
                    None => ("404 Not Found", b"{}".to_vec()),
                }
            } else {
                ("404 Not Found", b"{}".to_vec())
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    Served {
        registry: format!("oci+http://{addr}/inc/layers"),
        root_hex: hex::encode(pk),
        digest,
        hits,
        requests,
    }
}

struct Project {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    dir: std::path::PathBuf,
}

/// A project pinned to `acme`'s layer, with the realm's `registry` and
/// `mirrors` as given and `root_hex` as the realm's ONE trust root.
fn project(registry: &str, mirrors: &[&str], root_hex: &str) -> Project {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("varve-root");
    let dir = tmp.path().join("project");
    std::fs::create_dir_all(&dir).unwrap();
    let mirrors = mirrors
        .iter()
        .map(|m| format!("\"{m}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.join("varve-realms.toml"),
        format!(
            "[realm.acme]\nregistry = \"{registry}\"\nmirrors = [{mirrors}]\ntrust-root = \"{root_hex}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\nlayer = \"{LAYER}\"\n"
        ),
    )
    .unwrap();
    Project {
        _tmp: tmp,
        root,
        dir,
    }
}

fn varve(p: &Project) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", &p.root)
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&p.dir);
    cmd
}

fn installed_anything(p: &Project) -> bool {
    fn any_layer(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir).is_ok_and(|rd| {
            rd.filter_map(Result::ok).any(|e| {
                let p = e.path();
                (p.is_file() && p.file_name().is_some_and(|n| n == "layer.json"))
                    || (p.is_dir() && any_layer(&p))
            })
        })
    }
    any_layer(&p.root)
}

/// Clauses 1, 3, 4: the primary is down, a mirror serves the same layer, and
/// `varve install` succeeds and says which source answered.
// rivet: verifies REQ-MIRROR-002
#[test]
fn install_succeeds_through_a_mirror_when_the_primary_is_down_and_names_it() {
    let mirror = serve_layer();
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "install must fail over to the mirror:\nstdout:{}\nstderr:{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains(&mirror.registry) && stderr.contains("mirror"),
        "stderr must name the mirror that answered:\n{stderr}"
    );
    assert!(installed_anything(&p), "the layer must be installed");
}

/// Clause 3, the quiet half: when the primary answers nothing is said about
/// mirrors, so the note means something when it appears.
// rivet: verifies REQ-MIRROR-002
#[test]
fn install_from_a_healthy_primary_says_nothing_about_mirrors() {
    let primary = serve_layer();
    let mirror = serve_layer();
    let p = project(&primary.registry, &[&mirror.registry], &primary.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("mirror"), "unexpected note:\n{stderr}");
    // The layer and its blobs came from the primary. The mirror may be asked
    // for the OPTIONAL baseline line-status the primary carries none of (an
    // absent answer does not end that search), but never for a layer blob.
    assert!(
        mirror
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| !r.contains("/blobs/")),
        "a healthy primary means no layer bytes come from the mirror: {:?}",
        mirror.requests.lock().unwrap()
    );
}

/// Clauses 2, 4: the mirror is reachable but serves a layer the realm's root
/// did not sign. A mirror is transport, not authority: fail closed, install
/// nothing.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_mirror_serving_bytes_the_root_did_not_sign_fails_closed() {
    let real = serve_layer();
    let forged = serve_layer(); // a different key signs it
    let p = project(DEAD, &[&forged.registry], &real.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    assert!(
        !out.status.success(),
        "a forged mirror must not install:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!installed_anything(&p), "nothing may be installed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&forged.registry) && stderr.contains("does not verify"),
        "the mirror's OWN refusal reason (signature against the root) must be \
         reported, not just a wrapper's word:\n{stderr}"
    );
    assert!(
        forged.hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the mirror must actually have been fetched from"
    );
}

/// Clause 1 on a fetch that is not an install: `support-horizon` reads an
/// included layer's signed line-status from the realm. With the primary down
/// it must still be answered by the mirror, and say so.
// rivet: verifies REQ-MIRROR-002
#[test]
fn support_horizon_reads_an_include_through_a_mirror() {
    let mirror = serve_layer();
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    // The double serves a layer but no line-status, so the horizon is refused
    // ("states no support window") — which proves the include WAS read, from
    // the mirror, rather than the realm being unreachable.
    std::fs::write(
        p.dir.join("layer.toml"),
        format!(
            "[varve]\nversion = \"v0.41.0\"\n\n[realm]\nname = \"acme\"\nchannel = \"rolling\"\n\
             registry = \"oci://ghcr.io/acme/layers\"\n\n[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\n\
             [[include]]\ndigest = \"{}\"\nrealm = \"acme\"\nlayer = \"{LAYER}\"\n",
            mirror.digest
        ),
    )
    .unwrap();
    let out = varve(&p)
        .args([
            "support-horizon",
            "--channel",
            "rolling",
            "--issued-at",
            "2026-10-02T10:00:00Z",
            "--manifest",
            "layer.toml",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("states no support window"),
        "the include must have been READ (from the mirror):\n{stderr}"
    );
    assert!(
        stderr.contains(&mirror.registry) && stderr.contains("mirror"),
        "the mirror must be named:\n{stderr}"
    );
}

/// Clause 2, the reverse: the PRIMARY serves bytes that fail the realm's root
/// and a mirror serves the genuine layer. The refused source is not the end of
/// the road: the next source is tried, and still verified against the one root.
// rivet: verifies REQ-MIRROR-002
#[test]
fn bytes_that_fail_the_root_are_refused_and_the_next_source_is_tried() {
    let forged = serve_layer();
    let real = serve_layer();
    let p = project(&forged.registry, &[&real.registry], &real.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&real.registry),
        "must name the mirror:\n{stderr}"
    );
    assert!(installed_anything(&p));
}

/// Clause 2: no source verifies, so install fails and the error lists every
/// source it tried rather than only the last.
// rivet: verifies REQ-MIRROR-002
#[test]
fn when_no_source_verifies_the_error_names_every_source_tried() {
    let real = serve_layer();
    let forged_a = serve_layer();
    let forged_b = serve_layer();
    let p = project(&forged_a.registry, &[&forged_b.registry], &real.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains(&forged_a.registry) && stderr.contains(&forged_b.registry));
    assert!(!installed_anything(&p));
}

/// Seed the machine's high-water mark for the realm's line, as an earlier
/// install of counter `counter` would have.
fn seed_high_water(p: &Project, counter: u64) {
    let realm = varve_core::resolve_realm(&p.dir, "acme").unwrap();
    let store = varve_core::Store::at(realm.effective_root(&p.root));
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"2026.10.9","eu.pulseengine.varve.line":"2026.10","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"{counter}","org.opencontainers.image.created":"2026-09-24T00:00:00Z"}},"manifests":[]}}"#
    );
    let manifest = varve_core::LayerManifest::parse(payload.as_bytes()).unwrap();
    let mut marks = varve_core::HighWaterMarks::load(store.root()).unwrap();
    marks.advance(&manifest).unwrap();
}

/// A VERIFIED verdict is not a reason to ask another source. The primary
/// serves a genuine, root-signed layer that this machine refuses as a
/// rollback (its high-water mark is higher). A mirror serving a layer the
/// machine WOULD accept must not get a second chance against a lower bar:
/// that would let failover itself mount a freeze/rollback attack.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_verified_rollback_refusal_is_terminal_and_the_mirror_is_never_asked() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = serve_layer_signed(&sk, &pk, 1);
    let mirror = serve_layer_signed(&sk, &pk, 9);
    let p = project(&primary.registry, &[&mirror.registry], &primary.root_hex);
    seed_high_water(&p, 5);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a rolled-back layer must not install:\n{stderr}"
    );
    assert!(stderr.contains("rollback refused"), "{stderr}");
    assert_eq!(
        mirror.hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the mirror must not be consulted after a verified verdict"
    );
    assert!(!stderr.contains("mirror"), "{stderr}");
    assert!(!installed_anything(&p));
}

// ───────────── blobs, a different layer for a digest, credentials ─────────────

fn probe_bytes() -> Vec<u8> {
    b"#!/bin/sh\necho probe\n".to_vec()
}

/// A source with a real blob. Its tool is signed as `probe_bytes()`, and the
/// server SERVES `served` for that digest.
fn serve_with_tool(sk: &[u8], pk: &[u8], served: Vec<u8>, drop_blob: bool) -> Served {
    serve_spec(Spec {
        sk,
        pk,
        counter: 1,
        tool: Some((probe_bytes(), served)),
        drop_tool_blob: drop_blob,
    })
}

fn installed_probe(p: &Project) -> Option<Vec<u8>> {
    fn find(dir: &std::path::Path) -> Option<Vec<u8>> {
        for e in std::fs::read_dir(dir).ok()?.filter_map(Result::ok) {
            let path = e.path();
            if path.is_dir() {
                if let Some(b) = find(&path) {
                    return Some(b);
                }
            } else if path.file_name().is_some_and(|n| n == "probe") {
                return std::fs::read(&path).ok();
            }
        }
        None
    }
    find(&p.root)
}

/// Blob failover, source serves a WRONG blob: the digest check refuses it and
/// the mirror's right one is used. Every blob is digest-verified.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_wrong_blob_from_the_primary_is_refused_and_the_mirror_supplies_the_right_one() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = serve_with_tool(&sk, &pk, b"#!/bin/sh\necho PWNED\n".to_vec(), false);
    let mirror = serve_with_tool(&sk, &pk, probe_bytes(), false);
    let p = project(&primary.registry, &[&mirror.registry], &primary.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains(&mirror.registry), "{stderr}");
    assert_eq!(
        installed_probe(&p).as_deref(),
        Some(probe_bytes().as_slice()),
        "the installed tool must be the SIGNED bytes, not the primary's"
    );
}

/// Blob failover, source dies after serving its manifest.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_primary_that_dies_after_its_manifest_is_replaced_by_the_mirror_for_the_blob() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = serve_with_tool(&sk, &pk, probe_bytes(), true);
    let mirror = serve_with_tool(&sk, &pk, probe_bytes(), false);
    let p = project(&primary.registry, &[&mirror.registry], &primary.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains(&mirror.registry), "{stderr}");
    assert_eq!(
        installed_probe(&p).as_deref(),
        Some(probe_bytes().as_slice())
    );
}

/// A wrong blob and NO other source: fails closed, nothing installed.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_wrong_blob_with_no_alternative_installs_nothing() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let only = serve_with_tool(&sk, &pk, b"#!/bin/sh\necho PWNED\n".to_vec(), false);
    let p = project(&only.registry, &[], &only.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    assert!(!out.status.success());
    assert!(installed_probe(&p).is_none());
}

/// "A different layer for a digest": the pin names a digest; the only
/// reachable source serves ANOTHER genuinely signed layer under that name.
/// The digest is the artifact, so it is refused and nothing is installed.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_mirror_serving_a_different_layer_for_the_pinned_digest_is_refused() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let wanted = serve_layer_signed(&sk, &pk, 1); // the layer the pin means
    let other = serve_layer_signed(&sk, &pk, 2); // same name, same root, other bytes
    let p = project(DEAD, &[&other.registry], &wanted.root_hex);
    std::fs::write(
        p.dir.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\nlayer = \"{LAYER}\"\ndigest = \"{}\"\n",
            wanted.digest
        ),
    )
    .unwrap();
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&other.registry) && stderr.contains("no layer matching"),
        "the mirror's own refusal must be reported:\n{stderr}"
    );
    assert!(!installed_anything(&p));
}

/// A registry that answers EVERY request 401 with a bearer challenge naming
/// `token_realm`, recording what it was sent.
fn challenge_server(
    token_realm: String,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut seen = String::new();
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                seen.push_str(&line);
                line.clear();
            }
            recorded.lock().unwrap().push(seen);
            let _ = write!(
                stream,
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{token_realm}\",service=\"s\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (format!("oci+http://{addr}/inc/layers"), requests)
}

/// A token endpoint that records every request and issues nothing.
fn token_server() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut seen = String::new();
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                seen.push_str(&line);
                line.clear();
            }
            recorded.lock().unwrap().push(seen);
            let _ = write!(
                stream,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (format!("http://{addr}/token"), requests)
}

const SECRET: &str = "s3cr3t-pa55w0rd-DO-NOT-LEAK";

fn basic(user_pass: &str) -> String {
    // Standard base64, enough for a Basic header.
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in user_pass.as_bytes().chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn any_carries_secret(reqs: &std::sync::Mutex<Vec<String>>) -> bool {
    let b64 = basic(&format!("ci:{SECRET}"));
    reqs.lock()
        .unwrap()
        .iter()
        .any(|r| r.contains(SECRET) || r.contains(&b64))
}

/// A hostile mirror names a token realm of its own. The credential the
/// operator configured for the realm's PRIMARY must reach neither the mirror
/// nor the token endpoint it points at.
// rivet: verifies REQ-MIRROR-002
#[test]
fn the_primarys_credential_is_never_sent_to_a_mirror_or_its_token_realm() {
    let (token_url, token_reqs) = token_server();
    let (mirror, mirror_reqs) = challenge_server(token_url);
    let (_, pk) = varve_core::generate_root_keypair();
    let p = project(DEAD, &[&mirror], &hex::encode(&pk));
    let out = varve(&p)
        .env("VARVE_REGISTRY_AUTH", format!("ci:{SECRET}"))
        .arg("install")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !mirror_reqs.lock().unwrap().is_empty(),
        "the mirror must actually have been contacted"
    );
    assert!(
        !any_carries_secret(&mirror_reqs),
        "the mirror was sent the primary's credential:\n{:?}",
        mirror_reqs.lock().unwrap()
    );
    assert!(
        !any_carries_secret(&token_reqs),
        "the mirror's token realm was sent the primary's credential:\n{:?}",
        token_reqs.lock().unwrap()
    );
}

/// The same configuration still authenticates to the PRIMARY: the fix binds
/// the secret to its host, it does not remove it.
// rivet: verifies REQ-MIRROR-002
#[test]
fn the_primary_still_receives_its_credential() {
    let (token_url, token_reqs) = token_server();
    let (primary, _) = challenge_server(token_url);
    let (_, pk) = varve_core::generate_root_keypair();
    let p = project(&primary, &[], &hex::encode(&pk));
    let out = varve(&p)
        .env("VARVE_REGISTRY_AUTH", format!("ci:{SECRET}"))
        .arg("install")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        any_carries_secret(&token_reqs),
        "the primary's token request must carry its credential:\n{:?}",
        token_reqs.lock().unwrap()
    );
}

/// Clause 2 on the support walk (`DefinedRealms`): a primary serving bytes that
/// fail the realm's root must not END the walk; the next source is tried.
// rivet: verifies REQ-MIRROR-002
#[test]
fn support_horizon_tries_the_mirror_when_the_primary_serves_bytes_the_root_did_not_sign() {
    let real = serve_layer();
    let forged = serve_layer();
    let p = project(&forged.registry, &[&real.registry], &real.root_hex);
    std::fs::write(
        p.dir.join("layer.toml"),
        format!(
            "[varve]\nversion = \"v0.41.0\"\n\n[realm]\nname = \"acme\"\nchannel = \"rolling\"\n\
             registry = \"oci://ghcr.io/acme/layers\"\n\n[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\n\
             [[include]]\ndigest = \"{}\"\nrealm = \"acme\"\nlayer = \"{LAYER}\"\n",
            real.digest
        ),
    )
    .unwrap();
    let out = varve(&p)
        .args([
            "support-horizon",
            "--channel",
            "rolling",
            "--issued-at",
            "2026-10-02T10:00:00Z",
            "--manifest",
            "layer.toml",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("states no support window"),
        "the genuine include must have been READ from the mirror:\n{stderr}"
    );
    assert!(stderr.contains(&real.registry), "{stderr}");
}

/// A bad mirror spec breaks the realm it belongs to, and names it when that
/// realm is walked. It does not stop `support-horizon` for every other realm.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_bad_mirror_spec_breaks_only_its_own_realm() {
    let good = serve_layer();
    let p = project(&good.registry, &[], &good.root_hex);
    let realms = std::fs::read_to_string(p.dir.join("varve-realms.toml")).unwrap();
    std::fs::write(
        p.dir.join("varve-realms.toml"),
        format!(
            "{realms}\n[realm.broken]\nregistry = \"oci://ghcr.io/x/y\"\nmirrors = [\"https://not-a-registry.example/z\"]\ntrust-root = \"{}\"\n",
            good.root_hex
        ),
    )
    .unwrap();
    let layer_toml = |realm: &str| {
        format!(
            "[varve]\nversion = \"v0.41.0\"\n\n[realm]\nname = \"acme\"\nchannel = \"rolling\"\n\
             registry = \"oci://ghcr.io/acme/layers\"\n\n[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\n\
             [[include]]\ndigest = \"{}\"\nrealm = \"{realm}\"\nlayer = \"{LAYER}\"\n",
            good.digest
        )
    };
    let run = |p: &Project| {
        varve(p)
            .args([
                "support-horizon",
                "--channel",
                "rolling",
                "--issued-at",
                "2026-10-02T10:00:00Z",
                "--manifest",
                "layer.toml",
            ])
            .output()
            .unwrap()
    };
    // The healthy realm is still walked.
    std::fs::write(p.dir.join("layer.toml"), layer_toml("acme")).unwrap();
    let out = run(&p);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("states no support window"),
        "a broken OTHER realm must not stop this one:\n{stderr}"
    );
    // The broken one is refused by name, saying why.
    std::fs::write(p.dir.join("layer.toml"), layer_toml("broken")).unwrap();
    let out = run(&p);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("realm 'broken'") && stderr.contains("https://not-a-registry.example/z"),
        "{stderr}"
    );
}
