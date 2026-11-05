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
    /// A line-status baseline carried beside the layer, stating this
    /// `support-until`.
    baseline_until: Option<&'a str>,
    /// A correction published under the line's own tag, stating this
    /// `support-until`.
    published_until: Option<&'a str>,
    /// Sign the published correction with a key that is NOT the realm's.
    forge_published: bool,
    /// Serve everything but the layer itself (no tag, no layer manifest): a
    /// primary that answers the CORRECTION question but cannot supply bytes.
    no_layer: bool,
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
        baseline_until: None,
        published_until: None,
        forge_published: false,
        no_layer: false,
    })
}

fn serve_spec(spec: Spec<'_>) -> Served {
    let Spec {
        sk,
        pk,
        counter,
        tool,
        drop_tool_blob,
        baseline_until,
        published_until,
        forge_published,
        no_layer,
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
    let signed_status = |until: &str, counter: u64| {
        varve_core::LineStatus {
            line: "2026.10".into(),
            counter,
            issued_at: "2026-09-24T00:00:00Z".into(),
            support_until: Some(until.into()),
            min_counter: None,
            yanked: Default::default(),
            known_problems: Vec::new(),
        }
        .sign(sk, "k")
        .unwrap()
        .into_bytes()
    };
    let mut layers = vec![serde_json::json!({
        "mediaType": "application/json", "digest": env_digest, "size": 0,
        "annotations": { "eu.pulseengine.varve.role": "envelope" }
    })];
    if let Some(until) = baseline_until {
        let doc = signed_status(until, 1);
        let d = varve_core::manifest_digest(&doc);
        blobs.insert(d.clone(), doc);
        layers.push(serde_json::json!({
            "mediaType": "application/json", "digest": d, "size": 0,
            "annotations": { "eu.pulseengine.varve.role": "line-status" }
        }));
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": layers,
    }))
    .unwrap();
    let status_tag = varve_core::linestatus::status_tag("2026.10");
    let mut published_manifest = None;
    if let Some(until) = published_until {
        let doc = if forge_published {
            // An envelope for the right line, from the wrong signer.
            let (other_sk, _) = varve_core::generate_root_keypair();
            varve_core::LineStatus {
                line: "2026.10".into(),
                counter: 2,
                issued_at: "2026-09-24T00:00:00Z".into(),
                support_until: Some(until.into()),
                min_counter: None,
                yanked: Default::default(),
                known_problems: Vec::new(),
            }
            .sign(&other_sk, "k")
            .unwrap()
            .into_bytes()
        } else {
            signed_status(until, 2)
        };
        let d = varve_core::manifest_digest(&doc);
        blobs.insert(d.clone(), doc);
        published_manifest = Some(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [{
                    "mediaType": "application/json", "digest": d, "size": 0,
                    "annotations": { "eu.pulseengine.varve.role": "line-status" }
                }],
            }))
            .unwrap(),
        );
    }
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
                let tags = if no_layer {
                    String::new()
                } else {
                    format!("\"{LAYER}\"")
                };
                (
                    "200 OK",
                    format!(r#"{{"name":"inc/layers","tags":[{tags}]}}"#).into_bytes(),
                )
            } else if !no_layer && path == format!("/v2/inc/layers/manifests/{LAYER}") {
                ("200 OK", manifest.clone())
            } else if let Some(pm) = published_manifest
                .as_ref()
                .filter(|_| path == format!("/v2/inc/layers/manifests/{status_tag}"))
            {
                ("200 OK", pm.clone())
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
    // A first contact through a mirror needs the signed status that states the
    // realm's floor, so the mirror carries one.
    let mirror = serve_with_status(Some("2027-01-01"), None);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    seed_high_water(&p, 1);
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
    seed_high_water(&p, 1);
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
    // The primary is up for CORRECTIONS (it states one) but cannot supply the
    // layer; the mirror carries the layer and its baseline. The layer bytes
    // and baseline come from the mirror, the correction from the primary.
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: None,
        published_until: Some("2026-10-24"),
        forge_published: false,
        no_layer: true,
    });
    let mirror = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: Some("2026-12-01"),
        published_until: None,
        forge_published: false,
        no_layer: false,
    });
    let p = project(&primary.registry, &[&mirror.registry], &mirror.root_hex);
    let out = support_horizon_via(&p, &mirror.digest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "2026-10-24\n",
        "the primary's correction binds the mirror's baseline"
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
    let real = serve_with_status(Some("2027-01-01"), None);
    let p = project(&forged.registry, &[&real.registry], &real.root_hex);
    seed_high_water(&p, 1);
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
    seed_high_water(&p, 1);
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
        baseline_until: Some("2027-01-01"),
        published_until: None,
        forge_published: false,
        no_layer: false,
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
    seed_high_water(&p, 1);
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
    seed_high_water(&p, 1);
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
    seed_high_water(&p, 1);
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
    seed_high_water(&p, 1);
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
    let real = serve_with_status(Some("2026-10-24"), None);
    let forged = serve_layer(); // same payload, signed by another key
    assert_eq!(forged.digest, real.digest);
    let p = project(&forged.registry, &[&real.registry], &real.root_hex);
    let out = support_horizon_via(&p, &real.digest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "2026-10-24\n",
        "the genuine include must have been READ from the mirror"
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

fn support_horizon_via(p: &Project, digest: &str) -> std::process::Output {
    std::fs::write(
        p.dir.join("layer.toml"),
        format!(
            "[varve]\nversion = \"v0.41.0\"\n\n[realm]\nname = \"acme\"\nchannel = \"rolling\"\n\
             registry = \"oci://ghcr.io/acme/layers\"\n\n[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\n\
             [[include]]\ndigest = \"{digest}\"\nrealm = \"acme\"\nlayer = \"{LAYER}\"\n"
        ),
    )
    .unwrap();
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
}

fn serve_with_status(baseline: Option<&str>, published: Option<&str>) -> Served {
    let (sk, pk) = varve_core::generate_root_keypair();
    serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: baseline,
        published_until: published,
        forge_published: false,
        no_layer: false,
    })
}

/// "Could not ask" is not "nothing published". The primary is unreachable, so
/// whether it holds a correction that SHORTENS the window is unknown; a mirror
/// that carries the layer and its baseline but no correction cannot prove the
/// primary has none. The horizon must not be signed on its say-so.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_mirror_saying_nothing_is_published_does_not_stand_in_for_a_primary_that_could_not_be_asked() {
    let mirror = serve_with_status(Some("2026-10-24"), None);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    let out = support_horizon_via(&p, &mirror.digest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a horizon was signed with the primary unasked:\nstdout:{}\nstderr:{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(stderr.contains("could not be established"), "{stderr}");
}

/// When the primary ANSWERS (no correction published) nothing failed before it,
/// so absence is established and the baseline stands.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_primary_that_answers_with_no_correction_establishes_absence() {
    let primary = serve_with_status(Some("2026-10-24"), None);
    let p = project(&primary.registry, &[], &primary.root_hex);
    let out = support_horizon_via(&p, &primary.digest);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "2026-10-24\n");
}

/// Fail CLOSED on credential binding: when the primary is not a registry at all
/// (a local directory), there is no origin a mirror could be "the same as", so
/// every registry mirror is restricted and sees nothing of $VARVE_REGISTRY_AUTH.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_directory_primary_does_not_unlock_the_credential_for_registry_mirrors() {
    let (token_url, token_reqs) = token_server();
    let (mirror, mirror_reqs) = challenge_server(token_url);
    let (_, pk) = varve_core::generate_root_keypair();
    let empty = tempfile::tempdir().unwrap();
    let p = project(
        empty.path().to_str().unwrap(),
        &[&mirror],
        &hex::encode(&pk),
    );
    seed_high_water(&p, 1);
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
        "{:?}",
        mirror_reqs.lock().unwrap()
    );
    assert!(
        !any_carries_secret(&token_reqs),
        "{:?}",
        token_reqs.lock().unwrap()
    );
}

/// Digest CONSENT lifts the machine's own rollback protection, so it cannot be
/// obtained by failover: the primary's status is unavailable, and a mirror
/// that would happily consent is never asked.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_mirror_cannot_grant_the_rollback_consent_the_primary_could_not_give() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = serve_layer_signed(&sk, &pk, 1);
    let mirror = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: Some("2027-01-01"),
        published_until: None,
        forge_published: false,
        no_layer: false,
    });
    let p = project(&primary.registry, &[&mirror.registry], &primary.root_hex);
    std::fs::write(
        p.dir.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\nlayer = \"{LAYER}\"\ndigest = \"{}\"\n",
            primary.digest
        ),
    )
    .unwrap();
    seed_high_water(&p, 5);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "consent was obtained from a mirror:\n{stderr}"
    );
    assert!(stderr.contains("rollback refused"), "{stderr}");
    assert!(
        mirror
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| !r.contains("/blobs/")),
        "the mirror must not be asked for its status: {:?}",
        mirror.requests.lock().unwrap()
    );
    assert!(!installed_anything(&p));
}

/// "Present" is not "established": a published envelope the realm's root did
/// not sign is no answer. With the primary unreachable, a mirror that serves a
/// valid baseline beside a FORGED correction must not have its baseline window
/// signed as though the correction had been read and found harmless.
// rivet: verifies REQ-MIRROR-002
#[test]
fn an_unverifiable_published_correction_on_a_mirror_does_not_establish_the_window() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let mirror = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: Some("2026-12-01"),
        published_until: Some("2026-10-24"),
        forge_published: true,
        no_layer: false,
    });
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    let out = support_horizon_via(&p, &mirror.digest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a window was signed on an unverifiable correction:\nstdout:{}\nstderr:{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(stderr.contains("could not be established"), "{stderr}");
}

/// A registry that answers EVERY request with `status` (e.g. "503 Service
/// Unavailable", "404 Not Found"): a primary that is up but cannot help.
fn error_server(status: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                line.clear();
            }
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    format!("oci+http://{addr}/inc/layers")
}

/// Rollback CONSENT is only ever taken from the realm's primary. The primary
/// no longer serves the layer (garbage-collected after a yank); a lagging
/// mirror still has it and an older status that SUPPORTS it. Asking the mirror
/// would install a layer the realm has since yanked.
// rivet: verifies REQ-MIRROR-002
#[test]
fn rollback_consent_is_never_granted_by_a_mirror_after_the_primary_failed() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let primary = error_server("404 Not Found");
    let mirror = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 1,
        tool: None,
        drop_tool_blob: false,
        baseline_until: Some("2027-01-01"),
        published_until: None,
        forge_published: false,
        no_layer: false,
    });
    let p = project(&primary, &[&mirror.registry], &mirror.root_hex);
    std::fs::write(
        p.dir.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\nlayer = \"{LAYER}\"\ndigest = \"{}\"\n",
            mirror.digest
        ),
    )
    .unwrap();
    seed_high_water(&p, 5);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a mirror granted rollback consent:\n{stderr}"
    );
    assert!(stderr.contains("primary"), "{stderr}");
    assert!(!installed_anything(&p), "nothing may be installed");
}

/// A registry that answers every request 401, naming ITS OWN `/token` as the
/// realm (the common ghcr/ECR shape), recording what it was sent.
fn self_challenge_server() -> (
    String,
    String,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let realm = format!("http://{addr}/token");
    let challenge = realm.clone();
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
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{challenge}\",service=\"s\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    (
        format!("oci+http://{addr}/inc/layers"),
        addr.to_string(),
        requests,
    )
}

/// A docker-config `auths` entry is keyed by host and ignores the scheme, so
/// it matches a CLEARTEXT mirror on that host. A restricted cleartext source
/// sends no credential at all, from any source: env or docker config.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_cleartext_mirror_never_receives_a_docker_config_credential() {
    let (mirror, authority, mirror_reqs) = self_challenge_server();
    let (_, pk) = varve_core::generate_root_keypair();
    let empty = tempfile::tempdir().unwrap();
    let p = project(
        empty.path().to_str().unwrap(),
        &[&mirror],
        &hex::encode(&pk),
    );
    seed_high_water(&p, 1);
    let docker = p.dir.join("docker");
    std::fs::create_dir_all(&docker).unwrap();
    std::fs::write(
        docker.join("config.json"),
        format!(
            r#"{{"auths":{{"{authority}":{{"auth":"{}"}}}}}}"#,
            basic(&format!("ci:{SECRET}"))
        ),
    )
    .unwrap();
    let out = varve(&p)
        .env("DOCKER_CONFIG", &docker)
        .env_remove("VARVE_REGISTRY_AUTH")
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
        "a cleartext mirror was sent a credential:\n{:?}",
        mirror_reqs.lock().unwrap()
    );
}

/// A status taken from a MIRROR must raise nothing that later grants consent.
/// The mirror serves a newer layer and a status that supports every layer of
/// the line; that install is ordinary and succeeds. If the status were then
/// CACHED, a later digest pin below the mark would be granted consent from the
/// cache, laundering a mirror's word through it.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_status_taken_from_a_mirror_is_not_cached_to_grant_consent_later() {
    let (sk, pk) = varve_core::generate_root_keypair();
    let mirror = serve_spec(Spec {
        sk: &sk,
        pk: &pk,
        counter: 2,
        tool: None,
        drop_tool_blob: false,
        baseline_until: Some("2027-01-01"),
        published_until: None,
        forge_published: false,
        no_layer: false,
    });
    // The older layer, as the primary (back up) serves it: no status at all.
    let older = serve_layer_signed(&sk, &pk, 1);
    assert_ne!(older.digest, mirror.digest);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    seed_high_water(&p, 1);

    // 1. An ordinary install of the newer layer, through the mirror.
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains(&mirror.registry), "{stderr}");

    // 2. The primary is back (carrying the OLDER layer, and no status). A pin
    // by the older layer's digest is below the mark and needs consent.
    std::fs::write(
        p.dir.join("varve-realms.toml"),
        format!(
            "[realm.acme]\nregistry = \"{}\"\ntrust-root = \"{}\"\n",
            older.registry, mirror.root_hex
        ),
    )
    .unwrap();
    std::fs::write(
        p.dir.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nrealm = \"acme\"\nchannel = \"rolling\"\nlayer = \"{LAYER}\"\ndigest = \"{}\"\n",
            older.digest
        ),
    )
    .unwrap();
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "consent was granted from a status a mirror supplied:\n{stderr}"
    );
    assert!(stderr.contains("rollback refused"), "{stderr}");
}

// ───── "Primary required where there is no history" (maintainer, 2026-11-05) ─────

/// A mirror serving a genuine layer and a genuine but OLD baseline status (it
/// states no floor) must not answer a FIRST CONTACT: this machine has no mark
/// and no cached status to bound what a lagging mirror says, and the primary,
/// were it up, would apply the floor the newer status raised.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_first_contact_is_answered_only_by_the_primary() {
    let mirror = serve_with_status(Some("2027-01-01"), None);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a fresh machine installed from a mirror:\n{stderr}"
    );
    assert!(
        stderr.contains("first contact with line 2026.10 needs the realm's primary"),
        "{stderr}"
    );
    assert!(!installed_anything(&p));
    assert_eq!(
        mirror.hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing is asked of a mirror that cannot be allowed to answer"
    );
}

/// With local history a mirror's answer is accepted, bounded by what this
/// machine has recorded, and the notice says exactly that.
// rivet: verifies REQ-MIRROR-002
#[test]
fn with_history_a_mirror_answers_and_the_notice_says_what_bounds_it() {
    let mirror = serve_with_status(Some("2027-01-01"), None);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    seed_high_water(&p, 1);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains(&mirror.registry), "{stderr}");
    assert!(
        stderr.contains("may lag the primary's")
            && stderr.contains("not older than what this machine has already recorded")
            && stderr.contains("2026.10"),
        "the notice must say what bounds a mirror's answer:\n{stderr}"
    );
}

/// Corrections are taken ONLY from the primary. The primary is down, so
/// whether it holds a correction is unknown, and a mirror that carries one
/// (an older one could LENGTHEN the window) does not stand in for it.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_correction_on_a_mirror_never_stands_in_for_the_primarys() {
    let mirror = serve_with_status(Some("2026-12-01"), Some("2026-10-24"));
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    let out = support_horizon_via(&p, &mirror.digest);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a window was signed from a mirror's correction:\nstdout:{}\nstderr:{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(
        stderr.contains("could not be established")
            && stderr.contains("only taken from the realm's primary"),
        "{stderr}"
    );
}

/// The omission check cannot run against a mirror that carries no index; with
/// history the install proceeds, and SAYS the check did not run.
// rivet: verifies REQ-MIRROR-002
#[test]
fn a_mirror_without_an_index_is_reported_as_an_omission_check_that_could_not_run() {
    let mirror = serve_with_status(Some("2027-01-01"), None);
    let p = project(DEAD, &[&mirror.registry], &mirror.root_hex);
    seed_high_water(&p, 1);
    let out = varve(&p).arg("install").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("omission check could not run against the mirror"),
        "{stderr}"
    );
}
