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
}

/// An OCI registry on a loopback port serving one layer signed by a fresh
/// root. Two calls serve the same layer name signed by DIFFERENT roots.
fn serve_layer() -> Served {
    let (sk, pk) = varve_core::generate_root_keypair();
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{LAYER}","eu.pulseengine.varve.line":"2026.10","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-09-24T00:00:00Z"}},"manifests":[]}}"#
    );
    let digest = varve_core::manifest_digest(payload.as_bytes());
    let envelope = varve_core::sign_layer_manifest(payload.as_bytes(), &sk, "test-root").unwrap();
    let env_digest = varve_core::manifest_digest(envelope.as_bytes());
    let mut blobs = std::collections::BTreeMap::new();
    blobs.insert(env_digest.clone(), envelope.into_bytes());
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
            let mut header = String::new();
            while reader.read_line(&mut header).is_ok() && header != "\r\n" && !header.is_empty() {
                header.clear();
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
        root_hex: hex::encode(&pk),
        digest,
        hits,
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
    assert_eq!(
        mirror.hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a healthy primary means the mirror is never asked"
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
        stderr.contains(&forged.registry) && stderr.contains("trust"),
        "the mirror WAS asked, and refused on the root, not skipped:\n{stderr}"
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
