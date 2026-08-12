//! REQ-UPDATE-001 end-to-end against a release-API double: the running
//! binary verifies its successor before replacement, and every failure
//! refuses.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

use varve_core::update::{UpdateDecision, check_latest, perform, resolve_update};

/// Serve a fake "latest release" API + asset downloads.
fn serve(tag: &str, assets: BTreeMap<String, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let asset_list: Vec<serde_json::Value> = assets
        .keys()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "browser_download_url": format!("http://{addr}/assets/{name}")
            })
        })
        .collect();
    let latest = serde_json::to_vec(&serde_json::json!({
        "tag_name": tag,
        "assets": asset_list,
    }))
    .unwrap();
    let assets = Arc::new(assets);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let assets = Arc::clone(&assets);
            let latest = latest.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok() {
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    header.clear();
                }
                let mut stream = stream;
                let body: Vec<u8> = if path == "/latest" {
                    latest.clone()
                } else if let Some(name) = path.strip_prefix("/assets/") {
                    assets.get(name).cloned().unwrap_or_default()
                } else {
                    Vec::new()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            });
        }
    });
    format!("http://{addr}/latest")
}

fn release_fixture(tag: &str, binary: &[u8], sign: bool) -> (String, Vec<u8>, Vec<u8>) {
    let (sk, pk) = varve_core::generate_root_keypair();
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(binary.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    builder.append_data(&mut header, "varve", binary).unwrap();
    let targz = builder.into_inner().unwrap().finish().unwrap();

    let platform = varve_core::host_platform();
    let archive_name = format!("varve-{tag}-{platform}.tar.gz");
    let digest = varve_core::manifest_digest(&targz);
    let sums = format!(
        "{}  ./{archive_name}\n",
        digest.strip_prefix("sha256:").unwrap()
    );
    let mut assets = BTreeMap::new();
    assets.insert(archive_name, targz);
    if sign {
        let envelope =
            varve_core::sign_release_sums(sums.as_bytes(), &sk, "varve-rolling-1").unwrap();
        assets.insert(
            "SHA256SUMS.txt.dsse.json".to_string(),
            envelope.into_bytes(),
        );
    }
    let api = serve(tag, assets);
    (api, pk, sk)
}

// rivet: verifies REQ-UPDATE-001
#[test]
fn the_running_binary_verifies_and_installs_its_successor() {
    let (api, pk, _) = release_fixture("v99.0.0", b"new-varve-bytes", true);
    let plan = check_latest(&api, "0.8.0", &varve_core::host_platform())
        .unwrap()
        .expect("v99 is newer than 0.8.0");
    assert_eq!(plan.latest, "v99.0.0");
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("varve");
    let digest = perform(&plan, &pk, &dest).unwrap();
    assert!(digest.starts_with("sha256:"));
    assert_eq!(std::fs::read(&dest).unwrap(), b"new-varve-bytes");
}

// rivet: verifies REQ-UPDATE-002
#[test]
fn a_mis_reported_version_converges_on_artifact_identity_not_a_loop() {
    // The varve#38 loop: the running binary reports "0.13.1" but IS the latest
    // release bytes. Version strings alone say "update forever"; resolving on
    // artifact identity says AlreadyCurrent — a no-op, so the loop terminates.
    let release_binary = b"the-genuine-v99-binary";
    let (api, pk, _) = release_fixture("v99.0.0", release_binary, true);
    let platform = varve_core::host_platform();

    // On-disk bytes are byte-identical to the (verified) latest release.
    let decision = resolve_update(&api, "0.13.1", &platform, Some(release_binary), &pk).unwrap();
    assert!(
        matches!(decision, UpdateDecision::AlreadyCurrent { .. }),
        "identical verified bytes must resolve to AlreadyCurrent, got {decision:?}"
    );

    // Different on-disk bytes → a genuine, verified update is available.
    let decision = resolve_update(&api, "0.13.1", &platform, Some(b"stale-bytes"), &pk).unwrap();
    assert!(
        matches!(decision, UpdateDecision::Available { .. }),
        "differing bytes must resolve to Available, got {decision:?}"
    );

    // A version that is not newer never fetches — UpToDate, root untouched path.
    let decision = resolve_update(&api, "100.0.0", &platform, Some(b"x"), &pk).unwrap();
    assert!(matches!(decision, UpdateDecision::UpToDate));
}

// rivet: verifies REQ-UPDATE-002
#[test]
fn resolve_update_verifies_before_it_offers_an_impostor() {
    // A release signed by an impostor must not surface as Available even though
    // its version is newer — resolve_update verifies before comparing/offering.
    let (api, _real_pk, _) = release_fixture("v99.0.0", b"evil-bytes", true);
    let (_, other_pk) = varve_core::generate_root_keypair();
    let err = resolve_update(
        &api,
        "0.13.1",
        &varve_core::host_platform(),
        Some(b"current"),
        &other_pk,
    )
    .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("signature"),
        "{err}"
    );
}

// rivet: verifies REQ-UPDATE-001
#[test]
fn an_older_or_equal_release_is_a_no_op() {
    let (api, _, _) = release_fixture("v0.1.0", b"old", true);
    assert!(
        check_latest(&api, "0.8.0", &varve_core::host_platform())
            .unwrap()
            .is_none()
    );
}

// rivet: verifies REQ-UPDATE-001
#[test]
fn an_unsigned_release_is_refused_not_installed() {
    let (api, pk, _) = release_fixture("v99.0.0", b"new", false);
    let err = check_latest(&api, "0.8.0", &varve_core::host_platform()).unwrap_err();
    assert!(
        err.to_string().contains("varve-native signed sums"),
        "{err}"
    );
    let _ = pk;
}

// rivet: verifies REQ-UPDATE-001
#[test]
fn a_successor_signed_by_an_impostor_is_refused_and_nothing_is_replaced() {
    let (api, _real_pk, _) = release_fixture("v99.0.0", b"evil", true);
    // The client pins a DIFFERENT root than the one that signed the release.
    let (_, other_pk) = varve_core::generate_root_keypair();
    let plan = check_latest(&api, "0.8.0", &varve_core::host_platform())
        .unwrap()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("varve");
    std::fs::write(&dest, b"current-binary").unwrap();
    assert!(perform(&plan, &other_pk, &dest).is_err());
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"current-binary",
        "a refused update must leave the current binary untouched"
    );
}
