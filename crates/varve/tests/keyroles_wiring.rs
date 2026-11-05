//! REQ-KEYROLES-001, end to end: a consumer verifies BY ROLE.
//!
//! The producer CLI makes the artifacts (`keyroles_producer.rs` covers its own
//! refusals) and the consumer CLI reads them in a project that pins a realm
//! declaring `key-roles = true`. The same artifacts are then read in a realm
//! declaring no roles, which behaves exactly as it always did.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

struct Key {
    pk: Vec<u8>,
    file: PathBuf,
}

struct World {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    project: PathBuf,
    root: Key,
    layer: Key,
    status: Key,
    delegation: PathBuf,
}

fn key(dir: &Path, name: &str) -> Key {
    let (sk, pk) = varve_core::generate_root_keypair();
    let file = dir.join(format!("{name}.key"));
    std::fs::write(&file, hex::encode(&sk)).unwrap();
    Key { pk, file }
}

fn varve(w: &World) -> Command {
    let mut cmd = Command::cargo_bin("varve").unwrap();
    cmd.env("PATH", "/usr/bin:/bin")
        .env("VARVE_ROOT", w.dir.join("varve-root"))
        .env_remove("VARVE_TRUST_ROOT")
        .current_dir(&w.project);
    cmd
}

/// A project pinning realm `r`. With `roles` the realm declares key roles and
/// points at a root-signed delegation naming one LAYER and one STATUS key;
/// without, it is a flat realm that trusts its root alone.
fn world(roles: bool) -> World {
    world_with(roles, "oci://example/x", false)
}

/// `world`, with the realm's registry spec and `signed-index` stated.
fn world_with(roles: bool, registry: &str, signed_index: bool) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let root = key(&dir, "root");
    let layer = key(&dir, "layer");
    let status = key(&dir, "status");
    let doc = serde_json::json!({
        "realm-root": hex::encode(&root.pk),
        "counter": 1,
        "issued-at": "2026-11-05T00:00:00Z",
        "roles": {
            "layer": {"threshold": 1, "keys": [{"key": hex::encode(&layer.pk), "keyid": "layer-1"}]},
            "status": {"threshold": 1, "keys": [{"key": hex::encode(&status.pk), "keyid": "status-1"}]},
        }
    });
    std::fs::write(dir.join("delegation.json"), doc.to_string()).unwrap();
    let delegation = project.join("r.delegation.dsse");
    let w = World {
        _tmp: tmp,
        dir: dir.clone(),
        project: project.clone(),
        root,
        layer,
        status,
        delegation: delegation.clone(),
    };
    varve(&w)
        .args(["sign-delegation", "--file"])
        .arg(dir.join("delegation.json"))
        .arg("--key")
        .arg(&w.root.file)
        .arg("--out")
        .arg(&delegation)
        .assert()
        .success();
    write_realms(&w, roles, registry, signed_index);
    std::fs::write(
        project.join("varve.toml"),
        "manifest-version = 1\n[toolchain]\nrealm = \"r\"\nchannel = \"qualified\"\n\
         layer = \"2026.08.0\"\n",
    )
    .unwrap();
    w
}

/// (Re)write the project's realms file: realm `r`, trusting the root, with or
/// without roles.
fn write_realms(w: &World, roles: bool, registry: &str, signed_index: bool) {
    let mut extra = String::new();
    if roles {
        extra.push_str("key-roles = true\ndelegation-file = \"r.delegation.dsse\"\n");
    }
    if signed_index {
        extra.push_str("signed-index = true\n");
    }
    std::fs::write(
        w.project.join("varve-realms.toml"),
        format!(
            "[realm.r]\nregistry = \"{registry}\"\ntrust-root = \"{}\"\n{extra}",
            hex::encode(&w.root.pk)
        ),
    )
    .unwrap();
}

/// Deposit layer 2026.08.0 signed by `signer`, into `<dir>/layout-<name>`.
fn deposit(w: &World, signer: &Key, name: &str) -> PathBuf {
    let tool = w.dir.join("synth-bin");
    std::fs::write(&tool, b"synth-bytes").unwrap();
    let out = w.dir.join(format!("layout-{name}"));
    let assert = varve(w)
        .args([
            "deposit",
            "--json",
            "--layer",
            "2026.08.0",
            "--channel",
            "qualified",
        ])
        .args(["--counter", "1", "--issued-at", "2026-08-07T00:00:00Z"])
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .arg("--tool")
        .arg(format!("synth@0.45.0={}", tool.display()))
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("deposit --json");
    std::fs::write(
        out.with_extension("digest"),
        report["manifest_digest"]
            .as_str()
            .expect("deposit reports a digest"),
    )
    .unwrap();
    out
}

fn status_doc(w: &World, yanked: bool) -> PathBuf {
    let yanks = if yanked {
        r#"{"2026.08.0":"CVE-2026-0001"}"#
    } else {
        "{}"
    };
    let p = w.dir.join(format!("status-{yanked}.json"));
    std::fs::write(
        &p,
        format!(
            r#"{{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z",
                "support-until":"2028-07-31","yanked":{yanks},"known-problems":[]}}"#
        ),
    )
    .unwrap();
    p
}

/// Sign a line-status with `signer` and NO delegation: how a flat realm signs,
/// and how an attacker holding only a LAYER key would.
fn sign_status(w: &World, signer: &Key, yanked: bool, name: &str) -> PathBuf {
    let out = w.dir.join(format!("status-{name}.dsse"));
    varve(w)
        .args(["sign-status", "--force", "--file"])
        .arg(status_doc(w, yanked))
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    out
}

fn install(w: &World, layout: &Path) -> assert_cmd::assert::Assert {
    varve(w).args(["install", "--from"]).arg(layout).assert()
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_installs_a_layer_signed_layer() {
    let w = world(true);
    let layout = deposit(&w, &w.layer, "layer");
    install(&w, &layout)
        .success()
        .stdout(predicate::str::contains("2026.08.0"));
    varve(&w).arg("verify").assert().success();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_refuses_a_root_signed_layer_and_a_status_signed_one() {
    let w = world(true);
    let by_root = deposit(&w, &w.root, "root");
    install(&w, &by_root)
        .failure()
        .stderr(predicate::str::contains("signed by this realm's ROOT key"));
    let by_status = deposit(&w, &w.status, "status");
    install(&w, &by_status)
        .failure()
        .stderr(predicate::str::contains(
            "signed by this realm's STATUS key",
        ));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_roles_realm_reads_a_status_signed_line_status_and_refuses_a_layer_signed_one() {
    let w = world(true);
    let layout = deposit(&w, &w.layer, "layer");
    install(&w, &layout).success();

    // The STATUS key's document is read (and cached).
    let good = sign_status(&w, &w.status, false, "by-status");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&good)
        .assert()
        .success()
        .stdout(predicate::str::contains("not yanked"));

    // A yank signed by the LAYER key, the depositor's, is valid cryptography
    // and out of role: refused, and what the machine holds is not displaced.
    let yank = sign_status(&w, &w.layer, true, "by-layer");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&yank)
        .assert()
        .failure()
        .stderr(predicate::str::contains("signed by this realm's LAYER key"));
    // The ROOT is out of role for a status too.
    let by_root = sign_status(&w, &w.root, true, "by-root");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&by_root)
        .assert()
        .failure()
        .stderr(predicate::str::contains("signed by this realm's ROOT key"));
    varve(&w)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not yanked"));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_realm_declaring_no_roles_behaves_as_it_always_did() {
    let w = world(false);
    // Root-signed layer and root-signed status are accepted.
    let layout = deposit(&w, &w.root, "root");
    install(&w, &layout).success();
    let yank = sign_status(&w, &w.root, true, "by-root");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&yank)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("YANKED"));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_realm_declaring_no_roles_trusts_its_root_alone() {
    // Negative control: the delegation file exists beside the realm and names a
    // LAYER key, but a realm that does not opt in never consults it, so the
    // LAYER key is just a stranger there.
    let w = world(false);
    assert!(w.delegation.exists());
    let by_layer = deposit(&w, &w.layer, "layer");
    install(&w, &by_layer).failure();
    let status = sign_status(&w, &w.layer, true, "by-layer");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(&status)
        .assert()
        .failure();
}

// ---------------------------------------------------------------------------
// Every consumer site, in a roles realm (REQ-KEYROLES-001).
//
// Each test below accepts the document signed by the RIGHT role and refuses the
// ones the other keys signed. A site that quietly judged by the realm root
// alone would accept the root's signature and refuse the role key's, so these
// fail for it in both directions.
// ---------------------------------------------------------------------------

const ROOT_REFUSED: &str = "signed by this realm's ROOT key";
const STATUS_REFUSED: &str = "signed by this realm's STATUS key";

/// The sha256 of `bytes`, as `sha256sum` prints it.
fn sha_hex(bytes: &[u8]) -> String {
    varve_core::manifest_digest(bytes)
        .strip_prefix("sha256:")
        .unwrap()
        .to_string()
}

/// Sign an attestation statement for the installed layer 2026.08.0. With
/// `delegated` the command signs AS the LAYER role (and refuses any other key);
/// without, it signs with whatever key it is given, as a flat realm would.
fn sign_att(
    w: &World,
    signer: &Key,
    delegated: bool,
    name: &str,
    attach: Option<&Path>,
) -> PathBuf {
    let file = w.dir.join("sbom.json");
    std::fs::write(&file, br#"{"sbom":"varve-keyroles"}"#).unwrap();
    let out = w.dir.join(format!("att-{name}.dsse"));
    let mut cmd = varve(w);
    cmd.args(["sign-attestation", "--layer", "2026.08.0", "--kind", "sbom"])
        .args(["--producer", "tester", "--file"])
        .arg(&file)
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out);
    if delegated {
        cmd.arg("--delegation").arg(&w.delegation);
    }
    if let Some(layout) = attach {
        cmd.arg("--attach-to").arg(layout);
    }
    cmd.assert().success();
    out
}

fn check_att(w: &World, statement: &Path) -> assert_cmd::assert::Assert {
    varve(w)
        .args(["check-attestation", "--statement"])
        .arg(statement)
        .arg("--file")
        .arg(w.dir.join("sbom.json"))
        .assert()
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn check_attestation_in_a_roles_realm_takes_the_layer_role_and_refuses_the_others() {
    let w = world(true);
    install(&w, &deposit(&w, &w.layer, "layer")).success();

    let by_layer = sign_att(&w, &w.layer, true, "layer", None);
    check_att(&w, &by_layer)
        .success()
        .stdout(predicate::str::contains("attestation OK"));

    let by_root = sign_att(&w, &w.root, false, "root", None);
    check_att(&w, &by_root)
        .failure()
        .stderr(predicate::str::contains(ROOT_REFUSED));
    let by_status = sign_att(&w, &w.status, false, "status", None);
    check_att(&w, &by_status)
        .failure()
        .stderr(predicate::str::contains(STATUS_REFUSED));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn verify_reports_a_layer_signed_attestation_as_binding_and_a_root_signed_one_as_not() {
    let w = world(true);
    // A first store only to learn the layer's identity, which the statement
    // names; the statements are then carried in two copies of the same layer.
    install(&w, &deposit(&w, &w.layer, "seed")).success();
    let carried = deposit(&w, &w.layer, "carried-layer");
    let by_layer = sign_att(&w, &w.layer, true, "layer", Some(&carried));
    let carried_root = deposit(&w, &w.layer, "carried-root");
    let by_root = sign_att(&w, &w.root, false, "root", Some(&carried_root));
    assert!(by_layer.exists() && by_root.exists());

    let fresh = |layout: &Path, store: &str| {
        let mut cmd = varve(&w);
        cmd.env("VARVE_ROOT", w.dir.join(store));
        cmd.args(["install", "--from"])
            .arg(layout)
            .assert()
            .success();
        let mut v = varve(&w);
        v.env("VARVE_ROOT", w.dir.join(store));
        v.arg("verify").assert()
    };
    fresh(&carried, "store-layer")
        .success()
        .stdout(predicate::str::contains("binds to this layer"))
        .stdout(predicate::str::contains("DOES NOT BIND").not());
    fresh(&carried_root, "store-root")
        .success()
        .stdout(predicate::str::contains("DOES NOT BIND"))
        .stdout(predicate::str::contains(ROOT_REFUSED));
}

/// A release-sums envelope over `archive`, signed with `signer`.
fn sign_sums(w: &World, archive: &Path, signer: &Key, delegated: bool, name: &str) -> PathBuf {
    let sums = w.dir.join(format!("SHA256SUMS-{name}.txt"));
    let bytes = std::fs::read(archive).unwrap();
    std::fs::write(
        &sums,
        format!(
            "{}  {}\n",
            sha_hex(&bytes),
            archive.file_name().unwrap().to_string_lossy()
        ),
    )
    .unwrap();
    let out = w.dir.join(format!("sums-{name}.dsse.json"));
    let mut cmd = varve(w);
    cmd.args(["sign-sums", "--sums"])
        .arg(&sums)
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out);
    if delegated {
        cmd.arg("--delegation").arg(&w.delegation);
    }
    cmd.assert().success();
    out
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn self_verify_in_a_project_pinning_a_roles_realm_takes_layer_signed_sums_only() {
    let w = world(true);
    let archive = w.dir.join("varve-release.tar.gz");
    std::fs::write(&archive, b"release-bytes").unwrap();
    let verify = |env: &Path| {
        varve(&w)
            .args(["self-verify", "--archive"])
            .arg(&archive)
            .arg("--envelope")
            .arg(env)
            .assert()
    };
    let by_layer = sign_sums(&w, &archive, &w.layer, true, "layer");
    verify(&by_layer).success().stdout(predicate::str::contains(
        "verified against the signed release sums",
    ));
    let by_root = sign_sums(&w, &archive, &w.root, false, "root");
    verify(&by_root)
        .failure()
        .stderr(predicate::str::contains(ROOT_REFUSED));
    let by_status = sign_sums(&w, &archive, &w.status, false, "status");
    verify(&by_status)
        .failure()
        .stderr(predicate::str::contains(STATUS_REFUSED));
}

/// A release-API double: `/latest` names `tag` and its assets, which are served
/// under `/assets/`. Returns the `/latest` URL.
fn release_api(tag: &str, assets: std::collections::BTreeMap<String, Vec<u8>>) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let list: Vec<serde_json::Value> = assets
        .keys()
        .map(|n| {
            serde_json::json!({"name": n, "browser_download_url": format!("http://{addr}/assets/{n}")})
        })
        .collect();
    let latest = serde_json::to_vec(&serde_json::json!({"tag_name": tag, "assets": list})).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let assets = assets.clone();
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
                let body = if path == "/latest" {
                    latest
                } else {
                    path.strip_prefix("/assets/")
                        .and_then(|n| assets.get(n).cloned())
                        .unwrap_or_default()
                };
                let mut stream = stream;
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

// rivet: verifies REQ-KEYROLES-001
#[test]
fn self_update_in_a_project_pinning_a_roles_realm_installs_only_layer_signed_sums() {
    let w = world(true);
    let tag = "v99.0.0";
    let mut tarball = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let new_binary = b"successor-varve-bytes";
    let mut header = tar::Header::new_gnu();
    header.set_size(new_binary.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tarball
        .append_data(&mut header, "varve", &new_binary[..])
        .unwrap();
    let targz = tarball.into_inner().unwrap().finish().unwrap();
    let archive_name = format!("varve-{tag}-{}.tar.gz", varve_core::host_platform());
    let archive = w.dir.join(&archive_name);
    std::fs::write(&archive, &targz).unwrap();

    let update = |envelope: &Path, dest: &Path| {
        let mut assets = std::collections::BTreeMap::new();
        assets.insert(archive_name.clone(), targz.clone());
        assets.insert(
            "SHA256SUMS.txt.dsse.json".to_string(),
            std::fs::read(envelope).unwrap(),
        );
        varve(&w)
            .env("VARVE_UPDATE_API", release_api(tag, assets))
            .args(["self-update", "--to"])
            .arg(dest)
            .assert()
    };

    let by_layer = sign_sums(&w, &archive, &w.layer, true, "layer");
    let dest = w.dir.join("varve-updated");
    update(&by_layer, &dest).success();
    assert_eq!(std::fs::read(&dest).unwrap(), new_binary);

    for (signer, name, refused) in [
        (&w.root, "root", ROOT_REFUSED),
        (&w.status, "status", STATUS_REFUSED),
    ] {
        let env = sign_sums(&w, &archive, signer, false, name);
        let dest = w.dir.join(format!("varve-refused-{name}"));
        update(&env, &dest)
            .failure()
            .stderr(predicate::str::contains(refused));
        assert!(!dest.exists(), "a refused update must install nothing");
    }
}

fn index_file(w: &World, digest: &str) -> PathBuf {
    let p = w.dir.join("index.json");
    std::fs::write(
        &p,
        format!(
            r#"{{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z",
                "layers":[{{"layer":"2026.08.0","digest":"{digest}","channel":"qualified","counter":1}}]}}"#
        ),
    )
    .unwrap();
    p
}

/// The manifest digest of the layer a `deposit` wrote to `layout`, which
/// `deposit` recorded beside it.
fn layout_digest(layout: &Path) -> String {
    std::fs::read_to_string(layout.with_extension("digest")).unwrap()
}

/// Sign the line-index for `layout`'s layer with `signer`, no delegation.
fn sign_index(w: &World, layout: &Path, signer: &Key, name: &str) -> PathBuf {
    let out = w.dir.join(format!("index-{name}.dsse"));
    varve(w)
        .args(["sign-index", "--file"])
        .arg(index_file(w, &layout_digest(layout)))
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    out
}

fn attach_index(w: &World, layout: &Path, envelope: &Path) {
    varve(w)
        .args(["attach-index", "--layout"])
        .arg(layout)
        .arg("--index")
        .arg(envelope)
        .assert()
        .success();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn install_with_signed_index_in_a_roles_realm_takes_the_status_role_only() {
    let w = world_with(true, "oci://example/x", true);
    let accept = deposit(&w, &w.layer, "accept");
    let env = sign_index(&w, &accept, &w.status, "status");
    attach_index(&w, &accept, &env);
    install(&w, &accept)
        .success()
        .stdout(predicate::str::contains("signed index"));

    for (signer, name) in [(&w.root, "root"), (&w.layer, "layer")] {
        let w = world_with(true, "oci://example/x", true);
        let layout = deposit(&w, &w.layer, name);
        let env = sign_index(&w, &layout, signer, name);
        attach_index(&w, &layout, &env);
        install(&w, &layout)
            .failure()
            .stderr(predicate::str::contains(
                "under any STATUS key of this realm",
            ));
    }
}

/// A line-status stating a first-contact floor (`min-counter`), signed with
/// `signer` and no delegation.
fn sign_floor(w: &World, signer: &Key, min_counter: u64, name: &str) -> PathBuf {
    let doc = w.dir.join(format!("floor-{name}.json"));
    std::fs::write(
        &doc,
        format!(
            r#"{{"line":"2026.08","counter":1,"issued-at":"2026-08-07T00:00:00Z",
                "support-until":"2028-07-31","min-counter":{min_counter},
                "yanked":{{}},"known-problems":[]}}"#
        ),
    )
    .unwrap();
    let out = w.dir.join(format!("floor-{name}.dsse"));
    varve(w)
        .args(["sign-status", "--force", "--file"])
        .arg(&doc)
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();
    out
}

fn attach_status(w: &World, layout: &Path, envelope: &Path) {
    varve(w)
        .args(["attach-status", "--force", "--layout"])
        .arg(layout)
        .arg("--status")
        .arg(envelope)
        .assert()
        .success();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_status_signed_served_status_raises_the_first_contact_floor_and_a_root_signed_one_does_not() {
    // The layer's counter is 1. A served status whose floor is 5 refuses it on
    // a machine with no mark of its own, but only when the STATUS role signed
    // it: in a roles realm the root's signature on a status is out of role, so
    // it yields no floor rather than a trusted one.
    let w = world(true);
    let raised = deposit(&w, &w.layer, "raised");
    attach_status(&w, &raised, &sign_floor(&w, &w.status, 5, "status"));
    install(&w, &raised)
        .failure()
        .stderr(predicate::str::contains("below the floor of 5"));

    let w = world(true);
    let ignored = deposit(&w, &w.layer, "ignored");
    attach_status(&w, &ignored, &sign_floor(&w, &w.root, 5, "root"));
    install(&w, &ignored).success();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn outdated_in_a_roles_realm_consults_a_status_signed_index_and_refuses_the_others() {
    let answer = |signer: fn(&World) -> &Key| {
        // The realm's registry IS the layout, so `outdated` reads the index the
        // layout carries, from the realm's own source.
        let w = world(true);
        let layout = w.dir.join("layout-served");
        write_realms(&w, true, &layout.display().to_string(), true);
        let made = deposit(&w, &w.layer, "served");
        assert_eq!(made, layout);
        let env = sign_index(&w, &layout, signer(&w), "served");
        attach_index(&w, &layout, &env);
        varve(&w).args(["outdated", "--json"]).assert()
    };
    answer(|w| &w.status)
        .success()
        .stdout(predicate::str::contains("\"answerable\": true"));
    for signer in [(|w| &w.root) as fn(&World) -> &Key, |w| &w.layer] {
        answer(signer).failure().stderr(predicate::str::contains(
            "a line-index must be signed by a STATUS key",
        ));
    }
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn verify_all_checks_a_roles_realm_partition_by_role() {
    let w = world(true);
    install(&w, &deposit(&w, &w.layer, "layer")).success();
    varve(&w)
        .args(["verify", "--all"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[realm r] verified"));

    // A layer the ROOT signed, installed while the realm was a flat one, sits
    // in the same partition once the realm declares roles: out of role there.
    let w = world(false);
    install(&w, &deposit(&w, &w.root, "root")).success();
    write_realms(&w, true, "oci://example/x", false);
    varve(&w)
        .args(["verify", "--all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("in realm r FAILED"))
        .stderr(predicate::str::contains(
            "a layer manifest must be signed by a LAYER key",
        ));
}

/// A project pinning flat realm `r`, whose layer composes a layer of realm
/// `inc`. `inc` is the realm under test: its own root, LAYER and STATUS keys
/// and a delegation, and its registry is the directory the included layer was
/// deposited into.
struct Composition {
    w: World,
    inc_root: Key,
    /// The layout holding the composing layer, signed by `r`'s root.
    includer: PathBuf,
    included: PathBuf,
}

/// `inc` declares roles or not; the included layer is signed by `signer`
/// (`"layer"` through the delegation, or the realm `"root"` as a flat realm
/// would).
fn composition(inc_signer: &str) -> Composition {
    let w = world(false);
    let inc_root = key(&w.dir, "inc-root");
    let inc_layer = key(&w.dir, "inc-layer");
    let inc_status = key(&w.dir, "inc-status");
    std::fs::write(
        w.dir.join("inc-delegation.json"),
        serde_json::json!({
            "realm-root": hex::encode(&inc_root.pk),
            "counter": 1,
            "issued-at": "2026-11-05T00:00:00Z",
            "roles": {
                "layer": {"threshold": 1, "keys": [{"key": hex::encode(&inc_layer.pk), "keyid": "l1"}]},
                "status": {"threshold": 1, "keys": [{"key": hex::encode(&inc_status.pk), "keyid": "s1"}]},
            }
        })
        .to_string(),
    )
    .unwrap();
    varve(&w)
        .args(["sign-delegation", "--file"])
        .arg(w.dir.join("inc-delegation.json"))
        .arg("--key")
        .arg(&inc_root.file)
        .arg("--out")
        .arg(w.project.join("inc.delegation.dsse"))
        .assert()
        .success();

    let tool = w.dir.join("inc-tool");
    std::fs::write(&tool, b"included-bytes").unwrap();
    let included = w.dir.join("layout-included");
    let signer = if inc_signer == "root" {
        &inc_root
    } else {
        &inc_layer
    };
    let assert = varve(&w)
        .args([
            "deposit",
            "--json",
            "--layer",
            "2026.07.0",
            "--channel",
            "qualified",
        ])
        .args(["--counter", "1", "--issued-at", "2026-07-07T00:00:00Z"])
        .arg("--key")
        .arg(&signer.file)
        .arg("--out")
        .arg(&included)
        .arg("--tool")
        .arg(format!("base@1.0.0={}", tool.display()))
        .assert()
        .success();
    let report: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("deposit --json");
    let digest = report["manifest_digest"].as_str().unwrap().to_string();

    let spec = w.dir.join("includer.toml");
    std::fs::write(
        &spec,
        format!(
            "layer = \"2026.08.0\"\nchannel = \"qualified\"\ncounter = 1\n\
             [[include]]\ndigest = \"{digest}\"\nrealm = \"inc\"\nlayer = \"2026.07.0\"\n"
        ),
    )
    .unwrap();
    let includer = w.dir.join("layout-includer");
    varve(&w)
        .args(["deposit", "--spec"])
        .arg(&spec)
        .args(["--issued-at", "2026-08-07T00:00:00Z", "--key"])
        .arg(&w.root.file)
        .arg("--out")
        .arg(&includer)
        .assert()
        .success();
    Composition {
        w,
        inc_root,
        includer,
        included,
    }
}

/// Realm `r` (flat, the project's pin) and realm `inc`, with or without roles.
fn write_composition_realms(c: &Composition, inc_roles: bool) {
    let extra = if inc_roles {
        "key-roles = true\ndelegation-file = \"inc.delegation.dsse\"\n"
    } else {
        ""
    };
    std::fs::write(
        c.w.project.join("varve-realms.toml"),
        format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n\
             [realm.inc]\nregistry = \"{}\"\ntrust-root = \"{}\"\n{extra}",
            hex::encode(&c.w.root.pk),
            c.included.display(),
            hex::encode(&c.inc_root.pk)
        ),
    )
    .unwrap();
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn an_include_from_a_roles_realm_is_fetched_and_composed_when_layer_signed() {
    let c = composition("layer");
    write_composition_realms(&c, true);
    install(&c.w, &c.includer)
        .success()
        .stdout(predicate::str::contains("fetched composed layer"));
    // The composition walk judges the included layer by ITS realm's roles. (The
    // export then has nothing with source provenance to write, which is not
    // what is under test: the walk's own verdict is on stdout.)
    varve(&c.w)
        .args(["export-bazel", "--out"])
        .arg(c.w.dir.join("bazel-out"))
        .assert()
        .stdout(predicate::str::contains("(verified against realm 'inc')"));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn fetching_an_include_refuses_a_root_signed_layer_of_a_roles_realm() {
    let c = composition("root");
    write_composition_realms(&c, true);
    install(&c.w, &c.includer)
        .failure()
        .stderr(predicate::str::contains(
            "a layer manifest must be signed by a LAYER key",
        ));
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn the_composition_walk_refuses_a_root_signed_included_layer_once_its_realm_has_roles() {
    // The included layer was fetched while `inc` was a flat realm, as it could
    // legitimately be. Once `inc` declares roles the same bytes are out of role
    // and the walk over the composition says so, rather than judging `inc` by
    // its root alone.
    let c = composition("root");
    write_composition_realms(&c, false);
    install(&c.w, &c.includer).success();
    write_composition_realms(&c, true);
    varve(&c.w)
        .args(["export-bazel", "--out"])
        .arg(c.w.dir.join("bazel-out"))
        .assert()
        .failure()
        .stdout(predicate::str::contains("(verified against realm 'inc')").not());
}

// rivet: verifies REQ-KEYROLES-001
#[test]
fn a_status_signed_cached_status_raises_the_first_contact_floor_in_a_roles_realm() {
    // The floor can also come from a status this machine cached before it ever
    // installed from the line (`varve status --from-file`): read back by role.
    let w = world(true);
    let layout = deposit(&w, &w.layer, "layer");
    varve(&w)
        .args(["status", "--from-file"])
        .arg(sign_floor(&w, &w.status, 5, "cached"))
        .assert()
        .success();
    install(&w, &layout)
        .failure()
        .stderr(predicate::str::contains("below the floor of 5"));
}
