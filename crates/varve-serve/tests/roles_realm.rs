//! REQ-KEYROLES-001, PR 3b: `varve-serve` resolves a pinned realm's TRUST, not
//! just its root, so a layer of a roles realm verifies under the realm's LAYER
//! keys on the viewer's realm path.

#[path = "support/fixture.rs"]
mod fixture;
use fixture::*;

use std::path::PathBuf;

use varve_core::install::{InstallPolicy, install};
use varve_core::keyroles::DELEGATION_PAYLOAD_TYPE;
use varve_core::rollback::HighWaterMarks;
use varve_core::source::MemorySource;
use varve_core::store::{Store, manifest_digest};
use varve_core::verify::{PinnedKeyVerifier, dsse_sign_typed, generate_root_keypair};
use varve_core::{DepositSpec, Pin};

const BIN: &str = env!("CARGO_BIN_EXE_varve-serve");

struct Project {
    tmp: tempfile::TempDir,
    root: PathBuf,
    project: PathBuf,
}

/// A project pinning realm `r`, whose trust is `key-roles = true` with a
/// delegation naming one LAYER key and one STATUS key, and one layer of the
/// realm signed by `signer` and installed into the realm's store.
fn project(signer: Which, roles: bool) -> Project {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let (root_sk, root_pk) = generate_root_keypair();
    let (layer_sk, layer_pk) = generate_root_keypair();
    let (status_sk, status_pk) = generate_root_keypair();

    let delegation = serde_json::json!({
        "realm-root": hx(&root_pk),
        "counter": 1,
        "issued-at": "2026-11-05T00:00:00Z",
        "roles": {
            "layer": {"threshold": 1, "keys": [{"key": hx(&layer_pk)}]},
            "status": {"threshold": 1, "keys": [{"key": hx(&status_pk)}]},
        }
    });
    let env = dsse_sign_typed(
        delegation.to_string().as_bytes(),
        DELEGATION_PAYLOAD_TYPE,
        &root_sk,
        "root",
    )
    .unwrap();
    std::fs::write(project.join("r.delegation.dsse"), env).unwrap();
    let extra = if roles {
        "key-roles = true\ndelegation-file = \"r.delegation.dsse\"\n"
    } else {
        ""
    };
    std::fs::write(
        project.join("varve-realms.toml"),
        format!(
            "[realm.r]\nregistry = \"oci://example/x\"\ntrust-root = \"{}\"\n{extra}",
            hx(&root_pk)
        ),
    )
    .unwrap();
    let pin_text = "manifest-version = 1\n[toolchain]\nrealm = \"r\"\nchannel = \"rolling\"\n\
                    layer = \"2026.11.0\"\n";
    std::fs::write(project.join("varve.toml"), pin_text).unwrap();

    let sk = match signer {
        Which::Layer => &layer_sk,
        Which::Status => &status_sk,
    };
    let layout = tmp.path().join("layout");
    varve_core::deposit(
        &DepositSpec {
            includes: Vec::new(),
            layer: "2026.11.0".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-11-05T00:00:00Z".into(),
            tools: vec![docs_tool(
                "handbook",
                None,
                &[("index.html", &page("roles-realm"))],
            )],
        },
        sk,
        "k-1",
        &layout,
    )
    .expect("deposits");
    let realm = varve_core::resolve_realm(&project, "r").unwrap();
    let store_root = realm.effective_root(&root);
    let store = Store::at(&store_root);
    let envelope = std::fs::read(layout.join("layer.dsse.json")).unwrap_or_else(|_| {
        for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            if serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| v.get("payload").cloned())
                .is_some()
            {
                return b;
            }
        }
        panic!("no envelope")
    });
    let mut source = MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        source = source.with_blob(&manifest_digest(&b), &b);
    }
    // Installed with a verifier that trusts the signer outright: this test is
    // about what the VIEWER accepts afterwards, not about install.
    let signer_pk = match signer {
        Which::Layer => &layer_pk,
        Which::Status => &status_pk,
    };
    let mut marks = HighWaterMarks::load(&store_root).unwrap();
    install(
        &Pin::parse(pin_text, "varve.toml").unwrap(),
        &source,
        &PinnedKeyVerifier::from_public_key_bytes(signer_pk).unwrap(),
        &store,
        &mut marks,
        &InstallPolicy {
            index: None,
            now: "2026-11-05T00:00:00Z",
            staleness_threshold_days: 3650,
            platform: &varve_core::host_platform(),
        },
    )
    .expect("installs");
    Project { tmp, root, project }
}

#[derive(Clone, Copy)]
enum Which {
    Layer,
    Status,
}

fn run(p: &Project) -> std::process::Output {
    std::process::Command::new(BIN)
        .args(["--check"])
        .current_dir(&p.project)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", p.tmp.path())
        .env("TMPDIR", p.tmp.path())
        .env("VARVE_ROOT", &p.root)
        .output()
        .expect("runs")
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_roles_realms_layer_signed_layer_is_served() {
    let p = project(Which::Layer, true);
    let o = run(&p);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stdout).contains("handbook API"));
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn a_roles_realms_status_signed_layer_is_refused() {
    let p = project(Which::Status, true);
    let o = run(&p);
    assert!(!o.status.success(), "a STATUS-signed layer was served");
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(e.contains("STATUS") && e.contains("LAYER"), "{e}");
}

// rivet: partially-verifies REQ-KEYROLES-001
#[test]
fn the_same_layer_signed_layer_is_refused_by_a_realm_declaring_no_roles() {
    let p = project(Which::Layer, false);
    let o = run(&p);
    assert!(
        !o.status.success(),
        "a realm without roles must trust only its root"
    );
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
