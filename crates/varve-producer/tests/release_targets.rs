//! `install.sh` and `release.yml` must agree about which targets exist.
//!
//! Two places decide one thing. `release.yml`'s matrix decides what is BUILT;
//! `install.sh` decides what a host may ASK FOR, and its error message tells a
//! user on an unsupported platform what the release actually publishes. Adding
//! the musl targets made that message wrong the moment the matrix changed, and
//! nothing would have said so — the script is shell, run by strangers, and
//! never executed by a test that reads the workflow.
//!
//! The rule is one-directional on purpose. Every triple the installer can
//! SELECT must be built, or `curl | sh` resolves a host to an asset the
//! release does not have. The reverse is allowed: the release may publish a
//! target the installer does not hand out by default, which is exactly the
//! musl case — the archives exist for the layer to ingest before the bootstrap
//! script changes its default to them.
//!
//! What must never drift is the ADVERTISED list: a user reading "varve
//! publishes binaries for exactly these targets" is owed the truth.

use std::collections::BTreeSet;

fn read(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Every `target:` in the release build matrix.
fn built_targets() -> BTreeSet<String> {
    read(".github/workflows/release.yml")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- target:"))
        .map(|t| t.trim().to_string())
        .collect()
}

/// Every triple `install.sh` can resolve a host to.
fn selectable_targets() -> BTreeSet<String> {
    let s = read("install.sh");
    let body = s
        .split("case \"${os}/${arch}\" in")
        .nth(1)
        .expect("install.sh no longer maps a host to a target")
        .split("esac")
        .next()
        .unwrap();
    body.lines()
        .filter_map(|l| l.split("echo \"").nth(1))
        .filter_map(|l| l.split('"').next())
        .map(str::to_string)
        .collect()
}

// rivet: verifies REQ-BOOTSTRAP-001
// rivet: verifies REQ-LIBCFLOOR-001
#[test]
fn every_target_the_installer_selects_is_actually_built() {
    let built = built_targets();
    let selectable = selectable_targets();
    assert!(
        !built.is_empty() && !selectable.is_empty(),
        "parsed nothing"
    );
    let missing: Vec<&String> = selectable.difference(&built).collect();
    assert!(
        missing.is_empty(),
        "install.sh resolves a host to {missing:?}, which the release matrix does not build — \
         `curl | sh` would 404 on exactly those platforms. Either build them or stop selecting \
         them."
    );
}

/// The message a stranded user reads must list what the release really ships.
// rivet: verifies REQ-BOOTSTRAP-001
// rivet: verifies REQ-LIBCFLOOR-001
#[test]
fn the_advertised_target_list_is_the_one_that_is_published() {
    let s = read("install.sh");
    let advertised = s
        .split("varve publishes binaries for exactly these targets:")
        .nth(1)
        .expect("install.sh no longer tells an unsupported host what exists")
        .split("Build from source")
        .next()
        .unwrap()
        .to_string();
    for target in built_targets() {
        assert!(
            advertised.contains(&target),
            "the release publishes {target} but install.sh's message does not mention it — a user \
             on that platform is told varve has nothing for them while the archive is sitting in \
             the release. Advertised text was:\n{advertised}"
        );
    }
}
