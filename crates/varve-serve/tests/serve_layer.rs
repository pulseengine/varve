//! REQ-SERVELAYER-001 (varve#286): `--layer` was declared, documented, and
//! never read, so `varve-serve --layer X` served the PIN's documentation.

#[path = "support/fixture.rs"]
mod fixture;
use fixture::*;

const BIN: &str = env!("CARGO_BIN_EXE_varve-serve");

fn two_layers() -> Fx {
    let fx = install_layer(vec![docs_tool(
        "pinned-api",
        None,
        &[("index.html", &page("pinned"))],
    )]);
    fx.install_another(
        "2026.10.2",
        2,
        vec![docs_tool(
            "other-api",
            None,
            &[("index.html", &page("other"))],
        )],
    );
    fx
}

/// With `--layer X` different from the pin, X's documentation is what is read.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn layer_selects_another_installed_layers_docs() {
    let fx = two_layers();
    let pinned = fx.run(BIN, &["--check"]);
    assert!(
        pinned.status.success(),
        "{}",
        String::from_utf8_lossy(&pinned.stderr)
    );
    assert!(String::from_utf8_lossy(&pinned.stdout).contains("pinned-api API"));

    let other = fx.run(BIN, &["--check", "--layer", "2026.10.2"]);
    assert!(
        other.status.success(),
        "{}",
        String::from_utf8_lossy(&other.stderr)
    );
    let out = String::from_utf8_lossy(&other.stdout);
    assert!(out.contains("other-api API"), "--layer was ignored: {out}");
    assert!(!out.contains("pinned-api"), "{out}");
}

/// An uninstalled `--layer` exits non-zero and names the layer.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn an_uninstalled_layer_is_refused_by_name() {
    let fx = two_layers();
    let o = fx.run(BIN, &["--check", "--layer", "2026.10.9"]);
    assert!(
        !o.status.success(),
        "an unknown layer must not fall back to the pin"
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("2026.10.9"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.stdout.is_empty());
}

/// `context` and `ask` read the layer `--layer` names, too.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn layer_applies_to_context_and_ask() {
    let fx = two_layers();
    let o = fx.run(BIN, &["--layer", "2026.10.2", "context"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let md = String::from_utf8_lossy(&o.stdout);
    assert!(md.contains("layer 2026.10.2"), "{md}");
    let a = fx.run(BIN, &["--layer", "2026.10.2", "ask", "other"]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("other-api"),
        "{}",
        String::from_utf8_lossy(&a.stdout)
    );
}
