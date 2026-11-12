//! `varve-serve context` for a MIXED toolchain (REQ-OVERRIDE-001 clause 3,
//! DD-043 (5)), end to end: the shipped binary, a real signed store, a
//! varve.toml with `[toolchain.override.<tool>]`.

#[path = "support/fixture.rs"]
mod fixture;

use fixture::*;

const BIN: &str = env!("CARGO_BIN_EXE_varve-serve");

/// The fixture's layer with `meld` 0.65 and `plain`, plus 2026.09.0 carrying
/// `meld` 0.57; the pin overrides meld. Returns the override layer's digest.
fn mixed() -> (Fx, String) {
    let fx = install_layer(vec![
        script_tool("meld", "0.65.0", "echo meld-0.65"),
        script_tool("plain", "1.0.0", "echo plain"),
    ]);
    fx.install_another(
        "2026.09.0",
        1,
        vec![script_tool("meld", "0.57.0", "echo meld-0.57")],
    );
    let older = fx
        .store
        .list()
        .unwrap()
        .into_iter()
        .find(|e| e.layer.to_string() == "2026.09.0")
        .unwrap()
        .digest;
    std::fs::write(
        fx.project.join("varve.toml"),
        format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.10.1\"\n\
             [toolchain.override.meld]\nlayer = \"2026.09.0\"\ndigest = \"{older}\"\n"
        ),
    )
    .unwrap();
    (fx, older)
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn context_orients_a_mixed_toolchain_as_mixed_never_as_the_pinned_layer() {
    let (fx, older) = mixed();
    let o = fx.run(BIN, &["context"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let md = String::from_utf8(o.stdout).unwrap();
    assert!(
        md.starts_with("# MIXED toolchain: realm (this project), layer 2026.10.1 (rolling)"),
        "{md}"
    );
    assert!(
        md.contains(&format!("- `meld` runs from layer 2026.09.0 (`{older}`)")),
        "{md}"
    );
    assert!(
        md.contains("### meld 0.57.0"),
        "the override's meld is listed: {md}"
    );
    assert!(!md.contains("meld 0.65.0"), "the pin's meld is not: {md}");
    assert!(md.contains("### plain 1.0.0"), "{md}");

    let o = fx.run(BIN, &["context", "--format", "json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["state"], "mixed");
    assert_eq!(j["identity"], "2026.10.1+mixed");
    assert_eq!(j["overrides"][0]["digest"], older.as_str());
    let meld = j["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "meld")
        .unwrap();
    assert_eq!(meld["layer"], "2026.09.0");
}

// rivet: verifies REQ-OVERRIDE-001
#[test]
fn context_refuses_a_tampered_override_layer_and_prints_nothing() {
    let (fx, older) = mixed();
    let bin = fx
        .root
        .join("core")
        .join(older.replace(':', "-"))
        .join("bin")
        .join("meld");
    std::fs::write(&bin, "#!/bin/sh\necho evil\n").unwrap();
    let o = fx.run(BIN, &["context"]);
    assert!(!o.status.success());
    assert!(
        o.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("override meld"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
