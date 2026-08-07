//! REQ-PROV-001 integration: the provenance contract, both halves together.
//!
//! `varve run` sets `VARVE_LAYER` / `VARVE_LAYER_MANIFEST_DIGEST` in the
//! dispatched tool's environment (proven at the CLI boundary in cli.rs);
//! wsc-attestation 0.10 (sigil#221) reads exactly those variables into
//! `ToolInfo`, inside the signed artifact. This test pins the two halves to
//! the same names and shapes, so the contract cannot drift silently: if
//! either side renames a variable, this goes red.
//!
//! Environment mutation is process-global, so everything lives in ONE test
//! function — no parallel test races.

use wsc_attestation::ToolInfo;

fn base_tool() -> ToolInfo {
    ToolInfo {
        name: "loom".into(),
        version: "0.1.0".into(),
        tool_hash: None,
        parameters: Default::default(),
        toolchain: None,
        toolchain_manifest_digest: None,
    }
}

// rivet: verifies REQ-PROV-001
#[test]
fn toolinfo_captures_the_layer_identity_varve_run_exports() {
    // Outside a varve dispatch: identity stays absent and does not serialize.
    unsafe {
        std::env::remove_var("VARVE_LAYER");
        std::env::remove_var("VARVE_LAYER_MANIFEST_DIGEST");
    }
    let outside = base_tool().with_varve_env();
    assert_eq!(outside.toolchain, None);
    assert_eq!(outside.toolchain_manifest_digest, None);
    let json = serde_json::to_string(&outside).unwrap();
    assert!(
        !json.contains("toolchain"),
        "absent identity must not serialize: {json}"
    );

    // Under the exact variables `varve run` sets (see run_tool in main.rs):
    // the qualified-set identity lands in the attestation.
    unsafe {
        std::env::set_var("VARVE_LAYER", "2026.07.0");
        std::env::set_var(
            "VARVE_LAYER_MANIFEST_DIGEST",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    }
    let dispatched = base_tool().with_varve_env();
    assert_eq!(dispatched.toolchain.as_deref(), Some("2026.07.0"));
    assert_eq!(
        dispatched.toolchain_manifest_digest.as_deref(),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    // And it round-trips through the serialized attestation — the offline
    // reconstruction anchor an assessor reads from the artifact alone.
    let json = serde_json::to_string(&dispatched).unwrap();
    let parsed: ToolInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.toolchain.as_deref(), Some("2026.07.0"));

    unsafe {
        std::env::remove_var("VARVE_LAYER");
        std::env::remove_var("VARVE_LAYER_MANIFEST_DIGEST");
    }
}
