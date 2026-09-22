//! The viewer reads EVERY layer of a composition, not just the pinned one.
//!
//! Reported from real use: `varve inspect` listed a four-layer composition and
//! its realms, and `varve-serve` on the same pin answered
//!
//!   Error: layer 2026.09.1 carries no documentation.
//!
//! The documentation was in one of the other three. `varve export-docs` found
//! it, because it walks the composition; the viewer read the pinned layer's
//! manifest alone. Two commands disagreeing about what one pin contains.
//!
//! The walk itself is exercised in varve-core (tests/composition_payloads.rs).
//! What this guards is the WIRING — that the viewer uses it rather than growing
//! a second answer, which is how the defect happened in the first place.

fn main_rs() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn the_viewer_walks_the_composition_rather_than_one_manifest() {
    let s = main_rs();
    assert!(
        s.contains("compose::walk_installed"),
        "the viewer does not walk the composition — documentation in an included layer is \
         invisible, which is exactly what a four-layer pin reported"
    );
    assert!(
        s.contains("compose::payloads_of"),
        "the viewer collects payloads its own way instead of through the shared collector"
    );
    assert!(
        !s.contains("LayerManifest::parse(&std::fs::read(entry.root.join("),
        "the viewer still reads the pinned layer's manifest directly"
    );
}

/// "No documentation" is a very different sentence when four layers were
/// searched, so the viewer must say what it followed.
// rivet: verifies REQ-COMPOSEEXPORT-001
#[test]
fn the_viewer_says_which_layers_it_followed() {
    let s = main_rs();
    assert!(
        s.contains("following the composition"),
        "the viewer never reports the composition it walked"
    );
    assert!(
        s.contains("nor do the"),
        "the empty case does not distinguish one layer from a composition of several"
    );
}
