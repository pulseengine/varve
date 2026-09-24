//! The realms file we PUBLISH must parse with the parser that will read it.
//!
//! `varve-realms.toml` is copied verbatim into every release
//! (`release.yml`: `cp varve-realms.toml release-assets/`), and consumers are
//! told to `gh release download -p varve-realms.toml` rather than paste a key.
//! It is therefore a shipped artifact with no test of its own: a malformed
//! edit would be discovered by whoever downloaded it, after the tag.
//!
//! What this cannot check is whether a root is the RIGHT one — only the realm
//! holding the private half can say that, and the real proof is that a layer
//! signed by it verifies. What it can check is that the file we hand out is
//! well-formed, that every realm is completely specified, and that a root is
//! the shape a root has, so the failure is ours to see rather than theirs.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn realms_text() -> String {
    let p = repo_root().join("varve-realms.toml");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

// rivet: verifies REQ-REALM-001
#[test]
fn the_published_realms_file_parses_and_every_realm_is_complete() {
    let root = repo_root();
    let names = varve_core::realm::realm_names(&root)
        .unwrap_or_else(|e| panic!("the file shipped to every consumer does not parse: {e}"));
    assert!(
        names.len() >= 2,
        "expected at least the pulseengine and pulseengine-wasm realms, got {names:?}"
    );
    for name in &names {
        let realm = varve_core::realm::resolve_realm(&root, name)
            .unwrap_or_else(|e| panic!("realm '{name}' is listed but does not resolve: {e}"));
        assert!(
            realm.registry.starts_with("oci://") || realm.registry.starts_with("oci+http://"),
            "realm '{name}' registry {:?} is not an OCI reference — a consumer has nowhere to \
             fetch from",
            realm.registry
        );
    }
}

/// A root is 32 bytes, hex. A truncated or whitespace-damaged one would be
/// rejected at install with a parse error rather than a wrong answer, but it
/// would be rejected on the CONSUMER's machine, after the release.
// rivet: verifies REQ-REALM-001
#[test]
fn every_published_trust_root_is_the_shape_of_a_root() {
    let text = realms_text();
    let mut roots = 0usize;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("trust-root") else {
            continue;
        };
        let value = rest
            .trim_start_matches([' ', '=', '"'])
            .trim_end_matches(['"', ' '])
            .trim();
        assert_eq!(
            value.len(),
            64,
            "trust-root {value:?} is {} hex characters, not 64",
            value.len()
        );
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()),
            "trust-root {value:?} is not hex"
        );
        roots += 1;
    }
    assert!(roots >= 2, "expected a root per realm, found {roots}");
}
