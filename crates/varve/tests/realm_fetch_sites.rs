//! REQ-MIRROR-002 clause 5: no realm fetch site may build its source from the
//! realm's primary alone.
//!
//! `Realm::sources` is the primary followed by its mirrors. A fetch that reads
//! `realm.registry` (or `RegistrySource::parse`s anything by hand) decides on
//! the primary alone, so a down primary fails a realm that declares working
//! mirrors — which is exactly how `mirrors` came to be parsed and never used.
//!
//! The scan is over production code: each file is read up to its first
//! `#[cfg(test)]` line (every module here keeps its tests at the end).
//! A hit is allowed only if it matches an entry below, and every entry states
//! why that site is not a realm fetch.

use std::path::{Path, PathBuf};

/// What a fetch site must not contain outside the allowlist.
const FORBIDDEN: &[&str] = &["realm.registry", "RegistrySource::parse("];

/// (file suffix, a substring of the allowed line, why it is not a realm fetch).
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "varve-core/src/realm.rs",
        "registry: def.registry.clone()",
        "the definition of Realm::registry itself, which `sources` is built beside",
    ),
    (
        "varve-core/src/registry.rs",
        "RegistrySource::parse(",
        "the constructor and its doc examples; this is the type a source is made of",
    ),
    (
        "varve-core/src/mirror.rs",
        "RegistrySource::parse(",
        "the one place that turns a realm's source strings into sources, in order",
    ),
    (
        "varve-core/src/layerspec.rs",
        "registry: m.realm.registry.clone()",
        "PUBLISHING side: copies the producer manifest's registry into the \
         assembler's VARVE_REGISTRY, the place a deposit is pushed to. Pushing \
         goes to the primary; a mirror is a read-only copy",
    ),
    (
        "varve-producer/src/main.rs",
        "m.realm.registry.trim_start_matches",
        "PUBLISHING side: carry-forward reuse pulls blobs the producer itself \
         previously pushed to its primary (via oras, digest-checked) so it can \
         republish them; the primary is the producer's own write target and a \
         lagging mirror would only cause needless re-downloads",
    ),
    (
        "varve-producer/src/main.rs",
        "RegistrySource::parse(&m.realm.registry)",
        "PUBLISHING side: `advisories` reads back what the producer itself \
         published to its primary to decide what to draft; every result is \
         re-verified there, and the draft is pushed to the primary",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let p = entry.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every offending line in `crates/*/src`, as "file:line: text".
fn violations(crates_dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for c in std::fs::read_dir(crates_dir)
        .unwrap()
        .filter_map(Result::ok)
    {
        let src = c.path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    files.sort();
    let mut bad = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let name = f.to_string_lossy().replace('\\', "/");
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("#[cfg(test)]") {
                break;
            }
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if !FORBIDDEN.iter().any(|p| line.contains(p)) {
                continue;
            }
            let allowed = ALLOWED
                .iter()
                .any(|(suffix, frag, _)| name.ends_with(suffix) && line.contains(frag));
            if !allowed {
                bad.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    bad
}

fn workspace_crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// rivet: verifies REQ-MIRROR-002
#[test]
fn no_realm_fetch_site_builds_its_source_from_the_primary_alone() {
    let bad = violations(&workspace_crates());
    assert!(
        bad.is_empty(),
        "these sites build a source from `realm.registry` / a hand-parsed RegistrySource, \
         so a down primary fails a realm that declares mirrors. Build the source with \
         `varve_core::mirror::Mirrors::for_realm` (realm.sources), or add the site to \
         ALLOWED with the reason it is not a realm fetch:\n{}",
        bad.join("\n")
    );
}

/// The scan must be able to fail: run over a synthetic crates dir containing a
/// violation it has to report, and one it has to accept.
// rivet: verifies REQ-MIRROR-002
#[test]
fn the_scan_reports_a_violation_and_stops_at_the_test_module() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("demo/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("lib.rs"),
        "fn f(realm: &R) { let s = RegistrySource::parse(&realm.registry); }\n\
         // realm.registry in a comment is not a fetch\n\
         #[cfg(test)]\nmod t { fn g(realm: &R) { let _ = realm.registry; } }\n",
    )
    .unwrap();
    let bad = violations(tmp.path());
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].contains("lib.rs:1"));
}

#[test]
fn every_allowlist_entry_states_a_reason_and_still_matches_something() {
    let crates = workspace_crates();
    for (suffix, frag, why) in ALLOWED {
        assert!(why.len() > 20, "{suffix}: an allowance needs a real reason");
        let mut files = Vec::new();
        rust_files(&crates, &mut files);
        let matched = files.iter().any(|f| {
            f.to_string_lossy().ends_with(suffix)
                && std::fs::read_to_string(f).is_ok_and(|t| t.contains(frag))
        });
        assert!(
            matched,
            "stale allowlist entry ({suffix}, {frag}): remove it, it allows nothing"
        );
    }
}
