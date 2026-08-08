#![no_main]
//! Layer-manifest JSON arrives from registries/archives before verification.
//! Property: parsing arbitrary bytes never panics; a parsed manifest has a
//! well-formed issued-at (the F2 invariant) — never a silently-undated one.
use libfuzzer_sys::fuzz_target;
use varve_core::LayerManifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = LayerManifest::parse(data) {
        // If it parsed, the staleness verdict must be able to date it —
        // otherwise F2 (silent fail-open) has regressed.
        assert!(
            varve_core::staleness_warning(&m.issued_at, "2999-12-31T00:00:00Z", 0).is_some(),
            "a parsed manifest must carry a usable date: {:?}",
            m.issued_at
        );
    }
});
