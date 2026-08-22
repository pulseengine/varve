#![no_main]
//! varve-realms.toml maps names to trust roots; parsing untrusted content
//! must never panic. Property: a resolved realm always has a 32-byte root.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let dir = std::env::temp_dir().join(format!("varve-fuzz-realms-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        if std::fs::write(dir.join("varve-realms.toml"), s).is_ok() {
            if let Ok(realm) = varve_core::resolve_realm(&dir, "r") {
                assert_eq!(realm.trust_root.len(), 32);
            }
        }
    }
});
