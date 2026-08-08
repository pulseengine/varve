#![no_main]
//! The layer-identifier grammar (YYYY.MM.P) parses untrusted pin/manifest
//! text. Property: parse never panics, and a parse that succeeds must
//! Display back to a byte-identical string (round-trip).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(id) = s.parse::<varve_core::LayerId>() {
            assert_eq!(id.to_string(), s, "round-trip must be exact");
        }
    }
});
