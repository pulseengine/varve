#![no_main]
//! varve.toml is human-written untrusted config. Property: parsing never
//! panics; a parsed pin always has a three-part layer id.
use libfuzzer_sys::fuzz_target;
use varve_core::Pin;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(pin) = Pin::parse(s, "fuzz.toml") {
            // A parsed pin's layer must itself round-trip (three-part).
            assert_eq!(pin.layer.to_string().matches('.').count(), 2);
        }
    }
});
