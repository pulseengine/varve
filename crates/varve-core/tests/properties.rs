//! Property-based invariants (REQ-PROP-001) — the laws that must hold across
//! the whole input space, not just the examples the unit tests picked.

use proptest::prelude::*;
use varve_core::{HighWaterMarks, LayerId, LayerManifest, platform};

fn layer_id_str() -> impl Strategy<Value = String> {
    (2000u16..2100, 1u8..=12, 0u16..9999).prop_map(|(y, m, p)| format!("{y:04}.{m:02}.{p}"))
}

proptest! {
    // rivet: verifies REQ-PROP-001
    #[test]
    fn layer_id_parse_display_round_trips(s in layer_id_str()) {
        let id: LayerId = s.parse().unwrap();
        prop_assert_eq!(id.to_string(), s);
    }

    // rivet: verifies REQ-PROP-001
    #[test]
    fn layer_id_parse_never_panics(s in ".*") {
        let _ = s.parse::<LayerId>();
    }

    // rivet: verifies REQ-PROP-001
    #[test]
    fn platform_matching_is_total_and_wasm_is_universal(
        entry in prop::option::of("[a-z0-9_-]{0,20}"),
        host in "[a-z0-9_-]{0,20}",
    ) {
        // Never panics for any input pair (totality).
        let m = platform::entry_matches(entry.as_deref(), &host);
        // Unstamped matches everything; identical stamps match.
        if entry.is_none() {
            prop_assert!(m);
        }
        if entry.as_deref() == Some(host.as_str()) && !host.is_empty() {
            prop_assert!(m);
        }
        // wasm32 entries match every host (portability, REQ-RUNNER-001).
        prop_assert!(platform::entry_matches(Some("wasm32-wasip2"), &host));
    }
}

/// Build a signed-shape manifest at a given counter for the rollback laws.
fn manifest_at(line: &str, counter: u64) -> LayerManifest {
    let payload = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
"annotations":{{"eu.pulseengine.varve.layer":"{line}.0",
"eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"{counter}",
"org.opencontainers.image.created":"2026-08-07T00:00:00Z"}},"manifests":[]}}"#
    );
    LayerManifest::parse(payload.as_bytes()).unwrap()
}

proptest! {
    // rivet: verifies REQ-PROP-001
    #[test]
    fn rollback_is_monotone(seen in 0u64..1_000_000, presented in 0u64..1_000_000) {
        // After accepting `seen`, a `presented` counter is accepted iff it is
        // not below the recorded mark — the SUIT/Uptane law, over the space.
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        hwm.advance(&manifest_at("2050.01", seen)).unwrap();
        let verdict = hwm.check(&manifest_at("2050.01", presented));
        let accepted = matches!(verdict, varve_core::RollbackVerdict::Accept);
        prop_assert_eq!(accepted, presented >= seen);
    }

    // rivet: verifies REQ-PROP-001
    #[test]
    fn advance_never_lowers_the_mark(a in 0u64..1_000_000, b in 0u64..1_000_000) {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        let m = manifest_at("2050.02", 0);
        hwm.advance(&manifest_at("2050.02", a)).unwrap();
        hwm.advance(&manifest_at("2050.02", b)).unwrap();
        prop_assert_eq!(hwm.mark(m.layer.line()), Some(a.max(b)));
    }
}
