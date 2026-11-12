//! A MIXED toolchain (REQ-OVERRIDE-001 clause 3, DD-043 (5) and (6)).
//!
//! A pin with `[toolchain.override.<tool>]` dispatches that tool from another
//! verified layer of the realm. The toolchain is then neither the pinned layer
//! nor the override layer, and the one thing it must never be reported as is
//! the pinned layer. Every identity report — `status`, `which`, `verify`,
//! `run`'s environment, `varve-serve`, an export stamp, an attestation —
//! renders the overrides through this module, so they cannot disagree about
//! what "mixed" means or about the order the overrides are listed in.

use serde::{Deserialize, Serialize};

/// What an export stamp or an attestation statement records about one
/// override: the tool, the source layer's id and its manifest digest.
///
/// `deny_unknown_fields`, like the stamp and the statement that carry it: a
/// reader meeting a field it does not know fails closed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RecordedOverride {
    pub tool: String,
    pub layer: String,
    pub digest: String,
}

/// Appended to the pinned layer's id wherever a single layer identity is
/// written for a mixed toolchain (DD-043 (6)).
pub const MIXED_SUFFIX: &str = "+mixed";

/// The overrides in the one order every report uses: by tool.
pub fn sorted(overrides: &[RecordedOverride]) -> Vec<RecordedOverride> {
    let mut out = overrides.to_vec();
    out.sort();
    out
}

/// `tool=layer@digest`, comma-separated and sorted by tool — the value of
/// `VARVE_OVERRIDES` (DD-043 (5)) and the compact form every report prints.
/// Empty for a pure toolchain.
pub fn env_value(overrides: &[RecordedOverride]) -> String {
    sorted(overrides)
        .iter()
        .map(|o| format!("{}={}@{}", o.tool, o.layer, o.digest))
        .collect::<Vec<_>>()
        .join(",")
}

/// `pinned` | `mixed`: the `state` field of a JSON report.
pub fn state(overrides: &[RecordedOverride]) -> &'static str {
    if overrides.is_empty() {
        "pinned"
    } else {
        "mixed"
    }
}

/// The single layer identity of a toolchain: the pinned layer's id, with
/// [`MIXED_SUFFIX`] when anything is overridden. A mixed identity matches no
/// pin, so a reader that compares identities never takes it for the layer.
pub fn identity(layer: &str, overrides: &[RecordedOverride]) -> String {
    if overrides.is_empty() {
        layer.to_string()
    } else {
        format!("{layer}{MIXED_SUFFIX}")
    }
}

/// Does a recorded identity agree with the overrides recorded beside it?
///
/// A stamp whose layer says `+mixed` and records no overrides (or the reverse)
/// was edited or mis-written, and is not evidence of either state.
pub fn identity_consistent(identity: &str, overrides: &[RecordedOverride]) -> bool {
    identity.ends_with(MIXED_SUFFIX) != overrides.is_empty()
}

/// Why recorded overrides do not describe the project's current toolchain;
/// `None` when they are the same set.
///
/// Used where evidence is CHECKED against a project (check-attestation, an
/// export stamp): evidence about a pure toolchain does not describe a mixed
/// one, evidence about one mix does not describe another, and evidence about
/// a mix does not describe the pure pin.
pub fn mismatch(recorded: &[RecordedOverride], current: &[RecordedOverride]) -> Option<String> {
    let (recorded, current) = (sorted(recorded), sorted(current));
    if recorded == current {
        return None;
    }
    let show = |o: &[RecordedOverride]| {
        if o.is_empty() {
            "none (the pinned layer alone)".to_string()
        } else {
            env_value(o)
        }
    };
    Some(format!(
        "it records overrides {}, but this project's toolchain has {}",
        show(&recorded),
        show(&current)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(tool: &str, layer: &str, digest: &str) -> RecordedOverride {
        RecordedOverride {
            tool: tool.into(),
            layer: layer.into(),
            digest: digest.into(),
        }
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn the_environment_value_is_tool_layer_digest_sorted_and_comma_separated() {
        let v = env_value(&[
            o("synth", "2026.08.0", "sha256:bb"),
            o("loom", "2026.09.1", "sha256:aa"),
        ]);
        assert_eq!(v, "loom=2026.09.1@sha256:aa,synth=2026.08.0@sha256:bb");
        assert_eq!(env_value(&[]), "");
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_mixed_identity_is_never_the_pinned_layer() {
        let one = [o("synth", "2026.08.0", "sha256:bb")];
        assert_eq!(identity("2026.11.0", &[]), "2026.11.0");
        assert_eq!(identity("2026.11.0", &one), "2026.11.0+mixed");
        assert_eq!(state(&[]), "pinned");
        assert_eq!(state(&one), "mixed");
        assert!(identity_consistent("2026.11.0", &[]));
        assert!(identity_consistent("2026.11.0+mixed", &one));
        assert!(
            !identity_consistent("2026.11.0", &one),
            "mixed, labelled pure"
        );
        assert!(
            !identity_consistent("2026.11.0+mixed", &[]),
            "pure, labelled mixed"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn evidence_matches_only_the_same_set_of_overrides() {
        let a = o("synth", "2026.08.0", "sha256:bb");
        let b = o("loom", "2026.09.1", "sha256:aa");
        assert_eq!(mismatch(&[], &[]), None);
        assert_eq!(
            mismatch(&[a.clone(), b.clone()], &[b.clone(), a.clone()]),
            None,
            "order is not identity"
        );
        let pure_for_mixed = mismatch(&[], std::slice::from_ref(&a)).unwrap();
        assert!(
            pure_for_mixed.contains("none (the pinned layer alone)"),
            "{pure_for_mixed}"
        );
        assert!(
            pure_for_mixed.contains("synth=2026.08.0@sha256:bb"),
            "{pure_for_mixed}"
        );
        assert!(
            mismatch(std::slice::from_ref(&a), &[]).is_some(),
            "mixed for pure"
        );
        let other_digest = o("synth", "2026.08.0", "sha256:cc");
        assert!(mismatch(std::slice::from_ref(&a), &[other_digest]).is_some());
        assert!(
            mismatch(std::slice::from_ref(&a), &[a.clone(), b]).is_some(),
            "a subset is not the set"
        );
    }

    // rivet: verifies REQ-OVERRIDE-001
    #[test]
    fn a_recorded_override_refuses_a_field_it_does_not_know() {
        let ok: RecordedOverride =
            serde_json::from_str(r#"{"tool":"t","layer":"2026.08.0","digest":"sha256:a"}"#)
                .unwrap();
        assert_eq!(ok, o("t", "2026.08.0", "sha256:a"));
        assert!(
            serde_json::from_str::<RecordedOverride>(
                r#"{"tool":"t","layer":"2026.08.0","digest":"sha256:a","version":"1"}"#
            )
            .is_err()
        );
    }
}
