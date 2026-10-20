//! CVSS 3.1 base-score computation (REQ-ADVISORYWATCH-001 clause 5 note).
//!
//! A RustSec advisory does not carry a severity word — it carries a raw CVSS
//! vector string (`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`), and what
//! `varve status` eventually prints as "critical"/"high"/"medium"/"low" is
//! this module's own computation of it, against the exact base-score formula
//! the CVSS 3.1 specification defines — not an approximation. The four
//! reference vectors below (measured against the spec's own published
//! examples) are what a first draft of this got wrong in the fourth
//! significant figure: close enough that every informal spot-check passed,
//! and wrong enough to turn a 6.1 "medium" into a 5.9 that rounded down.
//!
//! `CVSS:3.0` vectors are scored by the SAME formula: the base-metric
//! equations (Impact, Exploitability, the scope-dependent terms, Roundup)
//! are byte-for-byte identical between 3.0 and 3.1 — only the temporal and
//! environmental metrics changed, and this module implements neither. A
//! vector of any OTHER version (`CVSS:4.0`, `CVSS:2.0`, …) is a genuinely
//! different scoring model this module does not implement, and `base_score`
//! refuses it rather than guess — REQ-ADVISORYWATCH-001's caller
//! (`rustsec_severity`) is what turns that refusal into a defaulted severity
//! instead of aborting a run over one advisory's metadata.
//!
//! No network, no CLI: given a vector string, this answers one question —
//! what score, and which of the four words varve's own severity field
//! accepts does it fall into.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CvssError {
    #[error("{0:?} is not a CVSS:3.1 vector string this calculator can decide")]
    BadVector(String),
    #[error("CVSS vector {0:?} is missing the required metric {1}")]
    MissingMetric(String, &'static str),
    #[error("CVSS vector {0:?} has an unrecognised value {1:?} for metric {2}")]
    BadMetricValue(String, String, &'static str),
}

/// Split `"CVSS:3.1/AV:N/AC:L/..."` into its metric map, checking the
/// prefix is `CVSS:3.1` or `CVSS:3.0` (identical base-metric equations —
/// see the module docs) and that every segment after it is a `KEY:VALUE`
/// pair. Extra metrics this calculator does not need (temporal,
/// environmental) are kept in the map and simply never looked up — a
/// vector carrying them is not malformed, only richer than this module
/// reads.
fn metrics(vector: &str) -> Result<BTreeMap<&str, &str>, CvssError> {
    let mut parts = vector.split('/');
    let prefix = parts
        .next()
        .ok_or_else(|| CvssError::BadVector(vector.to_string()))?;
    if prefix != "CVSS:3.1" && prefix != "CVSS:3.0" {
        return Err(CvssError::BadVector(vector.to_string()));
    }
    let mut map = BTreeMap::new();
    for tok in parts {
        let (k, v) = tok
            .split_once(':')
            .ok_or_else(|| CvssError::BadVector(vector.to_string()))?;
        if k.is_empty() || v.is_empty() {
            return Err(CvssError::BadVector(vector.to_string()));
        }
        map.insert(k, v);
    }
    Ok(map)
}

/// Look up one metric's numeric weight from its table, erroring by name
/// (missing) or by value (present but not a value this table recognises) —
/// the two refusals [`base_score`]'s callers need to tell apart.
fn weight(
    map: &BTreeMap<&str, &str>,
    vector: &str,
    key: &'static str,
    table: &[(&str, f64)],
) -> Result<f64, CvssError> {
    let v = *map
        .get(key)
        .ok_or_else(|| CvssError::MissingMetric(vector.to_string(), key))?;
    table
        .iter()
        .find(|(k, _)| *k == v)
        .map(|(_, w)| *w)
        .ok_or_else(|| CvssError::BadMetricValue(vector.to_string(), v.to_string(), key))
}

const AV: &[(&str, f64)] = &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)];
const AC: &[(&str, f64)] = &[("L", 0.77), ("H", 0.44)];
const UI: &[(&str, f64)] = &[("N", 0.85), ("R", 0.62)];
const CIA: &[(&str, f64)] = &[("H", 0.56), ("L", 0.22), ("N", 0.0)];
const PR_UNCHANGED: &[(&str, f64)] = &[("N", 0.85), ("L", 0.62), ("H", 0.27)];
const PR_CHANGED: &[(&str, f64)] = &[("N", 0.85), ("L", 0.68), ("H", 0.50)];

/// The CVSS 3.1 `Roundup` function: round UP to the nearest tenth, working
/// in integer hundred-thousandths so the comparison to "is this exactly a
/// multiple of 0.1" is exact rather than a floating-point `% 0.1 == 0.0`
/// that is never quite true. Per the spec's own reference pseudocode.
fn roundup(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

/// The CVSS 3.1 base score, 0.0 to 10.0, from a full vector string.
///
/// Implements the specification's base-metrics formula exactly: the impact
/// sub-score, the scope-dependent Impact and Exploitability terms, and the
/// final `Roundup`. Anything this calculator cannot place — an unknown
/// prefix, a missing required metric, an unrecognised value — is a typed
/// error, never a guessed score.
pub fn base_score(vector: &str) -> Result<f64, CvssError> {
    let m = metrics(vector)?;

    let scope = *m
        .get("S")
        .ok_or_else(|| CvssError::MissingMetric(vector.to_string(), "S"))?;
    let changed = match scope {
        "U" => false,
        "C" => true,
        other => {
            return Err(CvssError::BadMetricValue(
                vector.to_string(),
                other.to_string(),
                "S",
            ));
        }
    };

    let av = weight(&m, vector, "AV", AV)?;
    let ac = weight(&m, vector, "AC", AC)?;
    let ui = weight(&m, vector, "UI", UI)?;
    let pr_table = if changed { PR_CHANGED } else { PR_UNCHANGED };
    let pr = weight(&m, vector, "PR", pr_table)?;
    let c = weight(&m, vector, "C", CIA)?;
    let i = weight(&m, vector, "I", CIA)?;
    let a = weight(&m, vector, "A", CIA)?;

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Ok(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Ok(roundup(raw.min(10.0)))
}

/// The qualitative rating NVD/CVSS assigns a base score — the same four
/// bands `varve-producer`'s own severity field recognises, plus `"none"`
/// for a score of exactly 0.0, which that field does not: a 0-impact
/// vector is not a shape RustSec publishes, and a caller that reaches it
/// decides what to do, rather than this function inventing a mapping.
pub fn severity_label(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------
    // The requirement's own reference vectors.
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn critical_vector_scores_nine_point_eight() {
        let s = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 1e-9, "{s}");
        assert_eq!(severity_label(s), "critical");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn scope_changed_vector_scores_six_point_one_medium() {
        let s = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert!((s - 6.1).abs() < 1e-9, "{s}");
        assert_eq!(severity_label(s), "medium");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn low_attack_vector_high_privilege_vector_scores_four_point_zero_medium() {
        let s = base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N").unwrap();
        assert!((s - 4.0).abs() < 1e-9, "{s}");
        assert_eq!(severity_label(s), "medium");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn low_impact_vector_scores_three_point_seven_low() {
        let s = base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L").unwrap();
        assert!((s - 3.7).abs() < 1e-9, "{s}");
        assert_eq!(severity_label(s), "low");
    }

    // -------------------------------------------------------------
    // Zero impact.
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_vector_with_no_impact_at_all_scores_zero_and_none() {
        let s = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
        assert_eq!(s, 0.0);
        assert_eq!(severity_label(s), "none");
    }

    // -------------------------------------------------------------
    // Refusals.
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_vector_missing_the_cvss_prefix_is_refused() {
        assert!(matches!(
            base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Err(CvssError::BadVector(_))
        ));
        // CVSS:4.0 is a genuinely different scoring model this module does
        // not implement — refused, never guessed at with the 3.1 formula.
        assert!(matches!(
            base_score("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"),
            Err(CvssError::BadVector(_))
        ));
        assert!(matches!(
            base_score("garbage"),
            Err(CvssError::BadVector(_))
        ));
        assert!(matches!(base_score(""), Err(CvssError::BadVector(_))));
    }

    /// CVSS:3.0 is scored by the SAME formula as 3.1 — the base-metric
    /// equations did not change between the two revisions, only the
    /// temporal/environmental metrics this module does not implement.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_cvss_3_0_vector_is_scored_by_the_same_formula_as_3_1() {
        let v30 = base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        let v31 = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(v30, v31);
        assert!((v30 - 9.8).abs() < 1e-9, "{v30}");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_segment_with_no_colon_is_refused() {
        assert!(matches!(
            base_score("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Err(CvssError::BadVector(_))
        ));
    }

    /// Either side of a `KEY:VALUE` segment being empty is refused on its
    /// own — not only when BOTH are, which an `&&` in place of the `||`
    /// would still catch by accident for the all-empty case but miss for
    /// either half alone.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_empty_key_or_an_empty_value_alone_is_refused() {
        assert!(matches!(
            base_score("CVSS:3.1/:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Err(CvssError::BadVector(_))
        ));
        assert!(matches!(
            base_score("CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Err(CvssError::BadVector(_))
        ));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_missing_required_metric_names_which_one() {
        let e = base_score("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap_err();
        assert_eq!(
            e,
            CvssError::MissingMetric("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(), "AV")
        );

        let e = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H").unwrap_err();
        assert_eq!(
            e,
            CvssError::MissingMetric("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H".into(), "S")
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unrecognised_metric_value_names_the_metric_and_the_value() {
        let e = base_score("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap_err();
        assert_eq!(
            e,
            CvssError::BadMetricValue(
                "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
                "Q".into(),
                "AV"
            )
        );
        let e = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H").unwrap_err();
        assert_eq!(
            e,
            CvssError::BadMetricValue(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H".into(),
                "X".into(),
                "S"
            )
        );
    }

    /// A scope-changed vector whose impact is high enough that the scope's
    /// SECOND term — `3.25 * (ISS - 0.02)^15` — is not negligible, unlike
    /// the requirement's own `S:C` reference vector (6.1), where that term
    /// is six orders of magnitude smaller than the rest of the sum and a
    /// sign flip on either part of it does not move the rounded score at
    /// all. Computed by hand against the spec's own formula, independent of
    /// this module.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_scope_changed_second_term_is_not_negligible_at_high_impact() {
        let s = base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H").unwrap();
        assert!((s - 7.2).abs() < 1e-9, "{s}");
        assert_eq!(severity_label(s), "high");
    }

    /// Privileges Required reads a DIFFERENT table when Scope is Changed —
    /// the one axis in this formula that is not a flat lookup. `L` and `H`
    /// score differently depending on `S`; `N` does not.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn privileges_required_depends_on_scope() {
        let unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").unwrap();
        let changed = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert_ne!(
            unchanged, changed,
            "PR:L must score differently under S:U and S:C"
        );
    }

    // -------------------------------------------------------------
    // Roundup and severity boundaries.
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn roundup_leaves_an_exact_tenth_alone() {
        assert_eq!(roundup(4.0), 4.0);
        assert_eq!(roundup(7.0), 7.0);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn roundup_always_rounds_up_never_to_nearest() {
        assert_eq!(roundup(4.01), 4.1);
        assert_eq!(roundup(4.09), 4.1);
        assert_eq!(roundup(4.11), 4.2);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn severity_label_boundaries_match_the_published_cvss_bands() {
        for (score, want) in [
            (10.0, "critical"),
            (9.0, "critical"),
            (8.9, "high"),
            (7.0, "high"),
            (6.9, "medium"),
            (4.0, "medium"),
            (3.9, "low"),
            (0.1, "low"),
            (0.0, "none"),
        ] {
            assert_eq!(severity_label(score), want, "score {score}");
        }
    }
}
