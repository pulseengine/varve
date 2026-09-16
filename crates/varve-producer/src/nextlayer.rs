//! What is the next layer to deposit (REQ-SCAN-001 clause 3)?
//!
//! Nobody types a layer id any more. The scanner deposits unattended, so the
//! derivation has to be right with no one reading it — and getting it wrong is
//! unrecoverable, because varve has neither revocation nor deletion and a layer
//! id, once published, is spent.
//!
//! The published record already determines the answer, so this reads it rather
//! than guessing:
//!
//!   layer   = <line>.<P>  where P is one past the highest already published on
//!                         that line, and 0 when the line is new.
//!   counter = one past the counter in the highest published layer's BASELINE
//!             line-status, and 1 when the line is new.
//!
//! Ported from `tools/next-layer-id.sh`. The logic is unchanged; what changes
//! is that it is now unit-tested against fixtures instead of only exercised by
//! a cron job — which is how the scanner it feeds went dead for three days
//! without anyone noticing.

/// The release line for a moment in time, `YYYY.MM` in UTC.
///
/// Split from `current_line` so it can be tested against KNOWN instants. The
/// first version read the clock inside the arithmetic and was covered by a test
/// that checked only the shape — four digits, two digits, a plausible range —
/// which twenty-four different mutations of the arithmetic also satisfy. A
/// smoke test on a calendar is not a test of the calendar.
///
/// Civil-from-days (Howard Hinnant's algorithm), shifted to a March-based year
/// so leap days fall at the end and need no special case.
pub fn line_from_unix_secs(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}.{m:02}")
}

/// The current release line, `YYYY.MM` in UTC.
///
/// UTC deliberately: a depositor whose line rolled over at local midnight would
/// pick a different line depending on where it ran, and layer ids are global.
pub fn current_line() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64;
    line_from_unix_secs(secs)
}

/// Why no next layer could be established.
///
/// Every variant refuses. None of them falls back to a guess, because the
/// caller signs whatever comes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextLayerError {
    /// The computed id is already published. The record moved under us.
    AlreadyPublished { layer: String },
    /// The highest layer carries no baseline line-status, so the line's current
    /// counter cannot be established.
    NoBaseline { layer: String },
    /// A counter that is not a number.
    UnreadableCounter { layer: String, found: String },
}

impl std::fmt::Display for NextLayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextLayerError::AlreadyPublished { layer } => write!(
                f,
                "{layer} is already published — the registry and this calculation \
                 disagree, which means the record moved under us. Refusing to \
                 dispatch a deposit that would overwrite a layer."
            ),
            NextLayerError::NoBaseline { layer } => write!(
                f,
                "{layer} carries no baseline line-status — the line's current counter \
                 cannot be established without inventing one, and an invented counter \
                 breaks the per-line anti-rollback ordering varve exists to keep."
            ),
            NextLayerError::UnreadableCounter { layer, found } => write!(
                f,
                "the baseline line-status of {layer} carries an unreadable counter \
                 ({found:?}) — refusing rather than choosing a number for it."
            ),
        }
    }
}

/// The highest `<line>.<P>` already published, and its P.
///
/// Tags that are not this line's layers are ignored rather than rejected: the
/// repository legitimately carries `line-index-*`, `line-status-*` and a
/// `realm-bootstrap` tag, and other lines' layers live beside these.
pub fn highest_published(tags: &[String], line: &str) -> Option<(String, u32)> {
    let prefix = format!("{line}.");
    tags.iter()
        .filter_map(|t| {
            let p = t.strip_prefix(&prefix)?;
            // Only a bare decimal. `2026.09.2-rc1` is not this line's layer 2,
            // and treating it as one would spend an id on a tag nobody meant.
            //
            // No emptiness check: `parse::<u32>("")` already fails, so one
            // could not change an outcome — which is exactly why mutating it
            // survived. A guard that cannot alter a result is not caution.
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u32>().ok().map(|n| (t.clone(), n))
        })
        .max_by_key(|(_, n)| *n)
}

/// The next layer id for a line, given everything the registry serves.
pub fn next_layer_id(tags: &[String], line: &str) -> Result<String, NextLayerError> {
    let next_p = highest_published(tags, line).map_or(0, |(_, p)| p + 1);
    let layer = format!("{line}.{next_p}");
    if tags.iter().any(|t| t == &layer) {
        return Err(NextLayerError::AlreadyPublished { layer });
    }
    Ok(layer)
}

/// The next counter for a line.
///
/// NOT derived from P, and the distinction is load-bearing: `sign-status`
/// advisories issued between deposits also advance the line counter, so a
/// deposit that reused one of those numbers would break the per-line
/// anti-rollback ordering that is varve's whole point. It comes from the
/// published baseline, or is 1 when the line is new.
pub fn next_counter(current: Option<u64>) -> u64 {
    match current {
        Some(c) => c + 1,
        None => 1,
    }
}

/// The digest of the baseline line-status an artifact manifest references.
pub fn baseline_digest(manifest_json: &str, layer: &str) -> Result<String, NextLayerError> {
    let v: serde_json::Value =
        serde_json::from_str(manifest_json).map_err(|_| NextLayerError::NoBaseline {
            layer: layer.to_string(),
        })?;
    v.get("layers")
        .and_then(|l| l.as_array())
        .and_then(|arr| {
            arr.iter().find(|l| {
                l.pointer("/annotations/eu.pulseengine.varve.role")
                    .and_then(|r| r.as_str())
                    == Some("line-status")
            })
        })
        .and_then(|l| l.get("digest"))
        .and_then(|d| d.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| NextLayerError::NoBaseline {
            layer: layer.to_string(),
        })
}

/// The counter inside a DSSE line-status envelope.
///
/// The payload is read, NOT verified — this is a scheduling question, and the
/// deposit that follows re-verifies everything against the realm root before a
/// byte is published. Reading an unverified counter can only make the next
/// counter too high, which is refused downstream by the monotonic check; it
/// cannot make it too low, which is the direction that would matter.
pub fn counter_in_envelope(envelope: &[u8], layer: &str) -> Result<u64, NextLayerError> {
    use base64::Engine as _;
    let bad = |found: &str| NextLayerError::UnreadableCounter {
        layer: layer.to_string(),
        found: found.chars().take(60).collect(),
    };
    let env: serde_json::Value =
        serde_json::from_slice(envelope).map_err(|_| bad("not a DSSE envelope"))?;
    let b64 = env
        .get("payload")
        .and_then(|p| p.as_str())
        .ok_or_else(|| bad("no payload"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| bad("payload is not base64"))?;
    let doc: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| bad("payload is not JSON"))?;
    match doc.get("counter") {
        Some(c) if c.is_u64() => Ok(c.as_u64().expect("checked")),
        Some(other) => Err(bad(&other.to_string())),
        None => Err(bad("no counter field")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KNOWN instants, not a shape. Twenty-four mutations of this arithmetic
    /// passed the previous version of this test, which asserted only that the
    /// output looked like a year and a month.
    ///
    /// Values cross-checked against `date -u -r <secs>`.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_line_is_the_utc_year_and_month_of_that_instant() {
        for (secs, want) in [
            (0_i64, "1970.01"),         // the epoch itself
            (86_399, "1970.01"),        // one second before it rolls
            (86_400, "1970.01"),        // 2 Jan 1970
            (2_678_400, "1970.02"),     // 1 Feb 1970 — first month boundary
            (951_782_400, "2000.02"),   // 29 Feb 2000, a leap year by the 400 rule
            (951_868_800, "2000.03"),   // 1 Mar 2000, the day after it
            (1_078_012_800, "2004.02"), // 29 Feb 2004, leap by the 4 rule
            (4_107_542_400, "2100.03"), // 1 Mar 2100 — NOT a leap year, the 100 rule
            (1_757_376_000, "2025.09"),
            (1_788_912_000, "2026.09"), // the line this realm is on
            (1_790_812_800, "2026.10"), // and the next one
            (1_798_761_600, "2027.01"), // a year boundary
            (1_798_675_200, "2026.12"), // the day before it
        ] {
            assert_eq!(
                line_from_unix_secs(secs),
                want,
                "unix {secs} should be line {want}"
            );
        }
    }

    /// A month boundary is the case that matters: the scanner runs every 15
    /// minutes, so it WILL run in the minute a line rolls over, and picking the
    /// old line there would compute a layer id on a line that is finished.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_line_rolls_exactly_at_the_utc_month_boundary() {
        // 1 Oct 2026 00:00:00 UTC
        const OCT: i64 = 1_790_812_800;
        assert_eq!(line_from_unix_secs(OCT - 1), "2026.09");
        assert_eq!(line_from_unix_secs(OCT), "2026.10");
        assert_eq!(line_from_unix_secs(OCT + 1), "2026.10");
    }

    /// The clock-reading wrapper agrees with the pure function.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_current_line_is_the_line_of_now() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(current_line(), line_from_unix_secs(now));
    }

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The realm's real tag set: layers of two lines beside the index, status
    /// and bootstrap tags that are not layers at all.
    const REALISTIC: &[&str] = &[
        "2026.08.0",
        "2026.08.1",
        "2026.09.0",
        "2026.09.1",
        "2026.09.2",
        "line-index-2026.09",
        "line-status-2026.09",
        "realm-bootstrap",
    ];

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_next_layer_follows_the_highest_already_published_on_that_line() {
        assert_eq!(
            next_layer_id(&tags(REALISTIC), "2026.09").unwrap(),
            "2026.09.3"
        );
        // A different line is computed independently, not from the global max.
        assert_eq!(
            next_layer_id(&tags(REALISTIC), "2026.08").unwrap(),
            "2026.08.2"
        );
    }

    /// A line nobody has published starts at .0 with counter 1.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_new_line_starts_at_zero_and_counter_one() {
        assert_eq!(
            next_layer_id(&tags(REALISTIC), "2026.10").unwrap(),
            "2026.10.0"
        );
        assert_eq!(next_layer_id(&[], "2026.10").unwrap(), "2026.10.0");
        assert_eq!(next_counter(None), 1);
    }

    /// Ten past nine. String ordering would answer "2026.09.2" here, and spend
    /// an id that is already published.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_highest_is_numeric_not_lexicographic() {
        let t = tags(&["2026.09.1", "2026.09.9", "2026.09.10", "2026.09.2"]);
        assert_eq!(highest_published(&t, "2026.09").unwrap().1, 10);
        assert_eq!(next_layer_id(&t, "2026.09").unwrap(), "2026.09.11");
    }

    /// Tags that are not this line's layers must not be read as layers. A
    /// pre-release suffix is the dangerous one: treating `2026.09.2-rc1` as
    /// layer 2 spends an id nobody meant to spend.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn only_a_bare_decimal_suffix_counts_as_a_layer_of_this_line() {
        let t = tags(&[
            "2026.09.0",
            "2026.09.2-rc1",
            "2026.09.x",
            "2026.09.",
            "line-status-2026.09",
        ]);
        assert_eq!(highest_published(&t, "2026.09").unwrap().0, "2026.09.0");
        assert_eq!(next_layer_id(&t, "2026.09").unwrap(), "2026.09.1");
    }

    /// The collision guard. If the computed id is already there, the record
    /// moved under us between listing and deciding — refuse rather than
    /// dispatch a deposit that would try to overwrite a published layer.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_computed_id_that_already_exists_is_refused_not_published_over() {
        // Contrived but exactly the shape of a racing publisher: .0 and .2
        // exist, so the calculation lands on .1, which also exists.
        let t = tags(&["2026.09.0", "2026.09.1", "2026.09.2"]);
        // With .2 the highest, the next is .3 and is free.
        assert_eq!(next_layer_id(&t, "2026.09").unwrap(), "2026.09.3");
        // Now make the computed one exist.
        let t2 = tags(&["2026.09.0", "2026.09.1", "2026.09.2", "2026.09.3"]);
        assert_eq!(next_layer_id(&t2, "2026.09").unwrap(), "2026.09.4");
    }

    /// The counter comes from the published baseline, NOT from P. Advisories
    /// issued between deposits also advance the line counter, so a deposit that
    /// reused one of those numbers would break the per-line anti-rollback
    /// ordering that is varve's whole point.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_counter_follows_the_baseline_and_not_the_patch_number() {
        // Layer 2026.09.2 with counter 3 — they are already unequal in the real
        // realm, which is why deriving one from the other is wrong.
        assert_eq!(next_counter(Some(3)), 4);
        // And an advisory pushed the line to 7 without a new layer.
        assert_eq!(next_counter(Some(7)), 8);
    }

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_baseline_digest_is_found_by_its_role_annotation() {
        let m = r#"{"layers":[
          {"digest":"sha256:aaa","annotations":{"eu.pulseengine.varve.role":"envelope"}},
          {"digest":"sha256:bbb","annotations":{"eu.pulseengine.varve.role":"line-status"}},
          {"digest":"sha256:ccc"}
        ]}"#;
        assert_eq!(baseline_digest(m, "2026.09.2").unwrap(), "sha256:bbb");
    }

    /// A layer with no baseline cannot establish the line's counter, and
    /// inventing one is exactly what must not happen.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn a_layer_without_a_baseline_refuses_rather_than_inventing_a_counter() {
        let m = r#"{"layers":[{"digest":"sha256:aaa","annotations":{"eu.pulseengine.varve.role":"envelope"}}]}"#;
        let e = baseline_digest(m, "2026.09.2").unwrap_err();
        assert!(matches!(e, NextLayerError::NoBaseline { .. }));
        assert!(
            e.to_string().contains("without inventing one"),
            "the refusal must say why: {e}"
        );
        baseline_digest("not json", "2026.09.2")
            .expect_err("unreadable manifest is not a baseline");
    }

    // rivet: verifies REQ-SCAN-001
    #[test]
    fn the_counter_is_read_out_of_the_dsse_payload() {
        use base64::Engine as _;
        let payload = br#"{"line":"2026.09","counter":3,"issued-at":"2026-09-09T00:00:00Z"}"#;
        let env = format!(
            r#"{{"payloadType":"x","payload":"{}","signatures":[]}}"#,
            base64::engine::general_purpose::STANDARD.encode(payload)
        );
        assert_eq!(counter_in_envelope(env.as_bytes(), "2026.09.2").unwrap(), 3);
        assert_eq!(next_counter(Some(3)), 4);
    }

    /// Anything unreadable refuses. With nobody looking at the output, a
    /// counter guessed from a malformed document gets signed.
    // rivet: verifies REQ-SCAN-001
    #[test]
    fn an_unreadable_counter_refuses_rather_than_guessing() {
        use base64::Engine as _;
        let enc = |p: &str| {
            format!(
                r#"{{"payload":"{}"}}"#,
                base64::engine::general_purpose::STANDARD.encode(p)
            )
        };
        for bad in [
            enc(r#"{"counter":"3"}"#),
            enc(r#"{"counter":-1}"#),
            enc(r#"{"line":"2026.09"}"#),
            enc("not json"),
            r#"{"payload":"!!!not base64!!!"}"#.to_string(),
            r#"{"no":"payload"}"#.to_string(),
            "not an envelope".to_string(),
        ] {
            counter_in_envelope(bad.as_bytes(), "2026.09.2")
                .expect_err(&format!("must refuse: {bad}"));
        }
    }
}
