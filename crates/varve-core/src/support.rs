//! How long a layer is supported, and what to do when it is not
//! (REQ-SUPPORTUNTIL-001).
//!
//! ## A capability nobody populated
//!
//! `REQ-KP-001` shipped this metadata in v0.5.0 and it is verified: a support
//! window, DSSE-signed, attached as an OCI referrer so it can be added after
//! deposit without changing the layer digest. `LineStatus::support_until`
//! round-trips, is covered by tests, and `varve status` prints it.
//!
//! Nothing ever set it. Every published layer carried `None`, so every layer
//! printed *"no stated support window"* while `docs/manifest-format.md` said a
//! qualified channel "selects a line with a stated support window". A
//! capability nobody populates is worse than a missing one: the code, the
//! tests and the docs all imply a guarantee that no artifact carries.
//!
//! It was also never *parsed*. The field is a `String`, so `"2028-13-45"` or
//! `"next year"` would have signed cleanly — and nothing downstream could act
//! on it, which is why "warn when the window has passed" was not implementable
//! before this module existed.
//!
//! ## Time is data here
//!
//! Nothing in this module samples a clock. `varve` samples once at the CLI
//! boundary (`today_rfc3339`) and passes the day in, exactly as the staleness
//! verdict already does. A library that reads the clock cannot be tested for
//! what it does on a particular day, and "what does it do the day after
//! expiry" is the only interesting question about it.

use crate::rollback::epoch_days;
use std::fmt;

/// How long a channel supports a layer, in whole months from its issue date.
///
/// Policy, not per-release typing: a horizon a human enters each time is one
/// that drifts, and the drift is invisible because every value looks
/// plausible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub months: u32,
}

impl Policy {
    /// The stated policy for a channel.
    ///
    /// `rolling` is ONE month, and that is not a placeholder to be grown
    /// later. The rolling line ships monthly, so a layer is superseded about a
    /// month after it is issued, and nobody has undertaken to publish
    /// advisories or fixes for a superseded rolling layer. Six months was the
    /// first value written here and it promised five months of attention that
    /// no one had agreed to give — a support window is a commitment, and
    /// stating one longer than the commitment is the same class of untruth as
    /// stating none at all while the docs promise one.
    ///
    /// `qualified` is where a long horizon belongs, because that is the
    /// channel an assessor is pointed at and the one whose contents are
    /// deliberately frozen.
    pub fn for_channel(channel: &str) -> Option<Policy> {
        match channel {
            "rolling" => Some(Policy { months: 1 }),
            "qualified" => Some(Policy { months: 24 }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportError {
    UnknownChannel(String),
    BadDate {
        field: &'static str,
        value: String,
    },
    /// An include's own signed line-status states no window, so nothing
    /// bounds what the composition may promise about it.
    IncludeStatesNoWindow {
        layer: String,
        realm: String,
    },
    /// `--past-includes` was given with nothing in it.
    OverrideWithoutReason,
}

impl fmt::Display for SupportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupportError::UnknownChannel(c) => write!(
                f,
                "no support policy is stated for channel `{c}` (known: rolling, \
                 qualified). Refusing to invent one: a horizon nobody decided \
                 is a promise nobody made."
            ),
            SupportError::BadDate { field, value } => write!(
                f,
                "{field} `{value}` is not a date (expected YYYY-MM-DD). This \
                 field has never been validated, so an unparseable value would \
                 sign cleanly and then be unusable by everything that reads it."
            ),
            SupportError::IncludeStatesNoWindow { layer, realm } => write!(
                f,
                "included layer {layer} (realm '{realm}') states no support window, so \
                 nothing bounds how long this composition may promise to support it. \
                 Refusing rather than skipping it: the include nobody vouched for is \
                 the one that would have set the cap."
            ),
            SupportError::OverrideWithoutReason => write!(
                f,
                "promising support past an included layer's window needs a reason on \
                 the record; an empty one is not a decision"
            ),
        }
    }
}

impl std::error::Error for SupportError {}

/// The support horizon for a layer issued on `issued_at`, as `YYYY-MM-DD`.
pub fn horizon(issued_at: &str, channel: &str) -> Result<String, SupportError> {
    let policy =
        Policy::for_channel(channel).ok_or_else(|| SupportError::UnknownChannel(channel.into()))?;
    let date = issued_at.split_once('T').map_or(issued_at, |(d, _)| d);
    if epoch_days(date).is_none() {
        return Err(SupportError::BadDate {
            field: "issued-at",
            value: issued_at.to_string(),
        });
    }
    let y: i64 = date[0..4].parse().expect("checked by epoch_days");
    let m: i64 = date[5..7].parse().expect("checked by epoch_days");
    let d: i64 = date[8..10].parse().expect("checked by epoch_days");

    let total = (m - 1) + i64::from(policy.months);
    let (ny, nm) = (y + total / 12, total % 12 + 1);
    // Clamp into the target month: adding 6 months to the 31st must not
    // produce a date that does not exist. Ending a day early is correct; a
    // date that cannot be parsed is not.
    let nd = d.min(days_in_month(ny, nm));
    Ok(format!("{ny:04}-{nm:02}-{nd:02}"))
}

fn days_in_month(y: i64, m: i64) -> i64 {
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if leap {
                29
            } else {
                28
            }
        }
    }
}

/// One included layer's stated window, read from that layer's OWN signed
/// line-status and verified against ITS realm's root by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeWindow {
    pub layer: String,
    pub realm: String,
    /// `None` when the include's line-status states no window.
    pub support_until: Option<String>,
}

/// What set a composition's horizon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    /// The layer's own channel policy; no include ends sooner.
    Own,
    /// This include ends sooner, and the composition promises no more.
    Include { layer: String, realm: String },
    /// The composition promises past `earliest`, deliberately, for `reason`.
    PastIncludes { earliest: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capped {
    pub until: String,
    pub bound_by: Bound,
}

/// Cap a composition's horizon at the earliest window among its includes
/// (REQ-COMPOSEWINDOW-001).
///
/// A composition's window was derived from its own channel alone, so covalent
/// 2026.10.0 signed support until 2026-11-02 over a wasm layer whose own realm
/// stops vouching for it on 2026-10-24 (varve#254). The composition cannot
/// support bytes longer than the realm that publishes them does.
///
/// Capping, not refusing, is the default: an auto-deposit should produce the
/// true window without a person. Promising longer is possible and takes a
/// `past_includes` reason, which the caller prints beside the signed date.
pub fn cap_by_includes(
    own: &str,
    includes: &[IncludeWindow],
    past_includes: Option<&str>,
) -> Result<Capped, SupportError> {
    let own_days = epoch_days(own).ok_or_else(|| SupportError::BadDate {
        field: "support-until",
        value: own.to_string(),
    })?;
    let mut earliest: Option<(i64, &IncludeWindow, &str)> = None;
    for inc in includes {
        let until =
            inc.support_until
                .as_deref()
                .ok_or_else(|| SupportError::IncludeStatesNoWindow {
                    layer: inc.layer.clone(),
                    realm: inc.realm.clone(),
                })?;
        let days = epoch_days(until).ok_or_else(|| SupportError::BadDate {
            field: "include support-until",
            value: until.to_string(),
        })?;
        if earliest.is_none_or(|(e, _, _)| days < e) {
            earliest = Some((days, inc, until));
        }
    }
    let own_stands = Capped {
        until: own.to_string(),
        bound_by: Bound::Own,
    };
    let Some((_, inc, until)) = earliest.filter(|(d, _, _)| *d < own_days) else {
        return Ok(own_stands);
    };
    match past_includes {
        Some(reason) if reason.trim().is_empty() => Err(SupportError::OverrideWithoutReason),
        Some(reason) => Ok(Capped {
            until: own.to_string(),
            bound_by: Bound::PastIncludes {
                earliest: until.to_string(),
                reason: reason.trim().to_string(),
            },
        }),
        None => Ok(Capped {
            until: until.to_string(),
            bound_by: Bound::Include {
                layer: inc.layer.clone(),
                realm: inc.realm.clone(),
            },
        }),
    }
}

/// Why one include's window could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeWindowError {
    /// The include, by digest — all that is known before its manifest verifies.
    pub include: String,
    pub realm: String,
    pub reason: String,
}

impl fmt::Display for IncludeWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot read the support window of included layer {} (realm '{}'): {}",
            self.include, self.realm, self.reason
        )
    }
}

impl std::error::Error for IncludeWindowError {}

/// Read one include's stated window from the realm that vouches for it.
///
/// `source`, `verifier` and `root_pk` are THAT realm's — never the composing
/// realm's. The manifest is verified first, so the layer id the window is
/// reported against is one the realm signed; the line-status is then chosen by
/// [`crate::linestatus::current_line_status`], the same rule install uses, so
/// a correction that shortened the window binds here too.
///
/// No status at all yields `support_until: None`, which `cap_by_includes`
/// refuses. A status that is present and bad is an error.
pub fn include_window(
    source: &dyn crate::source::LayerSource,
    verifier: &dyn crate::install::ManifestVerifier,
    root_pk: &[u8],
    digest: &str,
    realm: &str,
) -> Result<IncludeWindow, IncludeWindowError> {
    let fail = |reason: String| IncludeWindowError {
        include: digest.to_string(),
        realm: realm.to_string(),
        reason,
    };
    let layer_ref = crate::source::LayerRef::Digest(digest.to_string());
    let fetched = source
        .fetch_manifest(&layer_ref)
        .map_err(|e| fail(format!("fetching its manifest: {e}")))?;
    let payload = verifier
        .verify(&fetched)
        .map_err(|e| fail(format!("its manifest does not verify: {}", e.0)))?;
    if crate::store::manifest_digest(&payload) != digest {
        return Err(fail(
            "the manifest served for this digest hashes to something else".to_string(),
        ));
    }
    let manifest = crate::manifest::LayerManifest::parse(&payload)
        .map_err(|e| fail(format!("its manifest does not parse: {e}")))?;
    let status =
        crate::linestatus::current_line_status(source, &layer_ref, manifest.layer.line(), root_pk)
            .map_err(|e| fail(format!("layer {}: its line-status: {e}", manifest.layer)))?;
    Ok(IncludeWindow {
        layer: manifest.layer.to_string(),
        realm: realm.to_string(),
        support_until: status.and_then(|(_, doc)| doc.report_for(&manifest.layer).support_until),
    })
}

/// Where a layer stands against its stated horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Supported, with this many days left. Zero means the last supported day.
    Supported { days_left: i64 },
    /// The window has passed, this many days ago.
    Expired { days_ago: i64 },
}

impl Standing {
    pub fn is_expired(self) -> bool {
        matches!(self, Standing::Expired { .. })
    }
}

/// Compare a stated horizon against a day. Neither is sampled here.
pub fn standing(support_until: &str, today: &str) -> Result<Standing, SupportError> {
    let until = epoch_days(support_until).ok_or_else(|| SupportError::BadDate {
        field: "support-until",
        value: support_until.to_string(),
    })?;
    let now = epoch_days(today).ok_or_else(|| SupportError::BadDate {
        field: "today",
        value: today.to_string(),
    })?;
    // The horizon day itself is still supported — a window stated as a date is
    // read by humans as "through that day", and expiring at its start would
    // surprise everyone by exactly one day.
    if now <= until {
        Ok(Standing::Supported {
            days_left: until - now,
        })
    } else {
        Ok(Standing::Expired {
            days_ago: now - until,
        })
    }
}

/// What an operator is told. Never a refusal: an expired layer is a
/// maintenance signal, and a tool that bricks a working build over a date
/// gets removed from the build (REQ-SUPPORTUNTIL-001 clause 4).
pub fn advisory(layer: &str, support_until: &str, standing: Standing) -> String {
    match standing {
        Standing::Expired { days_ago } => format!(
            "layer {layer} passed its stated support window on {support_until}, \
             {days_ago} day(s) ago. It still installs and still verifies — \
             nothing about the bytes has changed. What has changed is that no \
             one has undertaken to publish advisories or fixes for it, so a \
             problem found tomorrow will not be announced against this layer. \
             Move to a supported layer when you can."
        ),
        Standing::Supported { days_left } if days_left <= 30 => format!(
            "layer {layer} is supported until {support_until}, {days_left} \
             day(s) from now."
        ),
        Standing::Supported { days_left } => {
            format!("layer {layer} is supported until {support_until} ({days_left} days)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_horizon_is_derived_from_the_channel_not_typed_by_hand() {
        assert_eq!(
            horizon("2026-09-03T00:00:00Z", "rolling").unwrap(),
            "2026-10-03"
        );
        assert_eq!(
            horizon("2026-09-03T00:00:00Z", "qualified").unwrap(),
            "2028-09-03"
        );
        // A date with no time part works too.
        assert_eq!(horizon("2026-09-03", "rolling").unwrap(), "2026-10-03");
    }

    /// Adding a month to the 31st must not produce a date that does not exist.
    /// Ending a day early is correct; an unparseable horizon is not — and it
    /// would sign perfectly well, because nothing used to parse it.
    ///
    /// (Said "six months" until the rolling policy became one. The assertions
    /// below were always month-arithmetic; only the sentence describing them
    /// was stale — which is the drift REQ-SUPPORTUNTIL-001 corrected
    /// everywhere else in this file.)
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_horizon_that_would_fall_on_a_day_that_does_not_exist_is_clamped() {
        // 31 Aug + 1 month = 30 Sep, not 31 Sep.
        assert_eq!(horizon("2026-08-31", "rolling").unwrap(), "2026-09-30");
        // 31 Jan + 1 month = 28 Feb; the leap rule still applies.
        assert_eq!(horizon("2027-01-31", "rolling").unwrap(), "2027-02-28");
        // 31 Jan + 1 month in a LEAP year = 29 Feb.
        assert_eq!(horizon("2028-01-31", "rolling").unwrap(), "2028-02-29");
        // Every clamped result must itself parse.
        for d in ["2026-08-31", "2026-10-31", "2027-08-31", "2026-12-31"] {
            let h = horizon(d, "rolling").unwrap();
            assert!(epoch_days(&h).is_some(), "{d} -> {h} does not parse");
        }
    }

    /// The clamp is only exercised when the target month is SHORTER than the
    /// issue day. My first tests all landed in short months, so a
    /// `days_in_month` that returned 28 for every month passed them.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_thirty_one_day_target_month_keeps_all_thirty_one_days() {
        // Dec 31 + 1 = Jan 31, and January has 31 days.
        assert_eq!(horizon("2026-12-31", "rolling").unwrap(), "2027-01-31");
        // Mar 31 + 1 = Apr 30 — April does not.
        assert_eq!(horizon("2026-03-31", "rolling").unwrap(), "2026-04-30");
        // Jul 31 + 1 = Aug 31.
        assert_eq!(horizon("2026-07-31", "rolling").unwrap(), "2026-08-31");
        // A qualified layer still spans two years.
        assert_eq!(horizon("2026-01-31", "qualified").unwrap(), "2028-01-31");
    }

    /// The Gregorian rule has three parts and a leap check that only tested
    /// `y % 4` would get two of them wrong once a century.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn february_follows_the_whole_gregorian_leap_rule() {
        // 2024: divisible by 4 -> leap.
        assert_eq!(horizon("2024-01-31", "rolling").unwrap(), "2024-02-29");
        // 2100: divisible by 100, not by 400 -> NOT leap.
        assert_eq!(horizon("2100-01-31", "rolling").unwrap(), "2100-02-28");
        // 2000: divisible by 400 -> leap.
        assert_eq!(horizon("2000-01-31", "rolling").unwrap(), "2000-02-29");
        // 2026: not divisible by 4 -> not leap.
        assert_eq!(horizon("2026-01-31", "rolling").unwrap(), "2026-02-28");
    }

    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_supported_layer_does_not_report_itself_expired() {
        assert!(!standing("2027-03-03", "2026-09-03").unwrap().is_expired());
        assert!(!standing("2026-09-03", "2026-09-03").unwrap().is_expired());
        assert!(standing("2026-09-02", "2026-09-03").unwrap().is_expired());
    }

    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn the_year_rolls_over_correctly() {
        assert_eq!(horizon("2026-12-15", "rolling").unwrap(), "2027-01-15");
        assert_eq!(horizon("2026-12-31", "rolling").unwrap(), "2027-01-31");
        assert_eq!(horizon("2026-01-15", "qualified").unwrap(), "2028-01-15");
    }

    /// A channel with no stated policy must not get an invented one.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn an_unknown_channel_gets_no_horizon_rather_than_a_guessed_one() {
        let e = horizon("2026-09-03", "experimental").expect_err("must refuse");
        assert!(matches!(e, SupportError::UnknownChannel(_)), "{e:?}");
        assert!(e.to_string().contains("a promise nobody made"), "{e}");
        assert_eq!(Policy::for_channel("nope"), None);
    }

    /// The field has never been validated. `"2028-13-45"` would have signed.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn an_unparseable_horizon_is_refused_rather_than_compared() {
        for bad in [
            "",
            "next year",
            "2028-13-45",
            "2028-02-30",
            "28-01-01",
            "2028/01/01",
        ] {
            let e = standing(bad, "2026-09-03").expect_err(bad);
            assert!(matches!(e, SupportError::BadDate { .. }), "{bad}: {e:?}");
        }
        assert!(horizon("not-a-date", "rolling").is_err());
    }

    /// A window stated as a date reads to a human as "through that day".
    /// Expiring at its start would surprise everyone by exactly one day.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn the_stated_day_is_still_supported_and_the_next_one_is_not() {
        assert_eq!(
            standing("2027-03-03", "2027-03-03").unwrap(),
            Standing::Supported { days_left: 0 }
        );
        assert_eq!(
            standing("2027-03-03", "2027-03-04").unwrap(),
            Standing::Expired { days_ago: 1 }
        );
        assert_eq!(
            standing("2027-03-03", "2027-03-02").unwrap(),
            Standing::Supported { days_left: 1 }
        );
    }

    /// Clause 4. An expired layer is a maintenance signal, not a brick.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn an_expired_layer_is_explained_rather_than_refused() {
        let s = standing("2026-01-01", "2026-09-03").unwrap();
        assert!(s.is_expired());
        let msg = advisory("2026.01.0", "2026-01-01", s);
        assert!(msg.contains("still installs and still verifies"), "{msg}");
        assert!(msg.contains("245 day(s) ago"), "{msg}");
        // It says what actually changed, which is not the bytes.
        assert!(msg.contains("advisories"), "{msg}");
    }

    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_window_closing_soon_reads_differently_from_one_far_off() {
        let soon = advisory(
            "x",
            "2026-09-20",
            standing("2026-09-20", "2026-09-03").unwrap(),
        );
        assert!(soon.contains("17 day(s) from now"), "{soon}");
        let far = advisory(
            "x",
            "2027-09-20",
            standing("2027-09-20", "2026-09-03").unwrap(),
        );
        assert!(far.contains("(382 days)"), "{far}");
    }

    fn inc(layer: &str, until: Option<&str>) -> IncludeWindow {
        IncludeWindow {
            layer: layer.to_string(),
            realm: "wasm".to_string(),
            support_until: until.map(str::to_string),
        }
    }

    /// The measured case from varve#254: covalent's own channel says
    /// 2026-11-02, the wasm layer it includes says 2026-10-24.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn a_composition_is_capped_at_its_earliest_include() {
        let got = cap_by_includes(
            "2026-11-02",
            &[
                inc("2026.10.0", Some("2026-10-24")),
                inc("2026.10.3", Some("2026-10-30")),
            ],
            None,
        )
        .unwrap();
        assert_eq!(got.until, "2026-10-24");
        assert_eq!(
            got.bound_by,
            Bound::Include {
                layer: "2026.10.0".into(),
                realm: "wasm".into()
            }
        );
    }

    /// The earliest include binds wherever it is listed, and on a tie the
    /// first listed is named, so the message is the same on every run.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn the_earliest_include_binds_wherever_it_is_listed() {
        let got = cap_by_includes(
            "2026-11-02",
            &[
                inc("late", Some("2026-10-30")),
                inc("early", Some("2026-10-24")),
                inc("tied", Some("2026-10-24")),
            ],
            None,
        )
        .unwrap();
        assert_eq!(got.until, "2026-10-24");
        assert_eq!(
            got.bound_by,
            Bound::Include {
                layer: "early".into(),
                realm: "wasm".into()
            }
        );
    }

    /// An include supported for longer than the composition does not lengthen
    /// it, and a layer with no includes keeps its own window.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn the_own_window_stands_when_it_is_already_the_shortest() {
        let got = cap_by_includes("2026-11-02", &[inc("x", Some("2027-01-01"))], None).unwrap();
        assert_eq!(
            (got.until.as_str(), &got.bound_by),
            ("2026-11-02", &Bound::Own)
        );
        let alone = cap_by_includes("2026-11-02", &[], None).unwrap();
        assert_eq!(
            (alone.until.as_str(), &alone.bound_by),
            ("2026-11-02", &Bound::Own)
        );
    }

    /// The same day is not an overshoot: "through that day" on both sides.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn an_include_ending_the_same_day_is_not_a_cap() {
        let got = cap_by_includes("2026-11-02", &[inc("x", Some("2026-11-02"))], None).unwrap();
        assert_eq!(got.bound_by, Bound::Own);
    }

    /// Clause 2: an include that states no window is not skipped. Skipping it
    /// is how the cap goes vacuous — the one include nobody vouched for is
    /// exactly the one that would have bound it.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn an_include_that_states_no_window_refuses_rather_than_being_skipped() {
        let err = cap_by_includes(
            "2026-11-02",
            &[inc("a", Some("2026-12-01")), inc("b", None)],
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SupportError::IncludeStatesNoWindow {
                layer: "b".into(),
                realm: "wasm".into()
            }
        );
        assert!(err.to_string().contains("b"), "{err}");
    }

    /// A malformed include date refuses rather than comparing as text.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn an_unparseable_include_window_refuses() {
        let err = cap_by_includes("2026-11-02", &[inc("a", Some("soon"))], None).unwrap_err();
        assert!(matches!(err, SupportError::BadDate { .. }), "{err:?}");
    }

    /// Clause 3: a longer promise is possible, and it is a decision with a
    /// reason on the record — the reason is carried out so the caller can
    /// print it beside the signed date.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn exceeding_the_cap_takes_a_stated_reason() {
        let got = cap_by_includes(
            "2026-11-02",
            &[inc("2026.10.0", Some("2026-10-24"))],
            Some("wasm-layers 2026.11.0 is staged and carries the same tools"),
        )
        .unwrap();
        assert_eq!(got.until, "2026-11-02");
        assert_eq!(
            got.bound_by,
            Bound::PastIncludes {
                earliest: "2026-10-24".into(),
                reason: "wasm-layers 2026.11.0 is staged and carries the same tools".into()
            }
        );
    }

    /// An override that says nothing is not a decision.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn an_override_without_a_reason_is_refused() {
        let err =
            cap_by_includes("2026-11-02", &[inc("a", Some("2026-10-24"))], Some("  ")).unwrap_err();
        assert_eq!(err, SupportError::OverrideWithoutReason);
        assert!(!err.to_string().is_empty());
    }

    /// An override that was not needed changes nothing: it must not be
    /// recorded as though a longer promise had been made.
    // rivet: verifies REQ-COMPOSEWINDOW-001
    #[test]
    fn an_unneeded_override_is_not_recorded() {
        let got = cap_by_includes(
            "2026-11-02",
            &[inc("a", Some("2027-01-01"))],
            Some("because"),
        )
        .unwrap();
        assert_eq!(got.bound_by, Bound::Own);
    }

    mod from_source {
        use super::super::*;
        use crate::install::{ManifestVerifier, VerifyError};
        use crate::linestatus::LineStatus;
        use crate::manifest::fixtures::manifest_with_tools;
        use crate::source::MemorySource;
        use crate::store::manifest_digest;
        use crate::verify::generate_root_keypair;

        struct AcceptAll;
        impl ManifestVerifier for AcceptAll {
            fn verify(&self, fetched: &[u8]) -> Result<Vec<u8>, VerifyError> {
                Ok(fetched.to_vec())
            }
        }
        struct RejectAll;
        impl ManifestVerifier for RejectAll {
            fn verify(&self, _: &[u8]) -> Result<Vec<u8>, VerifyError> {
                Err(VerifyError("untrusted signature (test)".into()))
            }
        }

        fn wasm_layer() -> Vec<u8> {
            manifest_with_tools("2026.10.0", "rolling", 0, "2026-09-24T00:00:00Z", &[])
        }

        fn status(counter: u64, until: Option<&str>) -> LineStatus {
            LineStatus {
                min_counter: None,
                line: "2026.10".into(),
                counter,
                issued_at: "2026-09-24T00:00:00Z".into(),
                support_until: until.map(str::to_string),
                yanked: Default::default(),
                known_problems: Vec::new(),
            }
        }

        /// The include's window is read from ITS realm's signed status, and
        /// names the layer the digest turned out to be.
        // rivet: verifies REQ-COMPOSEWINDOW-001
        #[test]
        fn an_include_window_comes_from_its_own_signed_status() {
            let (sk, pk) = generate_root_keypair();
            let bytes = wasm_layer();
            let source = MemorySource::new().with_manifest(&bytes).with_line_status(
                status(1, Some("2026-10-24"))
                    .sign(&sk, "k")
                    .unwrap()
                    .as_bytes(),
            );
            let w =
                include_window(&source, &AcceptAll, &pk, &manifest_digest(&bytes), "wasm").unwrap();
            assert_eq!(
                w,
                IncludeWindow {
                    layer: "2026.10.0".into(),
                    realm: "wasm".into(),
                    support_until: Some("2026-10-24".into()),
                }
            );
        }

        /// A later correction that SHORTENS the window binds the cap — the
        /// same document install would cache.
        // rivet: verifies REQ-COMPOSEWINDOW-001
        #[test]
        fn a_published_correction_overtakes_the_baseline_window() {
            let (sk, pk) = generate_root_keypair();
            let bytes = wasm_layer();
            let source = MemorySource::new()
                .with_manifest(&bytes)
                .with_line_status(
                    status(1, Some("2026-10-24"))
                        .sign(&sk, "k")
                        .unwrap()
                        .as_bytes(),
                )
                .with_published_line_status(
                    status(5, Some("2026-10-10"))
                        .sign(&sk, "k")
                        .unwrap()
                        .as_bytes(),
                );
            let w =
                include_window(&source, &AcceptAll, &pk, &manifest_digest(&bytes), "wasm").unwrap();
            assert_eq!(w.support_until.as_deref(), Some("2026-10-10"));
        }

        /// A status signed by any other key is not that realm speaking.
        // rivet: verifies REQ-COMPOSEWINDOW-001
        #[test]
        fn a_status_not_signed_by_the_includes_realm_is_refused() {
            let (sk_other, _) = generate_root_keypair();
            let (_, pk) = generate_root_keypair();
            let bytes = wasm_layer();
            let source = MemorySource::new().with_manifest(&bytes).with_line_status(
                status(1, Some("2027-12-31"))
                    .sign(&sk_other, "k")
                    .unwrap()
                    .as_bytes(),
            );
            let err = include_window(&source, &AcceptAll, &pk, &manifest_digest(&bytes), "wasm")
                .unwrap_err();
            assert!(
                err.to_string().contains("2026.10.0") || err.to_string().contains("sha256:"),
                "{err}"
            );
        }

        /// No status at all is a window nobody stated — carried as `None`, so
        /// `cap_by_includes` refuses it (clause 2) rather than skipping it.
        // rivet: verifies REQ-COMPOSEWINDOW-001
        #[test]
        fn an_include_with_no_status_states_no_window() {
            let (_, pk) = generate_root_keypair();
            let bytes = wasm_layer();
            let source = MemorySource::new().with_manifest(&bytes);
            let w =
                include_window(&source, &AcceptAll, &pk, &manifest_digest(&bytes), "wasm").unwrap();
            assert_eq!(w.support_until, None);
            assert!(cap_by_includes("2026-11-02", &[w], None).is_err());
        }

        /// The include's manifest must verify under its realm before anything
        /// it says about itself is believed.
        // rivet: verifies REQ-COMPOSEWINDOW-001
        #[test]
        fn an_include_whose_manifest_does_not_verify_is_refused() {
            let (sk, pk) = generate_root_keypair();
            let bytes = wasm_layer();
            let source = MemorySource::new().with_manifest(&bytes).with_line_status(
                status(1, Some("2026-10-24"))
                    .sign(&sk, "k")
                    .unwrap()
                    .as_bytes(),
            );
            assert!(
                include_window(&source, &RejectAll, &pk, &manifest_digest(&bytes), "wasm").is_err()
            );
        }
    }
}
