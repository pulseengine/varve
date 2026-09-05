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
    /// `rolling` is short on purpose. It makes no qualification promise and
    /// moves continuously; a long window would imply a stability it does not
    /// have. `qualified` is where a long horizon belongs, because that is the
    /// channel an assessor is pointed at.
    pub fn for_channel(channel: &str) -> Option<Policy> {
        match channel {
            "rolling" => Some(Policy { months: 6 }),
            "qualified" => Some(Policy { months: 24 }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportError {
    UnknownChannel(String),
    BadDate { field: &'static str, value: String },
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
            "2027-03-03"
        );
        assert_eq!(
            horizon("2026-09-03T00:00:00Z", "qualified").unwrap(),
            "2028-09-03"
        );
        // A date with no time part works too.
        assert_eq!(horizon("2026-09-03", "rolling").unwrap(), "2027-03-03");
    }

    /// Adding six months to the 31st must not produce a date that does not
    /// exist. Ending a day early is correct; an unparseable horizon is not —
    /// and it would sign perfectly well, because nothing used to parse it.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn a_horizon_that_would_fall_on_a_day_that_does_not_exist_is_clamped() {
        // 31 Aug + 6 months = 28/29 Feb, not 31 Feb.
        assert_eq!(horizon("2026-08-31", "rolling").unwrap(), "2027-02-28");
        // ...and the leap year is respected.
        assert_eq!(horizon("2027-08-31", "rolling").unwrap(), "2028-02-29");
        // 31 Oct + 6 months = 30 Apr.
        assert_eq!(horizon("2026-10-31", "rolling").unwrap(), "2027-04-30");
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
        // Jan 31 + 6 = Jul 31, and July has 31 days.
        assert_eq!(horizon("2026-01-31", "rolling").unwrap(), "2026-07-31");
        // Mar 31 + 6 = Sep 30 — September does not.
        assert_eq!(horizon("2026-03-31", "rolling").unwrap(), "2026-09-30");
        // Jul 31 + 6 = Jan 31.
        assert_eq!(horizon("2026-07-31", "rolling").unwrap(), "2027-01-31");
    }

    /// The Gregorian rule has three parts and a leap check that only tested
    /// `y % 4` would get two of them wrong once a century.
    // rivet: verifies REQ-SUPPORTUNTIL-001
    #[test]
    fn february_follows_the_whole_gregorian_leap_rule() {
        // 2024: divisible by 4 -> leap.
        assert_eq!(horizon("2023-08-31", "rolling").unwrap(), "2024-02-29");
        // 2100: divisible by 100, not by 400 -> NOT leap.
        assert_eq!(horizon("2099-08-31", "rolling").unwrap(), "2100-02-28");
        // 2000: divisible by 400 -> leap.
        assert_eq!(horizon("1999-08-31", "rolling").unwrap(), "2000-02-29");
        // 2026: not divisible by 4 -> not leap.
        assert_eq!(horizon("2025-08-31", "rolling").unwrap(), "2026-02-28");
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
        assert_eq!(horizon("2026-12-15", "rolling").unwrap(), "2027-06-15");
        assert_eq!(horizon("2026-07-01", "rolling").unwrap(), "2027-01-01");
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
}
