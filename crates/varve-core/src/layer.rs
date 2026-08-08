//! Layer identifiers — `YYYY.MM.P`, three-part from day one (DD-004).
//!
//! `2026.07.0` is the initial deposit of the July 2026 line; `2026.07.1` is a
//! patch *inside* that frozen line. A two-part identifier is rejected outright:
//! the grammar freezes with manifest-version 1, and an identifier that could
//! mean "the line" or "a layer in it" is exactly the resolution ambiguity a
//! qualified pin must not have.

use std::fmt;
use std::str::FromStr;

/// A release line: the `YYYY.MM` a consumer freezes on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Line {
    year: u16,
    month: u8,
}

impl Line {
    pub fn year(&self) -> u16 {
        self.year
    }
    pub fn month(&self) -> u8 {
        self.month
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}.{:02}", self.year, self.month)
    }
}

/// A layer identifier: one dated, immutable deposit — `YYYY.MM.P`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayerId {
    line: Line,
    patch: u16,
}

impl LayerId {
    /// The frozen line this layer belongs to.
    pub fn line(&self) -> &Line {
        &self.line
    }
    pub fn patch(&self) -> u16 {
        self.patch
    }
}

impl FromStr for LayerId {
    type Err = LayerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || LayerIdError::Malformed(s.to_string());
        let parts: Vec<&str> = s.split('.').collect();
        match parts.as_slice() {
            [year, month] => {
                // Recognisably YYYY.MM: reject with the corrective three-part
                // guidance rather than the generic malformed error.
                if is_digits(year, 4) && is_digits(month, 2) {
                    Err(LayerIdError::MissingPatch(s.to_string()))
                } else {
                    Err(malformed())
                }
            }
            [year, month, patch] => {
                if !(is_digits(year, 4) && is_digits(month, 2)) || patch.is_empty() {
                    return Err(malformed());
                }
                let year: u16 = year.parse().map_err(|_| malformed())?;
                let month: u8 = month.parse().map_err(|_| malformed())?;
                // Patch is a plain number, no fixed width — but no signs,
                // whitespace, or leading emptiness.
                if !patch.chars().all(|c| c.is_ascii_digit()) {
                    return Err(malformed());
                }
                let patch: u16 = patch.parse().map_err(|_| malformed())?;
                if !(1..=12).contains(&month) {
                    return Err(LayerIdError::MonthOutOfRange(s.to_string()));
                }
                Ok(LayerId {
                    line: Line { year, month },
                    patch,
                })
            }
            _ => Err(malformed()),
        }
    }
}

fn is_digits(s: &str, width: usize) -> bool {
    s.len() == width && s.chars().all(|c| c.is_ascii_digit())
}

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.line, self.patch)
    }
}

/// Why a layer identifier failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerIdError {
    /// Two-part `YYYY.MM` — the pre-DD-004 shape, rejected with guidance.
    MissingPatch(String),
    /// Anything else that is not `YYYY.MM.P`.
    Malformed(String),
    /// Parsed, but the month is outside 01..=12.
    MonthOutOfRange(String),
}

impl fmt::Display for LayerIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerIdError::MissingPatch(s) => write!(
                f,
                "layer '{s}' is missing its patch component: layer identifiers \
                 are three-part (YYYY.MM.P) — the initial deposit of a line is \
                 '{s}.0'"
            ),
            LayerIdError::Malformed(s) => {
                write!(f, "layer '{s}' is not a valid YYYY.MM.P identifier")
            }
            LayerIdError::MonthOutOfRange(s) => {
                write!(f, "layer '{s}' has a month outside 01..=12")
            }
        }
    }
}

impl std::error::Error for LayerIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn parses_three_part_identifier_into_line_and_patch() {
        let id: LayerId = "2026.07.0".parse().unwrap();
        assert_eq!(id.line().year(), 2026);
        assert_eq!(id.line().month(), 7);
        assert_eq!(id.patch(), 0);
        assert_eq!(id.line().to_string(), "2026.07");
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn patch_stays_inside_the_frozen_line() {
        let base: LayerId = "2026.07.0".parse().unwrap();
        let patch: LayerId = "2026.07.1".parse().unwrap();
        assert_eq!(base.line(), patch.line());
        assert!(patch > base, "a patch orders after its baseline");
        let august: LayerId = "2026.08.0".parse().unwrap();
        assert_ne!(patch.line(), august.line());
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn rejects_two_part_identifier_with_corrective_guidance() {
        let err = "2026.07".parse::<LayerId>().unwrap_err();
        assert_eq!(err, LayerIdError::MissingPatch("2026.07".into()));
        let msg = err.to_string();
        assert!(
            msg.contains("three-part"),
            "message must teach the grammar: {msg}"
        );
        assert!(
            msg.contains("2026.07.0"),
            "message must show the fix: {msg}"
        );
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn patch_numbers_parse_to_their_value() {
        assert_eq!("2026.07.1".parse::<LayerId>().unwrap().patch(), 1);
        assert_eq!("2026.07.42".parse::<LayerId>().unwrap().patch(), 42);
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn two_part_guidance_requires_both_fields_well_formed() {
        // Only a well-formed YYYY.MM earns the corrective MissingPatch
        // guidance; a malformed two-parter is just malformed.
        for bad in ["26.07", "2026.7", "abcd.07", "2026.xx"] {
            assert_eq!(
                bad.parse::<LayerId>().unwrap_err(),
                LayerIdError::Malformed(bad.into()),
                "input: {bad:?}"
            );
        }
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn rejects_malformed_identifiers() {
        for bad in [
            "",
            "abc",
            "2026",
            "2026.7.0",
            "2026.007.0",
            "26.07.0",
            "2026.07.0.1",
            "2026.07.x",
        ] {
            let err = bad.parse::<LayerId>().unwrap_err();
            assert_eq!(err, LayerIdError::Malformed(bad.into()), "input: {bad:?}");
        }
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn rejects_month_outside_calendar_range() {
        for bad in ["2026.00.0", "2026.13.0"] {
            let err = bad.parse::<LayerId>().unwrap_err();
            assert_eq!(
                err,
                LayerIdError::MonthOutOfRange(bad.into()),
                "input: {bad:?}"
            );
        }
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn display_round_trips_canonically() {
        for s in ["2026.07.0", "2026.07.1", "2026.12.10"] {
            let id: LayerId = s.parse().unwrap();
            assert_eq!(id.to_string(), s);
        }
    }
}
