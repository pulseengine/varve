//! Anti-rollback and staleness verdicts (REQ-ROLLBACK-001, DD-005).
//!
//! The SUIT/Uptane discipline: the client persists, per release line, the
//! highest release counter it has ever accepted — the high-water mark — and
//! hard-rejects any layer below it. Counters are scoped *per line*, so a
//! consumer frozen on 2026.07 keeps rollback protection inside that line
//! without ever being pressured toward 2026.08.
//!
//! Time is an input, never sampled here: staleness verdicts are pure
//! functions of (issued-at, now, threshold), so they are testable and the
//! trusted base stays free of clock-reading policy.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::layer::Line;
use crate::manifest::LayerManifest;

/// Outcome of the anti-rollback check for one manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackVerdict {
    /// Counter at or above the recorded mark (or first contact): acceptable.
    Accept,
    /// Counter strictly below the recorded high-water mark: rejected.
    Rollback {
        line: String,
        presented: u64,
        high_water: u64,
    },
}

/// Persisted high-water marks, one per release line, stored under the varve
/// root (NOT inside the core — the core holds evidence, this is client state).
#[derive(Debug)]
pub struct HighWaterMarks {
    path: PathBuf,
    marks: BTreeMap<String, u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "{path}: high-water-mark state is corrupt: {reason} — refusing to guess; repair or remove the file"
    )]
    Corrupt { path: String, reason: String },
}

impl HighWaterMarks {
    /// Load the marks stored under `root` (missing file = first contact).
    pub fn load(root: &Path) -> Result<Self, RollbackError> {
        let path = root.join("state").join("high-water-marks.json");
        let marks = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| RollbackError::Corrupt {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(source) => {
                return Err(RollbackError::Io {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        Ok(HighWaterMarks { path, marks })
    }

    /// The recorded mark for a line, if any.
    pub fn mark(&self, line: &Line) -> Option<u64> {
        self.marks.get(&line.to_string()).copied()
    }

    /// Check a manifest against the marks. `Accept` does NOT advance the
    /// mark — call [`Self::advance`] after the layer is fully verified and
    /// laid down, so a failed install cannot burn the mark.
    pub fn check(&self, manifest: &LayerManifest) -> RollbackVerdict {
        let line = manifest.layer.line().to_string();
        match self.marks.get(&line) {
            Some(&high_water) if manifest.counter < high_water => RollbackVerdict::Rollback {
                line,
                presented: manifest.counter,
                high_water,
            },
            _ => RollbackVerdict::Accept,
        }
    }

    /// Record acceptance of a manifest: raise the line's mark to the
    /// manifest's counter (never lowers) and persist.
    pub fn advance(&mut self, manifest: &LayerManifest) -> Result<(), RollbackError> {
        let line = manifest.layer.line().to_string();
        let mark = self.marks.entry(line).or_insert(0);
        *mark = (*mark).max(manifest.counter);
        let io = |path: &Path, source: std::io::Error| RollbackError::Io {
            path: path.display().to_string(),
            source,
        };
        let dir = self.path.parent().expect("state file has a parent");
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        let bytes = serde_json::to_vec_pretty(&self.marks).expect("marks serialize");
        std::fs::write(&self.path, bytes).map_err(|e| io(&self.path, e))?;
        Ok(())
    }
}

/// Staleness verdict: how old is the layer's issued-at relative to `now`?
/// Both are RFC 3339 strings; `threshold_days` is policy supplied by the
/// caller. Returns `Some(age_days)` when the layer is older than the
/// threshold — a warning, never a rejection: a frozen consumer's layer aging
/// is expected, staying silently ignorant of it is not.
pub fn staleness_warning(issued_at: &str, now: &str, threshold_days: u32) -> Option<i64> {
    let age = epoch_days(now)? - epoch_days(issued_at)?;
    (age > i64::from(threshold_days)).then_some(age)
}

/// Days since the civil epoch for the date part of an RFC 3339 timestamp.
/// Day resolution is deliberate: staleness policy is measured in days, so
/// sub-day precision would only manufacture spurious boundary cases.
// Public so the manifest parser can reject a malformed issued-at at parse
// time (F2, 2026-08-08 audit) — the producer and the staleness verdict must
// agree on what a valid date is, so there is one function.
pub(crate) fn epoch_days(rfc3339: &str) -> Option<i64> {
    // Require the exact YYYY-MM-DD prefix shape, not just any 10 chars.
    let date = rfc3339.get(..10)?;
    if rfc3339.len() > 10 && !rfc3339[10..].starts_with('T') {
        return None;
    }
    let mut parts = date.split('-');
    let (yy, mm, dd) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || yy.len() != 4 || mm.len() != 2 || dd.len() != 2 {
        return None;
    }
    let y: i64 = yy.parse().ok()?;
    let m: i64 = mm.parse().ok()?;
    let d: i64 = dd.parse().ok()?;
    if !(1..=12).contains(&m) {
        return None;
    }
    // Real days-per-month incl. the Gregorian leap rule — Feb 31 is not a
    // date (the old 1..=31 check let impossible days through).
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > dim[(m - 1) as usize] {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{LayerManifest, fixtures};

    fn manifest(layer: &str, counter: u64) -> LayerManifest {
        LayerManifest::parse(&fixtures::manifest(
            layer,
            "qualified",
            counter,
            "2026-07-31T09:14:00Z",
        ))
        .unwrap()
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn first_contact_accepts_and_advance_records_the_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        let m = manifest("2026.07.0", 3);
        assert_eq!(hwm.check(&m), RollbackVerdict::Accept);
        assert_eq!(hwm.mark(m.layer.line()), None, "check must not advance");
        hwm.advance(&m).unwrap();
        assert_eq!(hwm.mark(m.layer.line()), Some(3));
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn a_counter_below_the_mark_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        hwm.advance(&manifest("2026.07.1", 4)).unwrap();
        let verdict = hwm.check(&manifest("2026.07.0", 3));
        assert_eq!(
            verdict,
            RollbackVerdict::Rollback {
                line: "2026.07".into(),
                presented: 3,
                high_water: 4
            }
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn an_equal_counter_reinstalls_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        hwm.advance(&manifest("2026.07.0", 3)).unwrap();
        assert_eq!(
            hwm.check(&manifest("2026.07.0", 3)),
            RollbackVerdict::Accept
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn counters_are_scoped_per_line() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        hwm.advance(&manifest("2026.08.0", 9)).unwrap();
        // The August line's mark must not embargo the July line: wohl stays
        // frozen on July without being pressured forward.
        assert_eq!(
            hwm.check(&manifest("2026.07.0", 1)),
            RollbackVerdict::Accept
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn marks_survive_a_new_session() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
            hwm.advance(&manifest("2026.07.1", 5)).unwrap();
        }
        let hwm = HighWaterMarks::load(tmp.path()).unwrap();
        assert_eq!(
            hwm.check(&manifest("2026.07.0", 2)),
            RollbackVerdict::Rollback {
                line: "2026.07".into(),
                presented: 2,
                high_water: 5
            }
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn advance_never_lowers_a_mark() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hwm = HighWaterMarks::load(tmp.path()).unwrap();
        hwm.advance(&manifest("2026.07.1", 5)).unwrap();
        hwm.advance(&manifest("2026.07.0", 2)).unwrap();
        assert_eq!(hwm.mark(manifest("2026.07.0", 2).layer.line()), Some(5));
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn corrupt_state_is_an_error_not_a_reset() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("high-water-marks.json"), b"{ nope").unwrap();
        // A silent reset would reopen the rollback window; refuse instead.
        assert!(matches!(
            HighWaterMarks::load(tmp.path()),
            Err(RollbackError::Corrupt { .. })
        ));
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn epoch_day_arithmetic_matches_the_civil_calendar() {
        // ABSOLUTE anchors (differences would let constant-offset mutants
        // cancel), computed independently: epoch, leap days, century rules,
        // and year 0000 — the one reachable negative-era branch. Kills the
        // arithmetic mutants in the Hinnant algorithm.
        for (ts, days) in [
            ("1970-01-01T00:00:00Z", 0i64),
            ("1970-01-02T00:00:00Z", 1),
            ("1969-12-31T00:00:00Z", -1),
            ("2000-02-29T00:00:00Z", 11016),
            ("2026-08-07T00:00:00Z", 20672),
            ("2026-03-01T00:00:00Z", 20513),
            ("2024-02-29T00:00:00Z", 19782),
            ("2100-01-01T00:00:00Z", 47482),
            ("1900-03-01T00:00:00Z", -25508),
            ("2026-12-31T00:00:00Z", 20818),
            ("0000-03-01T00:00:00Z", -719468),
            ("0000-01-01T00:00:00Z", -719528),
            ("0000-02-29T00:00:00Z", -719469),
        ] {
            assert_eq!(epoch_days(ts), Some(days), "epoch_days({ts})");
        }
        // Out-of-range calendar fields are None, not a number.
        for bad in [
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-00T00:00:00Z",
        ] {
            assert_eq!(epoch_days(bad), None, "{bad}");
        }
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn staleness_threshold_boundary_is_strictly_greater_than() {
        // Exactly at the threshold: quiet. One past: warn.
        assert_eq!(
            staleness_warning("2026-07-01T00:00:00Z", "2026-07-31T00:00:00Z", 30),
            None
        );
        assert_eq!(
            staleness_warning("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z", 30),
            Some(31)
        );
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn an_unreadable_state_file_is_an_io_error_not_first_contact() {
        // A directory where the state file should be: reading errors with
        // something other than NotFound — must surface, never silently
        // reset the marks (that would reopen the rollback window).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("state/high-water-marks.json")).unwrap();
        assert!(matches!(
            HighWaterMarks::load(tmp.path()),
            Err(RollbackError::Io { .. })
        ));
    }

    // rivet: verifies REQ-ROLLBACK-001
    #[test]
    fn staleness_is_a_pure_function_of_issued_at_now_and_threshold() {
        // 100 days old, threshold 90: warn with the age.
        assert_eq!(
            staleness_warning("2026-04-01T00:00:00Z", "2026-07-10T00:00:00Z", 90),
            Some(100)
        );
        // 10 days old, threshold 90: quiet.
        assert_eq!(
            staleness_warning("2026-06-30T00:00:00Z", "2026-07-10T00:00:00Z", 90),
            None
        );
        // Unparseable issued-at: warn conservatively? No — the manifest
        // parser already rejected it; here both inputs are trusted RFC 3339.
        // Clock skew (issued-at in the future) is quiet, not negative-aged.
        assert_eq!(
            staleness_warning("2026-08-01T00:00:00Z", "2026-07-10T00:00:00Z", 90),
            None
        );
    }
}
