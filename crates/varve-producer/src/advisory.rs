//! Advisory watching, pure core (REQ-ADVISORYWATCH-001).
//!
//! Two sources, one question: given a package and the exact dotted version
//! a layer carries, is there a published advisory that affects it? This
//! module parses both sources' native shapes — GitHub repository security
//! advisories (`gh api .../security-advisories`) and a RustSec
//! `RUSTSEC-YYYY-NNNN.md` file — and answers that question by exact numeric
//! version-range matching. No network, no CLI, no orchestration: those are
//! the caller's job. This module cannot reach them and must not grow the
//! ability.
//!
//! # Why "cannot decide" is not "not affected"
//!
//! A version carrying a PRE-RELEASE suffix (`1.2.3-rc.1`) does not have a
//! defined position in a numeric range: is `1.2.3-rc.1` before or after
//! `1.2.3`? Semver says before, but these advisory ranges are not semver —
//! they are ad hoc dotted-numeric windows, and silently answering "not
//! affected" for a version this module cannot place would be worse than
//! refusing, because it looks exactly like a real clearance. `Version::parse`
//! returns an error instead, and every caller in this module propagates it
//! rather than swallowing it into `false`.
//!
//! BUILD metadata (`1.2.3+x`, or real upstream SBOMs' `1.1.3+spec-1.1.0`,
//! `0.14.7+wasi-0.2.4`) is different: semver 2.0 clause 10 says it is
//! IGNORED for precedence, so `Version::parse` strips a `+…` suffix and
//! parses what is left — refusing it would abort every run against the
//! three most common real SBOM shapes measured, for text this comparator
//! never needed to read in the first place.
//!
//! The same rule governs an unparseable range or requirement string: it is
//! an `Err`, never an implicit "not affected" (REQ-ADVISORYWATCH-001 clause
//! 5; the covalent scanner's #16/#17 lesson, clause 4).

use serde::Deserialize;

// ---------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------

/// A dotted numeric version, `MAJOR.MINOR.PATCH`.
///
/// `MAJOR.MINOR` and `MAJOR` parse too, padded with zeros, and a leading
/// `v` is tolerated. A pre-release or build suffix is refused rather than
/// silently ignored — see the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self, AdvisoryError> {
        let trimmed = s.trim();
        let body = trimmed.strip_prefix('v').unwrap_or(trimmed);
        if body.is_empty() {
            return Err(AdvisoryError::BadVersion(s.to_string()));
        }
        // Build metadata is IGNORED for version PRECEDENCE (semver 2.0
        // clause 10), so it is split off FIRST — before the pre-release
        // check below. Order matters: build metadata may itself legally
        // contain a '-' (measured in real upstream SBOMs — wasi's own
        // "0.14.7+wasi-0.2.4"), and checking for a pre-release hyphen
        // before stripping the metadata would misread that hyphen as this
        // version's own.
        let body = match body.split_once('+') {
            Some((before, _build_metadata)) => before,
            None => body,
        };
        if body.is_empty() {
            return Err(AdvisoryError::BadVersion(s.to_string()));
        }
        if body.contains('-') {
            return Err(AdvisoryError::PreReleaseVersion(s.to_string()));
        }
        parse_numeric_core(body, s)
    }
}

/// `MAJOR[.MINOR[.PATCH]]`, zero-padded — the part every dotted version
/// string (a queried version, or a comparator bound) bottoms out in once
/// any `v` prefix, build metadata and pre-release suffix are stripped.
fn parse_numeric_core(body: &str, original: &str) -> Result<Version, AdvisoryError> {
    let parts: Vec<&str> = body.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(AdvisoryError::BadVersion(original.to_string()));
    }
    let mut nums = [0u64; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(AdvisoryError::BadVersion(original.to_string()));
        }
        nums[i] = part
            .parse::<u64>()
            .map_err(|_| AdvisoryError::BadVersion(original.to_string()))?;
    }
    Ok(Version {
        major: nums[0],
        minor: nums[1],
        patch: nums[2],
    })
}

/// Parses a COMPARATOR BOUND — one side of `>=`, `<`, `^`, … — into its
/// numeric core and whether it carried a pre-release suffix.
///
/// Unlike [`Version::parse`], this does NOT refuse a pre-release: a bound
/// is not a release anyone ships, it is a FENCE post, and a fence post with
/// a pre-release suffix still decides something about every real (and
/// therefore pre-release-free) release version — see
/// [`Constraint::matches`] and the GHSA interval builders below, which read
/// the bool this returns to pick the collapsed comparison
/// REQ-ADVISORYWATCH-001's pre-release-bounds rule defines. Build metadata
/// on a bound is ignored exactly as on a version.
fn parse_bound(s: &str) -> Result<(Version, bool), AdvisoryError> {
    let trimmed = s.trim();
    let body = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if body.is_empty() {
        return Err(AdvisoryError::BadVersion(s.to_string()));
    }
    let body = match body.split_once('+') {
        Some((before, _build_metadata)) => before,
        None => body,
    };
    if body.is_empty() {
        return Err(AdvisoryError::BadVersion(s.to_string()));
    }
    let (numeric, has_prerelease) = match body.split_once('-') {
        Some((before, pre)) => (before, !pre.is_empty()),
        None => (body, false),
    };
    if numeric.is_empty() {
        return Err(AdvisoryError::BadVersion(s.to_string()));
    }
    let version = parse_numeric_core(numeric, s)?;
    Ok((version, has_prerelease))
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdvisoryError {
    #[error("{0:?} is not a MAJOR[.MINOR[.PATCH]] version this comparator can decide")]
    BadVersion(String),
    #[error(
        "{0:?} carries a pre-release or build suffix; a numeric comparison cannot decide \
         whether it is affected, so this must be reported as undecidable, not clear"
    )]
    PreReleaseVersion(String),
    #[error("{0:?} is not a vulnerable_version_range this parser can decide")]
    BadGhsaRange(String),
    #[error("{0:?} is not a version requirement this parser can decide")]
    BadRequirement(String),
    #[error("GHSA advisory JSON is malformed: {0}")]
    MalformedGhsaJson(String),
    #[error("RustSec advisory markdown has no ```toml fence")]
    NoTomlFence,
    #[error("RustSec advisory TOML is malformed: {0}")]
    MalformedRustSecToml(String),
}

// ---------------------------------------------------------------------
// Constraints shared by both sources
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
    /// RustSec caret: same leftmost non-zero component, `>=` the given
    /// version. Never valid in a GHSA `vulnerable_version_range`.
    Caret,
}

#[derive(Debug, Clone)]
struct Constraint {
    op: Op,
    version: Version,
    /// Did the comparator's BOUND itself carry a pre-release suffix? The
    /// queried version never does — an SBOM component with a pre-release
    /// version is turned into an undecidable entry before it ever reaches
    /// here (REQ-ADVISORYWATCH-001's pre-release-bounds rule) — so this
    /// alone decides which of the two comparison tables `matches` reads.
    bound_has_prerelease: bool,
}

impl Constraint {
    /// REQ-ADVISORYWATCH-001's pre-release-bounds rule: for a version `v`
    /// WITHOUT a pre-release and a bound `X-pre` (pre non-empty), no real
    /// release lies in `[X-pre, X)` — nothing between a pre-release of X
    /// and X itself is ever published — so every comparator against a
    /// pre-release bound collapses to a plain comparison against `X`:
    /// `< X-pre` and `<= X-pre` both become `< X`; `> X-pre` and `>= X-pre`
    /// both become `>= X`; `= X-pre` matches nothing (a pre-release is
    /// never equal to any real release); `^X-pre` becomes `>= X` capped by
    /// `X`'s own caret upper bound. A bound with NO pre-release keeps the
    /// ordinary table, unchanged.
    fn matches(&self, v: &Version) -> bool {
        if self.bound_has_prerelease {
            return match self.op {
                Op::Lt | Op::Le => *v < self.version,
                Op::Ge | Op::Gt => *v >= self.version,
                Op::Eq => false,
                Op::Caret => *v >= self.version && *v < caret_upper_bound(&self.version),
            };
        }
        match self.op {
            Op::Ge => *v >= self.version,
            Op::Gt => *v > self.version,
            Op::Le => *v <= self.version,
            Op::Lt => *v < self.version,
            Op::Eq => *v == self.version,
            Op::Caret => {
                if *v < self.version {
                    return false;
                }
                *v < caret_upper_bound(&self.version)
            }
        }
    }
}

/// The exclusive upper bound of `^version`: bump the leftmost non-zero
/// component and zero everything to its right.
fn caret_upper_bound(v: &Version) -> Version {
    if v.major != 0 {
        Version {
            major: v.major + 1,
            minor: 0,
            patch: 0,
        }
    } else if v.minor != 0 {
        Version {
            major: 0,
            minor: v.minor + 1,
            patch: 0,
        }
    } else {
        Version {
            major: 0,
            minor: 0,
            patch: v.patch + 1,
        }
    }
}

/// Splits a single constraint token into its operator and the version text
/// that follows it. A token with no recognised operator is a bare version,
/// which is an exact match.
fn split_operator(tok: &str) -> (Op, &str) {
    if let Some(r) = tok.strip_prefix(">=") {
        (Op::Ge, r.trim())
    } else if let Some(r) = tok.strip_prefix("<=") {
        (Op::Le, r.trim())
    } else if let Some(r) = tok.strip_prefix('^') {
        (Op::Caret, r.trim())
    } else if let Some(r) = tok.strip_prefix('>') {
        (Op::Gt, r.trim())
    } else if let Some(r) = tok.strip_prefix('<') {
        (Op::Lt, r.trim())
    } else if let Some(r) = tok.strip_prefix('=') {
        (Op::Eq, r.trim())
    } else {
        (Op::Eq, tok)
    }
}

// ---------------------------------------------------------------------
// GHSA `vulnerable_version_range`: a union of intervals
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Bound {
    Inclusive(Version),
    Exclusive(Version),
}

#[derive(Debug, Clone)]
struct Interval {
    low: Option<Bound>,
    high: Option<Bound>,
}

impl Interval {
    fn contains(&self, v: &Version) -> bool {
        let low_ok = match &self.low {
            None => true,
            Some(Bound::Inclusive(b)) => *v >= *b,
            Some(Bound::Exclusive(b)) => *v > *b,
        };
        let high_ok = match &self.high {
            None => true,
            Some(Bound::Inclusive(b)) => *v <= *b,
            Some(Bound::Exclusive(b)) => *v < *b,
        };
        low_ok && high_ok
    }
}

/// Splits a GHSA `vulnerable_version_range` into its ordered
/// `(Op, Version, bound_has_prerelease)` constraints, tolerating the shapes
/// measured live on bytecodealliance/wasmtime: ONE trailing comma
/// (`"…, <= 43.0.1, 44.0.0,"`), `&&` used as a separator in place of `,`
/// (`">= 0.26.0 && <= 0.29.0"`), and a final list item spelled out in
/// English (`"0.34.0, 0.34.1, 0.35.0, and 0.35.1"` — a leading `and ` on a
/// token is stripped before that token is read). Any other empty segment
/// is still refused.
fn tokenize_ghsa_range(s: &str) -> Result<Vec<(Op, Version, bool)>, AdvisoryError> {
    let body = s.trim_end();
    let body = body.strip_suffix(',').unwrap_or(body);
    let body = body.replace("&&", ",");
    let mut tokens = Vec::new();
    for raw in body.split(',') {
        let tok = raw.trim();
        let tok = tok.strip_prefix("and ").map(str::trim).unwrap_or(tok);
        if tok.is_empty() {
            return Err(AdvisoryError::BadGhsaRange(s.to_string()));
        }
        let (op, version_str) = split_operator(tok);
        let (version, bound_has_prerelease) =
            parse_bound(version_str).map_err(|_| AdvisoryError::BadGhsaRange(s.to_string()))?;
        tokens.push((op, version, bound_has_prerelease));
    }
    Ok(tokens)
}

/// The LOW bound `>=`/`>` contributes to an interval, pre-release-aware:
/// `>= X-pre` is already `Inclusive(X)` by the ordinary table, and `> X-pre`
/// collapses from `Exclusive(X)` to `Inclusive(X)` too — there is no real
/// release strictly between a pre-release of X and X itself.
fn low_bound(op: Op, version: Version, has_prerelease: bool) -> Bound {
    match op {
        Op::Ge => Bound::Inclusive(version),
        Op::Gt if has_prerelease => Bound::Inclusive(version),
        Op::Gt => Bound::Exclusive(version),
        _ => unreachable!("low_bound is only called for Ge/Gt"),
    }
}

/// The HIGH bound `<=`/`<` contributes to an interval, pre-release-aware:
/// `< X-pre` is already `Exclusive(X)`, and `<= X-pre` collapses from
/// `Inclusive(X)` to `Exclusive(X)` — same reasoning as `low_bound`.
fn high_bound(op: Op, version: Version, has_prerelease: bool) -> Bound {
    match op {
        Op::Lt => Bound::Exclusive(version),
        Op::Le if has_prerelease => Bound::Exclusive(version),
        Op::Le => Bound::Inclusive(version),
        _ => unreachable!("high_bound is only called for Le/Lt"),
    }
}

/// Parses a GHSA `vulnerable_version_range` into a union of intervals.
///
/// Walks the constraints in order: a lower bound (`>=`, `>`) opens an
/// interval; the next upper bound (`<=`, `<`) closes it. A bare version or
/// `=`-prefixed one is its own exact-match interval. A lower bound left
/// open at the end of the list is an interval to infinity.
///
/// An upper bound with no open lower bound is normally an interval from
/// zero — UNLESS it is immediately followed by a lower bound whose value is
/// `<=` that upper bound, in which case the two form ONE interval
/// `[lower, upper]` instead. Measured live on bytecodealliance/wasmtime:
/// `"<= 6.0.0, >= 1.0.0"` is the single interval `[1.0.0, 6.0.0]`, not the
/// union `[0, 6.0.0] ∪ [1.0.0, ∞)` a naive zero-then-open reading would
/// produce — the latter silently affects every version from 1.0.0 up,
/// including releases decades newer than the advisory.
fn parse_ghsa_range(s: &str) -> Result<Vec<Interval>, AdvisoryError> {
    let tokens = tokenize_ghsa_range(s)?;
    let mut intervals = Vec::new();
    let mut pending_low: Option<Bound> = None;
    // A `Peekable` iterator, not a hand-kept index: advancing is always
    // `next()`, which is guaranteed to terminate, so there is no index
    // arithmetic here for a mutation to turn into an infinite loop.
    let mut iter = tokens.into_iter().peekable();
    while let Some((op, version, has_prerelease)) = iter.next() {
        match op {
            Op::Ge | Op::Gt => pending_low = Some(low_bound(op, version, has_prerelease)),
            Op::Le | Op::Lt => {
                let high = high_bound(op, version, has_prerelease);
                if pending_low.is_none()
                    && let Some(&(next_op, next_version, next_has_prerelease)) = iter.peek()
                    && matches!(next_op, Op::Ge | Op::Gt)
                    && next_version <= version
                {
                    let low = low_bound(next_op, next_version, next_has_prerelease);
                    iter.next(); // consume the paired lower bound
                    intervals.push(Interval {
                        low: Some(low),
                        high: Some(high),
                    });
                    continue;
                }
                let low = pending_low.take();
                intervals.push(Interval {
                    low,
                    high: Some(high),
                });
            }
            // `= X-pre` matches no real release (REQ-ADVISORYWATCH-001's
            // pre-release-bounds rule) — represented as the interval
            // `(X, X)`, exclusive on both ends, which by construction no
            // version can ever satisfy, rather than inventing a variant
            // `Interval::contains` would need a third branch for.
            Op::Eq if has_prerelease => intervals.push(Interval {
                low: Some(Bound::Exclusive(version)),
                high: Some(Bound::Exclusive(version)),
            }),
            Op::Eq => intervals.push(Interval {
                low: Some(Bound::Inclusive(version)),
                high: Some(Bound::Inclusive(version)),
            }),
            Op::Caret => return Err(AdvisoryError::BadGhsaRange(s.to_string())),
        }
    }
    if let Some(low) = pending_low {
        intervals.push(Interval {
            low: Some(low),
            high: None,
        });
    }
    Ok(intervals)
}

fn range_affects(intervals: &[Interval], v: &Version) -> bool {
    intervals.iter().any(|iv| iv.contains(v))
}

// ---------------------------------------------------------------------
// RustSec requirement strings: an AND of constraints
// ---------------------------------------------------------------------

/// Parses one RustSec requirement string (`">= 37.0.3, < 38.0.0"`) into the
/// AND of its constraints.
fn parse_requirement(s: &str) -> Result<Vec<Constraint>, AdvisoryError> {
    let mut constraints = Vec::new();
    for raw in s.split(',') {
        let tok = raw.trim();
        if tok.is_empty() {
            return Err(AdvisoryError::BadRequirement(s.to_string()));
        }
        let (op, version_str) = split_operator(tok);
        let (version, bound_has_prerelease) =
            parse_bound(version_str).map_err(|_| AdvisoryError::BadRequirement(s.to_string()))?;
        constraints.push(Constraint {
            op,
            version,
            bound_has_prerelease,
        });
    }
    Ok(constraints)
}

fn requirement_matches(constraints: &[Constraint], v: &Version) -> bool {
    constraints.iter().all(|c| c.matches(v))
}

fn any_requirement_matches(reqs: &[Vec<Constraint>], v: &Version) -> bool {
    reqs.iter().any(|cs| requirement_matches(cs, v))
}

// ---------------------------------------------------------------------
// GHSA JSON shape
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GhsaAdvisory {
    ghsa_id: String,
    #[serde(default)]
    cve_id: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<GhsaVulnerability>,
}

#[derive(Debug, Deserialize)]
struct GhsaVulnerability {
    package: GhsaPackage,
    vulnerable_version_range: String,
    #[serde(default)]
    patched_versions: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhsaPackage {
    name: String,
}

// ---------------------------------------------------------------------
// RustSec TOML shape
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RustSecDoc {
    advisory: RustSecAdvisoryMeta,
    #[serde(default)]
    versions: RustSecVersions,
}

#[derive(Debug, Deserialize)]
struct RustSecAdvisoryMeta {
    id: String,
    package: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    /// `"unmaintained"`, `"notice"` or `"unsound"` — RustSec's own
    /// classification of what KIND of advisory this is, not a numeric
    /// severity. `"unmaintained"`/`"notice"` are not vulnerabilities;
    /// `"unsound"` IS (a memory-safety defect), and anything absent is a
    /// vulnerability as always. See [`rustsec_outcome`].
    #[serde(default)]
    informational: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RustSecVersions {
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

// ---------------------------------------------------------------------
// One common view
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: Option<String>,
    pub summary: String,
    pub package: String,
    pub patched: Vec<String>,
    pub url: Option<String>,
}

/// Why a GHSA advisory could not be turned into a `Finding` for the queried
/// package and version, even though it was not simply "not affected".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndecidableReason {
    /// `vulnerable_version_range` itself did not parse.
    RangeCouldNotBeRead,
    /// The range says the version is affected, but `patched_versions`
    /// names a later release than the queried version — the advisory
    /// contradicts its own patched list, and a person must resolve which
    /// one is stale (measured on bytecodealliance/wasmtime
    /// GHSA-vc8c-j3xm-xj73: range `">= 29.0.0"`, `patched_versions`
    /// `"36.0.5, 40.0.3, 41.0.1"` — the range alone would call every
    /// release after 29.0.0 affected forever).
    RangeAndPatchedVersionsDisagree,
}

/// A GHSA advisory whose verdict for the queried package and version this
/// module could not decide. NOT a finding and NOT a clearance: the caller
/// must surface it to a person rather than silently treat it as "not
/// affected" (REQ-ADVISORYWATCH-001 clause 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undecidable {
    pub id: String,
    pub package: String,
    pub range: String,
    pub reason: UndecidableReason,
}

/// The result of [`ghsa_findings`]: every advisory that affects the queried
/// version, plus every advisory this module could not read for that
/// package — a disjoint split, since each matching vulnerability lands in
/// exactly one of the two lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GhsaResult {
    pub findings: Vec<Finding>,
    pub undecidable: Vec<Undecidable>,
}

fn split_patched_versions(raw: &Option<String>) -> Vec<String> {
    raw.as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The highest *parseable* entry of `patched_versions`, ignoring any entry
/// that is not a plain dotted version. `None` if there are no parseable
/// entries at all (an empty or entirely-unparseable list keeps the range's
/// own verdict — see [`ghsa_findings`]).
fn highest_patched_version(raw: &Option<String>) -> Option<Version> {
    split_patched_versions(raw)
        .iter()
        .filter_map(|s| Version::parse(s).ok())
        .max()
}

/// Every advisory in `json` (a `gh api .../security-advisories` response)
/// with a vulnerability whose `package.name == package` and whose range
/// affects `version`, plus every advisory for that package this module
/// could not decide.
///
/// A source that cannot be READ — malformed JSON — is still a hard `Err`
/// (REQ-ADVISORYWATCH-001 clause 4: the covalent scanner's #16/#17 lesson).
/// Two narrower cases are not a hard error, because failing the WHOLE query
/// over one bad advisory would silence every other advisory for the package
/// on every run — each goes to `undecidable` instead, never folded into
/// `findings` and never dropped:
///
/// * the range itself does not parse (measured on
///   bytecodealliance/wasmtime: `"<= 0.34.0 (excluding 0.33.1)"`);
/// * the range says the version is affected, but `patched_versions` names a
///   release at or before the queried version (measured on
///   bytecodealliance/wasmtime GHSA-vc8c-j3xm-xj73: range `">= 29.0.0"`
///   against `patched_versions` `"36.0.5, 40.0.3, 41.0.1"` would otherwise
///   call every release after 29.0.0 affected forever). An empty or
///   entirely-unparseable `patched_versions` cannot contradict anything, so
///   the range's own verdict stands.
pub fn ghsa_findings(
    json: &str,
    package: &str,
    version: &Version,
) -> Result<GhsaResult, AdvisoryError> {
    let advisories: Vec<GhsaAdvisory> =
        serde_json::from_str(json).map_err(|e| AdvisoryError::MalformedGhsaJson(e.to_string()))?;
    let mut result = GhsaResult::default();
    for advisory in &advisories {
        for vuln in &advisory.vulnerabilities {
            if vuln.package.name != package {
                continue;
            }
            let intervals = match parse_ghsa_range(&vuln.vulnerable_version_range) {
                Ok(intervals) => intervals,
                Err(_) => {
                    result.undecidable.push(Undecidable {
                        id: advisory.ghsa_id.clone(),
                        package: package.to_string(),
                        range: vuln.vulnerable_version_range.clone(),
                        reason: UndecidableReason::RangeCouldNotBeRead,
                    });
                    continue;
                }
            };
            if !range_affects(&intervals, version) {
                continue;
            }
            if let Some(highest) = highest_patched_version(&vuln.patched_versions)
                && *version >= highest
            {
                result.undecidable.push(Undecidable {
                    id: advisory.ghsa_id.clone(),
                    package: package.to_string(),
                    range: vuln.vulnerable_version_range.clone(),
                    reason: UndecidableReason::RangeAndPatchedVersionsDisagree,
                });
                continue;
            }
            result.findings.push(Finding {
                id: advisory.ghsa_id.clone(),
                aliases: advisory.cve_id.clone().into_iter().collect(),
                severity: advisory.severity.clone(),
                summary: advisory.summary.clone(),
                package: package.to_string(),
                patched: split_patched_versions(&vuln.patched_versions),
                url: advisory.html_url.clone(),
            });
        }
    }
    Ok(result)
}

/// A RustSec advisory whose `patched`/`unaffected` requirements this module
/// could not parse, for the queried package — NOT a finding and NOT a
/// clearance, the RustSec-side analogue of [`Undecidable`] (a GHSA advisory
/// whose range could not be read). Carries the advisory's own id, since the
/// caller (a report, a line-status draft) needs to name WHICH advisory
/// could not be decided, not merely that one could not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSecUndecidable {
    pub id: String,
    pub package: String,
    pub requirement: String,
    pub reason: String,
}

/// A RustSec `informational` advisory the queried version is "affected"
/// by in the sense that its `patched`/`unaffected` lists don't clear it —
/// but `informational = "unmaintained"` or `"notice"` means this is NOT a
/// vulnerability at all, just a fact worth saying (REQ-ADVISORYWATCH-001's
/// informational-advisories rule). `kind` carries the raw RustSec word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSecInformational {
    pub id: String,
    pub package: String,
    pub kind: String,
    pub title: String,
}

/// What [`rustsec_outcome`] decided about one RustSec advisory, for one
/// queried package and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustSecOutcome {
    /// The queried version is affected by a genuine vulnerability — no
    /// `informational` field, or `informational = "unsound"` (a
    /// memory-safety defect, which stays a real vulnerability).
    Affected(Finding),
    /// The advisory does not name this package, or the queried version is
    /// patched or already unaffected.
    NotAffected,
    /// The queried version is named by an `informational = "unmaintained"`
    /// or `"notice"` advisory — not a vulnerability, never a KnownProblem,
    /// but never silently dropped either.
    Informational(RustSecInformational),
    /// This advisory's `patched`/`unaffected` requirements could not be
    /// parsed. Never silently "not affected" — REQ-ADVISORYWATCH-001
    /// clause 4's rule, extended to RustSec requirements the way clause 4a
    /// already covers a GHSA range: one unreadable advisory must not
    /// abort a run that is also looking at every other advisory and
    /// payload.
    Undecidable(RustSecUndecidable),
}

/// Is this `informational` word one that means "not a vulnerability"?
/// `"unsound"` is deliberately NOT one of these — it is a memory-safety
/// defect and stays a real vulnerability; anything this function does not
/// recognise ALSO stays a vulnerability (the safer default: never silently
/// drop a real problem over a classification word this module does not
/// know yet).
fn is_non_vulnerability_informational(kind: &str) -> bool {
    kind == "unmaintained" || kind == "notice"
}

/// Parses one RustSec `RUSTSEC-YYYY-NNNN.md` file and decides whether
/// `version` of `package` is affected — the SAME decision
/// [`rustsec_finding`] makes, but with an unparseable requirement reported
/// as [`RustSecOutcome::Undecidable`] (carrying the advisory's own id)
/// rather than propagated as a hard `Err`. `rustsec_finding` stays the
/// narrower, error-propagating entry point so every one of its existing
/// callers and tests keeps its original shape; a caller that must not abort
/// a whole run over one unreadable advisory calls this instead.
///
/// A source that cannot be READ at all — the file has no ```` ```toml ````
/// fence, or the fence is not valid TOML — is still a hard `Err`: that is
/// genuinely "the source cannot be read", not "this one advisory's
/// requirements use a shape this parser does not decide".
pub fn rustsec_outcome(
    md: &str,
    package: &str,
    version: &Version,
) -> Result<RustSecOutcome, AdvisoryError> {
    let fence = extract_toml_fence(md)?;
    let doc: RustSecDoc =
        toml::from_str(fence).map_err(|e| AdvisoryError::MalformedRustSecToml(e.to_string()))?;
    if doc.advisory.package != package {
        return Ok(RustSecOutcome::NotAffected);
    }

    let patched_reqs = match parse_requirements(&doc.versions.patched) {
        Ok(reqs) => reqs,
        Err(bad) => return Ok(undecidable_outcome(&doc, bad)),
    };
    let unaffected_reqs = match parse_requirements(&doc.versions.unaffected) {
        Ok(reqs) => reqs,
        Err(bad) => return Ok(undecidable_outcome(&doc, bad)),
    };

    let affected = !any_requirement_matches(&patched_reqs, version)
        && !any_requirement_matches(&unaffected_reqs, version);
    if !affected {
        return Ok(RustSecOutcome::NotAffected);
    }
    if let Some(kind) = &doc.advisory.informational
        && is_non_vulnerability_informational(kind)
    {
        return Ok(RustSecOutcome::Informational(RustSecInformational {
            id: doc.advisory.id.clone(),
            package: doc.advisory.package.clone(),
            kind: kind.clone(),
            title: doc.advisory.title.clone().unwrap_or_default(),
        }));
    }
    Ok(RustSecOutcome::Affected(Finding {
        id: doc.advisory.id.clone(),
        aliases: doc.advisory.aliases.clone(),
        severity: None,
        summary: doc.advisory.title.clone().unwrap_or_default(),
        package: doc.advisory.package.clone(),
        patched: doc.versions.patched.clone(),
        url: doc.advisory.url.clone(),
    }))
}

/// Every requirement string parsed, or the FIRST one that could not be —
/// its own text, so the caller can report exactly which one.
fn parse_requirements(reqs: &[String]) -> Result<Vec<Vec<Constraint>>, String> {
    reqs.iter()
        .map(|r| parse_requirement(r).map_err(|_| r.clone()))
        .collect()
}

fn undecidable_outcome(doc: &RustSecDoc, bad_requirement: String) -> RustSecOutcome {
    RustSecOutcome::Undecidable(RustSecUndecidable {
        id: doc.advisory.id.clone(),
        package: doc.advisory.package.clone(),
        requirement: bad_requirement,
        reason: "requirement could not be read".to_string(),
    })
}

/// Parses one RustSec `RUSTSEC-YYYY-NNNN.md` file and decides whether
/// `version` of `package` is affected.
///
/// A version is affected iff it matches NONE of `patched` and NONE of
/// `unaffected` — RustSec's own meaning, including the case where both
/// lists are empty, which affects every version.
pub fn rustsec_finding(
    md: &str,
    package: &str,
    version: &Version,
) -> Result<Option<Finding>, AdvisoryError> {
    match rustsec_outcome(md, package, version)? {
        RustSecOutcome::Affected(f) => Ok(Some(f)),
        RustSecOutcome::NotAffected => Ok(None),
        // This narrower adapter predates the informational/vulnerability
        // distinction; its callers only ever asked "is this a
        // vulnerability", so an informational advisory reads as "no
        // finding" here — the richer distinction is what `rustsec_outcome`
        // itself exists to expose.
        RustSecOutcome::Informational(_) => Ok(None),
        RustSecOutcome::Undecidable(u) => Err(AdvisoryError::BadRequirement(u.requirement)),
    }
}

/// Extracts the content of the first ```` ```toml ```` fence in `md`.
///
/// `pub(crate)`, not private: the advisory watcher's orchestration
/// (REQ-ADVISORYWATCH-001) needs the SAME fence to read `withdrawn` and
/// `cvss` — fields this module's own [`rustsec_finding`] has no reason to
/// expose — and re-implementing fence extraction there would be a second
/// copy of the one string operation that has to agree with this module's.
pub(crate) fn extract_toml_fence(md: &str) -> Result<&str, AdvisoryError> {
    const START: &str = "```toml";
    let start_idx = md.find(START).ok_or(AdvisoryError::NoTomlFence)?;
    let rest = &md[start_idx + START.len()..];
    let end_idx = rest.find("```").ok_or(AdvisoryError::NoTomlFence)?;
    Ok(&rest[..end_idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------
    // Version
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn full_dotted_version_parses() {
        let v = Version::parse("0.23.46").expect("parses");
        assert_eq!(
            v,
            Version {
                major: 0,
                minor: 23,
                patch: 46
            }
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn major_minor_and_major_only_pad_with_zeros() {
        assert_eq!(
            Version::parse("1.2").unwrap(),
            Version {
                major: 1,
                minor: 2,
                patch: 0
            }
        );
        assert_eq!(
            Version::parse("49").unwrap(),
            Version {
                major: 49,
                minor: 0,
                patch: 0
            }
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_leading_v_is_tolerated() {
        assert_eq!(
            Version::parse("v1.2.3").unwrap(),
            Version::parse("1.2.3").unwrap()
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ordering_is_numeric_not_lexical() {
        assert!(Version::parse("0.23.46").unwrap() > Version::parse("0.23.5").unwrap());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_prerelease_suffix_is_still_an_error_a_build_metadata_suffix_now_parses() {
        // A pre-release has no defined numeric position; refusing it is
        // unchanged.
        assert!(matches!(
            Version::parse("1.2.3-rc.1"),
            Err(AdvisoryError::PreReleaseVersion(_))
        ));
        // Build metadata is IGNORED for version precedence (semver 2.0
        // clause 10) — it is stripped and the rest parses normally, rather
        // than refusing the whole version over text this comparator never
        // needed to read.
        assert_eq!(
            Version::parse("1.2.3+x").unwrap(),
            Version {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
    }

    /// The real shapes measured in upstream SBOMs — `toml`, `serde_yaml`
    /// and `wasi`'s own build metadata. The last one is WHY the hyphen
    /// check has to run on the pre-`+` half only: build metadata may itself
    /// legally contain a `-`, and reading that hyphen as this version's own
    /// pre-release marker is exactly the defect this test pins against.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn build_metadata_that_itself_contains_a_hyphen_still_parses() {
        assert_eq!(
            Version::parse("1.1.3+spec-1.1.0").unwrap(),
            Version {
                major: 1,
                minor: 1,
                patch: 3
            }
        );
        assert_eq!(
            Version::parse("0.9.34+deprecated").unwrap(),
            Version {
                major: 0,
                minor: 9,
                patch: 34
            }
        );
        assert_eq!(
            Version::parse("0.14.7+wasi-0.2.4").unwrap(),
            Version {
                major: 0,
                minor: 14,
                patch: 7
            }
        );
    }

    /// A pre-release WITH build metadata is still refused — the pre-release
    /// half is what makes it undecidable, and that does not go away because
    /// build metadata follows it.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_prerelease_with_build_metadata_is_still_refused() {
        assert!(matches!(
            Version::parse("1.2.3-rc.1+build.5"),
            Err(AdvisoryError::PreReleaseVersion(_))
        ));
    }

    /// Build metadata that is empty, or a version that is NOTHING but a
    /// `+suffix`, is a bad version — not a silently-accepted empty body.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_version_with_no_body_before_the_build_metadata_is_an_error() {
        assert!(matches!(
            Version::parse("+onlymetadata"),
            Err(AdvisoryError::BadVersion(_))
        ));
        assert!(matches!(
            Version::parse("1.2.3+"),
            Ok(Version {
                major: 1,
                minor: 2,
                patch: 3
            })
        ));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn garbage_version_text_is_an_error() {
        assert!(matches!(
            Version::parse("banana"),
            Err(AdvisoryError::BadVersion(_))
        ));
        assert!(matches!(
            Version::parse("1.2.3.4"),
            Err(AdvisoryError::BadVersion(_))
        ));
        assert!(matches!(
            Version::parse(""),
            Err(AdvisoryError::BadVersion(_))
        ));
    }

    // -------------------------------------------------------------
    // GHSA range parsing — the measured wasmtime vectors
    // -------------------------------------------------------------

    fn ghsa_json(range: &str) -> String {
        format!(
            r#"[{{
                "ghsa_id": "GHSA-m9f7-9w4p-gv38",
                "cve_id": "CVE-2026-00001",
                "severity": "high",
                "summary": "filesystem sandbox escape",
                "html_url": "https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-m9f7-9w4p-gv38",
                "published_at": "2026-10-14T00:00:00Z",
                "vulnerabilities": [{{
                    "package": {{"name": "wasmtime"}},
                    "vulnerable_version_range": "{range}",
                    "patched_versions": null
                }}]
            }}]"#
        )
    }

    fn affects(range: &str, version: &str) -> bool {
        let v = Version::parse(version).expect("test version parses");
        let result = ghsa_findings(&ghsa_json(range), "wasmtime", &v).expect("range parses");
        assert!(
            result.undecidable.is_empty(),
            "range {range:?} was reported undecidable"
        );
        !result.findings.is_empty()
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn multi_interval_range_with_spaces_affects_both_closed_windows() {
        let range = "<= 36.0.17, >= 37.0.0, <= 48.0.5, >= 49.0.0, <= 49.0.2";
        for v in ["36.0.17", "37.0.0", "48.0.5", "49.0.0", "49.0.1", "49.0.2"] {
            assert!(affects(range, v), "{v} should be affected");
        }
        for v in ["36.0.18", "48.0.6", "49.0.3"] {
            assert!(!affects(range, v), "{v} should NOT be affected");
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn multi_interval_range_with_lt_affects_half_open_windows() {
        let range = ">= 46.0.0, < 48.0.6, >= 49.0.0, < 49.0.3";
        for v in ["46.0.0", "48.0.5", "49.0.1"] {
            assert!(affects(range, v), "{v} should be affected");
        }
        for v in ["45.9.9", "48.0.6", "49.0.3"] {
            assert!(!affects(range, v), "{v} should NOT be affected");
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn multi_interval_range_with_no_spaces_still_parses() {
        let range = "<36.0.18, >= 37.0.0, <48.0.6, >=49.0.0, <49.0.3";
        assert!(affects(range, "36.0.17"));
        assert!(affects(range, "49.0.1"));
        assert!(!affects(range, "36.0.18"));
        assert!(!affects(range, "48.0.6"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn single_closed_interval_affects_only_inside() {
        let range = ">= 49.0.0, <= 49.0.2";
        assert!(affects(range, "49.0.1"));
        assert!(!affects(range, "49.0.3"));
        assert!(!affects(range, "48.9.9"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_trailing_open_lower_bound_is_an_interval_to_infinity() {
        let range = ">= 50.0.0";
        assert!(affects(range, "50.0.0"));
        assert!(affects(range, "999.0.0"));
        assert!(!affects(range, "49.9.9"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_exclusive_lower_bound_excludes_its_own_endpoint() {
        let range = "> 1.0.0, <= 2.0.0";
        assert!(!affects(range, "1.0.0"));
        assert!(affects(range, "1.0.1"));
        assert!(affects(range, "2.0.0"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_bare_version_or_equals_prefixed_one_is_an_exact_match() {
        assert!(affects("1.2.3", "1.2.3"));
        assert!(!affects("1.2.3", "1.2.4"));
        assert!(affects("=1.2.3", "1.2.3"));
        assert!(!affects("=1.2.3", "1.2.2"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unparseable_range_is_undecidable_never_not_affected_and_never_fails_the_call() {
        let v = Version::parse("1.0.0").unwrap();
        let result = ghsa_findings(&ghsa_json("not a range at all"), "wasmtime", &v)
            .expect("one bad range must not fail the whole query");
        assert!(result.findings.is_empty());
        assert_eq!(result.undecidable.len(), 1);
        assert_eq!(result.undecidable[0].id, "GHSA-m9f7-9w4p-gv38");
        assert_eq!(result.undecidable[0].package, "wasmtime");
        assert_eq!(result.undecidable[0].range, "not a range at all");
        assert_eq!(
            result.undecidable[0].reason,
            UndecidableReason::RangeCouldNotBeRead
        );
    }

    /// The real reason `undecidable` exists: GHSA-88xq-w8cq-xfg7's range on
    /// bytecodealliance/wasmtime is genuinely unparseable, but the SAME
    /// `ghsa_findings` call also carries other, good advisories for
    /// `wasmtime` — those must still be reported.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn one_undecidable_advisory_does_not_hide_a_good_one_for_the_same_package() {
        let json = r#"[
            {
                "ghsa_id": "GHSA-88xq-w8cq-xfg7",
                "cve_id": null,
                "severity": null,
                "summary": "unparseable live shape",
                "html_url": null,
                "vulnerabilities": [{"package": {"name": "wasmtime"}, "vulnerable_version_range": "<= 0.34.0 (excluding 0.33.1)", "patched_versions": null}]
            },
            {
                "ghsa_id": "GHSA-m9f7-9w4p-gv38",
                "cve_id": null,
                "severity": "high",
                "summary": "filesystem sandbox escape",
                "html_url": null,
                "vulnerabilities": [{"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"}]
            }
        ]"#;
        let v = Version::parse("49.0.1").unwrap();
        let result = ghsa_findings(json, "wasmtime", &v).expect("parses");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].id, "GHSA-m9f7-9w4p-gv38");
        assert_eq!(result.undecidable.len(), 1);
        assert_eq!(result.undecidable[0].id, "GHSA-88xq-w8cq-xfg7");
        assert_eq!(
            result.undecidable[0].reason,
            UndecidableReason::RangeCouldNotBeRead
        );
    }

    /// GHSA-vc8c-j3xm-xj73's own shape: a range that affects the version,
    /// but a `patched_versions` entry at or below it — the two disagree,
    /// so this must be undecidable, not a finding and not silently clear.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_range_that_contradicts_its_own_patched_versions_is_undecidable() {
        let json = r#"[{
            "ghsa_id": "GHSA-vc8c-j3xm-xj73",
            "cve_id": null,
            "severity": null,
            "summary": "stale range, later patched",
            "html_url": null,
            "vulnerabilities": [{"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 29.0.0", "patched_versions": "36.0.5, 40.0.3, 41.0.1"}]
        }]"#;
        let v = Version::parse("49.0.1").unwrap();
        let result = ghsa_findings(json, "wasmtime", &v).expect("parses");
        assert!(result.findings.is_empty());
        assert_eq!(result.undecidable.len(), 1);
        assert_eq!(result.undecidable[0].id, "GHSA-vc8c-j3xm-xj73");
        assert_eq!(
            result.undecidable[0].reason,
            UndecidableReason::RangeAndPatchedVersionsDisagree
        );

        // A version BELOW the highest patched entry has nothing to
        // disagree about: the range's own verdict stands.
        let v_old = Version::parse("40.0.0").unwrap();
        let result_old = ghsa_findings(json, "wasmtime", &v_old).expect("parses");
        assert!(result_old.undecidable.is_empty());
        assert_eq!(result_old.findings.len(), 1);
        assert_eq!(result_old.findings[0].id, "GHSA-vc8c-j3xm-xj73");
    }

    /// An empty or entirely-unparseable `patched_versions` has nothing to
    /// disagree with the range about, so it must not suppress a finding.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unparseable_patched_versions_list_does_not_suppress_the_range_verdict() {
        let json = r#"[{
            "ghsa_id": "GHSA-x",
            "cve_id": null,
            "severity": null,
            "summary": "s",
            "html_url": null,
            "vulnerabilities": [{"package": {"name": "p"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": "not a version"}]
        }]"#;
        let v = Version::parse("99.0.0").unwrap();
        let result = ghsa_findings(json, "p", &v).expect("parses");
        assert!(result.undecidable.is_empty());
        assert_eq!(result.findings.len(), 1);
    }

    /// Measured live on bytecodealliance/wasmtime: `&&` used as a separator
    /// in place of `,`.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_double_ampersand_separator_is_read_as_a_comma() {
        assert!(affects(">= 0.26.0 && <= 0.29.0", "0.27.0"));
        assert!(!affects(">= 0.26.0 && <= 0.29.0", "0.30.0"));
        assert!(affects(">=0.19.0 && <=0.29.0", "0.19.0"));
        assert!(!affects(">=0.19.0 && <=0.29.0", "0.30.0"));
    }

    /// Measured live on bytecodealliance/wasmtime: a plain-English final
    /// list item, `"0.34.0, 0.34.1, 0.35.0, and 0.35.1"` — four exact
    /// matches, the last one spelled out.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_final_list_item_spelled_with_and_is_read_as_a_bare_version() {
        let range = "0.34.0, 0.34.1, 0.35.0, and 0.35.1";
        for v in ["0.34.0", "0.34.1", "0.35.0", "0.35.1"] {
            assert!(affects(range, v), "{v} should be affected");
        }
        assert!(!affects(range, "0.35.2"));
    }
    /// Measured live on bytecodealliance/wasmtime: a published range that ends
    /// in a comma, with a bare exact version before it. One trailing comma is
    /// the shape GitHub stores; an empty segment in the MIDDLE is still refused.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_published_range_with_a_trailing_comma_is_read() {
        let r = ">= 30.0.0, <= 36.0.7, >= 37.0.0, <= 43.0.1, 44.0.0,";
        let iv = parse_ghsa_range(r).expect("the stored shape parses");
        let hit = |v: &str| iv.iter().any(|i| i.contains(&Version::parse(v).unwrap()));
        assert!(hit("36.0.7") && hit("43.0.1") && hit("44.0.0"));
        assert!(!hit("36.0.8") && !hit("44.0.1") && !hit("29.9.9"));
        assert!(parse_ghsa_range(">= 1.0.0,, < 2.0.0").is_err());
        assert!(parse_ghsa_range(",").is_err());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_caret_constraint_is_invalid_in_a_ghsa_range() {
        assert!(matches!(
            parse_ghsa_range("^1.0.0"),
            Err(AdvisoryError::BadGhsaRange(_))
        ));
        let v = Version::parse("1.0.0").unwrap();
        let result = ghsa_findings(&ghsa_json("^1.0.0"), "wasmtime", &v).expect("must not fail");
        assert!(result.findings.is_empty());
        assert_eq!(result.undecidable.len(), 1);
    }

    // -------------------------------------------------------------
    // GHSA findings — filtering, aliases, malformed JSON
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_findings_filters_by_package_and_carries_fields() {
        let json = r#"[
            {
                "ghsa_id": "GHSA-m9f7-9w4p-gv38",
                "cve_id": "CVE-2026-00001",
                "severity": "high",
                "summary": "filesystem sandbox escape",
                "html_url": "https://example.invalid/ghsa",
                "vulnerabilities": [
                    {"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"},
                    {"package": {"name": "other-crate"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null}
                ]
            },
            {
                "ghsa_id": "GHSA-irrelevant",
                "cve_id": null,
                "severity": "low",
                "summary": "unrelated",
                "html_url": null,
                "vulnerabilities": [
                    {"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 1.0.0, < 2.0.0", "patched_versions": ""}
                ]
            }
        ]"#;
        let v = Version::parse("49.0.1").unwrap();
        let result = ghsa_findings(json, "wasmtime", &v).expect("parses");
        assert!(result.undecidable.is_empty());
        assert_eq!(result.findings.len(), 1);
        let f = &result.findings[0];
        assert_eq!(f.id, "GHSA-m9f7-9w4p-gv38");
        assert_eq!(f.aliases, vec!["CVE-2026-00001".to_string()]);
        assert_eq!(f.severity, Some("high".to_string()));
        assert_eq!(f.summary, "filesystem sandbox escape");
        assert_eq!(f.package, "wasmtime");
        assert_eq!(f.patched, vec!["49.0.3".to_string()]);
        assert_eq!(f.url, Some("https://example.invalid/ghsa".to_string()));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_findings_with_null_cve_id_has_no_aliases() {
        let json = r#"[{
            "ghsa_id": "GHSA-x",
            "cve_id": null,
            "severity": null,
            "summary": "s",
            "html_url": null,
            "vulnerabilities": [{"package": {"name": "p"}, "vulnerable_version_range": "1.0.0", "patched_versions": null}]
        }]"#;
        let v = Version::parse("1.0.0").unwrap();
        let result = ghsa_findings(json, "p", &v).unwrap();
        assert!(result.undecidable.is_empty());
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].aliases.is_empty());
        assert!(result.findings[0].severity.is_none());
        assert!(result.findings[0].patched.is_empty());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn malformed_ghsa_json_is_an_error() {
        let v = Version::parse("1.0.0").unwrap();
        let err = ghsa_findings("not json", "p", &v);
        assert!(matches!(err, Err(AdvisoryError::MalformedGhsaJson(_))));
    }

    // -------------------------------------------------------------
    // RustSec — the measured rustls and wasmtime vectors
    // -------------------------------------------------------------

    fn rustsec_md(
        id: &str,
        package: &str,
        patched: &str,
        unaffected: &str,
        aliases: &str,
    ) -> String {
        format!(
            r#"Some prose above the fence that the parser must skip.

```toml
[advisory]
id = "{id}"
package = "{package}"
date = "2026-10-14"
url = "https://rustsec.org/advisories/{id}"
aliases = [{aliases}]
title = "test advisory"

[versions]
patched = [{patched}]
unaffected = [{unaffected}]
```

## Details

More prose below the fence.
"#
        )
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustls_rustsec_2026_0346_vectors() {
        let md = rustsec_md(
            "RUSTSEC-2026-0346",
            "rustls",
            r#"">= 0.23.46""#,
            r#""< 0.21.0""#,
            r#""GHSA-xxxx-xxxx-xxxx""#,
        );
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "rustls", &v).unwrap().is_some()
        };
        assert!(affected("0.23.34"));
        assert!(affected("0.23.45"));
        assert!(!affected("0.23.46"));
        assert!(!affected("0.20.9"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn wasmtime_rustsec_2025_0118_vectors() {
        let md = rustsec_md(
            "RUSTSEC-2025-0118",
            "wasmtime",
            r#"">= 38.0.4", ">= 37.0.3, < 38.0.0", ">= 36.0.3, < 37.0.0", ">= 24.0.5, < 25.0.0""#,
            "",
            "",
        );
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "wasmtime", &v).unwrap().is_some()
        };
        assert!(affected("38.0.3"));
        assert!(!affected("38.0.4"));
        assert!(affected("37.0.2"));
        assert!(!affected("37.0.3"));
        assert!(!affected("36.0.3"));
        assert!(affected("30.0.0"));
        assert!(!affected("24.0.5"));
        assert!(affected("24.0.4"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn both_lists_empty_affects_every_version() {
        let md = rustsec_md("RUSTSEC-0000-0000", "whatever", "", "", "");
        let v1 = Version::parse("0.0.1").unwrap();
        let v2 = Version::parse("999.999.999").unwrap();
        assert!(rustsec_finding(&md, "whatever", &v1).unwrap().is_some());
        assert!(rustsec_finding(&md, "whatever", &v2).unwrap().is_some());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_finding_requires_the_package_to_match() {
        let md = rustsec_md("RUSTSEC-2026-0346", "rustls", r#"">= 0.23.46""#, "", "");
        let v = Version::parse("0.1.0").unwrap();
        assert!(
            rustsec_finding(&md, "some-other-crate", &v)
                .unwrap()
                .is_none()
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_finding_carries_aliases_and_patched_requirements() {
        let md = rustsec_md(
            "RUSTSEC-2026-0346",
            "rustls",
            r#"">= 0.23.46""#,
            r#""< 0.21.0""#,
            r#""GHSA-xxxx-xxxx-xxxx", "CVE-2026-0346""#,
        );
        let v = Version::parse("0.23.34").unwrap();
        let f = rustsec_finding(&md, "rustls", &v)
            .unwrap()
            .expect("affected");
        assert_eq!(f.id, "RUSTSEC-2026-0346");
        assert_eq!(
            f.aliases,
            vec![
                "GHSA-xxxx-xxxx-xxxx".to_string(),
                "CVE-2026-0346".to_string()
            ]
        );
        assert_eq!(f.patched, vec![">= 0.23.46".to_string()]);
        assert_eq!(f.summary, "test advisory");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_rustsec_file_with_no_toml_fence_is_an_error() {
        let v = Version::parse("1.0.0").unwrap();
        let err = rustsec_finding("just prose, no fence here", "rustls", &v);
        assert!(matches!(err, Err(AdvisoryError::NoTomlFence)));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn malformed_toml_inside_the_fence_is_an_error() {
        let md = "```toml\nthis is not = valid [ toml\n```\n";
        let v = Version::parse("1.0.0").unwrap();
        let err = rustsec_finding(md, "rustls", &v);
        assert!(matches!(err, Err(AdvisoryError::MalformedRustSecToml(_))));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_garbage_requirement_string_is_an_error_never_not_affected() {
        let md = rustsec_md("RUSTSEC-0000-0000", "p", r#""not a requirement""#, "", "");
        let v = Version::parse("1.0.0").unwrap();
        let err = rustsec_finding(&md, "p", &v);
        assert!(matches!(err, Err(AdvisoryError::BadRequirement(_))));
    }

    /// `rustsec_outcome` is the caller a run that must not abort over one
    /// unreadable advisory uses: the SAME garbage requirement becomes
    /// `Undecidable`, carrying the advisory's own id and which requirement
    /// string could not be read — never an `Err` here.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_outcome_reports_a_garbage_requirement_as_undecidable_with_its_id() {
        let md = rustsec_md("RUSTSEC-0000-0030", "p", r#""not a requirement""#, "", "");
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "p", &v).expect("must not be a hard error");
        match outcome {
            RustSecOutcome::Undecidable(u) => {
                assert_eq!(u.id, "RUSTSEC-0000-0030");
                assert_eq!(u.package, "p");
                assert_eq!(u.requirement, "not a requirement");
                assert_eq!(u.reason, "requirement could not be read");
            }
            other => panic!("expected Undecidable, got {other:?}"),
        }
    }

    /// A garbage `unaffected` entry is undecidable too, not only `patched`.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_outcome_reports_a_garbage_unaffected_entry_as_undecidable() {
        let md = rustsec_md(
            "RUSTSEC-0000-0031",
            "p",
            "",
            r#""also not a requirement""#,
            "",
        );
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "p", &v).expect("must not be a hard error");
        assert!(
            matches!(outcome, RustSecOutcome::Undecidable(_)),
            "{outcome:?}"
        );
    }

    /// A fence that cannot be read at all — no fence, or malformed TOML —
    /// is still a hard error: this really is "the source cannot be read",
    /// not "one advisory's requirement uses a shape this parser cannot
    /// decide".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_outcome_still_hard_errors_on_an_unreadable_source() {
        let v = Version::parse("1.0.0").unwrap();
        assert!(matches!(
            rustsec_outcome("no fence here", "p", &v),
            Err(AdvisoryError::NoTomlFence)
        ));
        let bad_toml = "```toml\nthis is not = valid [ toml\n```\n";
        assert!(matches!(
            rustsec_outcome(bad_toml, "p", &v),
            Err(AdvisoryError::MalformedRustSecToml(_))
        ));
    }

    /// Same shape as `rustsec_md`, but with an `informational` line —
    /// REQ-ADVISORYWATCH-001's informational-advisories rule needs to
    /// distinguish `"unmaintained"`/`"notice"` (not a vulnerability) from
    /// `"unsound"` (still a vulnerability: memory-safety) from absent
    /// (a vulnerability, as every other test in this module already
    /// assumes). `patched`/`unaffected` are left empty so every queried
    /// version is "affected" by RustSec's own meaning, isolating the
    /// `informational` branch itself.
    fn rustsec_md_informational(id: &str, package: &str, informational: &str) -> String {
        format!(
            r#"```toml
[advisory]
id = "{id}"
package = "{package}"
date = "2026-10-14"
title = "test advisory"
informational = "{informational}"

[versions]
patched = []
unaffected = []
```
"#
        )
    }

    /// RustSec's own `informational = "unmaintained"` marks an advisory
    /// that is NOT a vulnerability (e.g. `im`, `sized-chunks` in the live
    /// run) — it must come back as `Informational`, never `Affected`,
    /// so its caller never turns it into a `KnownProblem`.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unmaintained_informational_advisory_is_informational_not_affected() {
        let md = rustsec_md_informational("RUSTSEC-2026-0900", "im", "unmaintained");
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "im", &v).expect("must not be a hard error");
        match outcome {
            RustSecOutcome::Informational(info) => {
                assert_eq!(info.id, "RUSTSEC-2026-0900");
                assert_eq!(info.package, "im");
                assert_eq!(info.kind, "unmaintained");
                assert_eq!(info.title, "test advisory");
            }
            other => panic!("expected Informational, got {other:?}"),
        }
        // The narrower adapter must agree: no finding, not an error.
        assert_eq!(rustsec_finding(&md, "im", &v).unwrap(), None);
    }

    /// `informational = "notice"` is the other non-vulnerability kind —
    /// same rule, different word.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_notice_informational_advisory_is_informational_not_affected() {
        let md = rustsec_md_informational("RUSTSEC-2026-0901", "somecrate", "notice");
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "somecrate", &v).expect("must not be a hard error");
        assert!(
            matches!(outcome, RustSecOutcome::Informational(_)),
            "{outcome:?}"
        );
    }

    /// `informational = "unsound"` STAYS a known problem — it names a
    /// memory-safety defect, not merely "unmaintained" or a "notice".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unsound_informational_advisory_is_still_affected() {
        let md = rustsec_md_informational("RUSTSEC-2026-0902", "somecrate", "unsound");
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "somecrate", &v).expect("must not be a hard error");
        match outcome {
            RustSecOutcome::Affected(f) => assert_eq!(f.id, "RUSTSEC-2026-0902"),
            other => panic!("expected Affected (unsound is a vulnerability), got {other:?}"),
        }
    }

    /// No `informational` field at all is a vulnerability as today — the
    /// field's ABSENCE must not be mistaken for any of its values.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_advisory_with_no_informational_field_is_still_affected() {
        let md = rustsec_md(
            "RUSTSEC-2026-0903",
            "somecrate",
            "",
            "",
            r#""GHSA-xxxx-xxxx-xxxx""#,
        );
        let v = Version::parse("1.0.0").unwrap();
        let outcome = rustsec_outcome(&md, "somecrate", &v).expect("must not be a hard error");
        assert!(
            matches!(outcome, RustSecOutcome::Affected(_)),
            "{outcome:?}"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn version_display_renders_dotted_form() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");
        assert_ne!(v.to_string(), "9.9.9");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn requirement_constraint_gt_excludes_its_own_endpoint() {
        let md = rustsec_md("RUSTSEC-0000-0010", "p", r#""> 1.0.0""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["> 1.0.0"]: 1.0.0 is NOT patched (still affected),
        // 1.0.1 IS patched (not affected).
        assert!(affected("1.0.0"));
        assert!(!affected("1.0.1"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn requirement_constraint_le_includes_its_own_endpoint() {
        let md = rustsec_md("RUSTSEC-0000-0011", "p", r#""<= 1.0.0""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["<= 1.0.0"]: 1.0.0 IS patched (not affected),
        // 1.0.1 is NOT patched (still affected).
        assert!(!affected("1.0.0"));
        assert!(affected("1.0.1"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn requirement_constraint_lt_excludes_its_own_endpoint() {
        let md = rustsec_md("RUSTSEC-0000-0012", "p", r#""< 1.0.0""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["< 1.0.0"]: 0.9.9 IS patched (not affected),
        // 1.0.0 is NOT patched (still affected).
        assert!(!affected("0.9.9"));
        assert!(affected("1.0.0"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn requirement_constraint_eq_matches_only_the_exact_version() {
        let md = rustsec_md("RUSTSEC-0000-0013", "p", r#""=1.0.0""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["=1.0.0"]: exactly 1.0.0 IS patched (not affected),
        // anything else is NOT patched (still affected).
        assert!(!affected("1.0.0"));
        assert!(affected("1.0.1"));
    }

    // -------------------------------------------------------------
    // Pre-release bounds (REQ-ADVISORYWATCH-001's pre-release-bounds rule)
    // -------------------------------------------------------------

    /// The exact string the live run aborted on. `patched` names it, so
    /// "affected" below means the version is OUTSIDE the patched window —
    /// the same `affected` helper every other requirement test here uses.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_aborting_requirement_now_parses_and_decides() {
        let md = rustsec_md(
            "RUSTSEC-0000-0020",
            "p",
            r#"">= 0.2.8, < 0.3.0-rc.1""#,
            "",
            "",
        );
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = [">= 0.2.8, < 0.3.0-rc.1"] ⇔ [">= 0.2.8, < 0.3.0"]:
        // 0.2.8 and 0.2.99 ARE patched (not affected); 0.2.7 and 0.3.0 are
        // NOT patched (still affected).
        assert!(!affected("0.2.8"));
        assert!(!affected("0.2.99"));
        assert!(affected("0.3.0"));
        assert!(affected("0.2.7"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_ge_prerelease_bound_matches_the_release_not_versions_strictly_below_it() {
        let md = rustsec_md("RUSTSEC-0000-0021", "p", r#"">= 1.0.0-alpha""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = [">= 1.0.0-alpha"] ⇔ [">= 1.0.0"]: 1.0.0 IS patched
        // (not affected); 0.9.9 is NOT (still affected).
        assert!(!affected("1.0.0"));
        assert!(affected("0.9.9"));
    }

    /// `= X-pre` matches NO real release at all — a pre-release is never
    /// equal to any release, so EVERY version stays affected.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_eq_prerelease_bound_matches_nothing() {
        let md = rustsec_md("RUSTSEC-0000-0022", "p", r#""=1.0.0-rc.1""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        assert!(affected("1.0.0"));
        assert!(affected("0.9.9"));
        assert!(affected("1.0.1"));
    }

    /// `^X-pre` becomes `>= X` capped by X's OWN caret upper bound — the
    /// pre-release suffix changes nothing about where the caret's ceiling
    /// sits.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_caret_prerelease_bound_is_capped_at_the_releases_own_caret_ceiling() {
        let md = rustsec_md("RUSTSEC-0000-0023", "p", r#""^1.2.3-rc.1""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["^1.2.3-rc.1"] ⇔ [">=1.2.3, <2.0.0"].
        assert!(affected("1.2.2"));
        assert!(!affected("1.2.3"));
        assert!(!affected("1.5.0"));
        assert!(affected("2.0.0"));
    }

    /// Build metadata on a BOUND is ignored exactly as on a version.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn build_metadata_on_a_bound_is_ignored() {
        let md = rustsec_md("RUSTSEC-0000-0024", "p", r#"">= 1.0.0+build.5""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        assert!(!affected("1.0.0"));
        assert!(affected("0.9.9"));
    }

    /// The SAME pre-release-bounds rule, for a GHSA `vulnerable_version_range`
    /// — the live-measured string, read the other way (a range states what
    /// IS affected, not what is patched).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_ranges_apply_the_same_prerelease_bounds_rule() {
        let range = ">= 0.2.8, < 0.3.0-rc.1";
        assert!(affects(range, "0.2.8"));
        assert!(affects(range, "0.2.99"));
        assert!(!affects(range, "0.3.0"));
        assert!(!affects(range, "0.2.7"));

        assert!(affects(">= 1.0.0-alpha", "1.0.0"));
        assert!(!affects(">= 1.0.0-alpha", "0.9.9"));

        assert!(!affects("=1.0.0-rc.1", "1.0.0"));
        assert!(!affects("=1.0.0-rc.1", "0.9.9"));
    }

    /// `>` and `<=` are where the pre-release collapse actually CHANGES the
    /// bound (unlike `>=`/`<`, which already read the same with or without
    /// one): `> X-pre` becomes `>= X` (inclusive of X itself), and
    /// `<= X-pre` becomes `< X` (exclusive of X itself).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_gt_and_le_prerelease_bounds_change_their_own_endpoint() {
        // `> 1.0.0-alpha, <= 2.0.0` ⇔ `>= 1.0.0, <= 2.0.0`: 1.0.0 IS
        // included (an ordinary `>` would exclude it).
        let range = "> 1.0.0-alpha, <= 2.0.0";
        assert!(affects(range, "1.0.0"));
        assert!(!affects(range, "0.9.9"));

        // `>= 1.0.0, <= 2.0.0-rc.1` ⇔ `>= 1.0.0, < 2.0.0`: 2.0.0 is NOT
        // included (an ordinary `<=` would include it).
        let range = ">= 1.0.0, <= 2.0.0-rc.1";
        assert!(affects(range, "1.9.9"));
        assert!(!affects(range, "2.0.0"));
    }

    // -------------------------------------------------------------
    // Caret requirements (RustSec-only)
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn caret_requirement_bumps_the_leftmost_nonzero_component() {
        let md = rustsec_md("RUSTSEC-0000-0001", "p", r#""^1.2.3""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        // patched = ["^1.2.3"] means >=1.2.3,<2.0.0 is NOT affected.
        assert!(affected("1.2.2"));
        assert!(!affected("1.2.3"));
        assert!(!affected("1.5.0"));
        assert!(affected("2.0.0"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn caret_requirement_with_zero_major_bumps_minor() {
        let md = rustsec_md("RUSTSEC-0000-0002", "p", r#""^0.2.3""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        assert!(!affected("0.2.3"));
        assert!(!affected("0.2.9"));
        assert!(affected("0.3.0"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn caret_requirement_with_zero_major_and_minor_bumps_patch() {
        let md = rustsec_md("RUSTSEC-0000-0003", "p", r#""^0.0.3""#, "", "");
        let affected = |ver: &str| {
            let v = Version::parse(ver).unwrap();
            rustsec_finding(&md, "p", &v).unwrap().is_some()
        };
        assert!(!affected("0.0.3"));
        assert!(affected("0.0.4"));
    }

    // -------------------------------------------------------------
    // Live fixtures — every published advisory GitHub actually returns.
    //
    // `wasmtime-ghsa-2026-10-15.json` is the UNEDITED `gh api
    // repos/bytecodealliance/wasmtime/security-advisories?state=published`
    // response measured 2026-10-15 (public data). It is what exposed the
    // `&&` separator, the `and X` tail, the one genuinely unparseable
    // range, and the one-trailing-comma shape — none of which a hand-built
    // fixture would have produced.
    // -------------------------------------------------------------

    const WASMTIME_LIVE: &str = include_str!("../tests/fixtures/wasmtime-ghsa-2026-10-15.json");
    const ORDEAL_LIVE: &str = include_str!("../tests/fixtures/ordeal-ghsa-2026-10-15.json");

    /// The 15 advisories the requirement names as published 2026-10-14,
    /// every one measured to cover 49.0.1.
    /// The 15 advisories the requirement names as published 2026-10-14.
    const WASMTIME_2026_10_14: &[&str] = &[
        "GHSA-3r89-v5mq-j5xf",
        "GHSA-54p9-vhhq-8f7q",
        "GHSA-5hhx-4wrr-3j9g",
        "GHSA-5qpp-g3j2-8frx",
        "GHSA-63h4-6cx9-pjfj",
        "GHSA-7v24-42x9-pxf7",
        "GHSA-93g3-36p8-x2gc",
        "GHSA-hmwq-g22x-qjw5",
        "GHSA-m6w2-jwq2-cv2c",
        "GHSA-m9f7-9w4p-gv38",
        "GHSA-p79w-pv2r-29qp",
        "GHSA-q554-3cjc-rx7p",
        "GHSA-vcg5-q8m5-8379",
        "GHSA-w36r-2hch-9xp9",
        "GHSA-wjc8-633q-pwxr",
    ];

    /// 8 older advisories (published 2026-10-02) whose ranges independently
    /// cover 49.0.1. Hand-checked against the fixture: every id below has a
    /// `vulnerable_version_range` that contains 49.0.1 on its own terms.
    const WASMTIME_2026_10_02: &[&str] = &[
        "GHSA-32h6-97mm-8q3c",
        "GHSA-96f6-r43r-8c24",
        "GHSA-cfhf-m2cr-62wj",
        "GHSA-gqmc-89g8-p25r",
        "GHSA-hw8m-q44c-ggrf",
        "GHSA-j366-h8gg-77pm",
        "GHSA-mr2v-56j5-cmfc",
        "GHSA-w4qr-p94g-mjhv",
    ];

    fn ghsa_ids_for(json: &str, package: &str, version: &Version) -> (Vec<String>, Vec<String>) {
        let result = ghsa_findings(json, package, version).expect("live JSON parses");
        (
            result.findings.into_iter().map(|f| f.id).collect(),
            result.undecidable.into_iter().map(|u| u.id).collect(),
        )
    }

    fn wasmtime_findings(version: &str) -> std::collections::BTreeSet<String> {
        let v = Version::parse(version).unwrap();
        let mut found = std::collections::BTreeSet::new();
        for package in ["wasmtime", "wasmtime-wasi", "wasmtime-wasi-http"] {
            let (ids, _undecidable) = ghsa_ids_for(WASMTIME_LIVE, package, &v);
            found.extend(ids);
        }
        found
    }

    /// Three advisories whose range, taken alone, would false-positive on
    /// every modern release: GHSA-xm67-587q-r2vw ("<= 6.0.0, >= 1.0.0"),
    /// GHSA-ff4p-7xrq-q5r8 ("<= 6.0.0, >= 0.37.0") and GHSA-5fhj-g3p3-pq9g
    /// ("<= 0.38.1, >=0.37.0"). Each is a reversed pair — one closed
    /// interval, not a union — so none of the three should appear anywhere
    /// (not a finding, not undecidable) for a version as far out as 49.x.
    const WASMTIME_REVERSED_PAIRS: &[&str] = &[
        "GHSA-xm67-587q-r2vw",
        "GHSA-ff4p-7xrq-q5r8",
        "GHSA-5fhj-g3p3-pq9g",
    ];

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn live_wasmtime_fixture_49_0_1_is_exactly_the_measured_id_set() {
        let found = wasmtime_findings("49.0.1");

        let mut expected: std::collections::BTreeSet<String> =
            WASMTIME_2026_10_14.iter().map(|s| s.to_string()).collect();
        expected.extend(WASMTIME_2026_10_02.iter().map(|s| s.to_string()));

        assert_eq!(
            found, expected,
            "49.0.1 findings must be exactly the 15 + 8 measured ids"
        );
        assert_eq!(found.len(), 23);

        let v = Version::parse("49.0.1").unwrap();
        let (_ids, undecidable) = ghsa_ids_for(WASMTIME_LIVE, "wasmtime", &v);
        let undecidable: std::collections::BTreeSet<String> = undecidable.into_iter().collect();
        assert_eq!(
            undecidable,
            ["GHSA-vc8c-j3xm-xj73", "GHSA-88xq-w8cq-xfg7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );

        for id in WASMTIME_REVERSED_PAIRS {
            assert!(
                !found.contains(*id),
                "reversed-pair advisory {id} must not false-positive on 49.0.1"
            );
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn live_wasmtime_fixture_vc8c_is_undecidable_with_the_disagree_reason() {
        let v = Version::parse("49.0.1").unwrap();
        let result = ghsa_findings(WASMTIME_LIVE, "wasmtime", &v).expect("live JSON parses");
        let vc8c = result
            .undecidable
            .iter()
            .find(|u| u.id == "GHSA-vc8c-j3xm-xj73")
            .expect("GHSA-vc8c-j3xm-xj73 must be undecidable, not a finding");
        assert_eq!(
            vc8c.reason,
            UndecidableReason::RangeAndPatchedVersionsDisagree
        );
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.id == "GHSA-vc8c-j3xm-xj73")
        );
    }

    /// GHSA-32h6-97mm-8q3c's range affects 49.0.1, and its
    /// `patched_versions` ("48.0.4, 49.0.2") does NOT disagree — 49.0.1 is
    /// still below the highest patched entry — so it must stay a genuine
    /// finding, not get swept into `undecidable` by the disagree rule.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_patched_versions_entry_above_the_queried_version_does_not_suppress_the_finding() {
        let v = Version::parse("49.0.1").unwrap();
        let result = ghsa_findings(WASMTIME_LIVE, "wasmtime", &v).expect("live JSON parses");
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.id == "GHSA-32h6-97mm-8q3c")
        );
        assert!(
            !result
                .undecidable
                .iter()
                .any(|u| u.id == "GHSA-32h6-97mm-8q3c")
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn live_wasmtime_fixture_49_0_2_is_exactly_the_2026_10_14_set() {
        let found = wasmtime_findings("49.0.2");
        let expected: std::collections::BTreeSet<String> =
            WASMTIME_2026_10_14.iter().map(|s| s.to_string()).collect();
        assert_eq!(found, expected);
        assert_eq!(found.len(), 15);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn live_wasmtime_fixture_49_0_3_has_zero_findings() {
        let found = wasmtime_findings("49.0.3");
        assert!(found.is_empty(), "found: {found:?}");
    }

    /// The real, measured shape rule 1 exists for: an upper bound with no
    /// open lower bound, immediately followed by a lower bound `<=` it, is
    /// ONE interval — not the zero-to-upper union an infinite-to-lower
    /// reading would silently produce.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_reversed_pair_is_one_interval_not_a_union_to_infinity() {
        // GHSA-xm67-587q-r2vw: "<= 6.0.0, >= 1.0.0" -> [1.0.0, 6.0.0].
        let r = "<= 6.0.0, >= 1.0.0";
        for v in ["6.0.0", "1.0.0"] {
            assert!(affects(r, v), "{v} should be affected by {r}");
        }
        for v in ["6.0.1", "49.0.1", "0.9.9"] {
            assert!(!affects(r, v), "{v} should NOT be affected by {r}");
        }

        // GHSA-ff4p-7xrq-q5r8: "<= 6.0.0, >= 0.37.0" -> [0.37.0, 6.0.0].
        let r = "<= 6.0.0, >= 0.37.0";
        for v in ["6.0.0", "0.37.0"] {
            assert!(affects(r, v), "{v} should be affected by {r}");
        }
        for v in ["6.0.1", "0.36.9"] {
            assert!(!affects(r, v), "{v} should NOT be affected by {r}");
        }

        // GHSA-5fhj-g3p3-pq9g: "<= 0.38.1, >=0.37.0" -> [0.37.0, 0.38.1].
        let r = "<= 0.38.1, >=0.37.0";
        for v in ["0.37.0", "0.38.1"] {
            assert!(affects(r, v), "{v} should be affected by {r}");
        }
        for v in ["0.38.2", "0.36.9"] {
            assert!(!affects(r, v), "{v} should NOT be affected by {r}");
        }
    }

    /// The merge in rule 1 must not disturb the original multi-interval
    /// vectors, where the upper bound IS immediately followed by a lower
    /// bound, but one that is GREATER than the upper bound — that is not a
    /// reversed pair, it is the start of the next, separate interval.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn multi_interval_vectors_are_unaffected_by_the_reversed_pair_rule() {
        let range = "<= 36.0.17, >= 37.0.0, <= 48.0.5, >= 49.0.0, <= 49.0.2";
        for v in ["36.0.17", "37.0.0", "48.0.5", "49.0.0", "49.0.1", "49.0.2"] {
            assert!(affects(range, v), "{v} should be affected");
        }
        for v in ["36.0.18", "48.0.6", "49.0.3"] {
            assert!(!affects(range, v), "{v} should NOT be affected");
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn live_ordeal_fixture_0_22_0_affected_0_22_1_not() {
        let affected_0_22_0 = Version::parse("0.22.0").unwrap();
        let affected_0_22_1 = Version::parse("0.22.1").unwrap();

        let result_0_22_0 = ghsa_findings(ORDEAL_LIVE, "ordeal", &affected_0_22_0).expect("parses");
        assert!(result_0_22_0.undecidable.is_empty());
        assert_eq!(result_0_22_0.findings.len(), 1);
        assert_eq!(result_0_22_0.findings[0].id, "GHSA-xfxf-qxr3-435x");

        let result_0_22_1 = ghsa_findings(ORDEAL_LIVE, "ordeal", &affected_0_22_1).expect("parses");
        assert!(result_0_22_1.undecidable.is_empty());
        assert!(result_0_22_1.findings.is_empty());
    }
}
