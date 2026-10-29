//! The advisory watcher's orchestration (REQ-ADVISORYWATCH-001).
//!
//! [`crate::advisory`] answers one pure question — does a published advisory
//! affect this exact package version — and [`crate::statusdraft`] answers
//! another: given a line's current signed status and a batch of findings,
//! what should the NEXT document say. Neither touches the network or a
//! filesystem, and neither is re-implemented here.
//!
//! This module is the seam between them and the outside world: for every
//! committed `line-index/<line>.json` in a layer repository, fetch that
//! line's layers from the realm registry, ask GHSA and RustSec through
//! `gh`, turn what comes back into [`statusdraft::Proposed`] findings, and
//! hand them to [`statusdraft::next_document`]. [`run`] is impure by
//! necessity — reading files, calling a registry, calling `gh` — and it is
//! also the part this module tests with FAKES, never a real network or a
//! real `gh`, so every ordering and fail-closed property below is decided
//! without one.
//!
//! # Two documents this module deliberately treats as PLAIN JSON
//!
//! `line-index/<line>.json` and `line-status/<line>.json`, committed in a
//! layer repository, are the unsigned source of truth a human reviews
//! before merging (REQ-ADVISORYWATCH-001 clause 3: "a prepared next
//! line-status document ... as a pull request ... which MERGING signs and
//! publishes"). They are read here as plain [`varve_core::LineIndex`] and
//! [`varve_core::LineStatus`] JSON — never through a DSSE envelope, because
//! nothing has signed them yet. The layer MANIFESTS the index points at are
//! a different matter: those travel as signed DSSE envelopes in the
//! registry, and clause 1's digest check exists precisely because a
//! committed index and a registry can disagree.
//!
//! # No line-status file: starting from an empty document
//!
//! A line with no `line-status/<line>.json` yet has never had a correction.
//! [`bootstrap_document`] starts it at counter 0, with the NEWEST layer's own
//! baseline support window when the registry can produce one, and falls
//! back to `--today` otherwise — a conservative choice: it never invents a
//! LONGER support window than the clock itself, only ever the SAME one the
//! newest layer already asserts.

use crate::advisory::{self, AdvisoryError, Finding, Version};
use crate::statusdraft::{self, DraftError, Proposed};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use varve_core::{LayerRef, LayerSource, LineIndex, LineStatus};

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Everything that can stop a run. Deliberately ONE shape for every I/O,
/// network and parse failure (`Failed`) rather than a case per call site:
/// clause 4 treats all of them alike — fail the run, name the reason, write
/// nothing — and a caller never needs to match on WHICH kind of unreadable
/// source this was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WatchError {
    #[error("{context}: {detail}")]
    Failed { context: String, detail: String },
    #[error(transparent)]
    Advisory(#[from] AdvisoryError),
    #[error(transparent)]
    Draft(#[from] DraftError),
}

fn failed(context: impl Into<String>, detail: impl std::fmt::Display) -> WatchError {
    WatchError::Failed {
        context: context.into(),
        detail: detail.to_string(),
    }
}

// ---------------------------------------------------------------------
// The seam to `gh` — scripted in tests, real `GhSource` in production.
// ---------------------------------------------------------------------

/// Everything the watcher asks of `gh`. The real implementation runs
/// through [`crate::source::GhSource`] (see the `impl` at the bottom of this
/// file); tests substitute a fake, so nothing in this module's own logic
/// ever touches a network.
pub trait AdvisoryGh {
    /// Every PUBLISHED security advisory of one repository
    /// (REQ-ADVISORYWATCH-001 clause 4a).
    fn security_advisories(&self, repo: &str) -> Result<String, WatchError>;
    /// The `.md` filenames a RustSec crate directory lists, or `None` when
    /// the crate has never had one (a 404 — not a failure).
    fn rustsec_crate_dir(&self, krate: &str) -> Result<Option<Vec<String>>, WatchError>;
    /// One RustSec advisory file's raw markdown.
    fn rustsec_advisory_md(&self, krate: &str, filename: &str) -> Result<String, WatchError>;
    /// One release asset's bytes — the RECORDED upstream SBOM, named by a
    /// layer manifest's own `ANN_SBOM` annotation (clause 4b).
    fn release_asset(&self, repo: &str, release: &str, asset: &str) -> Result<Vec<u8>, WatchError>;
    /// The release's OWN upstream SBOM, admitted through its own verified
    /// proof — the fallback for a payload whose manifest recorded no
    /// `ANN_SBOM` at all (clause 4b). Infallible by design: every way this
    /// can fail is a fact about the release, reported, never a reason to
    /// abort the run — see [`crate::orchestrate::ReleaseSbomOutcome`].
    fn release_sbom(
        &self,
        repo: &str,
        release: &str,
        version: &str,
    ) -> crate::orchestrate::ReleaseSbomOutcome;
}

// ---------------------------------------------------------------------
// Payloads: what one layer's signed manifest actually carries.
// ---------------------------------------------------------------------

/// One payload a layer's signed manifest names, as read off its
/// annotations (REQ-ADVISORYWATCH-001 clause 3). Not yet de-duplicated —
/// [`dedup_payloads`] does that across every layer and platform of a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub tool: String,
    pub repo: String,
    pub version: String,
    pub release: String,
    pub sbom_asset: Option<String>,
    pub sbom_sha256: Option<String>,
    /// The entry is `kind = crate`: its tool annotation is its own crate
    /// name, checked against RustSec by that name and `version`
    /// (REQ-ADVISORYWATCH-002 clause 2).
    pub is_crate: bool,
}

/// What the watcher could not check about one manifest entry, and why.
///
/// An entry used to be dropped silently when it lacked a version or a source
/// repository, and an included layer or a non-tool entry never reached the
/// report at all — so a line carrying them read "nothing new" over bytes
/// nobody had looked at (REQ-ADVISORYWATCH-001 clause 1: every payload is
/// checked, and one that cannot be is said so, never skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotChecked {
    /// A tool entry that names something but not enough to ask an upstream
    /// about it, or an included layer. Reported one by one.
    Entry(UncheckedReport),
    /// An entry of a kind that is not a tool (crate, sdk, docs, ...). Reported
    /// once per kind with a distinct count, keyed by `digest`.
    OfKind { kind: String, digest: String },
}

/// One manifest entry, classified: a [`Payload`] the watcher can check, or
/// the reason it cannot.
pub fn classify_entry(entry: &varve_core::manifest::ManifestEntry) -> Result<Payload, NotChecked> {
    use varve_core::PayloadKind;
    let ann = |k: &str| entry.annotations.get(k).cloned();
    let tool_name = ann("eu.pulseengine.tool");
    match entry.kind() {
        Ok(PayloadKind::Layer) => {
            let layer =
                ann(varve_core::compose::ANN_INCLUDE_LAYER).unwrap_or_else(|| entry.digest.clone());
            return Err(NotChecked::Entry(UncheckedReport {
                tool: "included layer".to_string(),
                version: layer,
                repo: ann(varve_core::compose::ANN_INCLUDE_REALM)
                    .unwrap_or_else(|| "-".to_string()),
                reason: "an included layer: this run reads the payloads of this line's own \
                         layers, so advisories against what the included layer carries are \
                         checked only where the realm that publishes it is watched, never here"
                    .to_string(),
            }));
        }
        Ok(PayloadKind::Tool) => {}
        Ok(other) if tool_name.is_none() => {
            return Err(NotChecked::OfKind {
                kind: other.to_string(),
                digest: entry.digest.clone(),
            });
        }
        Ok(_) => {}
        Err(e) => {
            return Err(NotChecked::Entry(UncheckedReport {
                tool: tool_name.unwrap_or_else(|| entry.digest.clone()),
                version: ann("eu.pulseengine.tool.version").unwrap_or_else(|| "-".to_string()),
                repo: ann("eu.pulseengine.source.repo").unwrap_or_else(|| "-".to_string()),
                reason: format!("an entry of a payload kind this build does not know ({e})"),
            }));
        }
    }
    let unchecked = |tool: String, reason: &str| {
        NotChecked::Entry(UncheckedReport {
            tool,
            version: ann("eu.pulseengine.tool.version").unwrap_or_else(|| "-".to_string()),
            repo: ann("eu.pulseengine.source.repo").unwrap_or_else(|| "-".to_string()),
            reason: reason.to_string(),
        })
    };
    let Some(tool) = tool_name else {
        return Err(unchecked(
            entry.digest.clone(),
            "no eu.pulseengine.tool annotation, so the entry names no tool to check",
        ));
    };
    let Some(version) = ann("eu.pulseengine.tool.version") else {
        return Err(unchecked(
            tool,
            "no eu.pulseengine.tool.version annotation, so there is no exact version to match \
             an advisory's range against",
        ));
    };
    let Some(repo) = ann("eu.pulseengine.source.repo") else {
        return Err(unchecked(
            tool,
            "no eu.pulseengine.source.repo annotation, so there is no upstream repository to ask \
             for advisories",
        ));
    };
    let release = ann("eu.pulseengine.source.release").unwrap_or_else(|| version.clone());
    Ok(Payload {
        tool,
        repo,
        version,
        release,
        sbom_asset: ann(varve_core::ANN_SBOM),
        sbom_sha256: ann(varve_core::ANN_SBOM_SHA256),
        is_crate: matches!(entry.kind(), Ok(PayloadKind::Crate)),
    })
}

/// One manifest entry as a [`Payload`], or `None` when it is not one. The
/// reason it is not is [`classify_entry`]'s to give; a caller that discards it
/// must say so elsewhere.
pub fn payload_from_entry(entry: &varve_core::manifest::ManifestEntry) -> Option<Payload> {
    classify_entry(entry).ok()
}

/// Every payload one layer's signed manifest carries, across every entry
/// (platform) it has, and everything else it carries that cannot be checked.
pub fn payloads_from_manifest(
    manifest: &varve_core::LayerManifest,
) -> (Vec<Payload>, Vec<NotChecked>) {
    let mut payloads = Vec::new();
    let mut not_checked = Vec::new();
    for entry in &manifest.entries {
        match classify_entry(entry) {
            Ok(p) => payloads.push(p),
            Err(n) => not_checked.push(n),
        }
    }
    (payloads, not_checked)
}

/// Fold what every layer of a line could not check into report entries:
/// individual ones de-duplicated (the same tool entry recurs per platform and
/// per layer), non-tool kinds once each with a distinct count.
pub fn unchecked_from_not_checked(items: &[NotChecked]) -> Vec<UncheckedReport> {
    let mut out: Vec<UncheckedReport> = Vec::new();
    let mut by_kind: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for item in items {
        match item {
            NotChecked::Entry(r) => {
                if !out.contains(r) {
                    out.push(r.clone());
                }
            }
            NotChecked::OfKind { kind, digest } => {
                by_kind.entry(kind).or_default().insert(digest);
            }
        }
    }
    for (kind, digests) in by_kind {
        out.push(UncheckedReport {
            tool: format!("{kind} entries"),
            version: format!("{} distinct", digests.len()),
            repo: "-".to_string(),
            reason: format!(
                "an entry of kind {kind} is not a tool payload: this watcher checks tool \
                 payloads against their upstream repository's advisories and does not check \
                 this kind"
            ),
        });
    }
    out
}

/// One (repo, version) payload, de-duplicated across every layer and
/// platform of a line, and the full list of layers that carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupedPayload {
    pub is_crate: bool,
    pub repo: String,
    pub version: String,
    pub release: String,
    pub tool: String,
    pub sbom_asset: Option<String>,
    pub sbom_sha256: Option<String>,
    /// Layers of this line that carry this exact (repo, version), sorted.
    pub layers: Vec<String>,
}

/// De-duplicate by (repo, version, release, tool) across every layer and platform of a
/// line (REQ-ADVISORYWATCH-001 clause 3). `per_layer` is `(layer id,
/// payloads that layer's manifest carries)`.
///
/// An SBOM annotation absent from one platform's entry but present on a
/// sibling's is carried forward — every entry for one (repo, version) is
/// the same release, so this is filling in what one entry happened to omit,
/// never choosing between two different claims.
///
/// The release and the tool name are part of the key (REQ-ADVISORYWATCH-002
/// clauses 4 and 5): two releases of one repository and version each have
/// their own SBOM, and an advisory is matched against the package that names
/// the payload, so a payload cannot lose its name to a sibling's.
pub fn dedup_payloads(per_layer: &[(String, Vec<Payload>)]) -> Vec<DedupedPayload> {
    type Key = (String, String, String, String, bool);
    let mut by_key: BTreeMap<Key, DedupedPayload> = BTreeMap::new();
    for (layer, payloads) in per_layer {
        for p in payloads {
            let key = (
                p.repo.clone(),
                p.version.clone(),
                p.release.clone(),
                p.tool.clone(),
                p.is_crate,
            );
            let entry = by_key.entry(key).or_insert_with(|| DedupedPayload {
                is_crate: p.is_crate,
                repo: p.repo.clone(),
                version: p.version.clone(),
                release: p.release.clone(),
                tool: p.tool.clone(),
                sbom_asset: None,
                sbom_sha256: None,
                layers: Vec::new(),
            });
            if entry.sbom_asset.is_none() {
                entry.sbom_asset = p.sbom_asset.clone();
            }
            if entry.sbom_sha256.is_none() {
                entry.sbom_sha256 = p.sbom_sha256.clone();
            }
            if !entry.layers.iter().any(|l| l == layer) {
                entry.layers.push(layer.clone());
            }
        }
    }
    let mut out: Vec<DedupedPayload> = by_key.into_values().collect();
    for d in &mut out {
        // By LAYER NUMBER, not lexicographically — `2026.10.9` must sort
        // before `2026.10.10`. Same `sort_by_key(|id|
        // id.parse::<LayerId>().ok())` pattern `LineIndex::newer_than`
        // already uses: `LayerId`'s derived `Ord` compares its `patch`
        // field numerically.
        d.layers
            .sort_by_key(|l| l.parse::<varve_core::LayerId>().ok());
    }
    // `by_key` iterates in key order: repo, version, release, tool, kind.
    out
}

// ---------------------------------------------------------------------
// Expiry and bootstrap (clause 2).
// ---------------------------------------------------------------------

/// Is a line's committed support window already over, as of `today`?
///
/// `support_until` and `today` are both ISO-8601 dates (`YYYY-MM-DD`), and a
/// `support_until` carrying extra time-of-day text still compares correctly
/// against a bare date, because an ISO-8601 prefix orders the same way as a
/// string prefix: `"2026-10-15" < "2026-10-15T00:00:00Z"` exactly as
/// `2026-10-15 < 2026-10-15, later that same day` does.
///
/// Absent (`None`) means the line's committed status has never stated an
/// end, which this reads as "never expires" — a line with no stated end has
/// not been told to stop, and skipping it on that basis would be guessing a
/// date nobody wrote down.
pub fn line_is_expired(support_until: Option<&str>, today: &str) -> bool {
    match support_until {
        Some(s) => s < today,
        None => false,
    }
}

/// The empty document a line with no committed `line-status/<line>.json`
/// starts from (clause 2, documented choice): counter 0, issued today, and
/// the support window the caller already worked out — the newest layer's
/// own baseline when the registry could produce one, `today` otherwise.
pub fn bootstrap_document(line: &str, today: &str, support_until: Option<String>) -> LineStatus {
    LineStatus {
        line: line.to_string(),
        counter: 0,
        issued_at: today.to_string(),
        support_until,
        min_counter: None,
        yanked: BTreeMap::new(),
        known_problems: Vec::new(),
    }
}

/// Peek a RELEASED DSSE payload's `support-until` field, WITHOUT verifying
/// its signature — exactly the same deliberate choice
/// [`crate::nextlayer::counter_in_envelope`] already documents for a
/// scheduling question: this only sets a bootstrap default a human reviews
/// before anything signs, and every failure mode here falls back to
/// `today`, never to a guess that looks more confident than it is.
fn peek_support_until(envelope_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(envelope_bytes).ok()?;
    let env = wsc::dsse::DsseEnvelope::from_json(text).ok()?;
    let payload = env.payload_bytes().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    v.get("support-until")
        .and_then(|s| s.as_str())
        .map(str::to_string)
}

// ---------------------------------------------------------------------
// GHSA: which package names a repository's advisories even mention.
// ---------------------------------------------------------------------

/// Every distinct `vulnerabilities[].package.name` across a repository's
/// fetched GHSA JSON.
///
/// A repository-wide security advisory versions every internal package in
/// lockstep (the requirement's own observation: "the payload IS the
/// release"), and GitHub's advisory can name any of several internal crate
/// names for ONE monorepo release. Querying every name that is PRESENT,
/// rather than only the varve payload's own tool name, is what
/// `ghsa_for_payload` below does — this is the enumeration step
/// (REQ-ADVISORYWATCH-001 clause 4a: "Use `ghsa_findings` per package name
/// present and union").
pub fn ghsa_package_names(json: &str) -> Result<Vec<String>, WatchError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| failed("GHSA advisories JSON", e))?;
    let arr = v.as_array().ok_or_else(|| {
        failed(
            "GHSA advisories JSON",
            "expected a JSON array of advisories",
        )
    })?;
    let mut names = BTreeSet::new();
    for advisory in arr {
        let Some(vulns) = advisory.get("vulnerabilities").and_then(|v| v.as_array()) else {
            continue;
        };
        for vuln in vulns {
            if let Some(name) = vuln
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                names.insert(name.to_string());
            }
        }
    }
    Ok(names.into_iter().collect())
}

/// What a repository's GHSA advisories say about one payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PayloadGhsa {
    /// Advisories whose vulnerable range names the payload itself: certain.
    pub findings: Vec<Finding>,
    /// Advisories naming only OTHER packages of the same repository, whose
    /// range covers the payload's version, with the sibling packages that
    /// matched. Affected only if the payload embeds that crate, so they are
    /// findings, but qualified (REQ-ADVISORYWATCH-002 clause 5).
    pub qualified: Vec<(Finding, Vec<String>)>,
    pub undecidable: Vec<advisory::Undecidable>,
}

/// The qualifier text a sibling-package finding carries in the line-status
/// entry's `detection` field. The fixed `qualified:` prefix keeps it
/// machine-readable; an exact match has no `detection` at all.
pub fn qualifier(packages: &[String], repo: &str) -> String {
    format!(
        "qualified: names {} from the same repository ({repo}); affects this binary if it \
         embeds that crate",
        packages.join(", ")
    )
}

/// Every finding and every undecidable advisory affecting `version` in the
/// repository's GHSA JSON, split by whether the advisory's range names the
/// payload (`own_names`, certain) or only a sibling package of the same
/// repository (qualified). An advisory that names the payload is certain
/// even when it also lists siblings. A single advisory id is kept at most
/// once in each list. A sibling whose range does not cover `version` is not
/// a finding at all.
pub fn ghsa_for_payload(
    json: &str,
    version: &Version,
    own_names: &[String],
) -> Result<PayloadGhsa, WatchError> {
    let mut out = PayloadGhsa::default();
    for name in ghsa_package_names(json)? {
        let own = own_names.contains(&name);
        let r = advisory::ghsa_findings(json, &name, version)?;
        for f in r.findings {
            if own {
                if !out.findings.iter().any(|e| e.id == f.id) {
                    out.findings.push(f);
                }
            } else if let Some((_, pkgs)) = out.qualified.iter_mut().find(|(e, _)| e.id == f.id) {
                pkgs.push(name.clone());
            } else {
                out.qualified.push((f, vec![name.clone()]));
            }
        }
        for u in r.undecidable {
            // By id alone: one advisory is one row in the report no matter
            // which package name's query surfaced it.
            if !out.undecidable.iter().any(|e| e.id == u.id) {
                out.undecidable.push(u);
            }
        }
    }
    let exact: Vec<String> = out.findings.iter().map(|f| f.id.clone()).collect();
    out.qualified.retain(|(f, _)| !exact.contains(&f.id));
    Ok(out)
}

/// One advisory can reach the draft through several payloads. If ANY of them
/// matched it exactly, the layer is certainly affected, so the entry is
/// certain everywhere: understating a security finding is the worse error
/// (maintainer, 2026-10-29). Only an advisory that every payload matched as a
/// sibling package keeps its qualifier.
pub fn unify_qualifiers(proposed: &mut [Proposed]) {
    let exact: Vec<String> = proposed
        .iter()
        .filter(|p| p.detection.is_none())
        .map(|p| p.id.clone())
        .collect();
    for p in proposed.iter_mut() {
        if exact.contains(&p.id) {
            p.detection = None;
        }
    }
}

// ---------------------------------------------------------------------
// RustSec: metadata `rustsec_finding` has no reason to expose.
// ---------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize)]
struct RustSecExtraDoc {
    #[serde(default)]
    advisory: RustSecExtraMeta,
}

#[derive(Debug, Default, serde::Deserialize)]
struct RustSecExtraMeta {
    #[serde(default)]
    withdrawn: Option<toml::Value>,
    #[serde(default)]
    cvss: Option<String>,
}

/// Whether a RustSec advisory is withdrawn, and its raw CVSS vector when it
/// states one — read from the SAME TOML fence `rustsec_finding` parses
/// (clause 4c: a withdrawn advisory is skipped entirely; clause 5 computes
/// severity from `cvss` when present).
pub fn rustsec_extra(md: &str) -> Result<(bool, Option<String>), WatchError> {
    let fence = advisory::extract_toml_fence(md)?;
    let doc: RustSecExtraDoc =
        toml::from_str(fence).map_err(|e| failed("RustSec advisory TOML", e))?;
    Ok((doc.advisory.withdrawn.is_some(), doc.advisory.cvss))
}

/// The text of the first `# ` heading in a RustSec advisory's markdown — the
/// title clause 5 names for a RustSec finding, distinct from the TOML
/// fence's own `title` field that [`advisory::rustsec_finding`] uses for its
/// `Finding::summary`.
pub fn first_heading(md: &str) -> Option<String> {
    md.lines()
        .find_map(|l| l.strip_prefix("# ").map(|t| t.trim().to_string()))
}

// ---------------------------------------------------------------------
// Upstream SBOM components (clause 4b).
// ---------------------------------------------------------------------

/// One component of a CycloneDX upstream SBOM, as the SBOM states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
}

fn component_of(value: &serde_json::Value) -> Option<SbomComponent> {
    let text = |k: &str| value.get(k).and_then(|x| x.as_str()).map(str::to_string);
    Some(SbomComponent {
        name: text("name")?,
        version: text("version"),
        purl: text("purl"),
    })
}

/// Walk `components[]` and every `components[]` nested inside a component,
/// however deep (CycloneDX nests; a walk that stops at the first level skips
/// what the nested components carry). Recursion is bounded by serde_json's
/// own parse depth limit.
fn walk_components(value: &serde_json::Value, into: &mut Vec<SbomComponent>) {
    let Some(comps) = value.get("components").and_then(|c| c.as_array()) else {
        return;
    };
    for c in comps {
        if let Some(sc) = component_of(c) {
            into.push(sc);
        }
        walk_components(c, into);
    }
}

/// Every component a CycloneDX upstream SBOM names — `metadata.component`
/// (the subject itself, and what is nested in it) plus every entry of
/// `components[]`, nested ones included (REQ-ADVISORYWATCH-002 clause 3).
pub fn sbom_components(bytes: &[u8]) -> Result<Vec<SbomComponent>, WatchError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| failed("upstream SBOM", e))?;
    let mut out = Vec::new();
    if let Some(mc) = v.get("metadata").and_then(|m| m.get("component")) {
        if let Some(sc) = component_of(mc) {
            out.push(sc);
        }
        walk_components(mc, &mut out);
    }
    walk_components(&v, &mut out);
    Ok(out)
}

/// The ecosystem a purl names, lowercased: `pkg:cargo/serde@1` is `cargo`.
/// `None` for text that is not a purl. Ecosystem is decided by THIS, never
/// by a bare component name, so an npm package called `serde` cannot match a
/// crate advisory (REQ-ADVISORYWATCH-002 clause 3).
pub fn purl_type(purl: &str) -> Option<String> {
    let rest = purl.strip_prefix("pkg:")?;
    let ty = rest.split('/').next()?;
    if ty.is_empty() || ty.len() == rest.len() {
        return None;
    }
    Some(ty.to_ascii_lowercase())
}

/// The package name a `pkg:cargo/<name>@<version>?...#...` purl names. A
/// nested bin-target component shares its parent crate's purl, so the purl —
/// not the component's display name — says which crate it is.
fn cargo_purl_name(purl: &str) -> String {
    // Only called for a purl whose type was read, which needs a `/`.
    let after = purl.split_once('/').map_or("", |(_, after)| after);
    // An empty or malformed name is returned as is: the caller refuses it
    // as "not a valid crate name" before it is ever looked up.
    after
        .split(['@', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// What one SBOM component is to the RustSec check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentClass {
    /// A crate with a version: look it up by this name and version.
    Crate { name: String, version: String },
    /// Not checkable, and why.
    Unchecked(String),
}

/// Decide what to do with one component: check it, or say why not.
pub fn classify_component(c: &SbomComponent) -> ComponentClass {
    let Some(purl) = c.purl.as_deref() else {
        return ComponentClass::Unchecked(format!(
            "SBOM component {} has no purl, so its ecosystem is unknown and a bare name is \
             never matched against crate advisories",
            c.name
        ));
    };
    match purl_type(purl).as_deref() {
        Some("cargo") => {}
        Some(other) => {
            return ComponentClass::Unchecked(format!(
                "SBOM component {} is of ecosystem {other} (purl type), which RustSec does \
                 not cover",
                c.name
            ));
        }
        None => {
            return ComponentClass::Unchecked(format!(
                "SBOM component {} has a purl this watcher cannot read ({purl}), so its \
                 ecosystem is unknown",
                c.name
            ));
        }
    }
    let Some(version) = c.version.clone() else {
        return ComponentClass::Unchecked(format!(
            "SBOM component {} has no version, so there is no exact version to match an \
             advisory's range against",
            c.name
        ));
    };
    let name = cargo_purl_name(purl);
    ComponentClass::Crate { name, version }
}

/// The sha256 of `bytes`, as lowercase hex — the same form `layer.toml`
/// records in [`varve_core::ANN_SBOM_SHA256`].
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------
// Titles and severities (clause 5).
// ---------------------------------------------------------------------

/// `"<tool> <version>: <summary> (fixed in <patched>)"`.
pub fn ghsa_title(tool: &str, version: &str, finding: &Finding) -> String {
    let patched = if finding.patched.is_empty() {
        "unspecified".to_string()
    } else {
        finding.patched.join(", ")
    };
    format!("{tool} {version}: {} (fixed in {patched})", finding.summary)
}

/// `"<tool> <version> embeds <crate> <ver>: <title>"`.
pub fn rustsec_title(tool: &str, version: &str, krate: &str, kver: &str, title: &str) -> String {
    format!("{tool} {version} embeds {krate} {kver}: {title}")
}

/// GHSA's own `severity`, lower-cased — or `("medium", Some(reason))` when
/// the advisory carries none. Severity is METADATA, never the affected
/// decision (REQ-ADVISORYWATCH-001's own severity-never-aborts rule): an
/// advisory this run could not read a severity for is still a real,
/// affected finding, reported with a defaulted severity and the reason —
/// never a reason to drop the finding, let alone abort the run.
pub fn ghsa_severity(finding: &Finding) -> (String, Option<String>) {
    match &finding.severity {
        Some(s) if !s.trim().is_empty() => (s.to_ascii_lowercase(), None),
        _ => ("medium".to_string(), Some("no stated severity".to_string())),
    }
}

/// Why a CVSS vector could not be scored, for the defaulted-severity
/// report: names the version it claims when that is readable (`"CVSS:4.0
/// vector, not scored"`), or says the vector itself could not be read at
/// all (a genuinely malformed `CVSS:3.1`/`CVSS:3.0` vector, or text with no
/// recognisable `CVSS:` prefix).
fn cvss_unscored_reason(vector: &str) -> String {
    match vector.split('/').next() {
        Some(prefix) if prefix == "CVSS:3.1" || prefix == "CVSS:3.0" => {
            "CVSS vector could not be read".to_string()
        }
        Some(prefix) if prefix.starts_with("CVSS:") => format!("{prefix} vector, not scored"),
        _ => "CVSS vector could not be read".to_string(),
    }
}

/// The `"owner/repo"` ANY `https://github.com/<owner>/<repo>/...` URL
/// names — a PR, a commit, an issue, a security advisory, whatever it
/// points at — the fallback severity source's REPOSITORY for a RustSec
/// advisory whose own CVSS vector cannot be scored
/// (REQ-ADVISORYWATCH-001's GHSA-alias-severity rule). Widened after a
/// live run: wasmtime's own RustSec entries name a PULL REQUEST in `url`
/// (`.../pull/14729`), not a `/security/advisories/` link, so the
/// repository has to come from ANY github.com URL shape, not only that
/// one. Both path segments are validated the same way every other
/// untrusted-text-into-a-request-path site in this crate is.
pub fn github_repo_from_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    let mut parts = rest.splitn(3, '/');
    let owner = parts
        .next()
        .filter(|s| crate::gh::is_valid_github_name(s))?;
    let repo = parts
        .next()
        .filter(|s| crate::gh::is_valid_github_name(s))?;
    Some(format!("{owner}/{repo}"))
}

/// The GHSA id a `url` of the exact shape
/// `https://github.com/<owner>/<repo>/security/advisories/<GHSA-id>`
/// itself names — narrower than [`github_repo_from_url`]: this only
/// fires when the URL IS the advisory, not merely something in the same
/// repository (a PR, say).
pub fn ghsa_id_from_advisory_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    let mut parts = rest.splitn(5, '/');
    parts
        .next()
        .filter(|s| crate::gh::is_valid_github_name(s))?;
    parts
        .next()
        .filter(|s| crate::gh::is_valid_github_name(s))?;
    if parts.next()? != "security" {
        return None;
    }
    if parts.next()? != "advisories" {
        return None;
    }
    let ghsa_id = parts.next()?;
    if !ghsa_id.starts_with("GHSA-") {
        return None;
    }
    Some(ghsa_id.to_string())
}

/// The first alias that is itself a GHSA id — RustSec's own place for a
/// GHSA cross-reference when `url` names something else entirely (a PR,
/// a commit), as wasmtime's real advisories do
/// (REQ-ADVISORYWATCH-001's GHSA-alias-severity rule, widened).
pub fn first_ghsa_alias(aliases: &[String]) -> Option<String> {
    aliases.iter().find(|a| a.starts_with("GHSA-")).cloned()
}

/// The `severity` a repository's fetched GHSA JSON states for one
/// advisory id, lower-cased — or `None` when that id is not in the
/// listing, or states no severity itself.
pub fn ghsa_severity_by_id(json: &str, ghsa_id: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let arr = v.as_array()?;
    for advisory in arr {
        if advisory.get("ghsa_id").and_then(|g| g.as_str()) == Some(ghsa_id) {
            return advisory
                .get("severity")
                .and_then(|s| s.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_ascii_lowercase);
        }
    }
    None
}

/// Severity from a RustSec advisory's CVSS vector — NEVER a hard error.
/// Severity is metadata, not the affected decision
/// (REQ-ADVISORYWATCH-001's severity-never-aborts rule, from a live run
/// that aborted entirely on one advisory's `CVSS:4.0` vector): a vector
/// this module cannot score — no vector at all, a version other than
/// `3.1`/`3.0` (this module does not implement CVSS 4.0, 2.0, or any other
/// scoring model), or one that claims `3.1`/`3.0` but is otherwise
/// malformed — yields `("medium", Some(reason))` rather than aborting. A
/// computed "none" (score 0.0) is mapped to "low" — not a shape RustSec
/// actually publishes, and `statusdraft` has no "none" severity to carry
/// it in.
pub fn rustsec_severity(cvss: Option<&str>) -> (String, Option<String>) {
    let Some(vector) = cvss else {
        return ("medium".to_string(), Some("no cvss vector".to_string()));
    };
    match crate::cvss::base_score(vector) {
        Ok(score) => {
            let label = crate::cvss::severity_label(score);
            let mapped = if label == "none" { "low" } else { label };
            (mapped.to_string(), None)
        }
        Err(_) => ("medium".to_string(), Some(cvss_unscored_reason(vector))),
    }
}

// ---------------------------------------------------------------------
// Reports.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct UndecidableReport {
    pub id: String,
    pub package: String,
    pub reason: String,
}

/// A RustSec `informational` advisory — NOT a vulnerability, never a
/// `KnownProblem`, but never silently dropped either
/// (REQ-ADVISORYWATCH-001's informational-advisories rule).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct NoteReport {
    pub id: String,
    pub package: String,
    pub kind: String,
    pub title: String,
}

/// An advisory id whose severity, unreadable from its own CVSS vector, was
/// instead read from a repository security advisory its `url` names
/// (REQ-ADVISORYWATCH-001's GHSA-alias-severity rule) — recorded so the
/// severity's actual source is traceable, not merely "not defaulted".
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct SeverityFromGhsaReport {
    pub id: String,
    pub ghsa_id: String,
}

/// Every report list keyed on an advisory id de-duplicates by it — the
/// SAME advisory, reached through more than one payload or component, is
/// one entry, not one per payload (REQ-ADVISORYWATCH-001's dedup rule).
trait HasId {
    fn id(&self) -> &str;
}
impl HasId for UndecidableReport {
    fn id(&self) -> &str {
        &self.id
    }
}
impl HasId for DefaultedSeverityReport {
    fn id(&self) -> &str {
        &self.id
    }
}
impl HasId for NoteReport {
    fn id(&self) -> &str {
        &self.id
    }
}
impl HasId for SeverityFromGhsaReport {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Push `item` onto `list` unless an entry with the same id is already
/// there.
fn push_unique<T: HasId>(list: &mut Vec<T>, item: T) {
    if !list.iter().any(|existing| existing.id() == item.id()) {
        list.push(item);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct LineReport {
    pub line: String,
    pub skipped_expired: bool,
    pub wrote: bool,
    /// Advisory ids that are brand new known-problems in this line.
    pub new_known_problems: Vec<String>,
    /// Advisory ids that already existed, and the layers newly added to
    /// their `affected` list by this run.
    pub newly_affected: BTreeMap<String, Vec<String>>,
    pub undecidable: Vec<UndecidableReport>,
    /// Advisory ids whose severity this run could not read from the source
    /// and defaulted to "medium", with why — never a reason to drop the
    /// finding or abort the run (severity is metadata, not the affected
    /// decision).
    pub defaulted_severities: Vec<DefaultedSeverityReport>,
    /// An SBOM component name or a RustSec directory listing entry that was
    /// never queried at all, and why (REQ-ADVISORYWATCH-001 clause 4): a
    /// name that cannot be a real crate, or a filename that is not the real
    /// shape of a RustSec advisory. Reported, never silently dropped — and
    /// never queried, because `name`/`filename` here are untrusted text
    /// this run does not control.
    pub skipped: Vec<SkippedReport>,
    /// Payloads whose advisory check was INCOMPLETE this run, and why —
    /// embedded components that could not be checked (REQ-ADVISORYWATCH-001
    /// clause 4b's fallback), the payload's own version could not be read
    /// for the GHSA comparison, or a manifest entry that never became a
    /// payload at all (no version, no source repository, an included layer, a
    /// non-tool kind — see [`NotChecked`]). Never silently absorbed into
    /// "nothing new" — see [`UncheckedReport`].
    pub unchecked: Vec<UncheckedReport>,
    /// RustSec `informational` advisories (`"unmaintained"`, `"notice"`) —
    /// never a `KnownProblem`, never silently dropped either.
    pub notes: Vec<NoteReport>,
    /// Advisory ids whose severity was read from a GHSA alias rather than
    /// scored or defaulted — see [`SeverityFromGhsaReport`].
    pub severity_from_ghsa: Vec<SeverityFromGhsaReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SkippedReport {
    pub what: String,
    pub reason: String,
}

/// An advisory id whose severity this run defaulted to "medium", and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DefaultedSeverityReport {
    pub id: String,
    pub reason: String,
}

/// One payload whose embedded components this run did NOT check — never
/// silently folded into "nothing new" (REQ-ADVISORYWATCH-001 clause 4b's
/// fallback). A coverage gap, not a read failure: the GHSA check for this
/// exact payload still ran and is reported normally.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UncheckedReport {
    pub tool: String,
    pub version: String,
    pub repo: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct RunReport {
    pub lines: Vec<LineReport>,
}

/// One payload's unchecked entry, rendered for a human:
/// `"<tool> <version> (<repo>): <reason>"`.
fn render_unchecked_one(u: &UncheckedReport) -> String {
    format!("{} {} ({}): {}", u.tool, u.version, u.repo, u.reason)
}

fn render_unchecked_list(items: &[UncheckedReport]) -> String {
    items
        .iter()
        .map(render_unchecked_one)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The human-readable report for ONE line, including a trailing newline.
///
/// The word "nothing new" must NEVER appear alone when `unchecked` is
/// non-empty (REQ-ADVISORYWATCH-001 clause 4b's fallback, clause 2 of the
/// supervisor review that found it fail-open): a payload this run could not
/// check for embedded components is a coverage gap, and burying it is
/// exactly what let `wsc` 0.11.0's embedded `rustls` 0.23.34 go unreported
/// against a live realm while this printed "nothing new".
pub fn render_line(line: &LineReport) -> String {
    let mut out = String::new();
    if line.skipped_expired {
        out.push_str(&format!(
            "{}\tskipped (support-until has passed)\n",
            line.line
        ));
        return out;
    }
    if line.wrote {
        out.push_str(&format!(
            "{}\twrote line-status/{}.json\n",
            line.line, line.line
        ));
    } else if line.unchecked.is_empty() {
        out.push_str(&format!("{}\tnothing new\n", line.line));
    } else {
        out.push_str(&format!(
            "{}\tnothing new among checked payloads; {} item(s) NOT checked: {}\n",
            line.line,
            line.unchecked.len(),
            render_unchecked_list(&line.unchecked),
        ));
    }
    for id in &line.new_known_problems {
        out.push_str(&format!("  new known problem: {id}\n"));
    }
    for (id, layers) in &line.newly_affected {
        out.push_str(&format!("  {id}: newly affects {}\n", layers.join(", ")));
    }
    for d in &line.defaulted_severities {
        out.push_str(&format!(
            "  {}: defaulted to medium severity ({})\n",
            d.id, d.reason
        ));
    }
    for g in &line.severity_from_ghsa {
        out.push_str(&format!(
            "  {}: severity from its GHSA alias {}\n",
            g.id, g.ghsa_id
        ));
    }
    for n in &line.notes {
        out.push_str(&format!(
            "  note: {} ({}, {}): {}\n",
            n.id, n.package, n.kind, n.title
        ));
    }
    for u in &line.undecidable {
        out.push_str(&format!(
            "  undecidable: {} ({}): {}\n",
            u.id, u.package, u.reason
        ));
    }
    for s in &line.skipped {
        out.push_str(&format!("  skipped: {} ({})\n", s.what, s.reason));
    }
    // A line that DID write something must still say which payloads were
    // not checked for embedded components — the headline above only
    // carries that sentence when "nothing new" is the whole story.
    if line.wrote && !line.unchecked.is_empty() {
        out.push_str(&format!(
            "  {} item(s) NOT checked: {}\n",
            line.unchecked.len(),
            render_unchecked_list(&line.unchecked),
        ));
    }
    out
}

/// The human-readable report for a whole run.
pub fn human_summary(report: &RunReport) -> String {
    if report.lines.is_empty() {
        return "no committed lines (line-index/*.json) found\n".to_string();
    }
    report.lines.iter().map(render_line).collect()
}

// ---------------------------------------------------------------------
// Per-line caches — each source fetched ONCE per key for the whole run.
// ---------------------------------------------------------------------

#[derive(Default)]
struct Caches {
    ghsa: BTreeMap<String, String>,
    rustsec_dir: BTreeMap<String, Option<Vec<String>>>,
    rustsec_md: BTreeMap<(String, String), String>,
    sbom: BTreeMap<(String, String, String), Vec<u8>>,
    /// (repo, release, payload version) -> the release's own SBOM, admitted
    /// through its own proof. Keyed on the payload version too, not only
    /// (repo, release): a hub release can publish several `.cdx.json`
    /// assets disambiguated by version, and two payloads sharing a release
    /// but not a version could otherwise read each other's cached
    /// selection.
    release_sbom: BTreeMap<(String, String, String), crate::orchestrate::ReleaseSbomOutcome>,
}

// ---------------------------------------------------------------------
// One line.
// ---------------------------------------------------------------------

struct PendingWrite {
    path: PathBuf,
    document: LineStatus,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, WatchError> {
    let text = std::fs::read_to_string(path).map_err(|e| failed(path.display().to_string(), e))?;
    serde_json::from_str(&text).map_err(|e| failed(path.display().to_string(), e))
}

fn watch_line<G: AdvisoryGh, S: LayerSource>(
    gh: &G,
    registry: &S,
    line: &str,
    index_path: &Path,
    status_path: &Path,
    today: &str,
    caches: &mut Caches,
) -> Result<(LineReport, Option<PendingWrite>), WatchError> {
    let index: LineIndex = read_json(index_path)?;

    let current: Option<LineStatus> = if status_path.exists() {
        Some(read_json(status_path)?)
    } else {
        None
    };

    if let Some(cur) = &current
        && line_is_expired(cur.support_until.as_deref(), today)
    {
        return Ok((
            LineReport {
                line: line.to_string(),
                skipped_expired: true,
                ..Default::default()
            },
            None,
        ));
    }

    // Fetch every layer's signed manifest, verifying the index's own digest
    // against the registry's bytes (clause 1) before trusting anything in it.
    let mut per_layer: Vec<(String, Vec<Payload>)> = Vec::new();
    let mut not_checked: Vec<NotChecked> = Vec::new();
    for entry in &index.layers {
        let envelope = registry
            .fetch_manifest(&LayerRef::Digest(entry.digest.clone()))
            .map_err(|e| {
                failed(
                    format!("fetching layer {} ({})", entry.layer, entry.digest),
                    e,
                )
            })?;
        let text = std::str::from_utf8(&envelope).map_err(|_| {
            failed(
                format!("layer {}", entry.layer),
                "the registry's bytes are not UTF-8 DSSE JSON",
            )
        })?;
        let env = wsc::dsse::DsseEnvelope::from_json(text).map_err(|e| {
            failed(
                format!("layer {}", entry.layer),
                format!("not a DSSE envelope: {e}"),
            )
        })?;
        let payload = env.payload_bytes().map_err(|e| {
            failed(
                format!("layer {}", entry.layer),
                format!("cannot decode the DSSE payload: {e}"),
            )
        })?;
        let got = varve_core::manifest_digest(&payload);
        if got != entry.digest {
            return Err(failed(
                format!("layer {} digest", entry.layer),
                format!(
                    "the line-index for {line} says {}, but the registry's signed payload \
                     hashes to {got} — the index and the registry disagree",
                    entry.digest
                ),
            ));
        }
        let manifest = varve_core::LayerManifest::parse(&payload)
            .map_err(|e| failed(format!("layer {} manifest", entry.layer), e))?;
        let (payloads, dropped) = payloads_from_manifest(&manifest);
        per_layer.push((entry.layer.clone(), payloads));
        not_checked.extend(dropped);
    }

    let deduped = dedup_payloads(&per_layer);

    // Bootstrap support window, best-effort, from the NEWEST layer (last in
    // publication order) — never fails the run; `today` is always a sound
    // fallback.
    let newest_support_until = index.layers.last().and_then(|newest| {
        registry
            .fetch_line_status(&LayerRef::Digest(newest.digest.clone()))
            .ok()
            .flatten()
            .and_then(|env| peek_support_until(&env))
    });

    let baseline = match &current {
        Some(c) => c.clone(),
        None => bootstrap_document(
            line,
            today,
            Some(newest_support_until.unwrap_or_else(|| today.to_string())),
        ),
    };

    let mut proposed: Vec<Proposed> = Vec::new();
    let mut undecidable_report: Vec<UndecidableReport> = Vec::new();
    let mut defaulted: Vec<DefaultedSeverityReport> = Vec::new();
    let mut skipped: Vec<SkippedReport> = Vec::new();
    // What the layers carry that is not a checkable payload comes first, so
    // it is in the report even when no payload remains to be queried.
    let mut unchecked: Vec<UncheckedReport> = unchecked_from_not_checked(&not_checked);
    let mut notes: Vec<NoteReport> = Vec::new();
    let mut severity_from_ghsa: Vec<SeverityFromGhsaReport> = Vec::new();

    // GHSA (clause 1 + 4a).
    for p in &deduped {
        // The payload's OWN version — not an advisory's field, but still a
        // per-payload one: a value this parser cannot decide blocks the
        // GHSA comparison for THIS payload alone, never the whole run.
        // Checked BEFORE asking GHSA anything, same reasoning as the
        // crate-name/filename checks below: no point spending a network
        // call on a comparison this payload can never complete.
        let version = match Version::parse(&p.version) {
            Ok(v) => v,
            Err(e) => {
                unchecked.push(UncheckedReport {
                    tool: p.tool.clone(),
                    version: p.version.clone(),
                    repo: p.repo.clone(),
                    reason: format!("payload version could not be read for GHSA comparison: {e}"),
                });
                continue;
            }
        };
        let json = match caches.ghsa.get(&p.repo) {
            Some(j) => j.clone(),
            None => {
                let j = gh.security_advisories(&p.repo)?;
                caches.ghsa.insert(p.repo.clone(), j.clone());
                j
            }
        };
        // The package range that NAMES this payload is certain; a range
        // naming only a sibling package of the repository is a qualified
        // finding (REQ-ADVISORYWATCH-002 clause 5).
        let result = ghsa_for_payload(&json, &version, std::slice::from_ref(&p.tool))?;
        let exact = result.findings.iter().map(|f| (f, None));
        let qualified = result
            .qualified
            .iter()
            .map(|(f, pkgs)| (f, Some(qualifier(pkgs, &p.repo))));
        for (f, detection) in exact.chain(qualified) {
            let (severity, defaulted_reason) = ghsa_severity(f);
            if let Some(reason) = defaulted_reason {
                push_unique(
                    &mut defaulted,
                    DefaultedSeverityReport {
                        id: f.id.clone(),
                        reason,
                    },
                );
            }
            proposed.push(Proposed {
                id: f.id.clone(),
                aliases: f.aliases.clone(),
                title: ghsa_title(&p.tool, &p.version, f),
                severity,
                affected: p.layers.clone(),
                workaround: None,
                detection,
            });
        }
        for u in &result.undecidable {
            // Deduplicated across every DedupedPayload this line queries —
            // the SAME repository's undecidable advisory is checked once
            // per distinct version present, and most of the time it is
            // undecidable independent of which version asked. By id alone,
            // same reasoning as `ghsa_for_payload`'s own dedup.
            push_unique(
                &mut undecidable_report,
                UndecidableReport {
                    id: u.id.clone(),
                    package: u.package.clone(),
                    reason: format!("{:?}", u.reason),
                },
            );
        }
    }

    // Upstream SBOM -> RustSec (clause 2 + 4b + 4c).
    for p in &deduped {
        // What this payload is checked against RustSec as: a crate payload
        // is its own first component (REQ-ADVISORYWATCH-002 clause 2).
        let mut to_check: Vec<(String, String)> = Vec::new();
        if p.is_crate {
            to_check.push((p.tool.clone(), p.version.clone()));
        }
        let bytes = match (&p.sbom_asset, &p.sbom_sha256) {
            (Some(asset), Some(sha)) => {
                let key = (p.repo.clone(), p.release.clone(), asset.clone());
                let b = match caches.sbom.get(&key) {
                    Some(b) => b.clone(),
                    None => {
                        let b = gh.release_asset(&p.repo, &p.release, asset)?;
                        let got = sha256_hex(&b);
                        if &got != sha {
                            return Err(failed(
                                format!("{} {}: SBOM {asset}", p.repo, p.release),
                                format!(
                                    "layer.toml records sha256 {sha}, the downloaded asset \
                                     hashes to {got}"
                                ),
                            ));
                        }
                        caches.sbom.insert(key.clone(), b.clone());
                        b
                    }
                };
                Some(b)
            }
            // No recorded SBOM annotation — fall back to the release's OWN
            // SBOM, admitted through its own verified proof
            // (REQ-ADVISORYWATCH-001 clause 4b's fallback). Deliberately
            // never a hard failure here: unlike a digest mismatch above
            // (which means a recorded claim was WRONG), every way this
            // fallback can fail is a fact about one release's proof, and
            // must not stop every OTHER payload this run is checking.
            (_, _) => {
                let key = (p.repo.clone(), p.release.clone(), p.version.clone());
                let outcome = match caches.release_sbom.get(&key) {
                    Some(o) => o.clone(),
                    None => {
                        let o = gh.release_sbom(&p.repo, &p.release, &p.version);
                        caches.release_sbom.insert(key, o.clone());
                        o
                    }
                };
                match outcome {
                    crate::orchestrate::ReleaseSbomOutcome::Found(b) => Some(b),
                    crate::orchestrate::ReleaseSbomOutcome::NoSbom => {
                        unchecked.push(UncheckedReport {
                            tool: p.tool.clone(),
                            version: p.version.clone(),
                            repo: p.repo.clone(),
                            reason: "no SBOM recorded and the release publishes none".to_string(),
                        });
                        None
                    }
                    crate::orchestrate::ReleaseSbomOutcome::Ambiguous => {
                        unchecked.push(UncheckedReport {
                            tool: p.tool.clone(),
                            version: p.version.clone(),
                            repo: p.repo.clone(),
                            reason: "release publishes several SBOMs and none uniquely names \
                                     this payload"
                                .to_string(),
                        });
                        None
                    }
                    crate::orchestrate::ReleaseSbomOutcome::NotCovered => {
                        unchecked.push(UncheckedReport {
                            tool: p.tool.clone(),
                            version: p.version.clone(),
                            repo: p.repo.clone(),
                            reason: "release SBOM not covered by its verified proof".to_string(),
                        });
                        None
                    }
                    crate::orchestrate::ReleaseSbomOutcome::VerifyFailed(detail) => {
                        unchecked.push(UncheckedReport {
                            tool: p.tool.clone(),
                            version: p.version.clone(),
                            repo: p.repo.clone(),
                            reason: format!("release could not be verified: {detail}"),
                        });
                        None
                    }
                }
            }
        };
        // The SBOM is scoped to THIS payload alone — not shared with any
        // other payload the way the GHSA repo listing is — so malformed
        // bytes are a coverage gap for this one payload, never a reason to
        // abort every other payload and line the run is looking at.
        if let Some(bytes) = bytes {
            match sbom_components(&bytes) {
                Ok(components) => {
                    // Every component is checked or reported with its reason
                    // (REQ-ADVISORYWATCH-002 clause 3).
                    for c in &components {
                        match classify_component(c) {
                            ComponentClass::Crate { name, version } => {
                                if !to_check.contains(&(name.clone(), version.clone())) {
                                    to_check.push((name, version));
                                }
                            }
                            ComponentClass::Unchecked(reason) => {
                                let report = UncheckedReport {
                                    tool: p.tool.clone(),
                                    version: p.version.clone(),
                                    repo: p.repo.clone(),
                                    reason,
                                };
                                if !unchecked.contains(&report) {
                                    unchecked.push(report);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    unchecked.push(UncheckedReport {
                        tool: p.tool.clone(),
                        version: p.version.clone(),
                        repo: p.repo.clone(),
                        reason: format!("SBOM could not be parsed: {e}"),
                    });
                }
            }
        }
        for (name, ver) in to_check {
            // Refuse BEFORE ever asking: `name` is untrusted text from an
            // upstream SBOM, and it is about to be interpolated into a URL
            // path. A name that cannot be a real crate cannot have RustSec
            // advisories either way (REQ-ADVISORYWATCH-001 clause 4).
            if !crate::gh::is_valid_crate_name(&name) {
                skipped.push(SkippedReport {
                    what: name.clone(),
                    reason: "not a valid crate name".to_string(),
                });
                continue;
            }

            // A version this parser cannot decide — pre-release (no
            // defined numeric position) or otherwise garbled — is one
            // COMPONENT this run cannot decide about, never a reason to
            // abort every other component the same SBOM names.
            let version = match Version::parse(&ver) {
                Ok(v) => v,
                Err(AdvisoryError::PreReleaseVersion(_)) => {
                    push_unique(
                        &mut undecidable_report,
                        UndecidableReport {
                            id: name.clone(),
                            package: name.clone(),
                            reason: "pre-release version, not compared".to_string(),
                        },
                    );
                    continue;
                }
                Err(e) => {
                    push_unique(
                        &mut undecidable_report,
                        UndecidableReport {
                            id: name.clone(),
                            package: name.clone(),
                            reason: format!("version could not be read: {e}"),
                        },
                    );
                    continue;
                }
            };

            let listing = match caches.rustsec_dir.get(&name) {
                Some(l) => l.clone(),
                None => {
                    let l = gh.rustsec_crate_dir(&name)?;
                    caches.rustsec_dir.insert(name.clone(), l.clone());
                    l
                }
            };
            let Some(files) = listing else {
                continue;
            };
            for filename in files {
                // Same reasoning as the crate name above, one hop later: a
                // directory LISTING is still untrusted network content, and
                // `parse_rustsec_dir_listing` only filters by `.md` suffix
                // — which `../evil.md` satisfies.
                if !crate::gh::is_valid_rustsec_filename(&filename) {
                    skipped.push(SkippedReport {
                        what: filename.clone(),
                        reason: "not a RustSec advisory filename".to_string(),
                    });
                    continue;
                }
                let md_key = (name.clone(), filename.clone());
                let md = match caches.rustsec_md.get(&md_key) {
                    Some(m) => m.clone(),
                    None => {
                        let m = gh.rustsec_advisory_md(&name, &filename)?;
                        caches.rustsec_md.insert(md_key, m.clone());
                        m
                    }
                };
                let (withdrawn, cvss) = rustsec_extra(&md)?;
                if withdrawn {
                    continue;
                }
                match advisory::rustsec_outcome(&md, &name, &version)? {
                    advisory::RustSecOutcome::Affected(finding) => {
                        let (mut severity, mut defaulted_reason) =
                            rustsec_severity(cvss.as_deref());
                        // The CVSS vector could not be scored — before
                        // accepting "medium", see whether a GHSA alias
                        // states the real severity
                        // (REQ-ADVISORYWATCH-001's GHSA-alias-severity
                        // rule): wasmtime's RustSec entries carry CVSS:4.0
                        // vectors this module cannot score. The REPO comes
                        // from ANY `https://github.com/<owner>/<repo>/...`
                        // url (a PR in the real wasmtime entries, not a
                        // `/security/advisories/` link); the GHSA id comes
                        // from that same url WHEN it is itself an advisory
                        // link, else from `aliases`.
                        //
                        // This lookup is enrichment, not the affected
                        // decision — unlike a payload's own repo (clause
                        // 4a, a hard error), a FAILURE to read the alias
                        // repo's advisories must not abort a run that is
                        // also looking at every other advisory this line
                        // has (security review: availability of the
                        // monitoring). It degrades to the same "medium,
                        // defaulted" outcome as no alias at all, with the
                        // fetch failure as the stated reason.
                        let mut from_ghsa: Option<String> = None;
                        if defaulted_reason.is_some()
                            && let Some(url) = &finding.url
                            && let Some(repo) = github_repo_from_url(url)
                            && let Some(ghsa_id) = ghsa_id_from_advisory_url(url)
                                .or_else(|| first_ghsa_alias(&finding.aliases))
                        {
                            let json = match caches.ghsa.get(&repo) {
                                Some(j) => Some(j.clone()),
                                None => match gh.security_advisories(&repo) {
                                    Ok(j) => {
                                        caches.ghsa.insert(repo.clone(), j.clone());
                                        Some(j)
                                    }
                                    Err(e) => {
                                        defaulted_reason =
                                            Some(format!("GHSA severity lookup failed: {e}"));
                                        None
                                    }
                                },
                            };
                            if let Some(json) = json
                                && let Some(s) = ghsa_severity_by_id(&json, &ghsa_id)
                            {
                                severity = s;
                                defaulted_reason = None;
                                from_ghsa = Some(ghsa_id);
                            }
                        }
                        if let Some(reason) = defaulted_reason {
                            push_unique(
                                &mut defaulted,
                                DefaultedSeverityReport {
                                    id: finding.id.clone(),
                                    reason,
                                },
                            );
                        }
                        if let Some(ghsa_id) = from_ghsa {
                            push_unique(
                                &mut severity_from_ghsa,
                                SeverityFromGhsaReport {
                                    id: finding.id.clone(),
                                    ghsa_id,
                                },
                            );
                        }
                        let heading = first_heading(&md).unwrap_or_else(|| finding.summary.clone());
                        proposed.push(Proposed {
                            id: finding.id.clone(),
                            aliases: finding.aliases.clone(),
                            title: rustsec_title(&p.tool, &p.version, &name, &ver, &heading),
                            severity,
                            affected: p.layers.clone(),
                            workaround: None,
                            detection: None,
                        });
                    }
                    advisory::RustSecOutcome::NotAffected => {}
                    // Not a vulnerability — never a KnownProblem — but
                    // never silently dropped either
                    // (REQ-ADVISORYWATCH-001's informational-advisories
                    // rule).
                    advisory::RustSecOutcome::Informational(info) => {
                        // The real title is the markdown's own `# `
                        // heading ("bitmaps is unmaintained"), not the
                        // TOML `title` field most informational advisories
                        // never set — the live run's own gap: `info.title`
                        // alone was empty for every one of them.
                        let title = first_heading(&md).unwrap_or(info.title);
                        push_unique(
                            &mut notes,
                            NoteReport {
                                id: info.id,
                                package: info.package,
                                kind: info.kind,
                                title,
                            },
                        );
                    }
                    // One unreadable advisory must not abort a run that is
                    // also looking at every other advisory and payload
                    // (REQ-ADVISORYWATCH-001 clause 4, this round's fix 2)
                    // — exactly the GHSA-side distinction `ghsa_for_payload`
                    // already draws.
                    advisory::RustSecOutcome::Undecidable(u) => {
                        push_unique(
                            &mut undecidable_report,
                            UndecidableReport {
                                id: u.id,
                                package: u.package,
                                reason: u.reason,
                            },
                        );
                    }
                }
            }
        }
    }

    unify_qualifiers(&mut proposed);
    let next = statusdraft::next_document(&baseline, &proposed, today)?;

    let mut report = LineReport {
        line: line.to_string(),
        undecidable: undecidable_report,
        defaulted_severities: defaulted,
        skipped,
        unchecked,
        notes,
        severity_from_ghsa,
        ..Default::default()
    };

    let pending = match next {
        None => None,
        Some(document) => {
            let old_ids: BTreeSet<&str> = baseline
                .known_problems
                .iter()
                .map(|k| k.id.as_str())
                .collect();
            for kp in &document.known_problems {
                if !old_ids.contains(kp.id.as_str()) {
                    report.new_known_problems.push(kp.id.clone());
                    continue;
                }
                if let Some(old) = baseline.known_problems.iter().find(|o| o.id == kp.id) {
                    let added: Vec<String> = kp
                        .affected
                        .iter()
                        .filter(|a| !old.affected.contains(a))
                        .cloned()
                        .collect();
                    if !added.is_empty() {
                        report.newly_affected.insert(kp.id.clone(), added);
                    }
                }
            }
            report.wrote = true;
            Some(PendingWrite {
                path: status_path.to_path_buf(),
                document,
            })
        }
    };

    Ok((report, pending))
}

// ---------------------------------------------------------------------
// The full run — every committed line, fail-closed, write-after-success.
// ---------------------------------------------------------------------

fn list_line_names(dir: &Path) -> Result<Vec<String>, WatchError> {
    let entries = std::fs::read_dir(dir).map_err(|e| failed(dir.display().to_string(), e))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| failed(dir.display().to_string(), e))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            out.push(stem.to_string());
        }
    }
    out.sort();
    Ok(out)
}

/// Watch every committed line of a layer repository rooted at `repo_root`
/// (which holds `line-index/<line>.json` and `line-status/<line>.json`),
/// and write each line's prepared next document.
///
/// Fail-closed across the WHOLE run (clause 4): every line is computed
/// first, entirely in memory, and nothing is written to disk until every
/// line has succeeded. A failure on line N must not leave line 1's
/// (already-correct) prepared document sitting on disk while the run as a
/// whole reports an error — that half-written state is exactly what a
/// retry, or a human reading the repository mid-failure, must never see.
pub fn run<G: AdvisoryGh, S: LayerSource>(
    repo_root: &Path,
    gh: &G,
    registry: &S,
    today: &str,
) -> Result<RunReport, WatchError> {
    let index_dir = repo_root.join("line-index");
    let status_dir = repo_root.join("line-status");

    let lines = list_line_names(&index_dir)?;

    let mut reports = Vec::with_capacity(lines.len());
    let mut writes = Vec::new();
    let mut caches = Caches::default();

    for line in &lines {
        let index_path = index_dir.join(format!("{line}.json"));
        let status_path = status_dir.join(format!("{line}.json"));
        let (report, pending) = watch_line(
            gh,
            registry,
            line,
            &index_path,
            &status_path,
            today,
            &mut caches,
        )?;
        reports.push(report);
        if let Some(p) = pending {
            writes.push(p);
        }
    }

    // Phase 2: every line succeeded — now, and only now, write.
    for w in writes {
        let text = serde_json::to_string_pretty(&w.document)
            .map_err(|e| failed("serialising the prepared line-status", e))?
            + "\n";
        if let Some(parent) = w.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| failed(parent.display().to_string(), e))?;
        }
        std::fs::write(&w.path, text).map_err(|e| failed(w.path.display().to_string(), e))?;
    }

    Ok(RunReport { lines: reports })
}

// ---------------------------------------------------------------------
// The real `gh`.
// ---------------------------------------------------------------------

impl<R: crate::gh::CommandRunner> AdvisoryGh for crate::source::GhSource<R> {
    fn security_advisories(&self, repo: &str) -> Result<String, WatchError> {
        self.ghsa_advisories_json(repo)
            .map_err(|e| failed(format!("GHSA advisories for {repo}"), e))
    }

    fn rustsec_crate_dir(&self, krate: &str) -> Result<Option<Vec<String>>, WatchError> {
        let listing = self
            .rustsec_crate_directory(krate)
            .map_err(|e| failed(format!("RustSec advisory-db for {krate}"), e))?;
        match listing {
            None => Ok(None),
            Some(stdout) => Ok(Some(
                crate::gh::parse_rustsec_dir_listing(&stdout)
                    .map_err(|e| failed(format!("RustSec advisory-db for {krate}"), e))?,
            )),
        }
    }

    fn rustsec_advisory_md(&self, krate: &str, filename: &str) -> Result<String, WatchError> {
        self.rustsec_advisory_markdown(krate, filename)
            .map_err(|e| failed(format!("RustSec advisory {filename}"), e))
    }

    fn release_asset(&self, repo: &str, release: &str, asset: &str) -> Result<Vec<u8>, WatchError> {
        crate::orchestrate::Source::asset_bytes(self, repo, release, asset)
            .map_err(|e| failed(format!("{repo} {release}: downloading {asset}"), e))
    }

    fn release_sbom(
        &self,
        repo: &str,
        release: &str,
        version: &str,
    ) -> crate::orchestrate::ReleaseSbomOutcome {
        self.release_sbom(repo, release, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_core::MemorySource;

    // -------------------------------------------------------------
    // payload extraction / dedup
    // -------------------------------------------------------------

    fn entry(anns: &[(&str, &str)]) -> varve_core::manifest::ManifestEntry {
        let mut map = BTreeMap::new();
        for (k, v) in anns {
            map.insert(k.to_string(), v.to_string());
        }
        varve_core::manifest::ManifestEntry {
            digest: "sha256:aaaa".into(),
            annotations: map,
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_entry_with_no_tool_or_version_is_not_a_payload() {
        assert!(payload_from_entry(&entry(&[])).is_none());
        assert!(
            payload_from_entry(&entry(&[("eu.pulseengine.tool", "wasmtime")])).is_none(),
            "a tool name with no version names nothing a check can decide"
        );
    }

    /// `payload_from_entry` still says "not a payload" for these, but
    /// `classify_entry` is where the reason lives, and it must give a
    /// distinct, specific one for each shape (REQ-ADVISORYWATCH-001 clause 1).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn classify_entry_gives_a_specific_reason_for_every_entry_it_cannot_check() {
        let reason = |anns: &[(&str, &str)]| match classify_entry(&entry(anns)) {
            Err(NotChecked::Entry(r)) => r,
            other => panic!("expected an individual unchecked entry, got {other:?}"),
        };
        let r = reason(&[]);
        assert!(
            r.reason.contains("no eu.pulseengine.tool annotation"),
            "{r:?}"
        );
        assert_eq!(
            r.tool, "sha256:aaaa",
            "an unnamed entry is named by its digest"
        );
        let r = reason(&[
            ("eu.pulseengine.tool", "t"),
            ("eu.pulseengine.source.repo", "o/t"),
        ]);
        assert!(r.reason.contains("tool.version"), "{r:?}");
        assert_eq!(
            (r.tool.as_str(), r.repo.as_str(), r.version.as_str()),
            ("t", "o/t", "-")
        );
        let r = reason(&[
            ("eu.pulseengine.tool", "t"),
            ("eu.pulseengine.tool.version", "1.0.0"),
        ]);
        assert!(r.reason.contains("source.repo"), "{r:?}");
        assert_eq!((r.repo.as_str(), r.version.as_str()), ("-", "1.0.0"));
        let r = reason(&[
            ("eu.pulseengine.varve.kind", "from-the-future"),
            ("eu.pulseengine.tool", "t"),
        ]);
        assert!(r.reason.contains("kind this build does not know"), "{r:?}");
        assert_eq!(r.tool, "t");
        // A layer include with no layer name is named by its digest, and its
        // realm is carried.
        let r = reason(&[
            ("eu.pulseengine.varve.kind", "layer"),
            ("eu.pulseengine.varve.include.realm", "r"),
        ]);
        assert_eq!(
            (r.tool.as_str(), r.version.as_str(), r.repo.as_str()),
            ("included layer", "sha256:aaaa", "r")
        );
        let r = reason(&[("eu.pulseengine.varve.kind", "layer")]);
        assert_eq!(r.repo, "-");
    }

    /// A non-tool kind is only set aside when it names no tool: an entry that
    /// carries a tool name and everything a check needs is still a payload,
    /// whatever kind it declares — that is what the watcher always did, and
    /// reporting must not change what it fetches.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_non_tool_kind_that_names_a_checkable_tool_is_still_a_payload() {
        let full = [
            ("eu.pulseengine.varve.kind", "wasm-component"),
            ("eu.pulseengine.tool", "t"),
            ("eu.pulseengine.tool.version", "1.0.0"),
            ("eu.pulseengine.source.repo", "o/t"),
        ];
        assert!(classify_entry(&entry(&full)).is_ok());
        match classify_entry(&entry(&[("eu.pulseengine.varve.kind", "wasm-component")])) {
            Err(NotChecked::OfKind { kind, digest }) => {
                assert_eq!(kind, "wasm-component");
                assert_eq!(digest, "sha256:aaaa");
            }
            other => panic!("{other:?}"),
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn release_defaults_to_version_when_absent() {
        let p = payload_from_entry(&entry(&[
            ("eu.pulseengine.tool", "wasmtime"),
            ("eu.pulseengine.tool.version", "49.0.1"),
            ("eu.pulseengine.source.repo", "bytecodealliance/wasmtime"),
        ]))
        .unwrap();
        assert_eq!(p.release, "49.0.1");

        let p = payload_from_entry(&entry(&[
            ("eu.pulseengine.tool", "with-device"),
            ("eu.pulseengine.tool.version", "0.2.2"),
            ("eu.pulseengine.source.repo", "pulseengine/jess"),
            ("eu.pulseengine.source.release", "v0.7.2"),
        ]))
        .unwrap();
        assert_eq!(p.release, "v0.7.2");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn sbom_annotations_are_carried_when_present() {
        let p = payload_from_entry(&entry(&[
            ("eu.pulseengine.tool", "wsc"),
            ("eu.pulseengine.tool.version", "0.11.0"),
            ("eu.pulseengine.source.repo", "pulseengine/wsc"),
            (varve_core::ANN_SBOM, "sbom.cdx.json"),
            (varve_core::ANN_SBOM_SHA256, "deadbeef"),
        ]))
        .unwrap();
        assert_eq!(p.sbom_asset, Some("sbom.cdx.json".to_string()));
        assert_eq!(p.sbom_sha256, Some("deadbeef".to_string()));
    }

    fn payload(repo: &str, version: &str) -> Payload {
        Payload {
            tool: "t".into(),
            repo: repo.into(),
            version: version.into(),
            release: version.into(),
            sbom_asset: None,
            sbom_sha256: None,
            is_crate: false,
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn dedup_merges_the_same_repo_version_across_layers_and_platforms() {
        let per_layer = vec![
            (
                "2026.10.0".to_string(),
                vec![
                    payload("o/r", "1.0.0"),
                    payload("o/r", "1.0.0"), // a second platform, same release
                ],
            ),
            ("2026.10.1".to_string(), vec![payload("o/r", "1.0.0")]),
            ("2026.10.2".to_string(), vec![payload("o/r", "1.0.1")]),
        ];
        let out = dedup_payloads(&per_layer);
        assert_eq!(out.len(), 2);
        let v100 = out.iter().find(|p| p.version == "1.0.0").unwrap();
        assert_eq!(v100.layers, vec!["2026.10.0", "2026.10.1"]);
        let v101 = out.iter().find(|p| p.version == "1.0.1").unwrap();
        assert_eq!(v101.layers, vec!["2026.10.2"]);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn dedup_fills_in_an_sbom_annotation_a_sibling_platform_omitted() {
        let mut with_sbom = payload("o/r", "1.0.0");
        with_sbom.sbom_asset = Some("sbom.json".into());
        with_sbom.sbom_sha256 = Some("abc".into());
        let per_layer = vec![(
            "2026.10.0".to_string(),
            vec![payload("o/r", "1.0.0"), with_sbom],
        )];
        let out = dedup_payloads(&per_layer);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sbom_asset, Some("sbom.json".to_string()));
    }

    // -------------------------------------------------------------
    // expiry / bootstrap
    // -------------------------------------------------------------

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_line_past_its_support_until_is_expired() {
        assert!(line_is_expired(Some("2026-09-01"), "2026-10-15"));
        assert!(!line_is_expired(Some("2026-10-15"), "2026-10-15"));
        assert!(!line_is_expired(Some("2027-01-01"), "2026-10-15"));
    }

    /// A full RFC3339 `support-until` still compares correctly against a
    /// bare `--today` date.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_full_timestamp_support_until_compares_correctly_against_a_bare_date() {
        assert!(line_is_expired(Some("2026-10-14T23:00:00Z"), "2026-10-15"));
        assert!(!line_is_expired(Some("2026-10-15T00:00:00Z"), "2026-10-15"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_line_with_no_stated_support_until_never_expires() {
        assert!(!line_is_expired(None, "2099-01-01"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn bootstrap_document_starts_at_counter_zero_with_no_known_problems() {
        let d = bootstrap_document("2026.10", "2026-10-15", Some("2027-04-15".into()));
        assert_eq!(d.line, "2026.10");
        assert_eq!(d.counter, 0);
        assert_eq!(d.issued_at, "2026-10-15");
        assert_eq!(d.support_until, Some("2027-04-15".to_string()));
        assert!(d.known_problems.is_empty());
    }

    // -------------------------------------------------------------
    // Rendering: "nothing new" must never stand alone over unchecked
    // payloads.
    // -------------------------------------------------------------

    fn unchecked(reason: &str) -> UncheckedReport {
        UncheckedReport {
            tool: "wsc".into(),
            version: "0.11.0".into(),
            repo: "pulseengine/wsc".into(),
            reason: reason.to_string(),
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_clean_line_with_nothing_unchecked_says_bare_nothing_new() {
        let line = LineReport {
            line: "2026.10".into(),
            ..Default::default()
        };
        assert_eq!(render_line(&line), "2026.10\tnothing new\n");
    }

    /// THE property the supervisor's live run broke: "nothing new" must
    /// never appear ALONE when a payload went unchecked.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn nothing_new_never_appears_alone_when_something_is_unchecked() {
        let line = LineReport {
            line: "2026.10".into(),
            unchecked: vec![unchecked("no SBOM recorded and the release publishes none")],
            ..Default::default()
        };
        let rendered = render_line(&line);
        assert!(
            rendered.contains("nothing new among checked payloads"),
            "{rendered}"
        );
        assert!(rendered.contains("1 item(s) NOT checked"), "{rendered}");
        assert!(rendered.contains("pulseengine/wsc"), "{rendered}");
        assert!(rendered.contains("no SBOM recorded"), "{rendered}");
        assert!(
            !rendered.contains("2026.10\tnothing new\n"),
            "the bare phrase must not appear: {rendered}"
        );
    }

    /// A line that DID write something must still say which payloads were
    /// not checked — the coverage gap does not go away because something
    /// else was found.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_written_line_still_reports_what_was_unchecked() {
        let line = LineReport {
            line: "2026.10".into(),
            wrote: true,
            new_known_problems: vec!["GHSA-x".into()],
            unchecked: vec![unchecked("release could not be verified: HTTP 403")],
            ..Default::default()
        };
        let rendered = render_line(&line);
        assert!(
            rendered.contains("wrote line-status/2026.10.json"),
            "{rendered}"
        );
        assert!(rendered.contains("new known problem: GHSA-x"), "{rendered}");
        assert!(rendered.contains("item(s) NOT checked"), "{rendered}");
    }

    /// The flip side: a line that wrote something AND has NOTHING
    /// unchecked must not grow a phantom "NOT checked" line either.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_written_line_with_nothing_unchecked_has_no_coverage_line() {
        let line = LineReport {
            line: "2026.10".into(),
            wrote: true,
            new_known_problems: vec!["GHSA-x".into()],
            ..Default::default()
        };
        let rendered = render_line(&line);
        assert!(
            !rendered.contains("NOT checked"),
            "nothing is unchecked here: {rendered}"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn human_summary_of_an_empty_run_says_no_committed_lines() {
        let report = RunReport { lines: vec![] };
        assert_eq!(
            human_summary(&report),
            "no committed lines (line-index/*.json) found\n"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn human_summary_concatenates_every_lines_rendering() {
        let report = RunReport {
            lines: vec![
                LineReport {
                    line: "2026.09".into(),
                    skipped_expired: true,
                    ..Default::default()
                },
                LineReport {
                    line: "2026.10".into(),
                    unchecked: vec![unchecked("no SBOM recorded and the release publishes none")],
                    ..Default::default()
                },
            ],
        };
        let out = human_summary(&report);
        assert!(out.contains("2026.09\tskipped"), "{out}");
        assert!(
            out.contains("2026.10\tnothing new among checked payloads"),
            "{out}"
        );
    }

    /// `peek_support_until` reads the REAL `support-until` field out of an
    /// (unsigned, unverified-by-design) DSSE-shaped envelope, and is `None`
    /// for anything that is not one — never an invented placeholder.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn peek_support_until_reads_the_real_field_or_nothing() {
        let payload = br#"{"line":"2026.10","counter":1,"issued-at":"2026-10-01T00:00:00Z","support-until":"2027-04-15"}"#;
        let env = wsc::dsse::DsseEnvelope::unsigned(
            payload,
            "application/vnd.pulseengine.varve.line-status.v1+json",
        );
        let bytes = env.to_json_pretty().unwrap().into_bytes();
        assert_eq!(peek_support_until(&bytes), Some("2027-04-15".to_string()));

        assert_eq!(peek_support_until(b"not an envelope at all"), None);

        let payload_no_field =
            br#"{"line":"2026.10","counter":1,"issued-at":"2026-10-01T00:00:00Z"}"#;
        let env2 = wsc::dsse::DsseEnvelope::unsigned(
            payload_no_field,
            "application/vnd.pulseengine.varve.line-status.v1+json",
        );
        assert_eq!(
            peek_support_until(&env2.to_json_pretty().unwrap().into_bytes()),
            None
        );
    }

    // -------------------------------------------------------------
    // GHSA package-name enumeration and union
    // -------------------------------------------------------------

    const MULTI_PACKAGE_GHSA: &str = r#"[
        {
            "ghsa_id": "GHSA-aaaa",
            "severity": "high",
            "summary": "a",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"}
            ]
        },
        {
            "ghsa_id": "GHSA-bbbb",
            "severity": "medium",
            "summary": "b",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "wasmtime-wasi"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": null}
            ]
        }
    ]"#;

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn package_names_are_every_distinct_name_the_advisories_mention() {
        let names = ghsa_package_names(MULTI_PACKAGE_GHSA).unwrap();
        assert_eq!(
            names,
            vec!["wasmtime".to_string(), "wasmtime-wasi".to_string()]
        );
    }

    /// A payload named "wasmtime" is matched by the advisory that names
    /// "wasmtime" and NOT by the one that only lists "wasmtime-wasi"
    /// (REQ-ADVISORYWATCH-002 clause 5; REQ-ADVISORYWATCH-001 clause 4a
    /// used to union every package name of the repository). Naming both
    /// names both.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn ghsa_for_payload_matches_only_the_packages_that_name_the_payload() {
        let v = Version::parse("49.0.1").unwrap();
        let ids = |names: &[&str]| -> BTreeSet<String> {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            ghsa_for_payload(MULTI_PACKAGE_GHSA, &v, &names)
                .unwrap()
                .findings
                .iter()
                .map(|f| f.id.clone())
                .collect()
        };
        assert_eq!(ids(&["wasmtime"]), ["GHSA-aaaa".to_string()].into());
        assert_eq!(ids(&["wasmtime-wasi"]), ["GHSA-bbbb".to_string()].into());
        assert_eq!(
            ids(&["wasmtime", "wasmtime-wasi"]),
            ["GHSA-aaaa".to_string(), "GHSA-bbbb".to_string()].into()
        );
        assert!(ids(&["unrelated"]).is_empty());
        // What names the payload is certain; the rest is qualified, once.
        let r = ghsa_for_payload(MULTI_PACKAGE_GHSA, &v, &["wasmtime".to_string()]).unwrap();
        assert_eq!(r.qualified.len(), 1, "{r:?}");
        assert_eq!(r.qualified[0].0.id, "GHSA-bbbb");
        let r = ghsa_for_payload(MULTI_PACKAGE_GHSA, &v, &["unrelated".to_string()]).unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.qualified.len(), 2, "{r:?}");
    }

    /// One advisory naming two sibling packages is ONE qualified finding
    /// that names both.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn one_advisory_naming_two_siblings_is_one_qualified_finding_naming_both() {
        let json = r#"[{
            "ghsa_id": "GHSA-two",
            "severity": "high",
            "summary": "s",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "a"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null},
                {"package": {"name": "b"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null},
                {"package": {"name": "c"}, "vulnerable_version_range": "< 0.5.0", "patched_versions": null}
            ]
        }]"#;
        let v = Version::parse("1.0.0").unwrap();
        let r = ghsa_for_payload(json, &v, &["me".to_string()]).unwrap();
        assert_eq!(r.qualified.len(), 1, "{r:?}");
        assert_eq!(r.qualified[0].1, ["a", "b"]);
    }

    /// A single advisory matched under TWO different package names must not
    /// appear twice.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_single_advisory_matching_two_package_names_is_counted_once() {
        let json = r#"[{
            "ghsa_id": "GHSA-dup",
            "severity": "high",
            "summary": "s",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "a"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null},
                {"package": {"name": "b"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null}
            ]
        }]"#;
        let v = Version::parse("1.0.0").unwrap();
        let result = ghsa_for_payload(json, &v, &["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(result.findings.len(), 1);
    }

    /// Same id, two different package names, BOTH unparseable ranges — one
    /// undecidable advisory, not two.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_single_undecidable_advisory_matching_two_package_names_is_counted_once() {
        let json = r#"[{
            "ghsa_id": "GHSA-dup-undecidable",
            "severity": "high",
            "summary": "s",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "a"}, "vulnerable_version_range": "not a range", "patched_versions": null},
                {"package": {"name": "b"}, "vulnerable_version_range": "also not a range", "patched_versions": null}
            ]
        }]"#;
        let v = Version::parse("1.0.0").unwrap();
        let result = ghsa_for_payload(json, &v, &["a".to_string(), "b".to_string()]).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.undecidable.len(), 1, "{:?}", result.undecidable);
        assert_eq!(result.undecidable[0].id, "GHSA-dup-undecidable");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn unparseable_ghsa_json_is_an_error() {
        let v = Version::parse("1.0.0").unwrap();
        assert!(ghsa_for_payload("not json", &v, &[]).is_err());
        assert!(ghsa_package_names("not json").is_err());
    }

    // -------------------------------------------------------------
    // RustSec extra metadata
    // -------------------------------------------------------------

    fn rustsec_md_with(extra: &str) -> String {
        format!(
            r#"# A real heading

```toml
[advisory]
id = "RUSTSEC-2026-0346"
package = "rustls"
date = "2026-10-14"
{extra}

[versions]
patched = [">= 0.23.46"]
unaffected = ["< 0.21.0"]
```
"#
        )
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_advisory_with_no_withdrawn_field_is_not_withdrawn() {
        let md = rustsec_md_with("");
        let (withdrawn, cvss) = rustsec_extra(&md).unwrap();
        assert!(!withdrawn);
        assert!(cvss.is_none());
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_withdrawn_date_marks_the_advisory_withdrawn() {
        let md = rustsec_md_with(r#"withdrawn = "2026-10-15""#);
        let (withdrawn, _) = rustsec_extra(&md).unwrap();
        assert!(withdrawn);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_cvss_vector_is_read_when_present() {
        let md = rustsec_md_with(r#"cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H""#);
        let (_, cvss) = rustsec_extra(&md).unwrap();
        assert_eq!(
            cvss,
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string())
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_first_heading_is_read_not_the_toml_title() {
        let md = rustsec_md_with("");
        assert_eq!(first_heading(&md), Some("A real heading".to_string()));
        assert_eq!(first_heading("no heading here"), None);
        assert_eq!(
            first_heading("prose\n\n# First\n\n# Second"),
            Some("First".to_string())
        );
    }

    // -------------------------------------------------------------
    // SBOM components
    // -------------------------------------------------------------

    const CYCLONEDX_SBOM: &str = r#"{
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "wsc", "version": "0.11.0"}},
        "components": [
            {"name": "rustls", "version": "0.23.34"},
            {"name": "ring", "version": "0.17.8"}
        ]
    }"#;

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn sbom_components_include_the_subject_and_every_component() {
        let out = sbom_components(CYCLONEDX_SBOM.as_bytes()).unwrap();
        assert_eq!(
            out,
            ["wsc:0.11.0", "rustls:0.23.34", "ring:0.17.8"]
                .iter()
                .map(|s| {
                    let (n, v) = s.split_once(':').unwrap();
                    SbomComponent {
                        name: n.to_string(),
                        version: Some(v.to_string()),
                        purl: None,
                    }
                })
                .collect::<Vec<_>>()
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn unparseable_sbom_bytes_are_an_error() {
        assert!(sbom_components(b"not json").is_err());
    }

    /// The real SBOMs measured against three varve-adjacent tools' own
    /// releases (wsc, rivet, kiln) — every one carries components whose
    /// version is build-metadata-suffixed (`1.1.3+spec-1.1.0`,
    /// `0.9.34+deprecated`, `0.14.7+wasi-0.2.4`, …), and the FIRST version of
    /// this command aborted the whole run on the first one it met.
    /// `sbom_components` plus `Version::parse` over every component must
    /// complete with no error at all.
    const SBOM_WSC: &str = include_str!("../tests/fixtures/sbom-wsc-0.11.0.cdx.json");
    const SBOM_RIVET: &str = include_str!("../tests/fixtures/sbom-rivet-0.40.0.cdx.json");
    const SBOM_KILN: &str = include_str!("../tests/fixtures/sbom-kiln-0.5.0.cdx.json");

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn every_real_upstream_sbom_parses_its_components_and_every_version_with_no_error() {
        for (label, sbom) in [
            ("wsc", SBOM_WSC),
            ("rivet", SBOM_RIVET),
            ("kiln", SBOM_KILN),
        ] {
            let components =
                sbom_components(sbom.as_bytes()).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert!(!components.is_empty(), "{label}: no components at all");
            let mut saw_build_metadata = false;
            for c in &components {
                let (name, version) = (&c.name, c.version.as_deref().expect("versioned"));
                if version.contains('+') {
                    saw_build_metadata = true;
                }
                Version::parse(version)
                    .unwrap_or_else(|e| panic!("{label}: {name} {version}: {e}"));
                assert!(
                    matches!(classify_component(c), ComponentClass::Crate { .. }),
                    "{label}: {name} is a cargo component and must be checkable"
                );
            }
            assert!(
                saw_build_metadata,
                "{label}: expected at least one build-metadata-suffixed version — \
                 otherwise this test is not exercising the defect it is named for"
            );
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn sha256_hex_matches_a_known_digest() {
        // sha256("") — the empty-input test vector every implementation of
        // this hash is checked against.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // -------------------------------------------------------------
    // Titles and severities
    // -------------------------------------------------------------

    fn finding(id: &str, severity: Option<&str>, patched: &[&str]) -> Finding {
        Finding {
            id: id.to_string(),
            aliases: vec![],
            severity: severity.map(str::to_string),
            summary: "a filesystem sandbox escape".to_string(),
            package: "wasmtime".to_string(),
            patched: patched.iter().map(|s| s.to_string()).collect(),
            url: None,
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_title_names_the_patched_version() {
        let f = finding("GHSA-x", Some("high"), &["49.0.3"]);
        assert_eq!(
            ghsa_title("wasmtime", "49.0.1", &f),
            "wasmtime 49.0.1: a filesystem sandbox escape (fixed in 49.0.3)"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_title_says_unspecified_with_no_patched_versions() {
        let f = finding("GHSA-x", Some("high"), &[]);
        assert!(ghsa_title("wasmtime", "49.0.1", &f).contains("fixed in unspecified"));
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_title_names_tool_and_embedded_crate() {
        assert_eq!(
            rustsec_title("wsc", "0.11.0", "rustls", "0.23.34", "buffer overread"),
            "wsc 0.11.0 embeds rustls 0.23.34: buffer overread"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_severity_is_lowercased_and_reported_when_absent() {
        assert_eq!(
            ghsa_severity(&finding("GHSA-x", Some("HIGH"), &[])),
            ("high".to_string(), None)
        );
        assert_eq!(
            ghsa_severity(&finding("GHSA-x", None, &[])),
            ("medium".to_string(), Some("no stated severity".to_string()))
        );
        // Present but blank is the same as absent — not "" taken literally.
        assert_eq!(
            ghsa_severity(&finding("GHSA-x", Some("   "), &[])),
            ("medium".to_string(), Some("no stated severity".to_string()))
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rustsec_severity_computes_from_cvss_and_defaults_without_one() {
        assert_eq!(
            rustsec_severity(Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            ("critical".to_string(), None)
        );
        assert_eq!(
            rustsec_severity(None),
            ("medium".to_string(), Some("no cvss vector".to_string()))
        );
    }

    /// THE live abort: `rustsec_severity` must NEVER error, not even on a
    /// vector this module cannot score at all — severity is metadata, not
    /// the affected decision.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unreadable_cvss_vector_defaults_rather_than_erroring() {
        // The exact live-aborting vector: CVSS 4.0.
        assert_eq!(
            rustsec_severity(Some(
                "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
            )),
            (
                "medium".to_string(),
                Some("CVSS:4.0 vector, not scored".to_string())
            )
        );
        // CVSS:3.0 is SCORED (same base-metric formula as 3.1), not defaulted.
        assert_eq!(
            rustsec_severity(Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            ("critical".to_string(), None)
        );
        // Genuine garbage, no recognisable CVSS prefix at all.
        assert_eq!(
            rustsec_severity(Some("garbage")),
            (
                "medium".to_string(),
                Some("CVSS vector could not be read".to_string())
            )
        );
        // A malformed vector that NAMES a supported version but is
        // otherwise unreadable (missing metric) — a different reason from
        // "wrong version".
        assert_eq!(
            rustsec_severity(Some("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            (
                "medium".to_string(),
                Some("CVSS vector could not be read".to_string())
            )
        );
    }

    /// The ORIGINAL live case: wasmtime's RustSec `url` names the
    /// repository advisory it was filed from directly — both the repo
    /// AND the GHSA id come from this one URL.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_advisory_url_names_both_its_own_repo_and_its_own_ghsa_id() {
        let url =
            "https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-m9f7-9w4p-gv38";
        assert_eq!(
            github_repo_from_url(url),
            Some("bytecodealliance/wasmtime".to_string())
        );
        assert_eq!(
            ghsa_id_from_advisory_url(url),
            Some("GHSA-m9f7-9w4p-gv38".to_string())
        );
    }

    /// THE round-6 live miss: wasmtime's REAL `url` is a pull request, not
    /// an advisory link — `github_repo_from_url` still reads its repo (ANY
    /// github.com URL names one), but `ghsa_id_from_advisory_url` must
    /// come back `None`: a PR names no GHSA id of its own, which is
    /// exactly why the id has to come from `aliases` instead
    /// (`first_ghsa_alias`).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_pull_request_url_names_its_repo_but_no_ghsa_id_of_its_own() {
        let url = "https://github.com/bytecodealliance/wasmtime/pull/14729";
        assert_eq!(
            github_repo_from_url(url),
            Some("bytecodealliance/wasmtime".to_string())
        );
        assert_eq!(ghsa_id_from_advisory_url(url), None);
    }

    /// A commit and an issue URL are the same shape as a PR: the repo
    /// resolves, the advisory-specific id does not.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_commit_or_issue_url_also_names_only_its_repo() {
        for url in [
            "https://github.com/bytecodealliance/wasmtime/commit/abc123",
            "https://github.com/bytecodealliance/wasmtime/issues/9999",
        ] {
            assert_eq!(
                github_repo_from_url(url),
                Some("bytecodealliance/wasmtime".to_string()),
                "{url}"
            );
            assert_eq!(ghsa_id_from_advisory_url(url), None, "{url}");
        }
    }

    /// Anything that does not even name a github.com owner/repo — a
    /// different host, or a github.com URL with a missing or unsafe path
    /// segment (path traversal, an empty segment) — resolves to no repo
    /// at all, never a wrong or partial guess.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn github_repo_from_url_is_none_for_anything_unsafe_or_foreign() {
        for url in [
            "https://rustsec.org/advisories/RUSTSEC-2026-0352",
            "https://example.com/owner/repo/security/advisories/GHSA-xxxx",
            "https://github.com/bytecodealliance",
            "https://github.com//wasmtime/pull/1",
            "https://github.com/../wasmtime/pull/1",
            "https://github.com/bytecodealliance/../pull/1",
        ] {
            assert_eq!(github_repo_from_url(url), None, "{url}");
        }
    }

    /// `ghsa_id_from_advisory_url` is just as unsafe-segment-aware: an
    /// advisory URL with a traversal attempt in owner or repo is refused,
    /// not merely one without the `security/advisories` shape.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_id_from_advisory_url_is_none_for_anything_else() {
        for url in [
            "https://github.com/bytecodealliance/wasmtime",
            "https://github.com/bytecodealliance/wasmtime/security/advisories/not-a-ghsa-id",
            "https://github.com/../wasmtime/security/advisories/GHSA-m9f7-9w4p-gv38",
        ] {
            assert_eq!(ghsa_id_from_advisory_url(url), None, "{url}");
        }
    }

    /// `first_ghsa_alias` picks the first GHSA id out of `aliases` — the
    /// CVE alongside it is skipped, and no GHSA alias at all is `None`.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn first_ghsa_alias_finds_the_ghsa_id_among_other_aliases() {
        assert_eq!(
            first_ghsa_alias(&[
                "CVE-2026-9999".to_string(),
                "GHSA-m9f7-9w4p-gv38".to_string()
            ]),
            Some("GHSA-m9f7-9w4p-gv38".to_string())
        );
        assert_eq!(first_ghsa_alias(&["CVE-2026-9999".to_string()]), None);
        assert_eq!(first_ghsa_alias(&[]), None);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_severity_by_id_finds_the_matching_advisory() {
        let json = r#"[
            {"ghsa_id": "GHSA-aaaa-aaaa-aaaa", "severity": "low"},
            {"ghsa_id": "GHSA-m9f7-9w4p-gv38", "severity": "HIGH"}
        ]"#;
        assert_eq!(
            ghsa_severity_by_id(json, "GHSA-m9f7-9w4p-gv38"),
            Some("high".to_string())
        );
    }

    /// An id not in the listing, and an id present but with no (or
    /// blank) severity, both come back `None` — never a wrong severity.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn ghsa_severity_by_id_is_none_when_absent_or_unstated() {
        let json = r#"[
            {"ghsa_id": "GHSA-aaaa-aaaa-aaaa", "severity": "low"},
            {"ghsa_id": "GHSA-bbbb-bbbb-bbbb", "severity": ""}
        ]"#;
        assert_eq!(ghsa_severity_by_id(json, "GHSA-nope-nope-nope"), None);
        assert_eq!(ghsa_severity_by_id(json, "GHSA-bbbb-bbbb-bbbb"), None);
        assert_eq!(
            ghsa_severity_by_id("not json at all", "GHSA-aaaa-aaaa-aaaa"),
            None
        );
    }

    /// `push_unique` dedupes by each item's REAL id — two
    /// `DefaultedSeverityReport`s with DIFFERENT ids must both survive,
    /// which a `HasId::id()` that ignored its argument (always `""` or
    /// any other constant) would wrongly collapse to one.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn push_unique_keeps_two_defaulted_severity_reports_with_different_ids() {
        let mut list: Vec<DefaultedSeverityReport> = Vec::new();
        push_unique(
            &mut list,
            DefaultedSeverityReport {
                id: "RUSTSEC-AAAA".to_string(),
                reason: "r1".to_string(),
            },
        );
        push_unique(
            &mut list,
            DefaultedSeverityReport {
                id: "RUSTSEC-BBBB".to_string(),
                reason: "r2".to_string(),
            },
        );
        assert_eq!(list.len(), 2, "{list:?}");
        // And a genuine repeat of the FIRST id is still dropped.
        push_unique(
            &mut list,
            DefaultedSeverityReport {
                id: "RUSTSEC-AAAA".to_string(),
                reason: "r3, a different reason text".to_string(),
            },
        );
        assert_eq!(list.len(), 2, "{list:?}");
    }

    /// Same proof for `SeverityFromGhsaReport` — the other `HasId` impl
    /// `cargo mutants` found this round's dedup tests had not yet pinned.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn push_unique_keeps_two_severity_from_ghsa_reports_with_different_ids() {
        let mut list: Vec<SeverityFromGhsaReport> = Vec::new();
        push_unique(
            &mut list,
            SeverityFromGhsaReport {
                id: "RUSTSEC-AAAA".to_string(),
                ghsa_id: "GHSA-aaaa-aaaa-aaaa".to_string(),
            },
        );
        push_unique(
            &mut list,
            SeverityFromGhsaReport {
                id: "RUSTSEC-BBBB".to_string(),
                ghsa_id: "GHSA-bbbb-bbbb-bbbb".to_string(),
            },
        );
        assert_eq!(list.len(), 2, "{list:?}");
        push_unique(
            &mut list,
            SeverityFromGhsaReport {
                id: "RUSTSEC-AAAA".to_string(),
                ghsa_id: "GHSA-cccc-cccc-cccc".to_string(),
            },
        );
        assert_eq!(list.len(), 2, "{list:?}");
    }

    // -------------------------------------------------------------
    // Full run, through fakes — no network.
    // -------------------------------------------------------------

    /// A scripted `gh`, keyed exactly like the real one would be asked.
    #[derive(Default)]
    struct FakeGh {
        ghsa: BTreeMap<String, Result<String, String>>,
        rustsec_dir: BTreeMap<String, Result<Option<Vec<String>>, String>>,
        rustsec_md: BTreeMap<(String, String), String>,
        assets: BTreeMap<(String, String, String), Vec<u8>>,
        release_sboms: BTreeMap<(String, String, String), crate::orchestrate::ReleaseSbomOutcome>,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl FakeGh {
        fn ghsa(mut self, repo: &str, json: &str) -> Self {
            self.ghsa.insert(repo.to_string(), Ok(json.to_string()));
            self
        }
        fn ghsa_fails(mut self, repo: &str, detail: &str) -> Self {
            self.ghsa.insert(repo.to_string(), Err(detail.to_string()));
            self
        }
        fn rustsec_dir(mut self, krate: &str, files: &[&str]) -> Self {
            self.rustsec_dir.insert(
                krate.to_string(),
                Ok(Some(files.iter().map(|s| s.to_string()).collect())),
            );
            self
        }
        fn rustsec_dir_404(mut self, krate: &str) -> Self {
            self.rustsec_dir.insert(krate.to_string(), Ok(None));
            self
        }
        fn rustsec_dir_fails(mut self, krate: &str, detail: &str) -> Self {
            self.rustsec_dir
                .insert(krate.to_string(), Err(detail.to_string()));
            self
        }
        fn rustsec_md(mut self, krate: &str, filename: &str, md: &str) -> Self {
            self.rustsec_md
                .insert((krate.to_string(), filename.to_string()), md.to_string());
            self
        }
        fn asset(mut self, repo: &str, release: &str, asset: &str, bytes: &[u8]) -> Self {
            self.assets.insert(
                (repo.to_string(), release.to_string(), asset.to_string()),
                bytes.to_vec(),
            );
            self
        }
        fn release_sbom_outcome(
            mut self,
            repo: &str,
            release: &str,
            version: &str,
            outcome: crate::orchestrate::ReleaseSbomOutcome,
        ) -> Self {
            self.release_sboms.insert(
                (repo.to_string(), release.to_string(), version.to_string()),
                outcome,
            );
            self
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl AdvisoryGh for FakeGh {
        fn security_advisories(&self, repo: &str) -> Result<String, WatchError> {
            self.calls.borrow_mut().push(format!("ghsa:{repo}"));
            match self.ghsa.get(repo) {
                Some(Ok(j)) => Ok(j.clone()),
                Some(Err(d)) => Err(failed(format!("GHSA advisories for {repo}"), d)),
                None => panic!("unscripted GHSA call for {repo}"),
            }
        }
        fn rustsec_crate_dir(&self, krate: &str) -> Result<Option<Vec<String>>, WatchError> {
            self.calls.borrow_mut().push(format!("rustsec-dir:{krate}"));
            match self.rustsec_dir.get(krate) {
                Some(Ok(l)) => Ok(l.clone()),
                Some(Err(d)) => Err(failed(format!("RustSec advisory-db for {krate}"), d)),
                None => panic!("unscripted RustSec dir call for {krate}"),
            }
        }
        fn rustsec_advisory_md(&self, krate: &str, filename: &str) -> Result<String, WatchError> {
            self.calls
                .borrow_mut()
                .push(format!("rustsec-md:{krate}/{filename}"));
            self.rustsec_md
                .get(&(krate.to_string(), filename.to_string()))
                .cloned()
                .ok_or_else(|| panic!("unscripted RustSec md call for {krate}/{filename}"))
        }
        fn release_asset(
            &self,
            repo: &str,
            release: &str,
            asset: &str,
        ) -> Result<Vec<u8>, WatchError> {
            self.calls
                .borrow_mut()
                .push(format!("asset:{repo}/{release}/{asset}"));
            self.assets
                .get(&(repo.to_string(), release.to_string(), asset.to_string()))
                .cloned()
                .ok_or_else(|| {
                    failed(
                        format!("{repo} {release}: downloading {asset}"),
                        "not found",
                    )
                })
        }
        fn release_sbom(
            &self,
            repo: &str,
            release: &str,
            version: &str,
        ) -> crate::orchestrate::ReleaseSbomOutcome {
            self.calls
                .borrow_mut()
                .push(format!("release-sbom:{repo}/{release}/{version}"));
            self.release_sboms
                .get(&(repo.to_string(), release.to_string(), version.to_string()))
                .cloned()
                .unwrap_or_else(|| {
                    panic!("unscripted release_sbom call for {repo}/{release}/{version}")
                })
        }
    }

    /// A unique scratch directory per CALL, not merely per test name — tests
    /// run in parallel threads of one process, so `name` + pid alone
    /// collided between tests that happened to reuse a name (`"sbom"`
    /// appears in several), each wiping the other's in-flight directory.
    static SCRATCH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn scratch(name: &str) -> PathBuf {
        let n = SCRATCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!(
            "varve-producer-advwatch-{name}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("line-index")).unwrap();
        std::fs::create_dir_all(d.join("line-status")).unwrap();
        d
    }

    fn write_index(root: &Path, line: &str, layers: &[(&str, &str)]) {
        let entries: Vec<String> = layers
            .iter()
            .map(|(l, d)| {
                format!(r#"{{"layer":"{l}","digest":"{d}","channel":"rolling","counter":1}}"#)
            })
            .collect();
        let json = format!(
            r#"{{"line":"{line}","counter":1,"issued-at":"2026-10-01T00:00:00Z","layers":[{}]}}"#,
            entries.join(",")
        );
        std::fs::write(root.join("line-index").join(format!("{line}.json")), json).unwrap();
    }

    /// Builds a layer manifest DSSE-envelope-shaped payload (unsigned —
    /// `MemorySource` requires no signature; only the digest match matters
    /// to this module) and registers it in a `MemorySource` keyed by its own
    /// digest, returning that digest.
    fn layer_manifest_payload(layer: &str, tools: &[(&str, &str, &str, &str)]) -> Vec<u8> {
        let entries: Vec<String> = tools
            .iter()
            .map(|(tool, version, repo, release)| {
                let release_ann = if release.is_empty() {
                    String::new()
                } else {
                    format!(r#","eu.pulseengine.source.release":"{release}""#)
                };
                format!(
                    r#"{{"digest":"sha256:{tool}{version}","annotations":{{"eu.pulseengine.tool":"{tool}","eu.pulseengine.tool.version":"{version}","eu.pulseengine.source.repo":"{repo}"{release_ann}}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-10-01T00:00:00Z"}},"manifests":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    fn envelope_for(payload: &[u8]) -> Vec<u8> {
        let env = wsc::dsse::DsseEnvelope::unsigned(
            payload,
            "application/vnd.pulseengine.varve.layer.v1+json",
        );
        env.to_json_pretty().unwrap().into_bytes()
    }

    /// Registers one layer's envelope in a `MemorySource`, returning the
    /// digest the line-index must record for it.
    fn with_layer(
        source: MemorySource,
        layer: &str,
        tools: &[(&str, &str, &str, &str)],
    ) -> (MemorySource, String) {
        let payload = layer_manifest_payload(layer, tools);
        let digest = varve_core::manifest_digest(&payload);
        let envelope = envelope_for(&payload);
        (source.with_manifest(&envelope), digest)
    }

    /// The real fixture the requirement names: 75 advisories, 59 of which name
    /// the `wasmtime` package; 15 of those are findings for 49.0.1 and none for
    /// 49.0.3.
    const WASMTIME_LIVE: &str = include_str!("../tests/fixtures/wasmtime-ghsa-2026-10-15.json");

    /// `affected` is sorted by layer NUMBER, not lexicographically — three
    /// layers carrying `.2`, `.9` and `.10` must come back `.2`, `.9`,
    /// `.10`, never the lexicographic `.10`, `.2`, `.9` a plain string
    /// sort would produce (REQ-ADVISORYWATCH-001's layer-order rule).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn affected_in_the_written_document_is_sorted_by_layer_number_not_lexicographically() {
        let root = scratch("layerorder");
        let (source, d2) = with_layer(
            MemorySource::new(),
            "2026.10.2",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let p9 = layer_manifest_payload(
            "2026.10.9",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let d9 = varve_core::manifest_digest(&p9);
        let source = source.with_manifest(&envelope_for(&p9));
        let p10 = layer_manifest_payload(
            "2026.10.10",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let d10 = varve_core::manifest_digest(&p10);
        let source = source.with_manifest(&envelope_for(&p10));

        write_index(
            &root,
            "2026.10",
            &[("2026.10.2", &d2), ("2026.10.9", &d9), ("2026.10.10", &d10)],
        );

        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.1",
                "49.0.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(report.lines[0].new_known_problems.len(), 23);

        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        for kp in &written.known_problems {
            assert_eq!(
                kp.affected,
                vec![
                    "2026.10.2".to_string(),
                    "2026.10.9".to_string(),
                    "2026.10.10".to_string()
                ],
                "{kp:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn two_layers_one_affected_one_not_produces_one_known_problem() {
        let root = scratch("wasmtime");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let payload2 = layer_manifest_payload(
            "2026.10.1",
            &[("wasmtime", "49.0.3", "bytecodealliance/wasmtime", "")],
        );
        let d2 = varve_core::manifest_digest(&payload2);
        let source = source.with_manifest(&envelope_for(&payload2));

        write_index(&root, "2026.10", &[("2026.10.0", &d1), ("2026.10.1", &d2)]);

        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.1",
                "49.0.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.3",
                "49.0.3",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");

        assert_eq!(report.lines.len(), 1);
        let line = &report.lines[0];
        assert_eq!(line.line, "2026.10");
        assert!(line.wrote);
        assert_eq!(line.new_known_problems.len(), 23, "{line:?}");

        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written.counter, 1);
        assert_eq!(written.known_problems.len(), 23);
        // 15 advisories name the `wasmtime` package itself and are certain;
        // 8 name only a sibling package of the same repository and are
        // qualified, never presented as certain (REQ-ADVISORYWATCH-002
        // clause 5).
        let qualified: Vec<&varve_core::linestatus::KnownProblem> = written
            .known_problems
            .iter()
            .filter(|kp| kp.detection.is_some())
            .collect();
        assert_eq!(qualified.len(), 8, "{qualified:?}");
        assert_eq!(written.known_problems.len() - qualified.len(), 15);
        // The advisory this requirement exists for names only `wasmtime-wasi`.
        let m9f7 = written
            .known_problems
            .iter()
            .find(|kp| kp.id == "GHSA-m9f7-9w4p-gv38")
            .expect("the wasmtime-wasi sandbox escape must be a finding");
        assert_eq!(
            m9f7.detection.as_deref(),
            Some(
                "qualified: names wasmtime-wasi from the same repository \
                 (bytecodealliance/wasmtime); affects this binary if it embeds that crate"
            )
        );
        // 49.0.1's layer is affected; 49.0.3's is not.
        for kp in &written.known_problems {
            assert_eq!(kp.affected, vec!["2026.10.0".to_string()], "{kp:?}");
        }
        // GHSA-vc8c-j3xm-xj73 and GHSA-88xq-w8cq-xfg7 are the fixture's own
        // two undecidable advisories — both undecidable independent of
        // version, so BOTH the 49.0.1 and the 49.0.3 payload queries
        // surface them, and the dedup must keep exactly these two ids, not
        // merely end up with a list of length two.
        let undecidable_ids: BTreeSet<String> =
            line.undecidable.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            undecidable_ids,
            ["GHSA-vc8c-j3xm-xj73", "GHSA-88xq-w8cq-xfg7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            "{:?}",
            line.undecidable
        );

        // GHSA is fetched exactly once per repo despite two layers sharing it.
        let ghsa_calls = gh.calls().iter().filter(|c| c.starts_with("ghsa:")).count();
        assert_eq!(ghsa_calls, 1, "{:?}", gh.calls());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// RustSec's own `informational = "unmaintained"` — not a vulnerability,
    /// never a `KnownProblem`, never silently dropped either
    /// (REQ-ADVISORYWATCH-001's informational-advisories rule). Shared by
    /// the dedup test below.
    const INFORMATIONAL_IM: &str = r#"# im: the crate is unmaintained

```toml
[advisory]
id = "RUSTSEC-2026-0900"
package = "im"
date = "2026-10-14"
title = "im is unmaintained"
informational = "unmaintained"

[versions]
patched = []
unaffected = []
```
"#;

    fn sbom_bytes_component_only(
        tool: &str,
        tool_version: &str,
        dep_name: &str,
        dep_version: &str,
    ) -> Vec<u8> {
        format!(
            r#"{{"metadata":{{"component":{{"name":"{tool}","version":"{tool_version}","purl":"pkg:cargo/{tool}@{tool_version}"}}}},"components":[{{"name":"{dep_name}","version":"{dep_version}","purl":"pkg:cargo/{dep_name}@{dep_version}"}}]}}"#
        )
        .into_bytes()
    }

    /// The exact live-run bug: the SAME crate (here `im`, `informational =
    /// "unmaintained"`) embedded in TWO DIFFERENT tools' SBOMs in one layer
    /// is still only ONE advisory — `notes` must carry exactly one entry
    /// for it, not one per payload (REQ-ADVISORYWATCH-001's dedup rule).
    /// It also must never become a `KnownProblem` (the informational rule),
    /// proving the two fixes compose correctly.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_same_informational_advisory_reached_through_two_payloads_is_one_note() {
        let sbom_a = sbom_bytes_component_only("witness", "1.0.0", "im", "1.0.0");
        let sbom_b = sbom_bytes_component_only("loom", "1.0.0", "im", "1.0.0");
        let sha_a = sha256_hex(&sbom_a);
        let sha_b = sha256_hex(&sbom_b);
        let (root, source, digest) = two_tool_layer_root(&sha_a, &sha_b);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/witness", "[]")
            .ghsa("pulseengine/loom", "[]")
            .rustsec_dir_404("witness")
            .rustsec_dir_404("loom")
            .rustsec_dir("im", &["RUSTSEC-2026-0900.md"])
            .rustsec_md("im", "RUSTSEC-2026-0900.md", INFORMATIONAL_IM)
            .asset("pulseengine/witness", "v1.0.0", "sbom.cdx.json", &sbom_a)
            .asset("pulseengine/loom", "v1.0.0", "sbom.cdx.json", &sbom_b);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert_eq!(
            line.notes,
            vec![NoteReport {
                id: "RUSTSEC-2026-0900".to_string(),
                package: "im".to_string(),
                kind: "unmaintained".to_string(),
                title: "im: the crate is unmaintained".to_string(),
            }],
            "{line:?}"
        );
        assert!(
            line.new_known_problems.is_empty(),
            "unmaintained is not a vulnerability: {line:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE exact live gap: a real `informational` advisory's TOML has no
    /// `title` field at all (bitmaps' real RUSTSEC-2026-0247 does not) —
    /// the live run's `notes` list showed `title: ""` for every one of
    /// them. The real title is the markdown's own `# ` heading,
    /// `"bitmaps is unmaintained"`, which `first_heading` already reads
    /// for a `KnownProblem`'s title and must read here too.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_note_title_comes_from_the_markdown_heading_not_an_absent_toml_field() {
        const RUSTSEC_0247_BITMAPS: &str = r#"# bitmaps is unmaintained

```toml
[advisory]
id = "RUSTSEC-2026-0247"
package = "bitmaps"
date = "2026-10-14"
informational = "unmaintained"

[versions]
patched = []
unaffected = []
```
"#;
        let sbom = sbom_bytes_with_component("bitmaps", "3.0.1");
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("bitmaps", &["RUSTSEC-2026-0247.md"])
            .rustsec_md("bitmaps", "RUSTSEC-2026-0247.md", RUSTSEC_0247_BITMAPS)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].notes,
            vec![NoteReport {
                id: "RUSTSEC-2026-0247".to_string(),
                package: "bitmaps".to_string(),
                kind: "unmaintained".to_string(),
                title: "bitmaps is unmaintained".to_string(),
            }],
            "{:?}",
            report.lines[0]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Negative control for the dedup fix: without `push_unique` guarding
    /// the `notes` push (simulated here by asserting on the UNDERLYING
    /// RustSec md fetch, which the per-crate cache already collapses to
    /// one regardless — the dedup bug lived in the REPORT list, not the
    /// network call), two payloads naming the same advisory must still
    /// collapse to the one report entry asserted above. This control
    /// instead flips the other way: two DIFFERENT advisories (one per
    /// payload) must NOT collapse into each other — dedup is by id, not
    /// by "already saw one note this line".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn two_different_informational_advisories_both_survive_dedup() {
        const OTHER: &str = r#"# sized-chunks: the crate is unmaintained

```toml
[advisory]
id = "RUSTSEC-2026-0901"
package = "sized-chunks"
date = "2026-10-14"
title = "sized-chunks is unmaintained"
informational = "unmaintained"

[versions]
patched = []
unaffected = []
```
"#;
        let sbom_a = sbom_bytes_component_only("witness", "1.0.0", "im", "1.0.0");
        let sbom_b = sbom_bytes_component_only("loom", "1.0.0", "sized-chunks", "1.0.0");
        let sha_a = sha256_hex(&sbom_a);
        let sha_b = sha256_hex(&sbom_b);
        let (root, source, digest) = two_tool_layer_root(&sha_a, &sha_b);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/witness", "[]")
            .ghsa("pulseengine/loom", "[]")
            .rustsec_dir_404("witness")
            .rustsec_dir_404("loom")
            .rustsec_dir("im", &["RUSTSEC-2026-0900.md"])
            .rustsec_md("im", "RUSTSEC-2026-0900.md", INFORMATIONAL_IM)
            .rustsec_dir("sized-chunks", &["RUSTSEC-2026-0901.md"])
            .rustsec_md("sized-chunks", "RUSTSEC-2026-0901.md", OTHER)
            .asset("pulseengine/witness", "v1.0.0", "sbom.cdx.json", &sbom_a)
            .asset("pulseengine/loom", "v1.0.0", "sbom.cdx.json", &sbom_b);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let ids: BTreeSet<String> = report.lines[0].notes.iter().map(|n| n.id.clone()).collect();
        assert_eq!(
            ids,
            ["RUSTSEC-2026-0900", "RUSTSEC-2026-0901"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            "{:?}",
            report.lines[0].notes
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    const RUSTSEC_0346: &str = r#"# rustls: internal buffer overread in TLS 1.3 handling

```toml
[advisory]
id = "RUSTSEC-2026-0346"
package = "rustls"
date = "2026-10-14"
aliases = ["GHSA-c8m5-c952-6cm4"]

[versions]
patched = [">= 0.23.46"]
unaffected = ["< 0.21.0"]
```
"#;

    const RUSTSEC_0347: &str = r#"# rustls: a different, unrelated issue

```toml
[advisory]
id = "RUSTSEC-2026-0347"
package = "rustls"
date = "2026-10-14"

[versions]
unaffected = ["< 0.23.44"]
```
"#;

    /// The exact live case: a wasmtime RustSec entry whose own `CVSS:4.0`
    /// vector this module cannot score, whose `url` names the repository
    /// advisory it was filed from (`GHSA-m9f7-9w4p-gv38`, "high" in
    /// `WASMTIME_LIVE`) — REQ-ADVISORYWATCH-001's GHSA-alias-severity rule.
    /// The EXACT real round-7 shape — `url` is a pull request, not an
    /// advisory link, and the GHSA id is only in `aliases`
    /// (REQ-ADVISORYWATCH-001's GHSA-alias-severity rule, widened: round
    /// 6's narrower `/security/advisories/`-only rule never fires against
    /// this, the actual live wasmtime text).
    const RUSTSEC_0352: &str = r#"# wasmtime: filesystem sandbox escape when renaming symlinks

```toml
[advisory]
id = "RUSTSEC-2026-0352"
package = "wasmtime"
date = "2026-10-14"
url = "https://github.com/bytecodealliance/wasmtime/pull/14729"
aliases = ["GHSA-m9f7-9w4p-gv38"]
cvss = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

[versions]
patched = [">= 48.0.0"]
```
"#;

    /// An advisory whose own requirement text this parser cannot decide —
    /// not a shape any real RustSec advisory has published, but exactly
    /// what "one unreadable advisory must not abort the run" has to be
    /// tested against.
    const RUSTSEC_BADREQ: &str = r#"# an advisory with an unreadable requirement

```toml
[advisory]
id = "RUSTSEC-2026-9999"
package = "rustls"
date = "2026-10-14"

[versions]
patched = ["not a requirement at all"]
```
"#;

    fn sbom_bytes() -> Vec<u8> {
        br#"{"metadata":{"component":{"name":"wsc","version":"0.11.0","purl":"pkg:cargo/wsc@0.11.0"}},"components":[{"name":"rustls","version":"0.23.34","purl":"pkg:cargo/rustls@0.23.34"}]}"#.to_vec()
    }

    /// A layer manifest payload for one tool, carrying a recorded
    /// `ANN_SBOM`/`ANN_SBOM_SHA256` annotation — the general form
    /// `wsc_layer_root` below specialises to one fixed tool.
    fn payload_with_sbom(
        layer: &str,
        tool: &str,
        version: &str,
        repo: &str,
        release: &str,
        sbom_sha: &str,
    ) -> Vec<u8> {
        let payload = layer_manifest_payload(layer, &[(tool, version, repo, release)]);
        let payload_text = String::from_utf8(payload).unwrap();
        payload_text
            .replacen(
                &format!(r#""eu.pulseengine.source.release":"{release}"}}"#),
                &format!(
                    r#""eu.pulseengine.source.release":"{release}","{}":"sbom.cdx.json","{}":"{sbom_sha}"}}"#,
                    varve_core::ANN_SBOM,
                    varve_core::ANN_SBOM_SHA256,
                ),
                1,
            )
            .into_bytes()
    }

    fn wsc_layer_root(sbom_sha: &str) -> (PathBuf, MemorySource, String) {
        let root = scratch("sbom");
        let payload = layer_manifest_payload(
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        // Inject the SBOM annotations the simple tuple-based builder above
        // cannot express.
        let payload_text = String::from_utf8(payload).unwrap();
        let payload_text = payload_text.replacen(
            r#""eu.pulseengine.source.release":"v0.11.0"}"#,
            &format!(
                r#""eu.pulseengine.source.release":"v0.11.0","{}":"sbom.cdx.json","{}":"{sbom_sha}"}}"#,
                varve_core::ANN_SBOM,
                varve_core::ANN_SBOM_SHA256,
            ),
            1,
        );
        let digest = varve_core::manifest_digest(payload_text.as_bytes());
        let source = MemorySource::new().with_manifest(&envelope_for(payload_text.as_bytes()));
        (root, source, digest)
    }

    /// One layer carrying TWO distinct top-level tools, each its own
    /// (repo, version) payload with its own `ANN_SBOM` annotation —
    /// the shape the live run hit (witness AND loom both embedding the
    /// same wasmtime/crate): two DIFFERENT `DedupedPayload`s whose SBOMs
    /// can still name the SAME advisory id, which is exactly what
    /// `push_unique` has to collapse to one report entry
    /// (REQ-ADVISORYWATCH-001's dedup rule).
    fn two_tool_layer_root(sbom_sha_a: &str, sbom_sha_b: &str) -> (PathBuf, MemorySource, String) {
        let root = scratch("dedup");
        let payload = layer_manifest_payload(
            "2026.10.0",
            &[
                ("witness", "1.0.0", "pulseengine/witness", "v1.0.0"),
                ("loom", "1.0.0", "pulseengine/loom", "v1.0.0"),
            ],
        );
        let payload_text = String::from_utf8(payload).unwrap();
        let payload_text = payload_text.replacen(
            r#""eu.pulseengine.source.repo":"pulseengine/witness","eu.pulseengine.source.release":"v1.0.0"}"#,
            &format!(
                r#""eu.pulseengine.source.repo":"pulseengine/witness","eu.pulseengine.source.release":"v1.0.0","{}":"sbom.cdx.json","{}":"{sbom_sha_a}"}}"#,
                varve_core::ANN_SBOM,
                varve_core::ANN_SBOM_SHA256,
            ),
            1,
        );
        let payload_text = payload_text.replacen(
            r#""eu.pulseengine.source.repo":"pulseengine/loom","eu.pulseengine.source.release":"v1.0.0"}"#,
            &format!(
                r#""eu.pulseengine.source.repo":"pulseengine/loom","eu.pulseengine.source.release":"v1.0.0","{}":"sbom.cdx.json","{}":"{sbom_sha_b}"}}"#,
                varve_core::ANN_SBOM,
                varve_core::ANN_SBOM_SHA256,
            ),
            1,
        );
        let digest = varve_core::manifest_digest(payload_text.as_bytes());
        let source = MemorySource::new().with_manifest(&envelope_for(payload_text.as_bytes()));
        (root, source, digest)
    }

    /// 0346's range covers 0.23.34; 0347's `unaffected` already clears it.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn sbom_embedded_component_is_checked_against_rustsec_and_only_one_advisory_affects_it() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            // `wsc` itself is the SBOM's `metadata.component`, which clause
            // 4b checks the same as every other component — it simply has
            // no RustSec advisories.
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md", "RUSTSEC-2026-0347.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .rustsec_md("rustls", "RUSTSEC-2026-0347.md", RUSTSEC_0347)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(report.lines.len(), 1);
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE requirement's own example: a RustSec entry whose `CVSS:4.0`
    /// vector cannot be scored (it would default to "medium") instead
    /// gets its severity from the repository advisory its `url` names —
    /// `GHSA-m9f7-9w4p-gv38`, "high" in the real `WASMTIME_LIVE` fixture —
    /// and that source is recorded in `severity_from_ghsa`, never in
    /// `defaulted_severities`.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_cvss4_rustsec_entry_takes_its_severity_from_its_ghsa_alias() {
        let sbom = sbom_bytes_with_component("wasmtime", "47.0.3");
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .rustsec_dir_404("wsc")
            .rustsec_dir("wasmtime", &["RUSTSEC-2026-0352.md"])
            .rustsec_md("wasmtime", "RUSTSEC-2026-0352.md", RUSTSEC_0352)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert_eq!(
            line.new_known_problems,
            vec!["RUSTSEC-2026-0352".to_string()]
        );
        assert_eq!(
            line.severity_from_ghsa,
            vec![SeverityFromGhsaReport {
                id: "RUSTSEC-2026-0352".to_string(),
                ghsa_id: "GHSA-m9f7-9w4p-gv38".to_string(),
            }],
            "{line:?}"
        );
        assert!(
            line.defaulted_severities.is_empty(),
            "the GHSA alias resolved the severity; it must not ALSO be reported as defaulted: {line:?}"
        );

        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        let kp = written
            .known_problems
            .iter()
            .find(|k| k.id == "RUSTSEC-2026-0352")
            .expect("written");
        assert_eq!(kp.severity, "high", "{kp:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The alias lookup is ENRICHMENT, not the affected decision — a
    /// FAILURE to read the alias repo's GHSA listing (network, a
    /// non-404) must not abort a run that is also looking at every other
    /// advisory this line has. The advisory still becomes a known
    /// problem, with severity defaulted to "medium" and the fetch
    /// failure as the stated reason, exactly as "no alias at all" would
    /// — unlike a PAYLOAD's own repo (clause 4a), where the same kind of
    /// failure is still a hard error, because that one IS the affected
    /// decision.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_failed_alias_lookup_degrades_to_defaulted_severity_rather_than_aborting() {
        let sbom = sbom_bytes_with_component("wasmtime", "47.0.3");
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .ghsa_fails("bytecodealliance/wasmtime", "connection reset by peer")
            .rustsec_dir_404("wsc")
            .rustsec_dir("wasmtime", &["RUSTSEC-2026-0352.md"])
            .rustsec_md("wasmtime", "RUSTSEC-2026-0352.md", RUSTSEC_0352)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15").expect("the run must NOT abort");
        let line = &report.lines[0];
        assert_eq!(
            line.new_known_problems,
            vec!["RUSTSEC-2026-0352".to_string()],
            "still a known problem despite the enrichment failure: {line:?}"
        );
        assert!(line.severity_from_ghsa.is_empty(), "{line:?}");
        let defaulted = line
            .defaulted_severities
            .iter()
            .find(|d| d.id == "RUSTSEC-2026-0352")
            .expect("{line:?}");
        assert!(
            defaulted.reason.starts_with("GHSA severity lookup failed:")
                && defaulted.reason.contains("connection reset by peer"),
            "{defaulted:?}"
        );

        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        let kp = written
            .known_problems
            .iter()
            .find(|k| k.id == "RUSTSEC-2026-0352")
            .expect("written");
        assert_eq!(kp.severity, "medium", "{kp:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Not a regression test for the fix itself (that is
    /// `a_cvss4_rustsec_entry_takes_its_severity_from_its_ghsa_alias`
    /// below) but its mirror: an advisory with NEITHER a github.com `url`
    /// NOR a GHSA `aliases` entry resolves no alias at all, so the SAME
    /// unscoreable `CVSS:4.0` vector still defaults to "medium" — proving
    /// the high severity really does come from having an alias to
    /// resolve, not from some other path.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn without_a_ghsa_alias_url_the_same_vector_still_defaults_to_medium() {
        let no_alias_md = RUSTSEC_0352
            .replace(
                r#"url = "https://github.com/bytecodealliance/wasmtime/pull/14729""#,
                r#"url = "https://rustsec.org/advisories/RUSTSEC-2026-0352""#,
            )
            .replace(r#"aliases = ["GHSA-m9f7-9w4p-gv38"]"#, "");
        assert_ne!(
            no_alias_md, RUSTSEC_0352,
            "both replaces must actually fire"
        );
        assert!(!no_alias_md.contains("GHSA-"), "no GHSA id left anywhere");

        let sbom = sbom_bytes_with_component("wasmtime", "47.0.3");
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("wasmtime", &["RUSTSEC-2026-0352.md"])
            .rustsec_md("wasmtime", "RUSTSEC-2026-0352.md", &no_alias_md)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert!(line.severity_from_ghsa.is_empty(), "{line:?}");
        assert_eq!(
            line.defaulted_severities,
            vec![DefaultedSeverityReport {
                id: "RUSTSEC-2026-0352".to_string(),
                reason: "CVSS:4.0 vector, not scored".to_string(),
            }],
            "{line:?}"
        );
        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        let kp = written
            .known_problems
            .iter()
            .find(|k| k.id == "RUSTSEC-2026-0352")
            .expect("written");
        assert_eq!(kp.severity, "medium", "{kp:?}");

        // bytecodealliance/wasmtime's GHSA listing is never even fetched
        // when the advisory names no alias to resolve.
        assert!(
            !gh.calls()
                .iter()
                .any(|c| c.contains("wasmtime") && c.starts_with("ghsa:")),
            "{:?}",
            gh.calls()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    fn sbom_bytes_with_component(name: &str, version: &str) -> Vec<u8> {
        format!(
            r#"{{"metadata":{{"component":{{"name":"wsc","version":"0.11.0","purl":"pkg:cargo/wsc@0.11.0"}}}},"components":[{{"name":"{name}","version":"{version}","purl":"pkg:cargo/{name}@{version}"}}]}}"#
        )
        .into_bytes()
    }

    /// An SBOM component whose name cannot be a real crate (crates.io's own
    /// rule) is SKIPPED — reported, and never queried at all. `../x` and the
    /// like are exactly the untrusted text that could otherwise steer a
    /// RustSec request to a different URL path.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_component_with_an_invalid_crate_name_is_skipped_and_never_queried() {
        for bad in ["../x", "a/b", ""] {
            let sbom = sbom_bytes_with_component(bad, "1.0.0");
            let sha = sha256_hex(&sbom);
            let (root, source, digest) = wsc_layer_root(&sha);
            write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

            let gh = FakeGh::default()
                .ghsa("pulseengine/wsc", "[]")
                .rustsec_dir_404("wsc")
                .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

            let report = run(&root, &gh, &source, "2026-10-15").expect(bad);
            assert!(
                !gh.calls()
                    .iter()
                    .any(|c| c == &format!("rustsec-dir:{bad}")),
                "{bad:?} must never be queried: {:?}",
                gh.calls()
            );
            assert_eq!(
                report.lines[0].skipped,
                vec![SkippedReport {
                    what: bad.to_string(),
                    reason: "not a valid crate name".to_string(),
                }],
                "{bad:?}: {:?}",
                report.lines[0]
            );

            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// A RustSec directory listing entry whose filename is not the real
    /// `RUSTSEC-YYYY-NNNN.md` shape is skipped, reported, and never fetched
    /// — `parse_rustsec_dir_listing` only filters by `.md` suffix, which
    /// `../evil.md` satisfies, so this check has to run downstream of it.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_rustsec_listing_entry_with_an_invalid_filename_is_skipped_and_never_fetched() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir(
                "rustls",
                &["RUSTSEC-2026-0346.md", "../evil.md", "README.md"],
            )
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert!(
            !gh.calls()
                .iter()
                .any(|c| c.starts_with("rustsec-md:")
                    && (c.contains("evil") || c.contains("README"))),
            "{:?}",
            gh.calls()
        );
        let skipped_whats: BTreeSet<String> = report.lines[0]
            .skipped
            .iter()
            .map(|s| s.what.clone())
            .collect();
        assert_eq!(
            skipped_whats,
            ["../evil.md", "README.md"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            "{:?}",
            report.lines[0].skipped
        );
        // The real advisory was still found despite the two bad entries.
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A component with a PRE-RELEASE version cannot be numerically
    /// compared at all (the pure core's own rule), and that must not abort
    /// the whole run — it is recorded as undecidable and the run continues,
    /// still finding whatever it legitimately can.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_component_with_a_prerelease_version_is_undecidable_not_aborting() {
        let sbom = br#"{"metadata":{"component":{"name":"wsc","version":"0.11.0","purl":"pkg:cargo/wsc@0.11.0"}},"components":[
            {"name":"rustls","version":"0.23.34","purl":"pkg:cargo/rustls@0.23.34"},
            {"name":"somecrate","version":"1.0.0-rc.1","purl":"pkg:cargo/somecrate@1.0.0-rc.1"}
        ]}"#
        .to_vec();
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("one pre-release component must not abort the run");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "the OTHER component must still be checked"
        );
        assert!(
            report.lines[0]
                .undecidable
                .iter()
                .any(|u| u.id == "somecrate" && u.reason == "pre-release version, not compared"),
            "{:?}",
            report.lines[0].undecidable
        );
        assert!(
            !gh.calls().iter().any(|c| c.contains("somecrate")),
            "a version that cannot be compared must never be queried either: {:?}",
            gh.calls()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A component version this parser cannot decide for a reason OTHER
    /// than pre-release (genuine garbage, not merely a pre-release suffix)
    /// is likewise undecidable, not an abort — the reclassification this
    /// round's audit made: a single component's garbled version must not
    /// take down every other component and payload with it.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_component_with_a_garbage_version_is_undecidable_not_aborting() {
        let sbom = br#"{"metadata":{"component":{"name":"wsc","version":"0.11.0","purl":"pkg:cargo/wsc@0.11.0"}},"components":[
            {"name":"rustls","version":"0.23.34","purl":"pkg:cargo/rustls@0.23.34"},
            {"name":"somecrate","version":"banana","purl":"pkg:cargo/somecrate@banana"}
        ]}"#
        .to_vec();
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom);

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("one garbage component version must not abort the run");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "the OTHER component must still be checked"
        );
        assert!(
            report.lines[0]
                .undecidable
                .iter()
                .any(|u| u.id == "somecrate" && u.reason.starts_with("version could not be read")),
            "{:?}",
            report.lines[0].undecidable
        );
        assert!(
            !gh.calls().iter().any(|c| c.contains("somecrate")),
            "{:?}",
            gh.calls()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An SBOM that cannot be parsed at all is a coverage gap for THIS
    /// payload alone — unchecked, not an abort — even though the bytes
    /// came back successfully (digest matched / proof covered them); the
    /// content itself is simply not readable JSON.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unparseable_sbom_is_unchecked_not_aborting() {
        let bad_sbom: &[u8] = b"not json at all";
        let sha = sha256_hex(bad_sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default().ghsa("pulseengine/wsc", "[]").asset(
            "pulseengine/wsc",
            "v0.11.0",
            "sbom.cdx.json",
            bad_sbom,
        );

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("an unparseable SBOM must not abort the run");
        assert_eq!(
            report.lines[0].unchecked.len(),
            1,
            "{:?}",
            report.lines[0].unchecked
        );
        assert!(
            report.lines[0].unchecked[0]
                .reason
                .starts_with("SBOM could not be parsed"),
            "{:?}",
            report.lines[0].unchecked
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A payload whose OWN version this parser cannot read is a coverage
    /// gap for the GHSA comparison alone — unchecked, not an abort, and
    /// every OTHER payload the line names is still checked normally.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_payload_with_an_unreadable_own_version_is_unchecked_not_aborting() {
        let root = scratch("badpayloadversion");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("weird-tool", "not-a-version", "o/weird", "")],
        );
        let payload2 = layer_manifest_payload(
            "2026.10.1",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let d2 = varve_core::manifest_digest(&payload2);
        let source = source.with_manifest(&envelope_for(&payload2));
        write_index(&root, "2026.10", &[("2026.10.0", &d1), ("2026.10.1", &d2)]);

        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .release_sbom_outcome(
                "o/weird",
                "not-a-version",
                "not-a-version",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.1",
                "49.0.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("an unreadable payload version must not abort the run");
        assert!(
            report.lines[0]
                .unchecked
                .iter()
                .any(|u| u.repo == "o/weird" && u.reason.contains("GHSA comparison")),
            "{:?}",
            report.lines[0].unchecked
        );
        // The OTHER payload (wasmtime) is still checked normally.
        assert_eq!(
            report.lines[0].new_known_problems.len(),
            23,
            "{:?}",
            report.lines[0]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// One RustSec advisory whose requirement cannot be read must not abort
    /// the run — it is reported undecidable, and a GOOD advisory for the
    /// SAME crate is still found. The real-world shape this pins against:
    /// the live run aborted entirely on one unreadable requirement, taking
    /// down every other advisory and every other payload with it.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn one_unreadable_rustsec_requirement_does_not_abort_the_run() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md", "RUSTSEC-2026-9999.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .rustsec_md("rustls", "RUSTSEC-2026-9999.md", RUSTSEC_BADREQ)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("one unreadable advisory must not abort the run");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "the good advisory must still be found"
        );
        assert_eq!(
            report.lines[0].undecidable.len(),
            1,
            "{:?}",
            report.lines[0].undecidable
        );
        let u = &report.lines[0].undecidable[0];
        assert_eq!(u.id, "RUSTSEC-2026-9999");
        assert_eq!(u.package, "rustls");
        assert_eq!(u.reason, "requirement could not be read");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The SAME unreadable RustSec advisory, reached from TWO DIFFERENT
    /// payloads that both embed `rustls` (two separate tools, each with
    /// their own recorded SBOM), is reported ONCE — not once per payload
    /// that happened to embed the same vulnerable crate.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_same_unreadable_rustsec_advisory_from_two_payloads_is_reported_once() {
        let root = scratch("dedup-undecidable-rustsec");
        let sbom1 = sbom_bytes();
        let sha1 = sha256_hex(&sbom1);
        let payload1 = payload_with_sbom(
            "2026.10.0",
            "wsc",
            "0.11.0",
            "pulseengine/wsc",
            "v0.11.0",
            &sha1,
        );
        let digest1 = varve_core::manifest_digest(&payload1);

        let sbom2 = sbom_bytes(); // same shape: metadata "wsc", component "rustls" 0.23.34
        let sha2 = sha256_hex(&sbom2);
        let payload2 = payload_with_sbom(
            "2026.10.1",
            "wsc2",
            "0.12.0",
            "pulseengine/wsc2",
            "v0.12.0",
            &sha2,
        );
        let digest2 = varve_core::manifest_digest(&payload2);

        let source = MemorySource::new()
            .with_manifest(&envelope_for(&payload1))
            .with_manifest(&envelope_for(&payload2));
        write_index(
            &root,
            "2026.10",
            &[("2026.10.0", &digest1), ("2026.10.1", &digest2)],
        );

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .ghsa("pulseengine/wsc2", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir_404("wsc2")
            .rustsec_dir("rustls", &["RUSTSEC-2026-9999.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-9999.md", RUSTSEC_BADREQ)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom1)
            .asset("pulseengine/wsc2", "v0.12.0", "sbom.cdx.json", &sbom2);

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("one unreadable advisory must not abort the run");
        assert_eq!(
            report.lines[0].undecidable.len(),
            1,
            "the SAME advisory id from two payloads must be reported once: {:?}",
            report.lines[0].undecidable
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Idempotence: running again on the already-written document, with the
    /// exact same sources, proposes nothing further.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_second_run_on_its_own_output_writes_nothing() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let first = run(&root, &gh, &source, "2026-10-15").expect("first run");
        assert!(first.lines[0].wrote);

        // Same `today` as the first run: idempotence is what this test
        // pins, not longevity across days — a bootstrapped document with
        // no readable baseline support window falls back to the day it was
        // created, which the NEXT day would (correctly) read as expired.
        let second = run(&root, &gh, &source, "2026-10-15").expect("second run");
        assert!(!second.lines[0].wrote, "{:?}", second.lines[0]);
        assert!(second.lines[0].new_known_problems.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A 404 RustSec crate directory is not an error, and not a finding.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_404_rustsec_crate_directory_is_not_an_error() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir_404("rustls")
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let report =
            run(&root, &gh, &source, "2026-10-15").expect("a 404 crate dir is not an error");
        assert!(report.lines[0].new_known_problems.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    // -------------------------------------------------------------
    // No recorded ANN_SBOM: fall back to the release's OWN SBOM
    // (REQ-ADVISORYWATCH-001 clause 4b's fallback — the supervisor's
    // live-run finding: wsc 0.11.0's embedded rustls 0.23.34 went
    // unreported because no PUBLISHED layer records ANN_SBOM yet).
    // -------------------------------------------------------------

    /// A payload with NO recorded `ANN_SBOM` whose release publishes a
    /// `.cdx.json` covered by its own verified proof: embedded `rustls` is
    /// still checked, and RUSTSEC-2026-0346 is still found.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn no_recorded_sbom_falls_back_to_the_releases_own_covered_sbom() {
        let root = scratch("fallback-found");
        let (source, digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md", "RUSTSEC-2026-0347.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346)
            .rustsec_md("rustls", "RUSTSEC-2026-0347.md", RUSTSEC_0347)
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::Found(sbom_bytes()),
            );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()]
        );
        assert!(
            report.lines[0].unchecked.is_empty(),
            "a found, covered SBOM is not a coverage gap: {:?}",
            report.lines[0].unchecked
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A layer whose manifest entries are given as raw JSON, so a test can
    /// carry exactly the shapes `layer_manifest_payload` cannot: an entry
    /// with no version, one with no repository, an included layer, a crate.
    fn with_raw_entries(
        source: MemorySource,
        layer: &str,
        raw_entries: &[&str],
    ) -> (MemorySource, String) {
        let payload = format!(
            r#"{{"annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"rolling","eu.pulseengine.varve.counter":"1","org.opencontainers.image.created":"2026-10-01T00:00:00Z"}},"manifests":[{}]}}"#,
            raw_entries.join(",")
        )
        .into_bytes();
        let digest = varve_core::manifest_digest(&payload);
        (source.with_manifest(&envelope_for(&payload)), digest)
    }

    /// Everything a layer carries that the watcher cannot check is REPORTED
    /// (clause 1 / clause 4): an entry with no version, one with no source
    /// repository, and an included layer used to be dropped by
    /// `payload_from_entry` and never mentioned, so a line carrying them read
    /// "nothing new" over payloads nobody had looked at.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn entries_a_layer_carries_but_the_watcher_cannot_check_are_reported_not_dropped() {
        let root = scratch("droppedentries");
        let (source, digest) = with_raw_entries(
            MemorySource::new(),
            "2026.10.0",
            &[
                r#"{"digest":"sha256:ok","annotations":{"eu.pulseengine.tool":"wsc","eu.pulseengine.tool.version":"0.11.0","eu.pulseengine.source.repo":"pulseengine/wsc"}}"#,
                r#"{"digest":"sha256:nov","annotations":{"eu.pulseengine.tool":"noversion","eu.pulseengine.source.repo":"o/noversion"}}"#,
                r#"{"digest":"sha256:norepo","annotations":{"eu.pulseengine.tool":"norepo","eu.pulseengine.tool.version":"1.2.3"}}"#,
                r#"{"digest":"sha256:inc","annotations":{"eu.pulseengine.varve.kind":"layer","eu.pulseengine.varve.include.realm":"bytecodealliance","eu.pulseengine.varve.include.layer":"2026.09.0"}}"#,
            ],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let unchecked = &report.lines[0].unchecked;
        let find = |tool: &str| unchecked.iter().find(|u| u.tool == tool);
        let nov =
            find("noversion").unwrap_or_else(|| panic!("no-version entry dropped: {unchecked:?}"));
        assert!(
            nov.reason.contains("eu.pulseengine.tool.version"),
            "the reason must name the missing annotation: {nov:?}"
        );
        assert_eq!(nov.repo, "o/noversion");
        let norepo =
            find("norepo").unwrap_or_else(|| panic!("no-repo entry dropped: {unchecked:?}"));
        assert!(
            norepo.reason.contains("eu.pulseengine.source.repo"),
            "{norepo:?}"
        );
        assert_eq!(norepo.version, "1.2.3");
        let inc = find("included layer")
            .unwrap_or_else(|| panic!("included layer dropped: {unchecked:?}"));
        assert_eq!(inc.version, "2026.09.0");
        assert_eq!(inc.repo, "bytecodealliance");
        assert!(inc.reason.contains("included layer"), "{inc:?}");
        // The checkable payload is still checked, and still reports its own gap.
        assert!(find("wsc").is_some(), "{unchecked:?}");

        let summary = human_summary(&report);
        assert!(
            !summary.contains("2026.10\tnothing new\n"),
            "bare \"nothing new\" must not stand over unchecked entries: {summary}"
        );
        assert!(summary.contains("o/noversion"), "{summary}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A line made ONLY of things the watcher cannot check must still say so:
    /// no payload means no GHSA query at all, which is exactly when a silent
    /// drop reads as a clean line.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_line_of_only_unchecked_entries_never_reads_as_nothing_new() {
        let root = scratch("onlydropped");
        let (source, digest) = with_raw_entries(
            MemorySource::new(),
            "2026.10.0",
            &[
                r#"{"digest":"sha256:nov","annotations":{"eu.pulseengine.tool":"noversion","eu.pulseengine.source.repo":"o/noversion"}}"#,
            ],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        let report = run(&root, &FakeGh::default(), &source, "2026-10-15").expect("runs");
        assert_eq!(report.lines[0].unchecked.len(), 1, "{:?}", report.lines[0]);
        let summary = human_summary(&report);
        assert!(
            summary.contains("nothing new among checked payloads"),
            "{summary}"
        );
        assert!(!summary.contains("2026.10\tnothing new\n"), "{summary}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Entries of a kind that is not a tool (crates, SDKs, docs...) are not
    /// payloads this watcher checks. They are reported once per kind with a
    /// count — a layer of a hundred crates must not be a hundred lines — and
    /// the same entry carried by two layers is counted once.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn non_tool_entries_are_reported_once_per_kind_with_a_distinct_count() {
        let root = scratch("kindsreported");
        let crate_a =
            r#"{"digest":"sha256:ca","annotations":{"eu.pulseengine.varve.kind":"crate"}}"#;
        let crate_b =
            r#"{"digest":"sha256:cb","annotations":{"eu.pulseengine.varve.kind":"crate"}}"#;
        let (source, d1) = with_raw_entries(MemorySource::new(), "2026.10.0", &[crate_a, crate_b]);
        let (source, d2) = with_raw_entries(source, "2026.10.1", &[crate_a]);
        write_index(&root, "2026.10", &[("2026.10.0", &d1), ("2026.10.1", &d2)]);
        let report = run(&root, &FakeGh::default(), &source, "2026-10-15").expect("runs");
        let unchecked = &report.lines[0].unchecked;
        assert_eq!(unchecked.len(), 1, "{unchecked:?}");
        assert_eq!(unchecked[0].tool, "crate entries");
        assert_eq!(unchecked[0].version, "2 distinct");
        assert!(
            unchecked[0].reason.contains("not a tool payload"),
            "{unchecked:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A release that publishes NO SBOM at all: the payload is unchecked
    /// for embedded components, with the reason recorded, and the human
    /// summary says so rather than printing a bare "nothing new".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_release_with_no_sbom_is_unchecked_and_the_summary_says_so() {
        let root = scratch("fallback-nosbom");
        let (source, digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert!(!report.lines[0].wrote);
        assert_eq!(
            report.lines[0].unchecked,
            vec![UncheckedReport {
                tool: "wsc".to_string(),
                version: "0.11.0".to_string(),
                repo: "pulseengine/wsc".to_string(),
                reason: "no SBOM recorded and the release publishes none".to_string(),
            }]
        );

        let summary = human_summary(&report);
        assert!(summary.contains("item(s) NOT checked"), "{summary}");
        assert!(
            !summary.contains("\tnothing new\n"),
            "the bare phrase must never appear alone over an unchecked payload: {summary}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A release whose SBOM exists but is NOT covered by its own verified
    /// proof: unchecked, and never used — no component from it is ever
    /// parsed or queried.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_uncovered_release_sbom_is_unchecked_and_never_used() {
        let root = scratch("fallback-notcovered");
        let (source, digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::NotCovered,
            );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].unchecked,
            vec![UncheckedReport {
                tool: "wsc".to_string(),
                version: "0.11.0".to_string(),
                repo: "pulseengine/wsc".to_string(),
                reason: "release SBOM not covered by its verified proof".to_string(),
            }]
        );
        // No RustSec call happened at all — an uncovered SBOM is never
        // parsed for components.
        assert!(
            !gh.calls().iter().any(|c| c.starts_with("rustsec-")),
            "{:?}",
            gh.calls()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A release that could not be verified at all: unchecked, with the
    /// verification failure's own detail carried in the reason, and the
    /// run continues rather than aborting.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_release_that_cannot_be_verified_is_unchecked_with_its_reason() {
        let root = scratch("fallback-verifyfailed");
        let (source, digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::VerifyFailed(
                    "HTTP 403: rate limited".to_string(),
                ),
            );

        let report = run(&root, &gh, &source, "2026-10-15")
            .expect("an unverifiable release must not abort the run");
        assert_eq!(report.lines[0].unchecked.len(), 1);
        assert_eq!(
            report.lines[0].unchecked[0].reason,
            "release could not be verified: HTTP 403: rate limited"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `release_sbom` is called exactly ONCE per (repo, release), cached —
    /// two deduped payloads from the same repo and release must not ask
    /// twice.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn release_sbom_is_cached_per_repo_and_release() {
        // The SAME (repo, release, payload version) requested by TWO
        // DIFFERENT LINES in one run — dedup already guarantees at most one
        // DedupedPayload per (repo, version) WITHIN a line, so the only way
        // this fallback is asked about the same key twice is across lines,
        // which share one `Caches` for the whole run.
        let root = scratch("fallback-cached");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        let payload2 = layer_manifest_payload(
            "2026.11.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        let d2 = varve_core::manifest_digest(&payload2);
        let source = source.with_manifest(&envelope_for(&payload2));
        write_index(&root, "2026.10", &[("2026.10.0", &d1)]);
        write_index(&root, "2026.11", &[("2026.11.0", &d2)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(report.lines.len(), 2, "{:?}", report.lines);
        assert_eq!(
            report
                .lines
                .iter()
                .map(|l| l.unchecked.len())
                .sum::<usize>(),
            2,
            "{:?}",
            report.lines
        );
        let release_sbom_calls = gh
            .calls()
            .iter()
            .filter(|c| c.starts_with("release-sbom:"))
            .count();
        assert_eq!(release_sbom_calls, 1, "{:?}", gh.calls());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The SAME (repo, release) requested with TWO DIFFERENT payload
    /// versions must NOT share a cache entry — the selection among several
    /// `.cdx.json` candidates can legitimately differ per version, so
    /// collapsing them would risk serving one payload's SBOM to another.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn release_sbom_cache_is_keyed_on_the_payload_version_too() {
        let root = scratch("fallback-cache-version");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        let payload2 = layer_manifest_payload(
            "2026.11.0",
            &[("wsc-cli", "0.11.1", "pulseengine/wsc", "v0.11.0")],
        );
        let d2 = varve_core::manifest_digest(&payload2);
        let source = source.with_manifest(&envelope_for(&payload2));
        write_index(&root, "2026.10", &[("2026.10.0", &d1)]);
        write_index(&root, "2026.11", &[("2026.11.0", &d2)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::Found(sbom_bytes()),
            )
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        // Line 2026.10 (version 0.11.0) got a Found SBOM and checked it;
        // line 2026.11 (version 0.11.1) got NoSbom and is unchecked.
        let line_10 = report.lines.iter().find(|l| l.line == "2026.10").unwrap();
        let line_11 = report.lines.iter().find(|l| l.line == "2026.11").unwrap();
        assert_eq!(
            line_10.new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "{line_10:?}"
        );
        assert!(line_10.unchecked.is_empty(), "{line_10:?}");
        assert_eq!(line_11.unchecked.len(), 1, "{line_11:?}");

        let release_sbom_calls = gh
            .calls()
            .iter()
            .filter(|c| c.starts_with("release-sbom:"))
            .count();
        assert_eq!(release_sbom_calls, 2, "{:?}", gh.calls());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A GHSA advisory stating no severity is reported as defaulted.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_severity_less_ghsa_advisory_is_reported_as_defaulted() {
        let root = scratch("nosev");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("t", "1.0.0", "o/sev", "")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &d1)]);

        let json = r#"[{
            "ghsa_id": "GHSA-nosev",
            "severity": null,
            "summary": "no stated severity",
            "html_url": null,
            "vulnerabilities": [{"package": {"name": "t"}, "vulnerable_version_range": ">= 1.0.0", "patched_versions": null}]
        }]"#;
        let gh = FakeGh::default().ghsa("o/sev", json).release_sbom_outcome(
            "o/sev",
            "1.0.0",
            "1.0.0",
            crate::orchestrate::ReleaseSbomOutcome::NoSbom,
        );

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].defaulted_severities,
            vec![DefaultedSeverityReport {
                id: "GHSA-nosev".to_string(),
                reason: "no stated severity".to_string(),
            }]
        );
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["GHSA-nosev".to_string()]
        );

        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written.known_problems[0].severity, "medium");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A non-404 GHSA failure fails the WHOLE run and writes nothing.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_non_404_ghsa_failure_is_an_error_and_writes_nothing() {
        let root = scratch("ghsa-fail");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &d1)]);

        let gh =
            FakeGh::default().ghsa_fails("bytecodealliance/wasmtime", "HTTP 403: rate limited");

        let err = run(&root, &gh, &source, "2026-10-15").expect_err("must fail");
        assert!(err.to_string().contains("rate limited"), "{err}");
        assert!(
            !root.join("line-status/2026.10.json").exists(),
            "a failed run must write nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A non-404 RustSec directory failure is likewise a hard error — rate
    /// limiting and the like must not be read as "this crate has no
    /// advisories".
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_non_404_rustsec_directory_failure_is_an_error_and_writes_nothing() {
        let sha = sha256_hex(&sbom_bytes());
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .rustsec_dir_404("wsc")
            .rustsec_dir_fails("rustls", "HTTP 403: API rate limit exceeded")
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom_bytes());

        let err = run(&root, &gh, &source, "2026-10-15").expect_err("must fail");
        assert!(err.to_string().contains("rate limit"), "{err}");
        assert!(!root.join("line-status/2026.10.json").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The strongest form of "write nothing for that run": line A succeeds
    /// completely and would write; line B, processed after it, fails. Line
    /// A's prepared document must NOT be on disk — the two-phase
    /// compute-then-write split is what this test is pinning.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn one_lines_failure_prevents_writing_a_different_lines_already_computed_success() {
        let root = scratch("two-lines");
        let (source, d_a) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let payload_b = layer_manifest_payload(
            "2026.11.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        let source = source.with_manifest(&envelope_for(&payload_b));

        write_index(&root, "2026.10", &[("2026.10.0", &d_a)]);
        // Line "2026.11" names a digest the registry does not actually
        // carry — a genuine source-cannot-be-read failure (clause 1), not
        // a per-payload/per-advisory field issue, so it is correctly a
        // hard error even after this round's reclassifications.
        write_index(
            &root,
            "2026.11",
            &[("2026.11.0", "sha256:not-the-real-one")],
        );

        // Line "2026.10" is processed FIRST (sorted order) and must
        // compute a complete, valid document — including its SBOM
        // fallback — before "2026.11" is even reached.
        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.1",
                "49.0.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );

        let err =
            run(&root, &gh, &source, "2026-10-15").expect_err("2026.11's digest must not verify");
        assert!(err.to_string().contains("2026.11.0"), "{err}");
        assert!(
            !root.join("line-status/2026.10.json").exists(),
            "2026.10 computed a real, valid prepared document and must still not be written \
             when a LATER line in the same run fails"
        );
        assert!(!root.join("line-status/2026.11.json").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An SBOM sha256 mismatch is an error.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_sbom_sha256_mismatch_is_an_error() {
        let (root, source, digest) =
            wsc_layer_root("0000000000000000000000000000000000000000000000000000000000000000");
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);

        let gh = FakeGh::default().ghsa("pulseengine/wsc", "[]").asset(
            "pulseengine/wsc",
            "v0.11.0",
            "sbom.cdx.json",
            &sbom_bytes(),
        );

        let err = run(&root, &gh, &source, "2026-10-15").expect_err("sha256 mismatch must refuse");
        assert!(err.to_string().to_lowercase().contains("sha256"), "{err}");
        assert!(!root.join("line-status/2026.10.json").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An expired line is skipped entirely — no registry fetch, no `gh`
    /// call, and no write.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_expired_line_is_skipped_with_no_sources_consulted() {
        let root = scratch("expired");
        // A registry/gh pair that would panic if touched at all.
        struct Untouchable;
        impl LayerSource for Untouchable {
            fn fetch_manifest(
                &self,
                _layer: &LayerRef,
            ) -> Result<Vec<u8>, varve_core::SourceError> {
                panic!("an expired line must never fetch a layer manifest");
            }
            fn fetch_blob(&self, _digest: &str) -> Result<Vec<u8>, varve_core::SourceError> {
                panic!("unused");
            }
        }
        impl AdvisoryGh for Untouchable {
            fn security_advisories(&self, _repo: &str) -> Result<String, WatchError> {
                panic!("an expired line must never ask GHSA anything");
            }
            fn rustsec_crate_dir(&self, _krate: &str) -> Result<Option<Vec<String>>, WatchError> {
                panic!("unused");
            }
            fn rustsec_advisory_md(
                &self,
                _krate: &str,
                _filename: &str,
            ) -> Result<String, WatchError> {
                panic!("unused");
            }
            fn release_asset(
                &self,
                _repo: &str,
                _release: &str,
                _asset: &str,
            ) -> Result<Vec<u8>, WatchError> {
                panic!("unused");
            }
            fn release_sbom(
                &self,
                _repo: &str,
                _release: &str,
                _version: &str,
            ) -> crate::orchestrate::ReleaseSbomOutcome {
                panic!("unused");
            }
        }

        write_index(&root, "2026.10", &[("2026.10.0", "sha256:whatever")]);
        std::fs::write(
            root.join("line-status/2026.10.json"),
            r#"{"line":"2026.10","counter":3,"issued-at":"2026-04-01T00:00:00Z","support-until":"2026-09-01"}"#,
        )
        .unwrap();

        let report = run(&root, &Untouchable, &Untouchable, "2026-10-15").expect("runs");
        assert_eq!(report.lines.len(), 1);
        assert_eq!(report.lines[0].line, "2026.10");
        assert!(report.lines[0].skipped_expired);
        assert!(!report.lines[0].wrote);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A line with no committed `line-status/<line>.json` starts from the
    /// empty document (clause 2's documented choice) rather than erroring.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_line_with_no_committed_status_bootstraps_from_an_empty_document() {
        let root = scratch("bootstrap");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.3", "bytecodealliance/wasmtime", "")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &d1)]);
        assert!(!root.join("line-status/2026.10.json").exists());

        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", WASMTIME_LIVE)
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.3",
                "49.0.3",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        // 49.0.3 has zero findings in the live fixture, so nothing changed
        // relative to an empty document and nothing is written — but the run
        // itself must succeed rather than treating "no status file" as an
        // error.
        assert!(!report.lines[0].wrote);
    }

    /// A digest mismatch between the line-index and what the registry
    /// actually serves is an error (clause 1).
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_registry_digest_mismatch_is_an_error() {
        let root = scratch("digest-mismatch");
        let (source, _real_digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        // The index names a digest the registry does not carry at all.
        write_index(
            &root,
            "2026.10",
            &[("2026.10.0", "sha256:not-the-real-one")],
        );

        let gh = FakeGh::default();
        let err = run(&root, &gh, &source, "2026-10-15").expect_err("must refuse");
        assert!(err.to_string().contains("2026.10.0"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_repository_root_with_no_line_index_directory_is_an_error() {
        let root = scratch("no-index-dir");
        std::fs::remove_dir_all(root.join("line-index")).unwrap();
        let gh = FakeGh::default();
        let source = MemorySource::new();
        assert!(run(&root, &gh, &source, "2026-10-15").is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn newly_affected_layers_are_reported_for_an_existing_known_problem() {
        // TWO advisories with DELIBERATELY DIFFERENT, non-overlapping
        // affected sets from the start — not a shared/uniform shape. That
        // distinguishes "found the matching existing entry by id" from
        // "found some OTHER entry and used ITS affected list", which a
        // uniform fixture (every advisory starting from the same single
        // layer) cannot: the wrong entry would read back the same.
        const JSON: &str = r#"[
            {
                "ghsa_id": "GHSA-a-exact-1-0-0",
                "severity": "high",
                "summary": "a",
                "html_url": null,
                "vulnerabilities": [{"package": {"name": "t3"}, "vulnerable_version_range": "1.0.0", "patched_versions": null}]
            },
            {
                "ghsa_id": "GHSA-b-exact-9-9-9",
                "severity": "high",
                "summary": "b",
                "html_url": null,
                "vulnerabilities": [{"package": {"name": "t3"}, "vulnerable_version_range": "9.9.9", "patched_versions": null}]
            }
        ]"#;

        let root = scratch("newly-affected");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("t3", "1.0.0", "o/r3", "")],
        );
        let payload_l2 = layer_manifest_payload("2026.10.1", &[("t3", "9.9.9", "o/r3", "")]);
        let d2 = varve_core::manifest_digest(&payload_l2);
        let source = source.with_manifest(&envelope_for(&payload_l2));
        write_index(&root, "2026.10", &[("2026.10.0", &d1), ("2026.10.1", &d2)]);

        let gh = FakeGh::default()
            .ghsa("o/r3", JSON)
            .release_sbom_outcome(
                "o/r3",
                "1.0.0",
                "1.0.0",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .release_sbom_outcome(
                "o/r3",
                "9.9.9",
                "9.9.9",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );
        let first = run(&root, &gh, &source, "2026-10-15").expect("first run");
        assert!(first.lines[0].wrote);
        let after_first: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        let a = after_first
            .known_problems
            .iter()
            .find(|k| k.id == "GHSA-a-exact-1-0-0")
            .unwrap();
        let b = after_first
            .known_problems
            .iter()
            .find(|k| k.id == "GHSA-b-exact-9-9-9")
            .unwrap();
        assert_eq!(a.affected, vec!["2026.10.0".to_string()]);
        assert_eq!(b.affected, vec!["2026.10.1".to_string()]);

        // A THIRD layer, same version as L2 — only GHSA-b's affected set
        // should grow, and only by this one new layer.
        let payload_l3 = layer_manifest_payload("2026.10.2", &[("t3", "9.9.9", "o/r3", "")]);
        let d3 = varve_core::manifest_digest(&payload_l3);
        let source = source.with_manifest(&envelope_for(&payload_l3));
        write_index(
            &root,
            "2026.10",
            &[("2026.10.0", &d1), ("2026.10.1", &d2), ("2026.10.2", &d3)],
        );

        let second = run(&root, &gh, &source, "2026-10-15").expect("second run");
        assert!(second.lines[0].wrote, "{:?}", second.lines[0]);
        assert_eq!(
            second.lines[0].newly_affected,
            BTreeMap::from([(
                "GHSA-b-exact-9-9-9".to_string(),
                vec!["2026.10.2".to_string()]
            )]),
            "{:?}",
            second.lines[0]
        );
        assert!(second.lines[0].new_known_problems.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    // -------------------------------------------------------------
    // The REAL `AdvisoryGh` impl, over `GhSource` — the one seam `FakeGh`
    // above never exercises, because every other test substitutes it
    // entirely. These confirm the wrapper passes through what `gh` (or,
    // for `release_asset`, the filesystem it actually wrote to) returned,
    // rather than some stub shape that merely type-checks.
    // -------------------------------------------------------------

    struct ScriptedRunner(Vec<(String, crate::gh::RunOutput)>);

    impl crate::gh::CommandRunner for ScriptedRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            _env: &[(String, String)],
        ) -> crate::gh::RunOutput {
            let key = format!("{program} {}", args.first().cloned().unwrap_or_default());
            for (k, v) in &self.0 {
                if *k == key {
                    return v.clone();
                }
            }
            crate::gh::RunOutput {
                code: 1,
                stdout: String::new(),
                stderr: format!("unscripted: {key}"),
            }
        }
    }

    fn gh_out(code: i32, stdout: &str, stderr: &str) -> crate::gh::RunOutput {
        crate::gh::RunOutput {
            code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_ghsource_security_advisories_passes_through_ghs_own_output() {
        const BODY: &str = r#"[{"ghsa_id":"GHSA-real-passthrough"}]"#;
        let runner = ScriptedRunner(vec![("gh api".into(), gh_out(0, BODY, ""))]);
        let src = crate::source::GhSource::new(
            runner,
            crate::forge::Forge::github_com(),
            "/tmp/advwatch-x",
        );
        let got = AdvisoryGh::security_advisories(&src, "o/r").expect("scripted success");
        assert_eq!(got, BODY);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_ghsource_rustsec_crate_dir_passes_through_the_real_listing_and_404() {
        let runner = ScriptedRunner(vec![(
            "gh api".into(),
            gh_out(0, r#"[{"name":"RUSTSEC-2026-9999.md"}]"#, ""),
        )]);
        let src = crate::source::GhSource::new(
            runner,
            crate::forge::Forge::github_com(),
            "/tmp/advwatch-x",
        );
        let got = AdvisoryGh::rustsec_crate_dir(&src, "somecrate").expect("scripted success");
        assert_eq!(got, Some(vec!["RUSTSEC-2026-9999.md".to_string()]));

        let runner_404 = ScriptedRunner(vec![(
            "gh api".into(),
            gh_out(1, "", "gh: Not Found (HTTP 404)"),
        )]);
        let src_404 = crate::source::GhSource::new(
            runner_404,
            crate::forge::Forge::github_com(),
            "/tmp/advwatch-x",
        );
        assert_eq!(
            AdvisoryGh::rustsec_crate_dir(&src_404, "nocrate").unwrap(),
            None
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_ghsource_rustsec_advisory_md_passes_through_the_real_markdown() {
        const MD: &str = "# A real advisory\n\n```toml\n[advisory]\n```\n";
        let runner = ScriptedRunner(vec![("gh api".into(), gh_out(0, MD, ""))]);
        let src = crate::source::GhSource::new(
            runner,
            crate::forge::Forge::github_com(),
            "/tmp/advwatch-x",
        );
        let got = AdvisoryGh::rustsec_advisory_md(&src, "somecrate", "RUSTSEC-2026-9999.md")
            .expect("scripted success");
        assert_eq!(got, MD);
    }

    /// `release_asset` returns the bytes a download ACTUALLY WROTE to
    /// disk, not an invented buffer — the same property `source.rs`'s own
    /// `what_is_read_back_is_what_the_download_actually_wrote` pins for
    /// every other caller of this path.
    struct ScriptedDownload {
        body: Vec<u8>,
    }

    impl crate::gh::CommandRunner for ScriptedDownload {
        fn run(
            &self,
            program: &str,
            args: &[String],
            _env: &[(String, String)],
        ) -> crate::gh::RunOutput {
            assert_eq!(program, "gh");
            let dir = args
                .iter()
                .position(|a| a == "-D")
                .map(|i| args[i + 1].clone());
            let asset = args
                .iter()
                .position(|a| a == "-p")
                .map(|i| args[i + 1].clone());
            if let (Some(dir), Some(asset)) = (dir, asset) {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(Path::new(&dir).join(asset), &self.body).unwrap();
            }
            crate::gh::RunOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_ghsource_release_asset_returns_the_bytes_actually_downloaded() {
        let dir = scratch("ghsource-asset");
        let runner = ScriptedDownload {
            body: b"real sbom bytes, not a stub".to_vec(),
        };
        let src = crate::source::GhSource::new(
            runner,
            crate::forge::Forge::github_com(),
            dir.join("work"),
        );
        let bytes =
            AdvisoryGh::release_asset(&src, "o/r", "v1", "sbom.json").expect("scripted success");
        assert_eq!(bytes, b"real sbom bytes, not a stub".to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The trait method genuinely reaches `orchestrate::release_sbom`
    /// through the real ladder — not a stub returning a fixed outcome.
    /// Scripted so every call fails closed; the real ladder reports WHY
    /// (a non-empty `VerifyFailed` detail, carrying `gh`'s own words),
    /// which a hardcoded `NoSbom`/`Found` stub could never produce.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_real_ghsource_release_sbom_reaches_the_real_ladder_not_a_stub() {
        struct AlwaysFails;
        impl crate::gh::CommandRunner for AlwaysFails {
            fn run(
                &self,
                _program: &str,
                _args: &[String],
                _env: &[(String, String)],
            ) -> crate::gh::RunOutput {
                crate::gh::RunOutput {
                    code: 1,
                    stdout: String::new(),
                    stderr: "a very specific scripted failure".to_string(),
                }
            }
        }
        let src = crate::source::GhSource::new(
            AlwaysFails,
            crate::forge::Forge::github_com(),
            "/tmp/advwatch-release-sbom-stub-check",
        );
        let outcome = AdvisoryGh::release_sbom(&src, "o/r", "v1", "1.0.0");
        match outcome {
            crate::orchestrate::ReleaseSbomOutcome::VerifyFailed(detail) => {
                assert!(
                    detail.contains("a very specific scripted failure"),
                    "{detail}"
                );
            }
            other => panic!("expected VerifyFailed carrying gh's own words, got {other:?}"),
        }
    }

    // -------------------------------------------------------------
    // REQ-ADVISORYWATCH-002 clauses 2-5.
    // -------------------------------------------------------------

    /// Clause 2. A crate payload is `kind = crate`; its own crate name is
    /// its tool annotation. Its repository has NO advisories, so only a
    /// RustSec lookup by its own name and version can flag it.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn a_crate_payload_is_checked_against_rustsec_by_its_own_name_and_version() {
        let root = scratch("crate-payload");
        let (source, digest) = with_raw_entries(
            MemorySource::new(),
            "2026.10.0",
            &[
                r#"{"digest":"sha256:c1","annotations":{"eu.pulseengine.varve.kind":"crate","eu.pulseengine.tool":"rustls","eu.pulseengine.tool.version":"0.23.34","eu.pulseengine.source.repo":"rustls/rustls"}}"#,
            ],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        let gh = FakeGh::default()
            .ghsa("rustls/rustls", "[]")
            .release_sbom_outcome(
                "rustls/rustls",
                "0.23.34",
                "0.23.34",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "{:?}",
            report.lines[0]
        );
        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written.known_problems[0].affected, vec!["2026.10.0"]);
        assert!(
            written.known_problems[0].title.contains("0.23.34"),
            "{:?}",
            written.known_problems[0]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Clause 2 negative control: the same crate at a patched version is
    /// looked up and is NOT flagged, and a crate payload that is also the
    /// SBOM's own subject is not reported twice.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn a_patched_crate_payload_is_looked_up_and_not_flagged() {
        let root = scratch("crate-payload-patched");
        let (source, digest) = with_raw_entries(
            MemorySource::new(),
            "2026.10.0",
            &[
                r#"{"digest":"sha256:c1","annotations":{"eu.pulseengine.varve.kind":"crate","eu.pulseengine.tool":"rustls","eu.pulseengine.tool.version":"0.23.50","eu.pulseengine.source.repo":"rustls/rustls"}}"#,
            ],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        let gh = FakeGh::default()
            .ghsa("rustls/rustls", "[]")
            .release_sbom_outcome(
                "rustls/rustls",
                "0.23.50",
                "0.23.50",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            )
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346);
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert!(
            report.lines[0].new_known_problems.is_empty(),
            "{:?}",
            report.lines[0]
        );
        assert!(
            gh.calls().iter().any(|c| c == "rustsec-dir:rustls"),
            "the crate must have been looked up: {:?}",
            gh.calls()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    const RUSTSEC_SERDE_NPM_BAIT: &str = r#"# serde: a crate advisory

```toml
[advisory]
id = "RUSTSEC-2026-1111"
package = "serde"
date = "2026-10-14"

[versions]
patched = [">= 1.0.5"]
```
"#;

    /// Clause 3. Ecosystem is the purl type, never the bare name; nested
    /// components are walked; a component with no version, and one of an
    /// ecosystem RustSec does not cover, are reported with their reason.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn every_sbom_component_is_checked_or_reported_unchecked_with_its_reason() {
        let sbom = br#"{
            "metadata":{"component":{"name":"wsc","version":"0.11.0","purl":"pkg:cargo/wsc@0.11.0"}},
            "components":[
                {"name":"serde","version":"1.0.0","purl":"pkg:npm/serde@1.0.0"},
                {"name":"nover","purl":"pkg:cargo/nover"},
                {"name":"noprl","version":"2.0.0"},
                {"name":"outer","version":"1.0.0","purl":"pkg:cargo/outer@1.0.0","components":[
                    {"name":"rustls","version":"0.23.34","purl":"pkg:cargo/rustls@0.23.34"},
                    {"name":"nestedver","purl":"pkg:cargo/nestedver"},
                    {"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}
                ]}
            ]
        }"#
        .to_vec();
        let sha = sha256_hex(&sbom);
        let (root, source, digest) = wsc_layer_root(&sha);
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        // `serde` is scripted with an advisory that WOULD match 1.0.0, and
        // `rustsec-dir:serde` must still never be asked.
        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .asset("pulseengine/wsc", "v0.11.0", "sbom.cdx.json", &sbom)
            .rustsec_dir_404("wsc")
            .rustsec_dir_404("outer")
            .rustsec_dir("serde", &["RUSTSEC-2026-1111.md"])
            .rustsec_md("serde", "RUSTSEC-2026-1111.md", RUSTSEC_SERDE_NPM_BAIT)
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert_eq!(
            line.new_known_problems,
            vec!["RUSTSEC-2026-0346".to_string()],
            "the NESTED cargo component must be checked: {line:?}"
        );
        assert!(
            !gh.calls().iter().any(|c| c.contains("serde")),
            "an npm package must never reach a crate advisory: {:?}",
            gh.calls()
        );
        let reasons: Vec<String> = line.unchecked.iter().map(|u| u.reason.clone()).collect();
        let about = |needle: &str| -> Vec<&String> {
            reasons.iter().filter(|r| r.contains(needle)).collect()
        };
        assert_eq!(about("serde").len(), 1, "{reasons:?}");
        assert!(about("serde")[0].contains("npm"), "{reasons:?}");
        assert_eq!(about("nover").len(), 1, "{reasons:?}");
        assert!(about("nover")[0].contains("no version"), "{reasons:?}");
        assert_eq!(about("nestedver").len(), 1, "{reasons:?}");
        assert!(about("nestedver")[0].contains("no version"), "{reasons:?}");
        assert_eq!(about("left-pad").len(), 1, "{reasons:?}");
        assert!(about("left-pad")[0].contains("npm"), "{reasons:?}");
        assert_eq!(about("noprl").len(), 1, "{reasons:?}");
        assert!(about("noprl")[0].contains("no purl"), "{reasons:?}");
        // Every unchecked entry names the payload it belongs to.
        assert!(
            line.unchecked
                .iter()
                .all(|u| u.tool == "wsc" && u.repo == "pulseengine/wsc"),
            "{:?}",
            line.unchecked
        );
        let summary = human_summary(&report);
        assert!(summary.contains("left-pad"), "{summary}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Clause 4. Same repository and version, different releases: each
    /// release's own SBOM is read, and a finding names only the layer whose
    /// release carries it.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn payloads_sharing_repo_and_version_from_different_releases_each_get_their_own_sbom() {
        let root = scratch("two-releases");
        let (source, d1) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0")],
        );
        let payload2 = layer_manifest_payload(
            "2026.10.1",
            &[("wsc", "0.11.0", "pulseengine/wsc", "v0.11.0-rebuild")],
        );
        let d2 = varve_core::manifest_digest(&payload2);
        let source = source.with_manifest(&envelope_for(&payload2));
        write_index(&root, "2026.10", &[("2026.10.0", &d1), ("2026.10.1", &d2)]);

        let gh = FakeGh::default()
            .ghsa("pulseengine/wsc", "[]")
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::Found(sbom_bytes_with_component(
                    "rustls", "0.23.34",
                )),
            )
            .release_sbom_outcome(
                "pulseengine/wsc",
                "v0.11.0-rebuild",
                "0.11.0",
                crate::orchestrate::ReleaseSbomOutcome::Found(sbom_bytes_with_component(
                    "rustls", "0.23.50",
                )),
            )
            .rustsec_dir_404("wsc")
            .rustsec_dir("rustls", &["RUSTSEC-2026-0346.md"])
            .rustsec_md("rustls", "RUSTSEC-2026-0346.md", RUSTSEC_0346);

        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let calls = gh.calls();
        for release in ["v0.11.0", "v0.11.0-rebuild"] {
            assert!(
                calls
                    .iter()
                    .any(|c| c == &format!("release-sbom:pulseengine/wsc/{release}/0.11.0")),
                "release {release} never had its own SBOM read: {calls:?}"
            );
        }
        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written.known_problems.len(), 1, "{report:?}");
        assert_eq!(
            written.known_problems[0].affected,
            vec!["2026.10.0".to_string()],
            "only the release whose SBOM carries rustls 0.23.34 is affected"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    const SIBLING_ONLY_GHSA: &str = r#"[{
            "ghsa_id": "GHSA-sibling",
            "severity": "high",
            "summary": "only the sibling package",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "wasmtime-wasi"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"}
            ]
        }]"#;

    fn wasmtime_49_0_1(name: &str, ghsa: &str) -> (PathBuf, MemorySource, FakeGh) {
        let root = scratch(name);
        let (source, digest) = with_layer(
            MemorySource::new(),
            "2026.10.0",
            &[("wasmtime", "49.0.1", "bytecodealliance/wasmtime", "")],
        );
        write_index(&root, "2026.10", &[("2026.10.0", &digest)]);
        let gh = FakeGh::default()
            .ghsa("bytecodealliance/wasmtime", ghsa)
            .release_sbom_outcome(
                "bytecodealliance/wasmtime",
                "49.0.1",
                "49.0.1",
                crate::orchestrate::ReleaseSbomOutcome::NoSbom,
            );
        (root, source, gh)
    }

    /// Clause 5. An advisory whose ranges name only a DIFFERENT package of
    /// the same repository, with a range that covers the payload's version,
    /// is a QUALIFIED finding: present, and marked as not certain.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn an_advisory_naming_a_sibling_package_is_a_qualified_finding() {
        let (root, source, gh) = wasmtime_49_0_1("sibling-qualified", SIBLING_ONLY_GHSA);
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert_eq!(line.new_known_problems, vec!["GHSA-sibling".to_string()]);
        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            written.known_problems[0].detection.as_deref(),
            Some(
                "qualified: names wasmtime-wasi from the same repository \
                 (bytecodealliance/wasmtime); affects this binary if it embeds that crate"
            )
        );
        assert!(
            line.unchecked
                .iter()
                .all(|u| !u.reason.contains("GHSA-sibling"))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Clause 5 negative control: a sibling package whose range does NOT
    /// cover the payload's version is not a finding, and is not an unchecked
    /// gap either (the versions were comparable and disagree).
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn a_sibling_package_whose_range_misses_the_payload_version_is_not_a_finding() {
        let ghsa = SIBLING_ONLY_GHSA.replace(">= 49.0.0, <= 49.0.2", "< 40.0.0");
        let (root, source, gh) = wasmtime_49_0_1("sibling-miss", &ghsa);
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        let line = &report.lines[0];
        assert!(line.new_known_problems.is_empty(), "{line:?}");
        assert!(!line.wrote, "{line:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An advisory naming the payload exactly is certain (no qualifier),
    /// even when the same advisory also lists a sibling package.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn an_exact_name_match_is_certain_and_carries_no_qualifier() {
        let ghsa = r#"[{
            "ghsa_id": "GHSA-both",
            "severity": "high",
            "summary": "both",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "wasmtime"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"},
                {"package": {"name": "wasmtime-wasi"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"}
            ]
        }]"#;
        let (root, source, gh) = wasmtime_49_0_1("exact-certain", ghsa);
        let report = run(&root, &gh, &source, "2026-10-15").expect("runs");
        assert_eq!(
            report.lines[0].new_known_problems,
            vec!["GHSA-both".to_string()]
        );
        let written: LineStatus = serde_json::from_str(
            &std::fs::read_to_string(root.join("line-status/2026.10.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written.known_problems.len(), 1);
        assert_eq!(written.known_problems[0].detection, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Clause 5, positive side: the range that names the payload still
    /// matches when the same advisory also lists other packages.
    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn the_range_that_names_the_payload_is_the_one_that_decides() {
        let json = r#"[{
            "ghsa_id": "GHSA-both",
            "severity": "high",
            "summary": "two packages, different ranges",
            "html_url": null,
            "vulnerabilities": [
                {"package": {"name": "wasmtime"}, "vulnerable_version_range": "< 40.0.0", "patched_versions": "40.0.0"},
                {"package": {"name": "wasmtime-wasi"}, "vulnerable_version_range": ">= 49.0.0, <= 49.0.2", "patched_versions": "49.0.3"}
            ]
        }]"#;
        let v = Version::parse("49.0.1").unwrap();
        let own = ["wasmtime".to_string()];
        let r = ghsa_for_payload(json, &v, &own).unwrap();
        assert!(r.findings.is_empty(), "{r:?}");
        // The sibling's range covers 49.0.1: qualified, naming that sibling.
        assert_eq!(r.qualified.len(), 1, "{r:?}");
        assert_eq!(r.qualified[0].1, ["wasmtime-wasi"]);
        let v = Version::parse("39.0.0").unwrap();
        let r = ghsa_for_payload(json, &v, &own).unwrap();
        assert_eq!(r.findings.len(), 1, "{r:?}");
        assert_eq!(r.findings[0].package, "wasmtime");
        // Certain wins: the same advisory is not also qualified.
        assert!(r.qualified.is_empty(), "{r:?}");
    }

    fn comp(name: &str, version: Option<&str>, purl: Option<&str>) -> SbomComponent {
        SbomComponent {
            name: name.to_string(),
            version: version.map(str::to_string),
            purl: purl.map(str::to_string),
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn purl_type_is_the_ecosystem_segment_lowercased_and_none_for_non_purls() {
        assert_eq!(purl_type("pkg:cargo/serde@1.0.0").as_deref(), Some("cargo"));
        assert_eq!(purl_type("pkg:NPM/serde@1.0.0").as_deref(), Some("npm"));
        assert_eq!(purl_type("pkg:cargo").as_deref(), None);
        assert_eq!(purl_type("pkg:/x").as_deref(), None);
        assert_eq!(purl_type("cargo/serde").as_deref(), None);
        assert_eq!(purl_type("serde").as_deref(), None);
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn a_component_is_a_crate_only_by_its_purl_type_and_is_named_by_its_purl() {
        assert_eq!(
            classify_component(&comp(
                "x",
                Some("1.2.3"),
                Some("pkg:cargo/real-name@1.2.3?a=b#c")
            )),
            ComponentClass::Crate {
                name: "real-name".into(),
                version: "1.2.3".into()
            },
            "the purl, not the display name, says which crate it is"
        );
        let unchecked = |c: SbomComponent| match classify_component(&c) {
            ComponentClass::Unchecked(r) => r,
            other => panic!("expected unchecked, got {other:?}"),
        };
        let r = unchecked(comp("serde", Some("1.0.0"), Some("pkg:npm/serde@1.0.0")));
        assert!(
            r.contains("serde") && r.contains("npm") && r.contains("RustSec"),
            "{r}"
        );
        let r = unchecked(comp("serde", Some("1.0.0"), None));
        assert!(r.contains("no purl") && r.contains("serde"), "{r}");
        let r = unchecked(comp("serde", Some("1.0.0"), Some("not-a-purl")));
        assert!(r.contains("cannot read") && r.contains("not-a-purl"), "{r}");
        let r = unchecked(comp("serde", None, Some("pkg:cargo/serde")));
        assert!(r.contains("no version"), "{r}");
        // An empty crate name is handed on, to be refused as an invalid name.
        assert_eq!(
            classify_component(&comp("", Some("1.0.0"), Some("pkg:cargo/@1.0.0"))),
            ComponentClass::Crate {
                name: String::new(),
                version: "1.0.0".into()
            }
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn sbom_components_walk_every_nesting_level_including_inside_the_subject() {
        let sbom = br#"{
            "metadata":{"component":{"name":"s","version":"1","components":[{"name":"in-subject","version":"2"}]}},
            "components":[
                {"name":"a","version":"1","components":[
                    {"name":"b","version":"1","components":[{"name":"c","version":"1"}]}]},
                {"version":"9"}
            ]}"#;
        let names: Vec<String> = sbom_components(sbom)
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, ["s", "in-subject", "a", "b", "c"]);
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn dedup_keeps_releases_tools_and_kinds_apart() {
        let base = payload("o/r", "1.0.0");
        let mut other_release = base.clone();
        other_release.release = "rebuild".into();
        let mut other_tool = base.clone();
        other_tool.tool = "u".into();
        let mut as_crate = base.clone();
        as_crate.is_crate = true;
        let out = dedup_payloads(&[
            ("2026.10.0".into(), vec![base.clone()]),
            (
                "2026.10.1".into(),
                vec![base, other_release, other_tool, as_crate],
            ),
        ]);
        assert_eq!(out.len(), 4, "{out:?}");
        let first = out
            .iter()
            .find(|d| d.release == "1.0.0" && d.tool == "t" && !d.is_crate)
            .unwrap();
        assert_eq!(first.layers, ["2026.10.0", "2026.10.1"]);
        assert!(out.iter().any(|d| d.is_crate));
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn the_qualifier_names_every_matching_sibling_and_the_repository() {
        assert_eq!(
            qualifier(&["wasmtime-wasi".to_string()], "bytecodealliance/wasmtime"),
            "qualified: names wasmtime-wasi from the same repository \
             (bytecodealliance/wasmtime); affects this binary if it embeds that crate"
        );
        assert!(
            qualifier(&["a".to_string(), "b".to_string()], "o/r")
                .starts_with("qualified: names a, b ")
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-002
    #[test]
    fn an_exact_match_on_any_proposal_makes_the_advisory_certain_for_all() {
        let mk = |id: &str, d: Option<&str>| Proposed {
            id: id.to_string(),
            aliases: vec![],
            title: String::new(),
            severity: "high".into(),
            affected: vec![],
            workaround: None,
            detection: d.map(str::to_string),
        };
        let mut v = vec![
            mk("A", None),
            mk("B", None),
            mk("A", Some("q")),
            mk("C", Some("r")),
        ];
        unify_qualifiers(&mut v);
        let d: Vec<Option<&str>> = v.iter().map(|p| p.detection.as_deref()).collect();
        // A: one payload matched it exactly, so the layer IS affected; the
        // qualifier would understate a certain finding. C: only ever
        // qualified, so it stays qualified.
        assert_eq!(d, [None, None, None, Some("r")]);
    }
}
