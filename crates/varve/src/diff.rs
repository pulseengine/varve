//! What changing from one layer to another would change (REQ-LAYERDIFF-001).
//!
//! A diff is a transcription, not a judgement: both manifests are signed, and
//! this only states what two trust roots already attested. Nothing here reads
//! a payload's bytes, and nothing fetches — the comparison is between what is
//! installed, and a side that is absent is said to be absent (clause 3).
//!
//! Per DD-032 this module is the ONLY producer of delta data. The text table
//! and `--json` are two renderings of one `Delta`; a future signed delta
//! referrer will be a third. A terminal and a browser that disagree about a
//! toolchain bump would be this codebase's recurring defect with consumers as
//! the audience.

use crate::inspect::Row;
use varve_core::Store;

/// What makes two payloads the same payload across layers.
///
/// Version is deliberately NOT part of the identity — a version bump is the
/// change this command exists to report, and folding it into the key would
/// turn every bump into an unrelated add plus an unrelated remove.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key {
    pub(crate) realm: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) platform: String,
    pub(crate) target: Option<String>,
}

pub(crate) fn key_of(r: &Row) -> Key {
    Key {
        realm: r.realm.clone(),
        kind: r.kind.clone(),
        name: r.name.clone(),
        platform: r.platform.clone(),
        target: r.target.clone(),
    }
}

/// What a payload's recorded proof says about whether anything vouched for it.
///
/// Deliberately NOT a rank. `IngestProof::is_verified` documents why:
/// `cosign-sums` and `build-provenance` are both accepted proofs carrying
/// different claims, and varve does not collapse that distinction for the
/// consumer. So this classifies only into the states a FINDING can rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vouch {
    /// Something vouched for these bytes.
    Verified,
    /// Explicitly nothing did, with a recorded operator reason.
    Unverified,
    /// The layer predates REQ-INGEST-001. Absence of a claim is not a claim.
    Unrecorded,
    /// A proof mechanism this varve does not know. Not guessed about.
    Unknown,
}

pub(crate) fn vouch(label: &str) -> Vouch {
    use varve_core::IngestProof as P;
    match label {
        l if l == P::CosignSums.as_str()
            || l == P::BuildProvenance.as_str()
            || l == P::UpstreamSums.as_str() =>
        {
            Vouch::Verified
        }
        l if l == P::Unverified.as_str() => Vouch::Unverified,
        "unrecorded" => Vouch::Unrecorded,
        _ => Vouch::Unknown,
    }
}

/// Which attributes of one payload moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Changed {
    pub(crate) key: Key,
    pub(crate) from_version: Option<String>,
    pub(crate) to_version: Option<String>,
    pub(crate) from_digest: String,
    pub(crate) to_digest: String,
    pub(crate) from_proof: String,
    pub(crate) to_proof: String,
}

impl Changed {
    pub(crate) fn version_moved(&self) -> bool {
        self.from_version != self.to_version
    }
    pub(crate) fn proof_moved(&self) -> bool {
        self.from_proof != self.to_proof
    }
}

/// Something an operator must not have to find by reading rows.
///
/// Clause 5: the ingestion proof travels into the diff, and a payload that
/// stopped being vouched for is a more consequential change than any version
/// bump in the same table. It is reported separately so a renderer cannot
/// bury it, and so a CI gate has something to key on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Finding {
    /// Was vouched for; is now explicitly vouched for by nothing.
    LostProofOfOrigin { key: Key, from: String },
    /// Was vouched for; the newer layer records no proof at all.
    StoppedRecordingProof { key: Key, from: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Delta {
    pub(crate) added: Vec<Row>,
    pub(crate) removed: Vec<Row>,
    pub(crate) changed: Vec<Changed>,
    pub(crate) findings: Vec<Finding>,
}

impl Delta {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Compare two layers' payload sets.
///
/// Keyed order throughout, so two runs — and two machines — agree, which is
/// what lets a CI gate compare this output against a previous one.
pub(crate) fn delta(from: &[Row], to: &[Row]) -> Delta {
    use std::collections::BTreeMap;
    let index = |rows: &[Row]| -> BTreeMap<Key, Row> {
        rows.iter().map(|r| (key_of(r), r.clone())).collect()
    };
    let (a, b) = (index(from), index(to));
    let mut d = Delta::default();

    for (k, to_row) in &b {
        let Some(from_row) = a.get(k) else {
            d.added.push(to_row.clone());
            continue;
        };
        if from_row.version != to_row.version
            || from_row.digest != to_row.digest
            || from_row.ingest_proof != to_row.ingest_proof
        {
            d.changed.push(Changed {
                key: k.clone(),
                from_version: from_row.version.clone(),
                to_version: to_row.version.clone(),
                from_digest: from_row.digest.clone(),
                to_digest: to_row.digest.clone(),
                from_proof: from_row.ingest_proof.clone(),
                to_proof: to_row.ingest_proof.clone(),
            });
        }
        // A finding rests only on the distinction varve-core sanctions:
        // something vouched for these bytes, and now nothing does. Moving
        // between two accepted proofs is a change and never a finding, and an
        // unknown mechanism is not judged in either direction.
        if vouch(&from_row.ingest_proof) == Vouch::Verified {
            let f = match vouch(&to_row.ingest_proof) {
                Vouch::Unverified => Some(Finding::LostProofOfOrigin {
                    key: k.clone(),
                    from: from_row.ingest_proof.clone(),
                }),
                Vouch::Unrecorded => Some(Finding::StoppedRecordingProof {
                    key: k.clone(),
                    from: from_row.ingest_proof.clone(),
                }),
                Vouch::Verified | Vouch::Unknown => None,
            };
            d.findings.extend(f);
        }
    }
    for (k, from_row) in &a {
        if !b.contains_key(k) {
            d.removed.push(from_row.clone());
        }
    }
    d
}

/// `varve diff <FROM> <TO>` — what changing between two installed layers
/// would change.
///
/// Both sides must already be installed. Clause 3: a side that is absent is
/// SAID to be absent rather than silently fetched, which `export_target`
/// already does ("layer X is not installed — varve install it first"). Clause
/// 4 is structural: nothing on this path writes to the store or the pin.
pub fn run(store: &Store, from: &str, to: &str, json: bool) -> anyhow::Result<()> {
    let (from_target, to_target) = (
        crate::export_target(store, Some(from))?,
        crate::export_target(store, Some(to))?,
    );
    let (from_layers, to_layers) = (
        crate::composition_for_export(&from_target)?,
        crate::composition_for_export(&to_target)?,
    );
    let d = delta(
        &crate::inspect::rows_of(&from_layers)?,
        &crate::inspect::rows_of(&to_layers)?,
    );
    if json {
        print_json(&from_target, &to_target, &d);
    } else {
        print_text(&from_target, &to_target, &d);
    }
    Ok(())
}

fn print_json(from: &crate::ExportTarget, to: &crate::ExportTarget, d: &Delta) {
    let payload = |r: &Row| {
        serde_json::json!({
            "name": r.name, "version": r.version, "kind": r.kind,
            "platform": r.platform, "target": r.target, "realm": r.realm,
            "digest": r.digest, "ingest_proof": r.ingest_proof,
            "proof_signer": r.proof_signer, "layer": r.layer,
        })
    };
    let key = |k: &Key| {
        serde_json::json!({
            "name": k.name, "kind": k.kind, "platform": k.platform,
            "target": k.target, "realm": k.realm,
        })
    };
    let changed: Vec<_> = d
        .changed
        .iter()
        .map(|c| {
            serde_json::json!({
                "payload": key(&c.key),
                "version": {"from": c.from_version, "to": c.to_version, "moved": c.version_moved()},
                "digest":  {"from": c.from_digest,  "to": c.to_digest},
                "ingest_proof": {"from": c.from_proof, "to": c.to_proof, "moved": c.proof_moved()},
            })
        })
        .collect();
    let findings: Vec<_> = d
        .findings
        .iter()
        .map(|f| match f {
            Finding::LostProofOfOrigin { key: k, from } => serde_json::json!({
                "finding": "lost-proof-of-origin", "payload": key(k), "from": from,
                "detail": "these bytes were vouched for in the older layer and are explicitly vouched for by nothing in the newer one",
            }),
            Finding::StoppedRecordingProof { key: k, from } => serde_json::json!({
                "finding": "stopped-recording-proof", "payload": key(k), "from": from,
                "detail": "the older layer recorded how these bytes were vouched for; the newer one records nothing",
            }),
        })
        .collect();
    let doc = serde_json::json!({
        "from": {"layer": from.entry.layer.to_string(), "manifest_digest": from.entry.digest},
        "to":   {"layer": to.entry.layer.to_string(),   "manifest_digest": to.entry.digest},
        "added":   d.added.iter().map(payload).collect::<Vec<_>>(),
        "removed": d.removed.iter().map(payload).collect::<Vec<_>>(),
        "changed": changed,
        "findings": findings,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
}

fn print_text(from: &crate::ExportTarget, to: &crate::ExportTarget, d: &Delta) {
    println!("layer {} -> {}", from.entry.layer, to.entry.layer);
    println!();
    if d.is_empty() {
        println!("  no payload changed");
    }
    // Findings are marked in place AND restated below, because a reader
    // scanning rows and a reader reading the summary must not reach different
    // conclusions about the same bump (DD-032).
    let lost: std::collections::BTreeSet<&Key> =
        d.findings
            .iter()
            .map(|f| match f {
                Finding::LostProofOfOrigin { key, .. }
                | Finding::StoppedRecordingProof { key, .. } => key,
            })
            .collect();
    // Column widths are computed, never guessed: a fixed width that a real
    // triple overruns runs two columns together, which is how a proof rung
    // ends up looking like part of a platform name.
    let ver_of = |from: &Option<String>, to: &Option<String>| match (from, to) {
        (Some(a), Some(b)) if a != b => format!("{a} -> {b}"),
        (Some(a), _) => a.clone(),
        (None, Some(b)) => b.clone(),
        (None, None) => String::new(),
    };
    let proof_of = |c: &Changed| {
        if c.proof_moved() {
            format!("{} -> {}", c.from_proof, c.to_proof)
        } else {
            c.from_proof.clone()
        }
    };
    let w = |it: &mut dyn Iterator<Item = usize>| it.max().unwrap_or(0);
    let name_w = w(&mut d
        .changed
        .iter()
        .map(|c| c.key.name.len())
        .chain(d.added.iter().chain(d.removed.iter()).map(|r| r.name.len())));
    let ver_w = w(&mut d
        .changed
        .iter()
        .map(|c| ver_of(&c.from_version, &c.to_version).len())
        .chain(
            d.added
                .iter()
                .chain(d.removed.iter())
                .map(|r| r.version.as_deref().unwrap_or("").len()),
        ));
    let plat_w = w(&mut d.changed.iter().map(|c| c.key.platform.len()).chain(
        d.added
            .iter()
            .chain(d.removed.iter())
            .map(|r| r.platform.len()),
    ));

    for c in &d.changed {
        let mark = if lost.contains(&c.key) { "!" } else { " " };
        println!(
            "{mark} CHANGED  {:<name_w$}  {:<ver_w$}  {:<plat_w$}  {}",
            c.key.name,
            ver_of(&c.from_version, &c.to_version),
            c.key.platform,
            proof_of(c)
        );
    }
    for (label, rows) in [("ADDED  ", &d.added), ("REMOVED", &d.removed)] {
        for r in rows {
            println!(
                "  {label}  {:<name_w$}  {:<ver_w$}  {:<plat_w$}  {}",
                r.name,
                r.version.clone().unwrap_or_default(),
                r.platform,
                r.ingest_proof
            );
        }
    }
    println!();
    println!(
        "{} changed, {} added, {} removed",
        d.changed.len(),
        d.added.len(),
        d.removed.len()
    );
    // Clause 5. Never a column to scan past.
    for f in &d.findings {
        match f {
            Finding::LostProofOfOrigin { key, from } => println!(
                "! {} ({}) LOST its proof of origin: {from} -> unverified",
                key.name, key.platform
            ),
            Finding::StoppedRecordingProof { key, from } => println!(
                "! {} ({}) records no proof in the newer layer (was {from})",
                key.name, key.platform
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, version: &str, proof: &str) -> Row {
        Row {
            name: name.to_string(),
            version: Some(version.to_string()),
            kind: "tool".to_string(),
            known_kind: true,
            platform: "x86_64-unknown-linux-gnu".to_string(),
            target: None,
            digest: format!("sha256:{name}-{version}"),
            dispatch: "dispatched",
            docs: None,
            ingest_proof: proof.to_string(),
            proof_signer: None,
            present: true,
            layer: "2026.09.0".to_string(),
            realm: "pulseengine".to_string(),
        }
    }

    fn on(mut r: Row, platform: &str) -> Row {
        r.platform = platform.to_string();
        r
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_only_in_the_newer_layer_is_added() {
        let d = delta(
            &[row("rivet", "0.39.0", "cosign-sums")],
            &[
                row("rivet", "0.39.0", "cosign-sums"),
                row("wac", "0.11.0", "unverified"),
            ],
        );
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "wac");
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_only_in_the_older_layer_is_removed() {
        let d = delta(
            &[
                row("rivet", "0.39.0", "cosign-sums"),
                row("kilnd", "0.5.0", "cosign-sums"),
            ],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].name, "kilnd");
        assert!(d.added.is_empty());
    }

    /// The whole reason version is not part of `Key`.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_version_bump_is_one_changed_row_not_an_add_and_a_remove() {
        let d = delta(
            &[row("synth", "0.74.0", "cosign-sums")],
            &[row("synth", "0.75.0", "cosign-sums")],
        );
        assert!(
            d.added.is_empty() && d.removed.is_empty(),
            "a version bump was reported as an unrelated add and remove: {d:?}"
        );
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].version_moved());
        assert_eq!(d.changed[0].from_version.as_deref(), Some("0.74.0"));
        assert_eq!(d.changed[0].to_version.as_deref(), Some("0.75.0"));
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn an_unchanged_payload_appears_nowhere() {
        let d = delta(
            &[row("rivet", "0.39.0", "cosign-sums")],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert!(d.is_empty(), "an identical layer produced a delta: {d:?}");
        assert!(d.findings.is_empty());
    }

    /// Clause 5. This is the headline a bump can carry.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_that_lost_its_proof_of_origin_is_a_finding() {
        let d = delta(
            &[row("wac", "0.11.0", "cosign-sums")],
            &[row("wac", "0.12.0", "unverified")],
        );
        assert_eq!(
            d.findings.len(),
            1,
            "losing a proof of origin was not reported as a finding: {d:?}"
        );
        match &d.findings[0] {
            Finding::LostProofOfOrigin { key, from } => {
                assert_eq!(key.name, "wac");
                assert_eq!(from, "cosign-sums");
            }
            other => panic!("wrong finding: {other:?}"),
        }
    }

    /// Negative control on the rule varve-core documents: `cosign-sums` and
    /// `build-provenance` are both accepted proofs and varve does not rank
    /// them. Reporting a finding here would be inventing a judgement.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_move_between_two_accepted_proofs_is_a_change_but_never_a_finding() {
        let d = delta(
            &[row("rivet", "0.39.0", "build-provenance")],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].proof_moved());
        assert!(
            d.findings.is_empty(),
            "varve ranked two accepted proofs against each other: {d:?}"
        );
    }

    /// Absence of a claim is not a claim — so gaining one is not a loss.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn unrecorded_becoming_unverified_is_not_a_loss() {
        let d = delta(
            &[row("wkg", "0.4.0", "unrecorded")],
            &[row("wkg", "0.4.0", "unverified")],
        );
        assert!(
            d.findings.is_empty(),
            "a layer that predates the requirement was treated as having lost something: {d:?}"
        );
    }

    /// …but a layer that HAD a proof and now records none has lost one.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_recorded_proof_becoming_unrecorded_is_a_finding() {
        let d = delta(
            &[row("wkg", "0.4.0", "cosign-sums")],
            &[row("wkg", "0.4.0", "unrecorded")],
        );
        assert!(matches!(
            d.findings.as_slice(),
            [Finding::StoppedRecordingProof { .. }]
        ));
    }

    /// One tool on two platforms is two payloads: bumping one must not read
    /// as bumping the tool.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn the_same_tool_on_two_platforms_is_two_payloads() {
        let linux = row("synth", "0.74.0", "cosign-sums");
        let mac = on(
            row("synth", "0.74.0", "cosign-sums"),
            "aarch64-apple-darwin",
        );
        let linux_new = row("synth", "0.75.0", "cosign-sums");
        let d = delta(&[linux, mac.clone()], &[linux_new, mac]);
        assert_eq!(d.changed.len(), 1, "both platforms moved: {d:?}");
        assert_eq!(
            d.changed[0].key.platform, "x86_64-unknown-linux-gnu",
            "the wrong platform was reported as the one that moved"
        );
    }

    /// An unknown proof mechanism is not guessed about in either direction.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn an_unknown_proof_mechanism_produces_no_finding() {
        let d = delta(
            &[row("wac", "0.11.0", "notarised-by-something-new")],
            &[row("wac", "0.11.0", "unverified")],
        );
        assert!(
            d.findings.is_empty(),
            "varve judged a proof mechanism it does not know: {d:?}"
        );
    }
}
