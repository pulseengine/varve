//! `varve diff` — rendering a layer delta (REQ-LAYERDIFF-001, DD-032).
//!
//! The comparison itself lives in `varve_core::delta`, where the mutation
//! gate can reach it: its kill criteria are `--workspace --lib`, and a
//! finding a CI gate refuses a bump on must not sit where no mutant can ever
//! be killed. This module decides nothing — it asks core what changed and
//! prints it, as a table or as the JSON every other view renders from.

use crate::inspect::Row;
use varve_core::Store;
use varve_core::delta::{Changed, Delta, Finding, Key, PayloadRow, delta};

/// The fields a comparison is entitled to see.
///
/// Explicit rather than derived: a new field on `Row` that ought to affect
/// what "changed" means has to be added here on purpose. Presentation fields
/// (dispatch, present, docs) are deliberately absent — whether a payload is
/// laid down on THIS machine is not a difference between two layers.
fn payload_row(r: &Row) -> PayloadRow {
    PayloadRow {
        name: r.name.clone(),
        version: r.version.clone(),
        kind: r.kind.clone(),
        platform: r.platform.clone(),
        target: r.target.clone(),
        digest: r.digest.clone(),
        ingest_proof: r.ingest_proof.clone(),
        proof_signer: r.proof_signer.clone(),
        realm: r.realm.clone(),
    }
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
    let rows = |ls: &[varve_core::compose::ComposedLayer]| -> anyhow::Result<Vec<PayloadRow>> {
        Ok(crate::inspect::rows_of(ls)?
            .iter()
            .map(payload_row)
            .collect())
    };
    let d = delta(&rows(&from_layers)?, &rows(&to_layers)?);
    if json {
        print_json(&from_target, &to_target, &d);
    } else {
        print_text(&from_target, &to_target, &d);
    }
    Ok(())
}

fn print_json(from: &crate::ExportTarget, to: &crate::ExportTarget, d: &Delta) {
    let payload = |r: &PayloadRow| {
        serde_json::json!({
            "name": r.name, "version": r.version, "kind": r.kind,
            "platform": r.platform, "target": r.target, "realm": r.realm,
            "digest": r.digest, "ingest_proof": r.ingest_proof,
            "proof_signer": r.proof_signer,
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
                "proof_signer": {"from": c.from_signer, "to": c.to_signer, "moved": c.signer_moved()},
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
