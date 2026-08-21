//! `varve inspect` (REQ-INSPECT-001) — what is actually in a layer.
//!
//! Nothing reported a layer's payload names, versions, kinds or platforms.
//! `varve list` prints layer ids; `varve sbom` collapses every non-tool kind to
//! a CycloneDX `library` and is blind to composition. In the ten-persona audit
//! the build engineer chose an export adapter by running all four and reading
//! which one errored, and the newcomer learned the tool set by typo-ing a name
//! into `varve which` so the error would list the alternatives.
//!
//! Three things this command is careful about:
//!
//! * **DISPATCHED vs HELD** (clause 3). Only a `tool` is dispatched by name.
//!   Every other kind is HELD: stored, verified, handed to an export adapter,
//!   and not on your PATH. `varve which` reported a held `wit` payload as "not
//!   part of layer", which is FALSE — the layer holds it.
//! * **The composition** (clause 4). A composed layer's payloads are part of
//!   what the pin delivers, so they are part of the answer. `sbom` being
//!   composition-blind is a known limitation and this must not repeat it.
//! * **No network** (clause 5). The store already holds the answer. The layer
//!   is re-verified against its realm's trust root first — reporting the
//!   contents of a layer varve cannot vouch for would look authoritative and
//!   be worthless.

use anyhow::Context;
use varve_core::Store;

/// One payload, as reported.
struct Row {
    name: String,
    version: Option<String>,
    /// The kind as written in the SIGNED annotation, so an unknown kind is
    /// reported verbatim rather than dropped or guessed (`sbom` labels such an
    /// entry rather than losing it; so does this).
    kind: String,
    known_kind: bool,
    /// The entry's signed platform, or `any` where it carries none — an
    /// unstamped platform means any-platform, as it does everywhere else.
    platform: String,
    digest: String,
    /// `dispatched` | `held` | `unknown` (the kind annotation is one this
    /// varve does not recognise, so whether it dispatches is not knowable).
    dispatch: &'static str,
    /// Which mechanism vouched for this payload's UPSTREAM bytes
    /// (REQ-INGEST-001 clause 5). `unrecorded` where the layer predates the
    /// requirement — absence of a claim is not a claim, and restating a
    /// hundred existing payloads as either verified or unverified would be
    /// inventing one. An unknown mechanism is reported verbatim, like `kind`.
    ingest_proof: String,
    /// The identity credited with vouching, where one is recorded — the fact
    /// a consumer might filter on ("refuse anything not signed under
    /// pulseengine/"), which is why it is its own field and not prose.
    proof_signer: Option<String>,
    /// Are these bytes on disk here? `install` lays down only the host
    /// platform's entries, so another platform's entry is present in the
    /// signed manifest and absent from the store — which is correct, and worth
    /// saying rather than leaving as a mystery.
    present: bool,
    layer: String,
    realm: String,
}

const DISPATCHED: &str = "dispatched";
const HELD: &str = "held";
const UNKNOWN: &str = "unknown";

pub fn run(store: &Store, layer: Option<&str>, json: bool) -> anyhow::Result<()> {
    let target = crate::export_target(store, layer)?;
    let layers = crate::composition_for_export(&target)?;
    let host = varve_core::host_platform();
    let mut rows = Vec::new();

    for l in &layers {
        let payload = std::fs::read(l.entry.root.join("layer.json")).with_context(|| {
            format!(
                "cannot read the signed manifest of layer {} — the store entry is incomplete",
                l.entry.layer
            )
        })?;
        let manifest = varve_core::LayerManifest::parse(&payload)?;
        for e in &manifest.entries {
            let parsed = e.kind();
            let kind = match &parsed {
                Ok(k) => k.as_str().to_string(),
                Err(varve_core::UnknownKind(raw)) => raw.clone(),
            };
            // A `layer` entry is a composition EDGE, not a payload: its digest
            // is another layer's signed manifest, and there is nothing to lay
            // down. It is reported in the `composition` block instead, where
            // its realm and digest belong.
            if parsed == Ok(varve_core::PayloadKind::Layer) {
                continue;
            }
            let name = e
                .annotations
                .get("eu.pulseengine.tool")
                .cloned()
                // An entry with no name annotation is malformed rather than
                // secret; say so instead of hiding the row.
                .unwrap_or_else(|| "(unnamed entry)".to_string());
            rows.push(Row {
                version: e.annotations.get("eu.pulseengine.tool.version").cloned(),
                kind,
                known_kind: parsed.is_ok(),
                platform: e
                    .annotations
                    .get(varve_core::platform::ANN_PLATFORM)
                    .cloned()
                    .unwrap_or_else(|| "any".to_string()),
                digest: e.digest.clone(),
                dispatch: match parsed {
                    Ok(k) if k.is_dispatchable() => DISPATCHED,
                    Ok(_) => HELD,
                    Err(_) => UNKNOWN,
                },
                ingest_proof: match e.ingest_proof() {
                    Ok(p) => varve_core::IngestProof::label(p).to_string(),
                    Err(varve_core::UnknownProof(raw)) => raw,
                },
                proof_signer: e.annotations.get(varve_core::ANN_PROOF_SIGNER).cloned(),
                present: store_of(l).entry_path(&l.entry, e).is_some(),
                layer: l.entry.layer.to_string(),
                realm: l.realm.clone(),
                name,
            });
        }
    }
    // Stable order, so two runs — and two machines — agree.
    rows.sort_by(|a, b| {
        (&a.layer, &a.kind, &a.name, &a.version, &a.platform).cmp(&(
            &b.layer,
            &b.kind,
            &b.name,
            &b.version,
            &b.platform,
        ))
    });

    if json {
        print_json(&target, &layers, &rows, &host);
    } else {
        print_text(&target, &layers, &rows, &host);
    }
    Ok(())
}

/// The store partition a composed layer lives in — a cross-realm include lives
/// under the INCLUDED realm's fingerprint, not the including project's.
fn store_of(l: &crate::ComposedLayer) -> &Store {
    &l.store
}

/// The machine-readable report.
///
/// The shape is a compatibility promise, so it is stated here rather than left
/// to whatever `serde` happened to derive:
///
/// ```text
/// {
///   "command": "inspect",
///   "layer", "channel", "manifest_digest",   the layer the pin resolved to
///   "host_platform",                          what `present` was decided against
///   "composition": [ {"layer","manifest_digest","realm","root"} ],
///   "payloads":    [ {"name","version","kind","known_kind","platform",
///                     "dispatch","ingest_proof","proof_signer","digest",
///                     "present","layer","realm"} ],
///   "summary": {"payloads","dispatched","held","layers",
///               "unverified","unrecorded"}
/// }
/// ```
///
/// `version` is null where the entry carries none. `platform` is the string
/// `"any"` where the entry is unstamped, never null — an unstamped platform is
/// a positive fact (it runs anywhere), not a missing one. `dispatch` is one of
/// `dispatched` | `held` | `unknown`. `composition` always has at least one
/// element, the root, flagged `"root": true`.
fn print_json(
    target: &crate::ExportTarget,
    layers: &[crate::ComposedLayer],
    rows: &[Row],
    host: &str,
) {
    let composition: Vec<_> = layers
        .iter()
        .map(|l| {
            serde_json::json!({
                "layer": l.entry.layer.to_string(),
                "manifest_digest": l.entry.digest,
                "realm": l.realm,
                "root": l.entry.digest == target.entry.digest,
            })
        })
        .collect();
    let payloads: Vec<_> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "kind": r.kind,
                "known_kind": r.known_kind,
                "platform": r.platform,
                "dispatch": r.dispatch,
                "ingest_proof": r.ingest_proof,
                "proof_signer": r.proof_signer,
                "digest": r.digest,
                "present": r.present,
                "layer": r.layer,
                "realm": r.realm,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "command": "inspect",
        "layer": target.entry.layer.to_string(),
        "channel": target.entry.channel,
        "manifest_digest": target.entry.digest,
        "host_platform": host,
        "composition": composition,
        "payloads": payloads,
        "summary": {
            "payloads": rows.len(),
            "dispatched": rows.iter().filter(|r| r.dispatch == DISPATCHED).count(),
            "held": rows.iter().filter(|r| r.dispatch == HELD).count(),
            "layers": layers.len(),
            // Surfaced in the SUMMARY, not only per payload, so a CI gate can
            // assert "nothing in this layer went unverified" without walking
            // the list. `unrecorded` is counted separately from `unverified`:
            // a layer minted before REQ-INGEST-001 made no claim either way,
            // and collapsing the two would invent one.
            "unverified": rows.iter().filter(|r| r.ingest_proof == "unverified").count(),
            "unrecorded": rows.iter().filter(|r| r.ingest_proof == "unrecorded").count(),
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("the inspect report serialises")
    );
}

fn print_text(
    target: &crate::ExportTarget,
    layers: &[crate::ComposedLayer],
    rows: &[Row],
    host: &str,
) {
    println!(
        "layer {} ({}) {}",
        target.entry.layer, target.entry.channel, target.entry.digest
    );
    if layers.len() > 1 {
        println!("composition: {} layers —", layers.len());
        for l in layers {
            println!(
                "  {} {} (verified against realm '{}'){}",
                l.entry.layer,
                l.entry.digest,
                l.realm,
                if l.entry.digest == target.entry.digest {
                    "  [pinned]"
                } else {
                    ""
                }
            );
        }
    }
    if rows.is_empty() {
        println!("\nno payloads — this layer carries no entries beyond its composition");
        return;
    }
    let dispatched = rows.iter().filter(|r| r.dispatch == DISPATCHED).count();
    let held = rows.len() - dispatched;
    println!(
        "\n{} payload(s): {dispatched} DISPATCHED, {held} HELD  (platform {host})\n",
        rows.len()
    );
    // Column widths from the data: a fixed width truncates the one crate name
    // somebody needed to read.
    let w = |f: fn(&Row) -> &str, head: &str| {
        rows.iter()
            .map(|r| f(r).chars().count())
            .chain(std::iter::once(head.chars().count()))
            .max()
            .unwrap_or(1)
    };
    let (wn, wk, wp) = (w(|r| &r.name, "NAME"), w(|r| &r.kind, "KIND"), {
        rows.iter()
            .map(|r| r.platform.chars().count())
            .chain(std::iter::once(8))
            .max()
            .unwrap_or(8)
    });
    let wv = rows
        .iter()
        .map(|r| r.version.as_deref().unwrap_or("-").chars().count())
        .chain(std::iter::once(7))
        .max()
        .unwrap_or(7);
    println!(
        "  {:<12}{:<wk$}  {:<wn$}  {:<wv$}  {:<wp$}  LAYER",
        "", "KIND", "NAME", "VERSION", "PLATFORM"
    );
    for r in rows {
        println!(
            "  {:<12}{:<wk$}  {:<wn$}  {:<wv$}  {:<wp$}  {}{}",
            r.dispatch.to_uppercase(),
            r.kind,
            r.name,
            r.version.as_deref().unwrap_or("-"),
            r.platform,
            r.layer,
            if r.present {
                ""
            } else {
                "  (not laid down here)"
            },
        );
    }
    if held > 0 {
        println!(
            "\nHELD payloads are stored and verified but NOT on your PATH — `varve which` will \
             not find them, by design. Only a `tool` is dispatched by name. See \
             `varve docs inspect`."
        );
    }
    if rows.iter().any(|r| !r.known_kind) {
        println!(
            "\nAn entry above carries a payload kind this varve does not know. Its bytes still \
             verify against the signed digest — only the adapters that must DO something \
             kind-specific will refuse it. A newer varve may handle it."
        );
    }
}
