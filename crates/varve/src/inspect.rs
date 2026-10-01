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

/// The documentation-specific half of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DocsRow {
    pub(crate) format: String,
    pub(crate) entry: Option<String>,
    pub(crate) title: Option<String>,
    /// The payload this documents, by name.
    pub(crate) documents: Option<String>,
}

/// How wide the REALM column must be, or `None` when every payload comes from
/// one realm and the column would say the same thing on every line.
///
/// Reported from use: on a four-realm composition the table gave a version and
/// a layer id per tool and never named the realm — which is the trust boundary,
/// and the only thing separating two realms that ship one name at one version.
fn realm_width(rows: &[Row]) -> Option<usize> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in rows {
        seen.insert(r.realm.as_str());
    }
    if seen.len() < 2 {
        return None;
    }
    Some(
        seen.iter()
            .map(|r| r.chars().count())
            .chain(std::iter::once("REALM".len()))
            .max()
            .unwrap_or(5),
    )
}

/// The platform cell: the machine that RUNS the payload, and — for a
/// cross-toolchain — what it BUILDS FOR, as the pair that identifies it.
///
/// Shown in the platform column rather than a column of its own because the
/// two are one fact: `x86_64-unknown-linux-gnu -> arm-zephyr-eabi` says what
/// neither half says alone, and a whole extra column would be empty for every
/// layer that carries no cross-toolchain.
fn platform_cell(r: &Row) -> String {
    // The measured libc goes in the SAME cell, for the same reason the target
    // does: the platform key is the slot, and what the bytes in it need is the
    // other half of one fact. Two payloads under one `-unknown-linux-gnu` key
    // can differ here (REQ-LIBCSTATED-001), and a reader comparing them needs
    // both side by side rather than in distant columns.
    let base = match &r.libc {
        Some(libc) => format!("{} ({libc})", r.platform),
        None => r.platform.clone(),
    };
    match &r.target {
        Some(t) => format!("{base} -> {t}"),
        None => base,
    }
}

/// One payload, as reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    /// The kind as written in the SIGNED annotation, so an unknown kind is
    /// reported verbatim rather than dropped or guessed (`sbom` labels such an
    /// entry rather than losing it; so does this).
    pub(crate) kind: String,
    pub(crate) known_kind: bool,
    /// The entry's signed platform, or `any` where it carries none — an
    /// unstamped platform means any-platform, as it does everywhere else.
    pub(crate) platform: String,
    /// What the payload BUILDS FOR, when it differs from what runs it
    /// (REQ-SDKTARGET-001 clause 5). A layer carrying three cross-toolchains
    /// and unable to say which is which is not inspectable.
    pub(crate) target: Option<String>,
    /// What the payload needs from the host's libc (REQ-LIBCSTATED-001),
    /// measured from its ELF at deposit. `None` where nothing was measurable
    /// — reported as absent rather than as `static`, because the layer makes
    /// no portability claim it did not check.
    ///
    /// The platform above is the SLOT; this is what the bytes in it need. Two
    /// payloads under one `-unknown-linux-gnu` key can differ here, and that
    /// difference is the whole reason the annotation exists.
    pub(crate) libc: Option<String>,
    pub(crate) digest: String,
    /// `dispatched` | `held` | `unknown` (the kind annotation is one this
    /// varve does not recognise, so whether it dispatches is not knowable).
    pub(crate) dispatch: &'static str,
    /// For a `docs` payload: what it IS, where a reader starts, and the label
    /// a human chooses by — all from SIGNED annotations
    /// (REQ-LAYERDOCS-001). `None` for every other kind.
    pub(crate) docs: Option<DocsRow>,
    /// Which mechanism vouched for this payload's UPSTREAM bytes
    /// (REQ-INGEST-001 clause 5). `unrecorded` where the layer predates the
    /// requirement — absence of a claim is not a claim, and restating a
    /// hundred existing payloads as either verified or unverified would be
    /// inventing one. An unknown mechanism is reported verbatim, like `kind`.
    pub(crate) ingest_proof: String,
    /// The identity credited with vouching, where one is recorded — the fact
    /// a consumer might filter on ("refuse anything not signed under
    /// pulseengine/"), which is why it is its own field and not prose.
    pub(crate) proof_signer: Option<String>,
    /// Are these bytes on disk here? `install` lays down only the host
    /// platform's entries, so another platform's entry is present in the
    /// signed manifest and absent from the store — which is correct, and worth
    /// saying rather than leaving as a mystery.
    pub(crate) present: bool,
    pub(crate) layer: String,
    pub(crate) realm: String,
}

const DISPATCHED: &str = "dispatched";
const HELD: &str = "held";
const UNKNOWN: &str = "unknown";

pub fn run(store: &Store, layer: Option<&str>, json: bool) -> anyhow::Result<()> {
    let target = crate::export_target(store, layer)?;
    let layers = crate::composition_for_export(&target)?;
    let host = varve_core::host_platform();
    let rows = rows_of(&layers)?;

    if json {
        print_json(&target, &layers, &rows, &host);
    } else {
        print_text(&target, &layers, &rows, &host);
    }
    Ok(())
}

/// Every payload of a composed layer, read from the SIGNED manifests.
///
/// The ONE place that answers "which payloads does this layer have". `inspect`
/// renders it and `diff` compares two of them; neither re-reads a manifest for
/// itself. A second implementation of this question is a second thing to keep
/// in step, and this codebase has paid for that shape more than once — the
/// platform rule answered differently by deposit and install, the store root
/// computed one way by the composing realm and another by the include.
pub(crate) fn rows_of(layers: &[varve_core::compose::ComposedLayer]) -> anyhow::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for l in layers {
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
                target: e.annotations.get(varve_core::platform::ANN_TARGET).cloned(),
                libc: e.annotations.get(varve_core::platform::ANN_LIBC).cloned(),
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
                docs: e
                    .annotations
                    .get(varve_core::deposit::ANN_DOCS_FORMAT)
                    .map(|format| DocsRow {
                        format: format.clone(),
                        entry: e
                            .annotations
                            .get(varve_core::deposit::ANN_DOCS_ENTRY)
                            .cloned(),
                        title: e
                            .annotations
                            .get(varve_core::deposit::ANN_DOCS_TITLE)
                            .cloned(),
                        documents: e
                            .annotations
                            .get(varve_core::deposit::ANN_DOCS_DOCUMENTS)
                            .cloned(),
                    }),
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

    Ok(rows)
}

/// The store partition a composed layer lives in — a cross-realm include lives
/// under the INCLUDED realm's fingerprint, not the including project's.
fn store_of(l: &varve_core::compose::ComposedLayer) -> &Store {
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
///   "layer", "channel", "realm", "manifest_digest",   the layer the pin
///                                             resolved to, and the realm that
///                                             vouched for it (a layer id is
///                                             unique only within a realm)
///   "host_platform",                          what `present` was decided against
///   "composition": [ {"layer","manifest_digest","realm","root"} ],
///   "payloads":    [ {"name","version","kind","known_kind","platform",
///                     "target","libc","dispatch","ingest_proof",
///                     "proof_signer","digest","present","layer","realm"} ],
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
/// The `payloads` array of `--format json`, as a value rather than as print
/// output.
///
/// Extracted so a test can compare it against what the text form shows. It
/// was inline in `print_json`, which meant the only way to check the two
/// agreed was to read both — and they did not: `target` was printed by the
/// text cell and absent from the json.
fn payload_json(rows: &[Row]) -> Vec<serde_json::Value> {
    rows.iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "kind": r.kind,
                "known_kind": r.known_kind,
                "platform": r.platform,
                // `target` was absent here while the text form printed it,
                // against this function's own rule two comments below. A
                // machine could not see which of three cross-toolchains a
                // payload was, which is the question REQ-SDKTARGET-001
                // clause 5 exists to answer.
                "target": r.target,
                // What the bytes in that platform slot need from the host,
                // measured at deposit (REQ-LIBCSTATED-001). `null` where
                // nothing was measurable — never "static" by default.
                "libc": r.libc,
                "dispatch": r.dispatch,
                "ingest_proof": r.ingest_proof,
                "proof_signer": r.proof_signer,
                "digest": r.digest,
                "present": r.present,
                "layer": r.layer,
                "realm": r.realm,
                // The text form prints a documentation block; a machine
                // reading --format json must be able to see the same facts, or
                // the two outputs disagree about what the layer contains.
                "docs_format": r.docs.as_ref().map(|d| &d.format),
                "docs_entry": r.docs.as_ref().and_then(|d| d.entry.as_ref()),
                "docs_title": r.docs.as_ref().and_then(|d| d.title.as_ref()),
                "docs_documents": r.docs.as_ref().and_then(|d| d.documents.as_ref()),
            })
        })
        .collect()
}

fn print_json(
    target: &crate::ExportTarget,
    layers: &[varve_core::compose::ComposedLayer],
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
    let payloads: Vec<_> = payload_json(rows);
    let doc = serde_json::json!({
        "command": "inspect",
        "layer": target.entry.layer.to_string(),
        "channel": target.entry.channel,
        // A layer id is YYYY.MM.P and is only unique WITHIN a realm; a
        // consumer diffing two inspect reports needs to know which realm each
        // came from. It was in `composition[]` and absent from the top level.
        "realm": layers
            .iter()
            .find(|l| l.entry.digest == target.entry.digest)
            .map(|l| l.realm.clone()),
        "manifest_digest": target.entry.digest,
        "host_platform": host,
        // Which platform this layer's payloads were laid down FOR. `null`
        // for layers installed before that was recorded. A consumer reading
        // `host_platform` alone cannot tell a cross-platform install from a
        // tampered store, and those want opposite responses (varve#178).
        "installed_for": target.entry.platform,
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
    layers: &[varve_core::compose::ComposedLayer],
    rows: &[Row],
    host: &str,
) {
    // The realm belongs on this line, not only in the composition block below.
    // Layer ids are YYYY.MM.P, so two realms can publish the same one --
    // "layer 2026.08.26" alone does not say WHICH 2026.08.26, and the realm is
    // what the trust root, the store partition and the pin all hang on.
    // Reported from a real session: a user read this output beside a
    // `realm = "linc"` pin and the word realm appeared nowhere in it.
    let realm = layers
        .iter()
        .find(|l| l.entry.digest == target.entry.digest)
        .map(|l| l.realm.as_str());
    match realm {
        Some(r) => println!(
            "layer {} ({}) realm '{}' {}",
            target.entry.layer, target.entry.channel, r, target.entry.digest
        ),
        None => println!(
            "layer {} ({}) {}",
            target.entry.layer, target.entry.channel, target.entry.digest
        ),
    }
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
    // The host qualifies PRESENCE, never dispatch. Printing it beside the
    // DISPATCHED/HELD counts read as "4 payloads dispatch on this host",
    // which was false whenever the layer was installed for another platform —
    // dispatch is decided by payload KIND and the host decides nothing about
    // it (varve#178). Nothing was computed wrongly; the label sat on the
    // wrong number.
    println!(
        "\n{} payload(s): {dispatched} DISPATCHED, {held} HELD",
        rows.len()
    );
    let present = rows.iter().filter(|r| r.present).count();
    match target.entry.platform.as_deref() {
        // Installed for somewhere else: say so plainly rather than leaving a
        // reader to notice that every PLATFORM cell disagrees with the host.
        // A store holding only another platform's bytes is worth knowing.
        Some(installed) if installed != host => println!(
            "installed for {installed}; host is {host} — {}",
            if present == 0 {
                "none of it present for this host".to_string()
            } else {
                format!("{present} of {} present for this host", rows.len())
            }
        ),
        _ => println!("presence checked against {host}"),
    }
    println!();
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
            .map(|r| platform_cell(r).chars().count())
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
    // WHOSE layer each payload came from, whenever more than one realm is in
    // play. Reported from use on a four-realm composition: the table showed a
    // version and a layer id for every tool and never said which realm vouched
    // for it — and the realm is the trust boundary, so "rivet 0.37.0 from
    // 2026.09.3" leaves the one question a composition raises unanswered. Two
    // realms can also ship one name at one version; only the realm separates
    // them. Omitted for a single-realm layer, where the header already says it
    // and a constant column is noise.
    let wr = realm_width(rows);
    let realms = wr.map(|w| (w, "REALM")).unwrap_or((0, ""));
    println!(
        "  {:<12}{:<wk$}  {:<wn$}  {:<wv$}  {:<wp$}  {:<rw$}{}LAYER",
        "",
        "KIND",
        "NAME",
        "VERSION",
        "PLATFORM",
        realms.1,
        if wr.is_some() { "  " } else { "" },
        rw = realms.0
    );
    for r in rows {
        println!(
            "  {:<12}{:<wk$}  {:<wn$}  {:<wv$}  {:<wp$}  {:<rw$}{}{}{}",
            r.dispatch.to_uppercase(),
            r.kind,
            r.name,
            r.version.as_deref().unwrap_or("-"),
            platform_cell(r),
            if wr.is_some() { r.realm.as_str() } else { "" },
            if wr.is_some() { "  " } else { "" },
            r.layer,
            if r.present {
                ""
            } else {
                "  (not laid down here)"
            },
            rw = realms.0,
        );
    }
    if held > 0 {
        println!(
            "\nHELD payloads are stored and verified but NOT on your PATH — `varve which` will \
             not find them, by design. Only a `tool` is dispatched by name. See \
             `varve docs inspect`."
        );
    }
    // Documentation, after the table rather than before it: the table is what
    // `inspect` is run for, and the natural next line once someone has seen
    // what a layer holds is where to start reading it (REQ-LAYERDOCS-001).
    //
    // Reported from the SIGNED annotations, so this says what the producer
    // declared rather than what the file name suggests.
    let docs: Vec<(&Row, &DocsRow)> = rows
        .iter()
        .filter_map(|r| r.docs.as_ref().map(|d| (r, d)))
        .collect();
    if !docs.is_empty() {
        println!("\ndocumentation for the versions this layer pins:");
        for (row, d) in &docs {
            let label = d.title.as_deref().unwrap_or(&row.name);
            println!(
                "  {label} {} ({})",
                row.version.as_deref().unwrap_or("-"),
                d.format
            );
            if let Some(entry) = &d.entry {
                println!("    starts at {entry}");
            }
            // Printed as the command that answers it, because "which document
            // is the API of varve-core" is the question this field exists for.
            if let Some(of) = &d.documents {
                println!("    documents {of}    (varve export-docs --for {of})");
            }
        }
        // One document needs no selector; several do. Printing the exact next
        // command beats describing it, and the reader has already said which
        // layer they want by pinning it.
        match docs.as_slice() {
            [(row, _)] => {
                println!("\n  read it, copying nothing:  varve-serve");
                println!(
                    "  or write a copy:           varve export-docs --out ./doc   ({})",
                    row.name
                );
            }
            many => {
                println!(
                    "\n  {} documents, so name one:  varve-serve --select <NAME>",
                    many.len()
                );
                println!(
                    "  or:                        varve export-docs --out ./doc --select <NAME>"
                );
            }
        }
    }
    if rows.iter().any(|r| !r.known_kind) {
        println!(
            "\nAn entry above carries a payload kind this varve does not know. Its bytes still \
             verify against the signed digest — only the adapters that must DO something \
             kind-specific will refuse it. A newer varve may handle it."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, docs: Option<DocsRow>) -> Row {
        Row {
            name: name.into(),
            version: Some("1.0.0".into()),
            kind: if docs.is_some() {
                "docs".into()
            } else {
                "tool".into()
            },
            known_kind: true,
            platform: "any".into(),
            digest: "sha256:0".into(),
            dispatch: if docs.is_some() { HELD } else { DISPATCHED },
            docs,
            ingest_proof: "cosign-sums".into(),
            proof_signer: None,
            present: true,
            layer: "2026.09.9".into(),
            realm: "t".into(),
            target: None,
            libc: None,
        }
    }

    /// Two payloads under ONE platform key, distinguished only by the floor
    /// their bytes need.
    ///
    /// This is the pair layer 2026.10.1 could not tell apart: `ordeal` filed
    /// under `x86_64-unknown-linux-gnu` from a musl asset, beside a genuinely
    /// glibc-linked payload in the same slot. If the cell did not carry the
    /// libc, these two rows would be identical in every visible field.
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn one_platform_key_two_floors_are_distinguishable() {
        let mut glibc = row("needs-glibc", None);
        glibc.platform = "x86_64-unknown-linux-gnu".into();
        glibc.libc = Some("glibc".into());
        let mut portable = row("needs-nothing", None);
        portable.platform = "x86_64-unknown-linux-gnu".into();
        portable.libc = Some("static".into());

        let a = platform_cell(&glibc);
        let b = platform_cell(&portable);
        assert_ne!(a, b, "the two floors render identically: {a}");
        assert!(a.contains("glibc"), "{a}");
        assert!(b.contains("static"), "{b}");

        // Unmeasured stays silent — no "(unknown)", no "(static)".
        let mut quiet = row("unmeasured", None);
        quiet.platform = "x86_64-unknown-linux-gnu".into();
        quiet.libc = None;
        assert_eq!(platform_cell(&quiet), "x86_64-unknown-linux-gnu");
    }

    /// The text form and `--format json` must not disagree about what a layer
    /// contains.
    ///
    /// Provoked by a defect: `target` was printed by the text form and ABSENT
    /// from the json, directly against the rule the json emitter states in its
    /// own comment. A reader of either output is entitled to the same facts,
    /// so this checks the json carries every field the row distinguishes
    /// payloads by rather than trusting that whoever adds the next one
    /// remembers both places.
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn the_json_carries_every_field_the_text_form_distinguishes_by() {
        let mut r = row("cross", None);
        r.platform = "x86_64-unknown-linux-gnu".into();
        r.target = Some("arm-zephyr-eabi".into());
        r.libc = Some("static".into());

        let json = payload_json(std::slice::from_ref(&r));
        let one = &json[0];
        for field in ["platform", "target", "libc"] {
            assert!(
                !one[field].is_null(),
                "json omits `{field}`, which the text cell prints: {one}"
            );
        }
        // And the values agree, not merely exist.
        assert_eq!(one["target"], "arm-zephyr-eabi");
        assert_eq!(one["libc"], "static");
        let cell = platform_cell(&r);
        assert!(
            cell.contains("static") && cell.contains("arm-zephyr-eabi"),
            "{cell}"
        );
    }

    /// Clause 5. Three cross-toolchains for one host are one name, one
    /// version and one platform three times over; the target is the only
    /// thing that tells them apart, so a report that omits it is not a
    /// report of this layer.
    ///
    /// Shown as the PAIR rather than in a column of its own: `platform`
    /// alone answers "can I run this", `target` alone answers nothing, and
    /// `x86_64-unknown-linux-gnu -> arm-zephyr-eabi` is the identity.
    // rivet: verifies REQ-SDKTARGET-001
    #[test]
    fn a_cross_toolchain_reports_the_pair_that_identifies_it() {
        let sdk = |target: &str| {
            let mut r = row("zephyr-sdk", None);
            r.platform = "x86_64-unknown-linux-gnu".into();
            r.target = Some(target.into());
            r
        };
        let rows = [
            sdk("arm-zephyr-eabi"),
            sdk("riscv64-zephyr-elf"),
            row("rivet", None),
        ];
        let cells: Vec<String> = rows.iter().map(platform_cell).collect();
        assert_eq!(
            cells,
            vec![
                "x86_64-unknown-linux-gnu -> arm-zephyr-eabi",
                "x86_64-unknown-linux-gnu -> riscv64-zephyr-elf",
                // A payload whose output runs where it ran says nothing extra:
                // clause 4, unchanged by this dimension.
                "any",
            ]
        );
        assert_ne!(
            cells[0], cells[1],
            "two toolchains a realm installs side by side must be \
             distinguishable in the one place that reports what a layer holds"
        );
    }

    /// `inspect` has two output paths and they must agree about what the layer
    /// contains. The text form grew a documentation block; a gate parsing
    /// `--format json` would otherwise be blind to it, and "the two renderings
    /// of one fact disagree" is the shape that cost three releases this month.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn both_renderings_report_the_same_documents() {
        let rows = [
            row("rivet", None),
            row(
                "handbook",
                Some(DocsRow {
                    format: "pdf".into(),
                    entry: None,
                    title: Some("The handbook".into()),
                    documents: None,
                }),
            ),
        ];

        // What the text form would say it has:
        let in_text: Vec<&str> = rows
            .iter()
            .filter(|r| r.docs.is_some())
            .map(|r| r.name.as_str())
            .collect();
        // What the JSON form would say it has: a payload is a document exactly
        // when it carries a format.
        let in_json: Vec<&str> = rows
            .iter()
            .filter(|r| r.docs.as_ref().map(|d| !d.format.is_empty()) == Some(true))
            .map(|r| r.name.as_str())
            .collect();

        assert_eq!(in_text, in_json, "the two renderings disagree");
        assert_eq!(in_text, vec!["handbook"]);
    }

    /// Reported from use on a four-realm composition: every tool showed a
    /// version and a layer id, and nothing said WHICH REALM vouched for it.
    // rivet: verifies REQ-INSPECT-001
    #[test]
    fn the_realm_is_shown_when_a_composition_spans_more_than_one() {
        let mut a = row("rivet", None);
        a.realm = "pulseengine".into();
        let mut b = row("wit-bindgen-wrpc", None);
        b.realm = "ulinc".into();
        let w = realm_width(&[a, b]).expect("a multi-realm composition needs the column");
        assert!(
            w >= "pulseengine".len(),
            "the column truncates the realm name: {w}"
        );
    }

    /// One realm, and the column would repeat the header line on every row.
    // rivet: verifies REQ-INSPECT-001
    #[test]
    fn a_single_realm_layer_gets_no_realm_column() {
        let a = row("rivet", None);
        let b = row("spar", None);
        assert_eq!(realm_width(&[a, b]), None);
    }

    /// Realms shorter than the word REALM still need a column wide enough for
    /// the header, or the heading runs into the next one.
    // rivet: verifies REQ-INSPECT-001
    #[test]
    fn the_column_is_never_narrower_than_its_heading() {
        let mut a = row("rivet", None);
        a.realm = "ul".into();
        let mut b = row("spar", None);
        b.realm = "pe".into();
        assert_eq!(realm_width(&[a, b]), Some("REALM".len()));
    }

    /// Two realms shipping ONE name at ONE version is the case the realm column
    /// exists for: nothing else in the row distinguishes them.
    // rivet: verifies REQ-INSPECT-001
    #[test]
    fn two_realms_shipping_one_name_are_distinguishable() {
        let mut a = row("wasm-tools", None);
        a.realm = "pulseengine".into();
        a.layer = "2026.09.5".into();
        let mut b = row("wasm-tools", None);
        b.realm = "pulseengine-wasm".into();
        b.layer = "2026.09.5".into();
        assert_eq!(a.name, b.name);
        assert_eq!(a.version, b.version);
        assert_eq!(
            a.layer, b.layer,
            "same id in two realms — only the realm separates them"
        );
        assert!(
            realm_width(&[a, b]).is_some(),
            "the one case where every other column is identical shows no realm"
        );
    }

    /// A document is HELD, never dispatched: it is read, not executed.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_document_is_never_reported_as_dispatched() {
        let d = row(
            "handbook",
            Some(DocsRow {
                format: "html".into(),
                entry: Some("index.html".into()),
                title: None,
                documents: None,
            }),
        );
        assert_eq!(d.dispatch, HELD);
        assert!(!varve_core::PayloadKind::Docs.is_dispatchable());
    }
}
