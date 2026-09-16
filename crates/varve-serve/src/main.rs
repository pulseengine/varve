//! `varve-serve` — read the documentation a layer carries, copying nothing.
//!
//! The companion to `varve export-docs`. Both answer "where is the
//! documentation for the versions this layer pins", and they answer it
//! differently: `export-docs` writes a copy you can hand to someone, while
//! this reads straight out of the verified store. Nothing is duplicated, and
//! nothing can go stale — when the pin moves, so does what is served.
//!
//! It is a separate binary on purpose. `varve` decides whether a toolchain can
//! be trusted; giving that program a listening socket would widen the surface
//! of exactly the thing whose smallness is the argument (varve#148). Shipping
//! the viewer beside it means one repository, one release and one signature,
//! and a realm can carry it or leave it out.
//!
//! Borrowed deliberately from `criticalup doc`: with one document there is
//! nothing to type. A reader has already said which layer they want by pinning
//! it, and asking them to name the document again is asking twice.

use varve_serve::{cli::Cli, docs, http};

use anyhow::{Context, bail};
use clap::Parser;
use varve_core::docsexport::DocsPayload;
use varve_core::layerspec::DocsFormat;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(topic) = &cli.docs {
        return docs::show(topic);
    }

    let payloads = collect()?;
    let chosen = varve_core::docsexport::select(&payloads, cli.select.as_deref())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let label = chosen.title.clone().unwrap_or_else(|| chosen.name.clone());

    if !chosen.format.is_tree() {
        // A PDF is one file. There is nothing to serve out of it and pointing
        // a browser at a single blob is worse than saying so: the reader wants
        // it on disk, which is what the other command is for.
        bail!(
            "{label} is a {} — a single file, not a site, so there is nothing to serve. \
             Write it out instead:\n\n  varve export-docs --out ./doc --select {}\n",
            chosen.format.as_str(),
            chosen.name
        );
    }

    // ONCE, not per request: a .tar.gz is sequential, so reading per request
    // would decompress the whole archive for every page.
    let members =
        varve_core::docsexport::members_of(chosen).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut pages = std::collections::BTreeMap::new();
    for m in members {
        if let varve_core::sdkexport::MemberBody::File { bytes, .. } = m.body {
            pages.insert(m.path.trim_start_matches("./").to_string(), bytes);
        }
    }

    let entry = chosen.entry.clone();
    if let Some(e) = &entry {
        // The deposit gate already checked this, so a miss here means the
        // payload and its annotation disagree — worth saying plainly rather
        // than serving a 404 at the front door.
        if !pages.contains_key(e.as_str()) {
            bail!(
                "{label} declares its entry point as {e:?}, and the payload does not contain \
                 it. The bytes verify, so this is not corruption — it is a manifest that \
                 describes a document it does not carry."
            );
        }
    }

    let site = http::Site {
        pages,
        entry,
        label: label.clone(),
    };

    println!(
        "{label} {} ({}) — {} page(s), read from the store, nothing copied",
        chosen.version,
        chosen.format.as_str(),
        site.pages.len()
    );
    if cli.check {
        match &site.entry {
            Some(e) => println!("  entry: {e}"),
            None => println!("  (no declared entry point)"),
        }
        return Ok(());
    }
    http::serve(&site, cli.port)
}

/// Every `docs` payload of the pinned layer, verified, with what the producer
/// signed about it.
///
/// This shells out to `varve export-docs`? No — it asks varve-core directly,
/// for the same reason the producer reads `layer.toml` itself: a second
/// implementation of "which payloads does this layer have" is a second thing
/// to keep in step.
fn collect() -> anyhow::Result<Vec<DocsPayload>> {
    let store = varve_core::Store::at(store_root()?);
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    let pin_path = varve_core::discover::find_pin(&cwd).context(
        "no varve.toml found walking up from here — this project pins no layer, so there \
         is no documentation to read",
    )?;
    let pin = varve_core::Pin::load(&pin_path)?;

    let (store, verifier) = match &pin.realm {
        Some(name) => {
            let realm = varve_core::resolve_realm(&cwd, name)?;
            let s = varve_core::Store::at(realm.effective_root(store.root()));
            let v = varve_core::PinnedKeyVerifier::from_public_key_bytes(&realm.trust_root)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            (s, v)
        }
        None => {
            let path = std::env::var_os("VARVE_TRUST_ROOT").context(
                "no trust root configured. Pin a realm in varve.toml, or set \
                 VARVE_TRUST_ROOT to the published root key.",
            )?;
            let hex = std::fs::read_to_string(&path)?;
            let bytes = hex_decode(hex.trim())?;
            let v = varve_core::PinnedKeyVerifier::from_public_key_bytes(&bytes)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            (store, v)
        }
    };

    // `resolve` already returns the installed layer the pin names, so asking
    // the store for it again would be a second way to answer one question.
    let entry = varve_core::resolve(&pin, &store)?.layer;
    // Re-verified before anything is read: serving the contents of a layer
    // varve cannot vouch for would look authoritative and be worthless.
    varve_core::verify_installed(&store, &entry, &verifier, &varve_core::host_platform())?;

    let manifest =
        varve_core::LayerManifest::parse(&std::fs::read(entry.root.join("layer.json"))?)?;
    let mut out = Vec::new();
    for e in &manifest.entries {
        if e.kind().ok() != Some(varve_core::PayloadKind::Docs) {
            continue;
        }
        let Some(path) = store.entry_path(&entry, e) else {
            continue;
        };
        let raw = e
            .annotations
            .get(varve_core::deposit::ANN_DOCS_FORMAT)
            .context("a docs payload carries no format annotation")?;
        out.push(DocsPayload {
            name: e
                .annotations
                .get("eu.pulseengine.tool")
                .cloned()
                .unwrap_or_else(|| "(unnamed)".into()),
            version: e
                .annotations
                .get("eu.pulseengine.tool.version")
                .cloned()
                .unwrap_or_default(),
            format: parse_format(raw)?,
            entry: e
                .annotations
                .get(varve_core::deposit::ANN_DOCS_ENTRY)
                .cloned(),
            title: e
                .annotations
                .get(varve_core::deposit::ANN_DOCS_TITLE)
                .cloned(),
            bytes: std::fs::read(&path)?,
        });
    }
    if out.is_empty() {
        bail!(
            "layer {} carries no documentation. `varve inspect` lists every payload it does \
             carry.",
            entry.layer
        );
    }
    Ok(out)
}

fn parse_format(raw: &str) -> anyhow::Result<DocsFormat> {
    Ok(match raw {
        "html" => DocsFormat::Html,
        "rustdoc" => DocsFormat::Rustdoc,
        "pdf" => DocsFormat::Pdf,
        "markdown" => DocsFormat::Markdown,
        "reqif" => DocsFormat::Reqif,
        other => bail!(
            "this layer declares a documentation format {other:?} that this varve-serve does \
             not know. The document is carried and verified; it cannot be opened here. A \
             newer varve-serve may know it."
        ),
    })
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("trust root is not valid hex: odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("trust root is not valid hex"))
        .collect()
}

/// Where the core lives. Mirrors varve's own rule so both programs read the
/// same store: `$VARVE_ROOT`, else `$HOME/.varve`.
fn store_root() -> anyhow::Result<std::path::PathBuf> {
    if let Some(root) = std::env::var_os("VARVE_ROOT") {
        return Ok(std::path::PathBuf::from(root));
    }
    let home = std::env::var_os("HOME").context("HOME is not set and VARVE_ROOT is not set")?;
    Ok(std::path::PathBuf::from(home).join(".varve"))
}
