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
    let listener = http::bind(cli.port)?;
    println!(
        "  http://127.0.0.1:{}  — ctrl-c to stop",
        listener.local_addr()?.port()
    );
    http::accept_loop(&site, &listener)
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

    // EVERY layer of the composition, not just the pinned one. Reading only
    // the pinned layer's manifest is why this answered "layer 2026.09.1 carries
    // no documentation" on a four-layer composition whose documentation lived
    // in one of the other three — while `varve export-docs`, walking the
    // composition, found it. Two commands disagreeing about what one pin
    // contains is the defect; the walk now lives in varve-core, where both use
    // the same one.
    let roots = realm_roots(&cwd)?;
    let own_realm = pin.realm.clone().unwrap_or_else(|| "(this project)".into());
    let layers = varve_core::compose::walk_installed(
        &store,
        &entry,
        &verifier,
        &own_realm,
        &roots,
        &varve_core::host_platform(),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if layers.len() > 1 {
        eprintln!(
            "following the composition: {} layers — {}",
            layers.len(),
            layers
                .iter()
                .map(|l| format!("{} (realm '{}')", l.entry.layer, l.realm))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut out = Vec::new();
    for p in varve_core::compose::payloads_of(
        &layers,
        varve_core::PayloadKind::Docs,
        &varve_core::host_platform(),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?
    {
        out.push(
            DocsPayload::from_signed(&p.annotations, p.bytes)
                .map_err(|err| anyhow::anyhow!(err.to_string()))?,
        );
    }
    if out.is_empty() {
        bail!(
            "layer {} carries no documentation{}. `varve inspect` lists every payload it \
             does carry.",
            entry.layer,
            if layers.len() > 1 {
                format!(", nor do the {} layer(s) it composes", layers.len() - 1)
            } else {
                String::new()
            }
        );
    }
    Ok(out)
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

/// Every realm this project can name, mapped to its trust root.
///
/// The composition walk verifies each included layer against the root of the
/// realm its include NAMES, and varve-core does not read varve-realms.toml —
/// resolving them is the caller's job, so that the crate that verifies has no
/// opinion about where trust material lives.
fn realm_roots(
    cwd: &std::path::Path,
) -> anyhow::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    let mut out = std::collections::BTreeMap::new();
    let names = match varve_core::realm::realm_names(cwd) {
        Ok(names) => names,
        // No realms file at all is not an error here: a project pinning no
        // realm composes nothing that needs one, and the walk says so itself
        // if an include names a realm.
        Err(_) => return Ok(out),
    };
    for name in names {
        if let Ok(realm) = varve_core::resolve_realm(cwd, &name) {
            out.insert(name, realm.trust_root.clone());
        }
    }
    Ok(out)
}
