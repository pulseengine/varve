//! `varve-producer` — assemble, sign and publish a layer (REQ-PRODUCER-002).
//!
//! A SEPARATE binary from `varve`, deliberately. `varve` contacts no network,
//! and that claim is load-bearing in `varve docs air-gap` and the threat
//! model; this program fetches releases, verifies signatures over the network
//! and pushes to a registry. Keeping them apart keeps that claim true.

use clap::{Parser, Subcommand};
use varve_producer::{asset, binfmt, deposit, forge::Forge, ingest, orchestrate, plan, source};

#[derive(Parser)]
#[command(name = "varve-producer", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report which forge this run would ingest from, and which authority
    /// would be expected to have signed it. Printed before anything is
    /// fetched, because a wrong issuer fails closed but confusingly.
    Forge,

    /// Show the work a deposit would do for a realm manifest, without
    /// fetching anything. Reads layer.toml directly — there is no
    /// TARBALL_TOOLS/WSC_VERSION encoding to corrupt, and no limit of one
    /// raw-per-platform tool.
    Plan {
        #[arg(long, default_value = "layer.toml")]
        manifest: std::path::PathBuf,
        #[arg(long = "platform", value_delimiter = ',')]
        platforms: Vec<String>,
    },
    /// Check a staged payload's architecture against the platform it would be
    /// deposited under, without executing it.
    Arch {
        /// The file to inspect.
        #[arg(long)]
        file: std::path::PathBuf,
        /// The target triple it would be filed under.
        #[arg(long)]
        platform: String,
    },
    /// Show which release assets a template selects, without downloading
    /// anything. The template language is the part of this pipeline that has
    /// silently dropped a tool from a published layer, so it is inspectable on
    /// its own.
    Assets {
        /// Asset name template, e.g. `rivet-v0.34.0-%T.tar.gz`.
        #[arg(long)]
        template: String,
        /// Release version as written, e.g. `v0.34.0`.
        #[arg(long)]
        version: String,
        /// Asset names the release actually publishes; repeat or comma-separate.
        #[arg(long = "available", value_delimiter = ',')]
        available: Vec<String>,
        /// Target triples to cover. Defaults to the layer's four.
        #[arg(long = "platform", value_delimiter = ',')]
        platforms: Vec<String>,
    },

    /// Assemble a layer: fetch every payload the manifest names, verify each
    /// release, stage the bytes, and write the deposit spec `varve deposit`
    /// consumes.
    ///
    /// This is the one subcommand that touches the network. It does NOT
    /// deposit, sign or publish — those need the signing key, and keeping them
    /// in a separate step keeps this program runnable by anyone who wants to
    /// see what a layer would contain.
    Deposit {
        #[arg(long, default_value = "layer.toml")]
        manifest: std::path::PathBuf,
        /// Where to write `deposit-spec.toml` and the staged payloads.
        #[arg(long)]
        stage: std::path::PathBuf,
        /// The layer id being built, e.g. `2026.09.1`.
        #[arg(long)]
        layer: String,
        /// The layer's monotonic counter.
        #[arg(long)]
        counter: u64,
        #[arg(long = "platform", value_delimiter = ',')]
        platforms: Vec<String>,
        /// The deposit spec from the previous layer, for carry-forward.
        /// Without it every payload is fetched.
        #[arg(long)]
        previous: Option<std::path::PathBuf>,
        /// Digests the registry already holds, one per line. Without it every
        /// payload is fetched — see the note in `deposit.rs`: assuming
        /// presence would publish a manifest naming bytes nobody can serve.
        #[arg(long = "present-digests")]
        present_digests: Option<std::path::PathBuf>,
    },
}

/// `GH_HOST` is what `gh` itself uses to target an instance, so varve reads
/// the same variable rather than inventing a second one.
fn forge_from_env() -> Forge {
    Forge::from_env(
        std::env::var("GH_HOST").ok().as_deref(),
        std::env::var("VARVE_OIDC_ISSUER").ok().as_deref(),
    )
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Plan {
            manifest,
            platforms,
        } => {
            let text = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", manifest.display()))?;
            let m = varve_core::layerspec::parse_layer_manifest(&text)?;
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let items = plan::plan(&m, &refs)?;
            let rels = plan::releases(&items);
            println!(
                "{} payload(s) from {} release(s), realm '{}'",
                items.len(),
                rels.len(),
                m.realm.name
            );
            let unverified = rels
                .iter()
                .filter(|(repo, _)| {
                    items
                        .iter()
                        .any(|i| &i.repo == repo && i.unverified_reason.is_some())
                })
                .count();
            if unverified > 0 {
                println!("{unverified} release(s) carry NO proof of origin (opt-in recorded)");
            }
            for i in &items {
                println!(
                    "  {:<14} {:<24} {:<26} {}{}",
                    i.name,
                    i.repo,
                    i.platform.as_deref().unwrap_or("(portable)"),
                    i.asset,
                    if i.unverified_reason.is_some() {
                        "  [unverified]"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        Cmd::Deposit {
            manifest,
            stage: stage_root,
            layer,
            counter,
            platforms,
            previous,
            present_digests,
        } => {
            let forge = forge_from_env();
            let text = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", manifest.display()))?;
            let m = varve_core::layerspec::parse_layer_manifest(&text)?;
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let planned = plan::plan(&m, &refs)?;

            let prev = match &previous {
                Some(p) => deposit::previous_from_spec(&std::fs::read_to_string(p)?)?,
                None => Default::default(),
            };
            let present = match &present_digests {
                Some(p) => deposit::parse_present_digests(&std::fs::read_to_string(p)?),
                None => Default::default(),
            };
            let optins =
                ingest::parse_optins(&std::env::var("UNVERIFIED_INGEST").unwrap_or_default());

            let downloads = stage_root.join("downloads");
            let scratch = stage_root.join("extract");
            let src = source::GhSource::new(source::Spawn, forge.clone(), &downloads);
            eprintln!(
                "assembling {} payload(s) for realm '{}' from {}",
                planned.len(),
                m.realm.name,
                forge.host
            );
            // Carry-forward is DECIDED by the orchestrator and not yet ACTED
            // on here, deliberately.
            //
            // REQ-CARRYFORWARD-001 clause 4 requires reuse only when the blob
            // is still in the destination registry — which is also what would
            // let a deposit REFERENCE that blob rather than upload it again.
            // But varve's DepositSpec requires a `path` for every tool: there
            // is no way to say "these bytes are already the registry's blob at
            // this digest". Until there is, skipping the download leaves the
            // deposit with nothing to point at.
            //
            // So every payload is fetched. Reporting a saving that did not
            // happen, or failing on a payload we chose to reuse, would both be
            // worse than doing the work. Tracked as varve#124.
            if !present.is_empty() {
                eprintln!(
                    "note: --present-digests is recorded but not yet acted on: a \
deposit spec cannot reference a blob it has no path for (varve#124). \
Every payload is fetched."
                );
            }
            let resolved = orchestrate::run(&src, &forge, &planned, &prev, &optins, &|_| false)?;

            // A payload the layer does not carry on some platform is reported
            // by name. An operator reading a shorter list than they expected
            // should not have to work out which entry went missing.
            for note in deposit::omitted(&planned, &resolved) {
                eprintln!("note: {note}");
            }

            let mut tools = Vec::with_capacity(resolved.len());
            for r in &resolved {
                let bin = m
                    .tools
                    .iter()
                    .find(|t| t.name == r.plan.name)
                    .and_then(|t| t.binary.clone())
                    .unwrap_or_else(|| r.plan.name.clone());
                let version = asset::bare_version(&r.plan.version).to_string();
                // The same function the downloader used, not a second copy
                // of the convention.
                let dl = source::release_dir(&downloads, &r.plan.repo, &r.plan.version);
                tools.push(deposit::stage_one(
                    &source::Spawn,
                    r,
                    &version,
                    &stage_root,
                    &dl,
                    &scratch,
                    &bin,
                )?);
            }

            let spec = deposit::describe(&layer, &m.realm.channel, counter, tools);
            // render() re-parses with varve's own parser and refuses a spec
            // `varve deposit` could not read — before the signing step, not
            // during it.
            let rendered = spec.render()?;
            let out = stage_root.join("deposit-spec.toml");
            std::fs::write(&out, &rendered)?;
            println!("{}", out.display());
            eprintln!(
                "{} payload(s) staged, {} carried forward",
                spec.tools.len(),
                resolved
                    .iter()
                    .filter(|r| matches!(
                        r.decision,
                        varve_producer::carryforward::Decision::Reuse { .. }
                    ))
                    .count()
            );
            Ok(())
        }
        Cmd::Arch { file, platform } => {
            let bytes = std::fs::read(&file)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", file.display()))?;
            let format = binfmt::check_platform(&file.display().to_string(), &bytes, &platform)?;
            println!("{:<28} {format:?}", platform);
            Ok(())
        }
        Cmd::Forge => {
            let f = forge_from_env();
            println!("host        {}", f.host);
            println!("oidc issuer {}", f.oidc_issuer);
            if !f.is_public_github() {
                println!(
                    "note        build-provenance availability differs by GitHub \
                     Enterprise Server version; a release publishing a \
                     cosign-signed SHA256SUMS.txt does not depend on it."
                );
            }
            Ok(())
        }
        Cmd::Assets {
            template,
            version,
            available,
            platforms,
        } => {
            let owned: Vec<String> = if platforms.is_empty() {
                asset::DEFAULT_PLATFORMS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                platforms
            };
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let sel = asset::select(&template, &version, &refs, &available)?;
            for (platform, name) in &sel.matched {
                if platform.is_empty() {
                    println!("match  (portable)  {name}");
                } else {
                    println!("match  {platform}  {name}");
                }
            }
            for name in &sel.missing {
                println!("absent {name}");
            }
            // Nothing anywhere is the 2026.08.3 defect: a layer that assembles,
            // signs and publishes while missing a tool it claims to carry.
            if sel.matched.is_empty() {
                anyhow::bail!(
                    "template {template:?} matched no asset on any platform — \
                     the payload would be dropped from a layer that still signs"
                );
            }
            Ok(())
        }
    }
}
