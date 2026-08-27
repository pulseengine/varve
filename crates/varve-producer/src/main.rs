//! `varve-producer` — assemble, sign and publish a layer (REQ-PRODUCER-002).
//!
//! A SEPARATE binary from `varve`, deliberately. `varve` contacts no network,
//! and that claim is load-bearing in `varve docs air-gap` and the threat
//! model; this program fetches releases, verifies signatures over the network
//! and pushes to a registry. Keeping them apart keeps that claim true.

use clap::{Parser, Subcommand};
use varve_producer::{asset, binfmt, forge::Forge};

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
