//! `varve` — the PulseEngine toolchain layer manager.
//!
//! v0.1 surface: purely local. `which` answers "which binary would actually
//! run here, and from which layer"; `list` shows the layers present in the
//! core. Both are read-only: selection and reporting never mutate the core
//! (REQ-SCOPE-001), and a pin that does not resolve exactly is an error
//! carrying its fix, never a fallback (REQ-PIN-001).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use varve_core::{Pin, Store, discover, resolve};

#[derive(Parser)]
#[command(
    name = "varve",
    about = "Pinned, signed, dated toolchain bundles — one layer per release",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Which binary would actually run here — and which layer it comes from.
    Which {
        /// Tool name, e.g. `synth`.
        tool: String,
    },
    /// Layers present in the local core.
    List,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let store = Store::at(store_root()?);
    match cli.command {
        Cmd::Which { tool } => which(&store, &tool),
        Cmd::List => list(&store),
    }
}

/// The core root: `$VARVE_ROOT` for tests and unusual setups, `~/.varve`
/// otherwise. Deliberately not configurable from the pin — the pin names a
/// layer, never where layers live.
fn store_root() -> anyhow::Result<PathBuf> {
    if let Some(root) = std::env::var_os("VARVE_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let home = std::env::var_os("HOME").context("HOME is not set and VARVE_ROOT is not set")?;
    Ok(PathBuf::from(home).join(".varve"))
}

fn load_pin() -> anyhow::Result<Pin> {
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    let Some(path) = discover::find_pin(&cwd) else {
        bail!(
            "no varve.toml found walking up from {} — this project has no pinned layer. \
             Create varve.toml next to your rust-toolchain.toml to pin one.",
            cwd.display()
        );
    };
    Ok(Pin::load(&path)?)
}

fn which(store: &Store, tool: &str) -> anyhow::Result<()> {
    let pin = load_pin()?;
    let resolved = resolve(&pin, store)?;
    let Some((_, path)) = resolved.tools.iter().find(|(name, _)| name == tool) else {
        bail!(
            "tool '{tool}' is not part of layer {} as pinned here — the pin exposes: {}",
            resolved.layer.layer,
            resolved
                .tools
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    println!("{}", path.display());
    println!(
        "layer {} ({}) {}",
        resolved.layer.layer, resolved.layer.channel, resolved.layer.digest
    );
    Ok(())
}

fn list(store: &Store) -> anyhow::Result<()> {
    let layers = store.list()?;
    if layers.is_empty() {
        println!("no layers installed in {}", store.root().display());
        return Ok(());
    }
    for entry in layers {
        println!("{}  {}  {}", entry.layer, entry.channel, entry.digest);
    }
    Ok(())
}
