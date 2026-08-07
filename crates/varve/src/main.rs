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
    /// Resolve this project's pin, fetch, verify against the trust root, and
    /// lay the layer down in the core.
    Install {
        /// Source to fetch from: a directory-shaped archive
        /// (`manifests/` + `blobs/`). The public-registry source lands with
        /// `varve deposit`; until then a source must be given explicitly.
        #[arg(long, value_name = "DIR")]
        from: PathBuf,
    },
    /// Re-verify the pinned layer against its retained signature and the
    /// signed digests — the install-time verdict, repeated offline.
    Verify {
        /// Verify every installed layer instead of only the pinned one.
        #[arg(long)]
        all: bool,
    },
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
        Cmd::Install { from } => install(&store, &from),
        Cmd::Verify { all } => verify(&store, all),
    }
}

/// Load the PulseEngine trust root: `$VARVE_TRUST_ROOT` names a file holding
/// the hex-encoded ed25519 root public key. No trust root, no acceptance —
/// there is deliberately no built-in default while the root ceremony is
/// pending.
fn trust_root() -> anyhow::Result<varve_core::PinnedKeyVerifier> {
    let Some(path) = std::env::var_os("VARVE_TRUST_ROOT") else {
        bail!(
            "no trust root configured — set VARVE_TRUST_ROOT to the file holding the \
             hex-encoded PulseEngine root public key"
        );
    };
    let path = PathBuf::from(path);
    let hex_key = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read trust root {}", path.display()))?;
    let bytes = hex_decode(hex_key.trim())
        .with_context(|| format!("trust root {} is not valid hex", path.display()))?;
    varve_core::PinnedKeyVerifier::from_public_key_bytes(&bytes).map_err(|e| anyhow::anyhow!("{e}"))
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("odd length or non-hex characters");
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked hex"))
        .collect())
}

/// Today, day-resolution, RFC 3339 — sampled once here at the CLI boundary;
/// everything below treats time as data.
fn today_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    let mut days = secs / 86_400;
    // Howard Hinnant's civil_from_days.
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

fn install(store: &Store, from: &std::path::Path) -> anyhow::Result<()> {
    let pin = load_pin()?;
    let verifier = trust_root()?;
    let source = varve_core::DirSource::at(from);
    let mut marks = varve_core::HighWaterMarks::load(store.root())?;
    let now = today_rfc3339();
    let policy = varve_core::InstallPolicy {
        now: &now,
        staleness_threshold_days: 90,
    };
    let outcome = varve_core::install(&pin, &source, &verifier, store, &mut marks, &policy)?;
    println!(
        "installed layer {} (counter {}) {}",
        outcome.layer, outcome.counter, outcome.digest
    );
    if let Some(age) = outcome.staleness_days {
        eprintln!(
            "warning: layer {} was issued {age} days ago — check whether a newer deposit of \
             its line exists",
            outcome.layer
        );
    }
    Ok(())
}

fn verify(store: &Store, all: bool) -> anyhow::Result<()> {
    let verifier = trust_root()?;
    let layers = if all {
        store.list()?
    } else {
        let pin = load_pin()?;
        vec![varve_core::resolve(&pin, store)?.layer]
    };
    if layers.is_empty() {
        bail!("nothing to verify — no layers installed");
    }
    for layer in layers {
        let checked = varve_core::verify_installed(store, &layer, &verifier)?;
        println!(
            "layer {} {} verified: signature OK, {checked} tool(s) match their signed digests",
            layer.layer, layer.digest
        );
    }
    Ok(())
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
