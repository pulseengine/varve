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
        /// Source to fetch from: an OCI registry reference
        /// (`oci://ghcr.io/org/repo`), an oci-layout archive directory, or a
        /// plain `manifests/`+`blobs/` directory.
        #[arg(long, value_name = "SOURCE")]
        from: String,
        /// Override the host platform (target triple) — cross-platform
        /// workflows only; the default is this machine.
        #[arg(long, value_name = "TRIPLE")]
        platform: Option<String>,
    },
    /// Re-verify the pinned layer against its retained signature and the
    /// signed digests — the install-time verdict, repeated offline.
    Verify {
        /// Verify every installed layer instead of only the pinned one.
        #[arg(long)]
        all: bool,
    },
    /// Extract the core: export an installed layer as a directory-shaped
    /// OCI image layout — the offline artifact of record.
    Archive {
        /// Layer to export, e.g. `2026.07.0`.
        layer: String,
        /// Destination directory for the oci-layout.
        dest: PathBuf,
    },
    /// Dispatch a tool from the pinned layer, with the layer identity in the
    /// environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance
    /// tooling can record which qualified set produced the output.
    Run {
        /// One-off layer override — runs another installed layer WITHOUT
        /// touching the checked-in pin.
        #[arg(long, value_name = "LAYER")]
        varve: Option<String>,
        /// Tool and its arguments, after `--`.
        #[arg(trailing_var_arg = true, required = true)]
        tool_and_args: Vec<String>,
    },
    /// (CI) Assemble, sign and publish a layer — the only way a layer comes
    /// into being. Writes the same OCI image layout `archive` produces.
    Deposit {
        /// Layer identifier, e.g. `2026.08.0`.
        #[arg(long)]
        layer: String,
        /// `qualified` or `rolling`.
        #[arg(long)]
        channel: String,
        /// Monotonic per-line release counter — the depositor owns
        /// monotonicity; clients enforce it.
        #[arg(long)]
        counter: u64,
        /// RFC 3339 issued-at timestamp.
        #[arg(long, value_name = "RFC3339")]
        issued_at: String,
        /// File holding the hex-encoded ed25519 root SECRET key.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        /// Key identifier recorded in the signature.
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        /// Destination directory for the oci-layout.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Tool to include, as `name@version=path`. Repeatable.
        #[arg(long = "tool", value_name = "NAME@VERSION=PATH")]
        tools: Vec<String>,
    },
    /// Support window, yank state and known problems for the pinned layer,
    /// from the newest verified line-status document.
    Status {
        /// Ingest a status envelope first: verify, cache (monotonic), then
        /// report. Without it, report from the local cache.
        #[arg(long = "from-file", value_name = "ENVELOPE")]
        from_file: Option<PathBuf>,
    },
    /// (CI) Validate and sign a line-status document into a DSSE envelope.
    SignStatus {
        /// The status document JSON (see docs: line, counter, issued-at,
        /// support-until, yanked, known-problems).
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// File holding the hex-encoded ed25519 root SECRET key.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Shims on PATH: thin dispatchers that resolve the pin from the
    /// invocation's working directory and exec — switching projects is cd.
    #[command(subcommand)]
    Shim(ShimCmd),
    /// Print idempotent shell code putting the shim directory on PATH.
    /// Setup is one line: `eval "$(varve env)"` — or source the env file
    /// `shim install` writes. Never hand-edit PATH.
    Env {
        /// Shell dialect: sh (default, works for bash/zsh) or fish.
        #[arg(long, default_value = "sh")]
        shell: String,
    },
    /// Emit shell completion scripts (zsh, bash, fish, ...).
    Completions { shell: clap_complete::Shell },
    /// (CI) Sign a release SHA256SUMS.txt into the DSSE envelope
    /// `self-verify` consumes — the producing half of DD-009.
    SignSums {
        #[arg(long, value_name = "FILE")]
        sums: PathBuf,
        /// File holding the hex-encoded ed25519 root SECRET key.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Update varve itself: check the latest release, verify it with the
    /// RUNNING binary against the trust root (old-verifies-new), replace
    /// atomically. Explicit act only — varve never phones home.
    SelfUpdate {
        /// Report what is available without changing anything.
        #[arg(long)]
        check: bool,
        /// Install destination (default: the running binary).
        #[arg(long, value_name = "PATH")]
        to: Option<PathBuf>,
    },
    /// Verify a varve release file against its signed SHA256SUMS envelope —
    /// the tool that gates the toolchain clearing its own gate.
    SelfVerify {
        /// The release file to check (e.g. a downloaded varve tar.gz).
        #[arg(long, value_name = "FILE")]
        archive: PathBuf,
        /// The SHA256SUMS.txt.dsse.json envelope from the same release.
        #[arg(long, value_name = "FILE")]
        envelope: PathBuf,
    },
}

#[derive(Subcommand)]
enum ShimCmd {
    /// Write shims for the pinned layer's tools into the shim directory
    /// (`$VARVE_ROOT/shims`). Add that directory to PATH once; each shim
    /// re-resolves the pin on every invocation, exactly like `varve run`.
    Install {
        /// Additional tool names to shim beyond the pinned layer's tools.
        #[arg(long = "tool", value_name = "NAME")]
        extra_tools: Vec<String>,
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
        Cmd::Install { from, platform } => install(&store, &from, platform),
        Cmd::Verify { all } => verify(&store, all),
        Cmd::Archive { layer, dest } => archive(&store, &layer, &dest),
        Cmd::Run {
            varve,
            tool_and_args,
        } => run_tool(&store, varve.as_deref(), &tool_and_args),
        Cmd::Deposit {
            layer,
            channel,
            counter,
            issued_at,
            key,
            key_id,
            out,
            tools,
        } => deposit_cmd(
            &layer, &channel, counter, &issued_at, &key, &key_id, &out, &tools,
        ),
        Cmd::Status { from_file } => status(&store, from_file.as_deref()),
        Cmd::SignStatus {
            file,
            key,
            key_id,
            out,
        } => sign_status(&file, &key, &key_id, &out),
        Cmd::Shim(ShimCmd::Install { extra_tools }) => shim_install(&store, &extra_tools),
        Cmd::Env { shell } => print_env(&store, &shell),
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut Cli::command(), "varve", &mut std::io::stdout());
            Ok(())
        }
        Cmd::SignSums {
            sums,
            key,
            key_id,
            out,
        } => sign_sums(&sums, &key, &key_id, &out),
        Cmd::SelfUpdate { check, to } => self_update(check, to.as_deref()),
        Cmd::SelfVerify { archive, envelope } => self_verify(&archive, &envelope),
    }
}

/// The idempotent sh fragment for a shim dir; the guard keeps repeated
/// evaluation (login shells, nested shells) from stacking PATH entries.
fn env_script_sh(shim_dir: &std::path::Path) -> String {
    format!(
        "case \":$PATH:\" in\n  *:\"{dir}\":*) ;;\n  *) export PATH=\"{dir}:$PATH\" ;;\nesac\n",
        dir = shim_dir.display()
    )
}

fn print_env(store: &Store, shell: &str) -> anyhow::Result<()> {
    let shim_dir = store.root().join("shims");
    match shell {
        "sh" | "bash" | "zsh" => print!("{}", env_script_sh(&shim_dir)),
        "fish" => println!(
            "if not contains \"{dir}\" $PATH\n    set -gx PATH \"{dir}\" $PATH\nend",
            dir = shim_dir.display()
        ),
        other => bail!("unknown shell '{other}' — supported: sh, bash, zsh, fish"),
    }
    Ok(())
}

fn shim_install(store: &Store, extra_tools: &[String]) -> anyhow::Result<()> {
    // Tool names come from the currently-pinned layer (plus explicit
    // extras); the names are only entry points — every invocation
    // re-resolves the pin from its own working directory.
    let pin = load_pin()?;
    let resolved = resolve(&pin, store)?;
    let mut names: Vec<String> = resolved.tools.iter().map(|(n, _)| n.clone()).collect();
    names.extend(extra_tools.iter().cloned());
    names.sort();
    names.dedup();
    if names.contains(&"varve".to_string()) {
        bail!("refusing to shim 'varve' itself — a shim that resolves through itself recurses");
    }

    let varve_exe = std::env::current_exe().context("cannot locate the varve binary")?;
    let shim_dir = store.root().join("shims");
    std::fs::create_dir_all(&shim_dir)
        .with_context(|| format!("cannot create {}", shim_dir.display()))?;
    for name in &names {
        let path = shim_dir.join(name);
        let script = format!(
            "#!/bin/sh\n# varve shim: resolves this project's pin on every invocation.\nexec \"{}\" run -- {name} \"$@\"\n",
            varve_exe.display()
        );
        std::fs::write(&path, script)
            .with_context(|| format!("cannot write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    // The sourceable environment, rustup-style: one line in the shell
    // config sets everything up, and re-sourcing never stacks PATH.
    let env_file = store.root().join("env");
    std::fs::write(&env_file, env_script_sh(&shim_dir))
        .with_context(|| format!("cannot write {}", env_file.display()))?;
    println!(
        "installed {} shim(s) in {} — switching projects is cd\n\nadd ONE line to your shell config:\n  . \"{}\"        # or: eval \"$(varve env)\"",
        names.len(),
        shim_dir.display(),
        env_file.display()
    );
    Ok(())
}

fn sign_sums(
    sums: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(sums).with_context(|| format!("cannot read {}", sums.display()))?;
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    let sk = hex_decode(hex_key.trim()).context("signing key is not valid hex")?;
    let envelope = varve_core::sign_release_sums(&bytes, &sk, key_id)?;
    std::fs::write(out, envelope).with_context(|| format!("cannot write {}", out.display()))?;
    println!("signed release sums -> {}", out.display());
    Ok(())
}

fn status(store: &Store, from_file: Option<&std::path::Path>) -> anyhow::Result<()> {
    let pin = load_pin()?;
    let root_pk = trust_root_bytes()?;
    let line = pin.layer.line().clone();
    let cache = varve_core::StatusCache::at_root(store.root());

    if let Some(path) = from_file {
        let envelope = std::fs::read(path)
            .with_context(|| format!("cannot read status envelope {}", path.display()))?;
        let doc = varve_core::LineStatus::verify_and_parse(&envelope, &root_pk)?;
        if doc.line != line.to_string() {
            bail!(
                "status document covers line {} but this project pins line {line}",
                doc.line
            );
        }
        cache.update(&line, &envelope, &doc)?;
    }

    let Some(doc) = cache.load(&line, &root_pk)? else {
        bail!(
            "no line-status document cached for line {line} — ingest one with `varve status --from-file <envelope>`"
        );
    };
    let report = doc.report_for(&pin.layer);
    println!(
        "layer {} (line {line}, status document #{})",
        pin.layer, doc.counter
    );
    match &report.yanked_reason {
        Some(reason) => println!("  YANKED: {reason}"),
        None => println!("  not yanked"),
    }
    match &report.support_until {
        Some(until) => println!("  supported until {until}"),
        None => println!("  no stated support window"),
    }
    println!(
        "  {} known problem(s) affect this layer, {} with workarounds",
        report.problems_total, report.problems_with_workaround
    );
    Ok(())
}

fn sign_status(
    file: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(file)
        .with_context(|| format!("cannot read status document {}", file.display()))?;
    // Validate through the typed model before signing: CI must not be able
    // to sign a malformed advisory.
    let doc: varve_core::LineStatus =
        serde_json::from_slice(&bytes).context("status document does not match the schema")?;
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    let sk = hex_decode(hex_key.trim()).context("signing key is not valid hex")?;
    let envelope = doc.sign(&sk, key_id)?;
    std::fs::write(out, envelope)
        .with_context(|| format!("cannot write envelope {}", out.display()))?;
    println!(
        "signed line-status #{} for line {} -> {}",
        doc.counter,
        doc.line,
        out.display()
    );
    Ok(())
}

fn self_update(check: bool, to: Option<&std::path::Path>) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    // The API endpoint decides AVAILABILITY only; acceptance is the signed
    // sums against the pinned root. Overridable for mirrors and tests.
    let api = std::env::var("VARVE_UPDATE_API").unwrap_or_else(|_| {
        "https://api.github.com/repos/pulseengine/varve/releases/latest".to_string()
    });
    let platform = varve_core::host_platform();
    let Some(plan) = varve_core::update::check_latest(&api, current, &platform)? else {
        println!("varve {current} is current");
        return Ok(());
    };
    if check {
        println!(
            "varve {current} installed; {} available — run `varve self-update` to install (verified)",
            plan.latest
        );
        return Ok(());
    }
    let root_pk = trust_root_bytes()?;
    let dest = match to {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe().context("cannot locate the running varve binary")?,
    };
    let digest = varve_core::update::perform(&plan, &root_pk, &dest)?;
    println!(
        "varve {current} -> {} installed at {} ({digest})",
        plan.latest,
        dest.display()
    );
    Ok(())
}

fn self_verify(archive: &std::path::Path, envelope: &std::path::Path) -> anyhow::Result<()> {
    let root_pk = trust_root_bytes()?;
    let name = archive
        .file_name()
        .context("archive path has no file name")?
        .to_string_lossy();
    let bytes =
        std::fs::read(archive).with_context(|| format!("cannot read {}", archive.display()))?;
    let env_bytes =
        std::fs::read(envelope).with_context(|| format!("cannot read {}", envelope.display()))?;
    let digest = varve_core::verify_release_file(&name, &bytes, &env_bytes, &root_pk)?;
    println!("{name} verified against the signed release sums ({digest})");
    Ok(())
}

fn run_tool(
    store: &Store,
    override_layer: Option<&str>,
    tool_and_args: &[String],
) -> anyhow::Result<()> {
    let (tool, args) = tool_and_args
        .split_first()
        .context("no tool named — usage: varve run [--varve LAYER] -- <tool> [args…]")?;
    let mut pin = load_pin()?;
    if let Some(layer) = override_layer {
        // A one-off: resolve another layer for this invocation only. The
        // checked-in pin is not read past this point and never written.
        pin.layer = layer.parse()?;
        pin.digest = None;
    }
    let resolved = resolve(&pin, store)?;
    let Some((_, path)) = resolved.tools.iter().find(|(name, _)| name == tool) else {
        bail!(
            "tool '{tool}' is not part of layer {} — it exposes: {}",
            resolved.layer.layer,
            resolved
                .tools
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    let mut cmd = std::process::Command::new(path);
    cmd.args(args)
        .env("VARVE_LAYER", resolved.layer.layer.to_string())
        .env("VARVE_LAYER_MANIFEST_DIGEST", &resolved.layer.digest);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec: varve leaves the picture entirely; the tool IS the process.
        Err(anyhow::Error::from(cmd.exec()).context(format!("failed to exec {tool}")))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to run {tool}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[allow(clippy::too_many_arguments)]
fn deposit_cmd(
    layer: &str,
    channel: &str,
    counter: u64,
    issued_at: &str,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    tools: &[String],
) -> anyhow::Result<()> {
    let mut deposit_tools = Vec::new();
    for spec in tools {
        let (name_version, path) = spec
            .split_once('=')
            .with_context(|| format!("--tool '{spec}' is not NAME@VERSION=PATH"))?;
        // NAME@VERSION[@PLATFORM]=PATH — platform optional for
        // platform-independent entries; new deposits should stamp it.
        let mut parts = name_version.split('@');
        let name = parts.next().unwrap_or_default();
        let version = parts
            .next()
            .with_context(|| format!("--tool '{spec}' is not NAME@VERSION[@PLATFORM]=PATH"))?;
        let platform = parts.next();
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read tool binary {path}"))?;
        deposit_tools.push(varve_core::DepositTool {
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.map(str::to_string),
            bytes,
        });
    }
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    let sk = hex_decode(hex_key.trim()).context("signing key is not valid hex")?;
    let spec = varve_core::DepositSpec {
        layer: layer.parse()?,
        channel: channel.to_string(),
        counter,
        issued_at: issued_at.to_string(),
        tools: deposit_tools,
    };
    let outcome = varve_core::deposit(&spec, &sk, key_id, out)?;
    println!(
        "deposited layer {} (counter {}) {} at {}",
        outcome.layer,
        outcome.counter,
        outcome.digest,
        out.display()
    );
    Ok(())
}

fn archive(store: &Store, layer: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    let wanted: varve_core::LayerId = layer.parse()?;
    let matching: Vec<_> = store
        .list()?
        .into_iter()
        .filter(|entry| entry.layer == wanted)
        .collect();
    let entry = match matching.len() {
        0 => bail!(
            "layer {layer} is not installed — run `varve install` in a project pinning it, then archive"
        ),
        1 => matching.into_iter().next().expect("len checked"),
        n => bail!(
            "layer {layer} is installed {n} times under different digests — archive by digest is \
             not supported yet; clean up the core first"
        ),
    };
    varve_core::export_archive(store, &entry, dest)?;
    println!(
        "archived layer {} {} as oci-layout at {}",
        entry.layer,
        entry.digest,
        dest.display()
    );
    Ok(())
}

/// Load the PulseEngine trust root: `$VARVE_TRUST_ROOT` names a file holding
/// the hex-encoded ed25519 root public key. No trust root, no acceptance —
/// there is deliberately no built-in default while the root ceremony is
/// pending.
fn trust_root() -> anyhow::Result<varve_core::PinnedKeyVerifier> {
    varve_core::PinnedKeyVerifier::from_public_key_bytes(&trust_root_bytes()?)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn trust_root_bytes() -> anyhow::Result<Vec<u8>> {
    let Some(path) = std::env::var_os("VARVE_TRUST_ROOT") else {
        bail!(
            "no trust root configured — set VARVE_TRUST_ROOT to the file holding the \
             hex-encoded PulseEngine root public key"
        );
    };
    let path = PathBuf::from(path);
    let hex_key = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read trust root {}", path.display()))?;
    hex_decode(hex_key.trim())
        .with_context(|| format!("trust root {} is not valid hex", path.display()))
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

fn install(store: &Store, from: &str, platform: Option<String>) -> anyhow::Result<()> {
    let platform = platform.unwrap_or_else(varve_core::host_platform);
    let pin = load_pin()?;
    let verifier = trust_root()?;
    // Auto-detect the source shape: an oci:// registry reference, a standard
    // OCI image layout (the `varve archive`/`deposit` output), or the plain
    // manifests/+blobs/ directory. Either way the same pipeline and the same
    // trust root decide — the source shape changes availability, never
    // acceptance.
    let source: Box<dyn varve_core::LayerSource> =
        if from.starts_with("oci://") || from.starts_with("oci+http://") {
            Box::new(varve_core::RegistrySource::parse(from)?)
        } else {
            let path = std::path::Path::new(from);
            if path.join("oci-layout").is_file() {
                Box::new(varve_core::OciLayoutSource::at(path))
            } else {
                Box::new(varve_core::DirSource::at(path))
            }
        };
    let source = &*source;
    let mut marks = varve_core::HighWaterMarks::load(store.root())?;
    let now = today_rfc3339();
    let policy = varve_core::InstallPolicy {
        now: &now,
        staleness_threshold_days: 90,
        platform: &platform,
    };
    let outcome = varve_core::install(&pin, source, &verifier, store, &mut marks, &policy)?;
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
        let checked =
            varve_core::verify_installed(store, &layer, &verifier, &varve_core::host_platform())?;
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
