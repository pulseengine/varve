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

mod docs;

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
        /// plain `manifests/`+`blobs/` directory. Defaults to the pinned
        /// realm's registry when the pin names one.
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
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
        /// Also check a committed export directory against the current pin: its
        /// `.varve-export.json` stamp must name the layer the pin resolves to,
        /// or verify fails (REQ-EXPORT-SYNC-001). Repeatable; run it in CI so a
        /// stale vendored tree cannot slip through.
        #[arg(long = "export", value_name = "DIR")]
        export: Vec<PathBuf>,
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
        /// Tool and its arguments, after `--`. `OsString`, so an argument
        /// that is not valid UTF-8 reaches the tool byte-for-byte instead of
        /// being lossily rewritten (unix arguments are arbitrary bytes).
        #[arg(trailing_var_arg = true, required = true)]
        tool_and_args: Vec<std::ffi::OsString>,
    },
    /// (CI) Assemble, sign and publish a layer — the only way a layer comes
    /// into being. Writes the same OCI image layout `archive` produces.
    Deposit {
        /// Deposit spec file (TOML: layer/channel/counter + [[tool]] with
        /// source provenance). Alternative to the individual flags below.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["layer", "channel", "counter", "tools"])]
        spec: Option<PathBuf>,
        /// Layer identifier, e.g. `2026.08.0`.
        #[arg(long, required_unless_present = "spec")]
        layer: Option<String>,
        /// `qualified` or `rolling`.
        #[arg(long, required_unless_present = "spec")]
        channel: Option<String>,
        /// Monotonic per-line release counter — the depositor owns
        /// monotonicity; clients enforce it.
        #[arg(long, required_unless_present = "spec")]
        counter: Option<u64>,
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
    /// Compile a Bazel checksum registry (rules_wasm_component schema) from
    /// a verified installed layer — every hash Bazel enforces becomes a
    /// transcription from the signed manifest instead of TOFU.
    ExportBazel {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output directory for the per-tool JSON registries.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Materialise a Cargo local registry from the layer's verified `crate`
    /// entries + a `.cargo/config.toml` source-replacement, so a consumer
    /// builds offline against varve-signed crates (REQ-CRATE-001).
    ExportCargo {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output directory (holds `registry/` and `.cargo/config.toml`).
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Materialise a `cargo vendor`-shaped directory from the layer's verified
    /// `crate` entries — consumed offline by bare Cargo and Corrosion
    /// (REQ-VENDOR-001). rules_rust needs BUILD files on top of this tree
    /// (REQ-VENDOR-002), not yet emitted.
    ExportCratesVendor {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output directory (holds `vendor/` and `.cargo/config.toml`).
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Materialise a Bazel distdir of the layer's verified `.crate` tarballs
    /// (REQ-VENDOR-002, air-gap rules_rust). Build with a pre-generated
    /// crate_universe output + `bazel build --distdir=<DIR>` (network off) —
    /// each crate resolves from varve's verified bytes by sha256.
    ExportBazelDistdir {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output distdir directory.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Emit an SBOM for a verified layer, transcribed from its SIGNED manifest
    /// rather than scanned from disk — every component, version and hash is
    /// copied from what the trust root anchored (REQ-SBOM-001). Answers "which
    /// components are in this product" for CRA Art. 13(5) due diligence.
    Sbom {
        /// Layer to describe, e.g. `2026.08.0`. Defaults to the resolved pin.
        #[arg(long)]
        layer: Option<String>,
        /// Document format (currently `cyclonedx`).
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        /// Write here instead of stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
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
    /// (CI) Attach a signed line-status envelope to a deposit layout as its
    /// baseline, so `varve status` works after an offline install and the
    /// registry can carry it (REQ-STATUS-DIST-001).
    AttachStatus {
        /// The oci-layout directory produced by `varve deposit`.
        #[arg(long, value_name = "DIR")]
        layout: PathBuf,
        /// The signed line-status DSSE envelope (from `varve sign-status`).
        #[arg(long, value_name = "ENVELOPE")]
        status: PathBuf,
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
    /// Embedded, queryable documentation (offline). `varve docs` lists topics;
    /// `varve docs <topic>` shows one; `varve docs check --coverage` asserts
    /// every subcommand is documented (REQ-DOCS-001).
    Docs {
        /// A topic slug to show, or `check` to run the coverage invariant.
        topic: Option<String>,
        /// List all topics.
        #[arg(long)]
        list: bool,
        /// Search across all topics.
        #[arg(long, value_name = "QUERY")]
        grep: Option<String>,
        /// (check) Report subcommands lacking a documented topic.
        #[arg(long)]
        coverage: bool,
        /// (check --coverage) Exit non-zero if any subcommand is undocumented.
        #[arg(long)]
        strict: bool,
        /// Output format: `text` (default) or `json` for machine queries —
        /// applies to the topic list and to a single `varve docs <topic>`.
        #[arg(long, value_name = "FMT", default_value = "text")]
        format: String,
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

/// The tool this process was invoked AS, if it is not varve itself
/// (REQ-SHIM-002 — the rustup pattern). A shim is a link to this very binary,
/// so `argv[0]` carries the tool name and no shell ever runs.
///
/// `argv[0]` is caller-controlled, so it is validated here rather than trusted:
/// only the file name is considered, it must be non-empty, must not be a path
/// traversal, and must contain no separators. Even then it merely NAMES a tool;
/// dispatch still resolves the pin and can only reach tools that layer exposes.
fn dispatch_tool_name(argv0: Option<&std::ffi::OsStr>) -> Option<String> {
    let raw = argv0?;
    let name = std::path::Path::new(raw).file_name()?.to_str()?;
    let name = name.strip_suffix(".exe").unwrap_or(name);
    if name.is_empty() || name == "varve" || name == ".." || name == "." {
        return None;
    }
    if name.contains('/') || name.contains('\\') {
        return None;
    }
    Some(name.to_string())
}

fn run() -> anyhow::Result<()> {
    // Invoked under another name? Then this binary IS the shim: dispatch.
    let mut args = std::env::args_os();
    let argv0 = args.next();
    if let Some(tool) = dispatch_tool_name(argv0.as_deref()) {
        let store = Store::at(store_root()?);
        // Arguments pass through as OsString: a shim must hand the tool the
        // exact bytes the caller typed, and unix arguments are arbitrary bytes.
        let rest: Vec<std::ffi::OsString> = args.collect();
        return run_tool(&store, None, &tool, &rest);
    }
    let cli = Cli::parse();
    let store = Store::at(store_root()?);
    match cli.command {
        Cmd::Which { tool } => which(&store, &tool),
        Cmd::List => list(&store),
        Cmd::Install { from, platform } => install(&store, from.as_deref(), platform),
        Cmd::Verify { all, export } => verify(&store, all, &export),
        Cmd::Archive { layer, dest } => archive(&store, &layer, &dest),
        Cmd::Run {
            varve,
            tool_and_args,
        } => {
            let (tool, args) = tool_and_args
                .split_first()
                .context("no tool named — usage: varve run [--varve LAYER] -- <tool> [args…]")?;
            let tool = tool
                .to_str()
                .context("tool name must be valid UTF-8 — it names an entry in the layer")?;
            run_tool(&store, varve.as_deref(), tool, args)
        }
        Cmd::Deposit {
            spec,
            layer,
            channel,
            counter,
            issued_at,
            key,
            key_id,
            out,
            tools,
        } => deposit_cmd(
            spec.as_deref(),
            layer.as_deref(),
            channel.as_deref(),
            counter,
            &issued_at,
            &key,
            &key_id,
            &out,
            &tools,
        ),
        Cmd::ExportBazel { layer, out } => export_bazel(&store, layer.as_deref(), &out),
        Cmd::ExportCargo { layer, out } => export_cargo(&store, layer.as_deref(), &out),
        Cmd::ExportCratesVendor { layer, out } => {
            export_crates_vendor(&store, layer.as_deref(), &out)
        }
        Cmd::ExportBazelDistdir { layer, out } => {
            export_bazel_distdir(&store, layer.as_deref(), &out)
        }
        Cmd::Sbom { layer, format, out } => {
            sbom_cmd(&store, layer.as_deref(), &format, out.as_deref())
        }
        Cmd::Status { from_file } => status(&store, from_file.as_deref()),
        Cmd::SignStatus {
            file,
            key,
            key_id,
            out,
        } => sign_status(&file, &key, &key_id, &out),
        Cmd::AttachStatus { layout, status } => attach_status(&layout, &status),
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
        Cmd::Docs {
            topic,
            list,
            grep,
            coverage,
            strict,
            format,
        } => docs_cmd(
            topic.as_deref(),
            list,
            grep.as_deref(),
            coverage,
            strict,
            &format,
        ),
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
    // re-resolves the pin (and its realm) from its own working directory,
    // so ONE shim directory serves every realm.
    let ctx = project_ctx(store)?;
    let resolved = resolve(&ctx.pin, &ctx.store)?;
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
    // A shim IS varve, reached under another name (REQ-SHIM-002): no shell on
    // the dispatch path, and no string handed to a parser. On unix a symlink,
    // so shims keep pointing at whatever varve currently is — `self-update`
    // cannot leave them stale. On Windows, a copy (no symlink guarantee).
    for name in &names {
        let path = shim_dir.join(name);
        // Replace any earlier shim, script or link alike.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("cannot replace {}", path.display()));
            }
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&varve_exe, &path).with_context(|| {
            format!("cannot link {} -> {}", path.display(), varve_exe.display())
        })?;
        #[cfg(not(unix))]
        std::fs::copy(&varve_exe, &path)
            .with_context(|| format!("cannot copy varve to {}", path.display()))?;
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
    let ctx = project_ctx(store)?;
    let pin = &ctx.pin;
    let root_pk = ctx_root_bytes(&ctx)?;
    let line = pin.layer.line().clone();
    let cache = varve_core::StatusCache::at_root(ctx.store.root());

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
            "no line-status document cached for line {line}.\n\
             \n\
             Line-status carries the support window, known problems, and yank state \
             for the line. `varve install` caches it automatically when the installed \
             layer's oci-layout carries one; otherwise ingest a signed envelope \
             explicitly:\n\
             \n    varve status --from-file <line-status.dsse.json>\n\
             \n\
             Distribution of line-status via the registry is tracked in \
             REQ-STATUS-DIST-001 (pulseengine/varve#34)."
        );
    };
    // Defense in depth: a cached doc is keyed and signed, but assert its own
    // line field agrees with the pin — the same guard the --from-file path
    // applies, so all three cache paths are consistent.
    if doc.line != line.to_string() {
        bail!(
            "cached status document covers line {} but this project pins line {line}",
            doc.line
        );
    }
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

fn attach_status(layout: &std::path::Path, status: &std::path::Path) -> anyhow::Result<()> {
    let envelope = std::fs::read(status)
        .with_context(|| format!("cannot read status envelope {}", status.display()))?;
    let (line, counter) = varve_core::attach_status_envelope_to_layout(layout, &envelope)?;
    println!(
        "attached baseline line-status #{counter} for line {line} to {}",
        layout.display()
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
    let dest = match to {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe().context("cannot locate the running varve binary")?,
    };
    // Decide on ARTIFACT IDENTITY, not the self-reported version string: a
    // binary that mis-reports its own version (varve#38) must not loop forever
    // re-installing identical bytes. resolve_update fetches and verifies the
    // candidate against the trust root, then compares it to what is on disk.
    let on_disk = std::fs::read(&dest).ok();
    // A first cheap check: if the API isn't even newer by version, skip the
    // trust-root requirement entirely so an up-to-date `--check` stays root-free.
    if varve_core::update::check_latest(&api, current, &platform)?.is_none() {
        println!("varve {current} is current");
        return Ok(());
    }
    let root_pk = trust_root_bytes().context(
        "self-update needs the trust root to confirm a verified update — set VARVE_TRUST_ROOT \
         or pin a realm",
    )?;
    match varve_core::update::resolve_update(
        &api,
        current,
        &platform,
        on_disk.as_deref(),
        &root_pk,
    )? {
        varve_core::update::UpdateDecision::UpToDate => {
            println!("varve {current} is current");
        }
        varve_core::update::UpdateDecision::AlreadyCurrent { latest } => {
            println!(
                "varve is already the latest release bytes ({latest}); the reported version \
                 {current} is stale but the binary is current — nothing to do"
            );
        }
        varve_core::update::UpdateDecision::Available {
            plan,
            binary,
            digest,
        } => {
            if check {
                println!(
                    "varve {current} installed; {} available — run `varve self-update` to install \
                     (verified)",
                    plan.latest
                );
            } else {
                varve_core::update::install_binary(&binary, &dest)?;
                println!(
                    "varve {current} -> {} installed at {} ({digest})",
                    plan.latest,
                    dest.display()
                );
            }
        }
    }
    Ok(())
}

fn docs_cmd(
    topic: Option<&str>,
    list: bool,
    grep: Option<&str>,
    coverage: bool,
    strict: bool,
    format: &str,
) -> anyhow::Result<()> {
    use clap::CommandFactory;
    let json = match format {
        "text" => false,
        "json" => true,
        other => bail!("unknown --format '{other}' (expected `text` or `json`)"),
    };
    // `varve docs check --coverage` (or --coverage) — the mechanical invariant.
    if coverage || topic == Some("check") {
        let gaps = docs::coverage_gaps(&Cli::command());
        if gaps.is_empty() {
            println!(
                "docs coverage: OK — all {} subcommands have a topic",
                Cli::command().get_subcommands().count()
            );
            return Ok(());
        }
        eprintln!("docs coverage: {} subcommand(s) undocumented:", gaps.len());
        for g in &gaps {
            eprintln!("  {g}");
        }
        if strict {
            bail!(
                "undocumented subcommands (REQ-DOCS-001): {}",
                gaps.join(", ")
            );
        }
        return Ok(());
    }
    if let Some(q) = grep {
        let hits = docs::grep(q);
        if hits.is_empty() {
            println!("no topic matches '{q}'");
        }
        for (slug, line) in hits {
            println!("{slug}: {line}");
        }
        return Ok(());
    }
    if list || topic.is_none() {
        if json {
            println!("{}", docs::render_json(None));
        } else {
            print!("{}", docs::render_list());
        }
        return Ok(());
    }
    let slug = topic.unwrap();
    match docs::find(slug) {
        Some(_) if json => println!("{}", docs::render_json(Some(slug))),
        Some(t) => println!("{}", t.body.trim_end()),
        None => {
            eprintln!("no topic '{slug}'.\n");
            print!("{}", docs::render_list());
            bail!("unknown topic: {slug}");
        }
    }
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
    tool: &str,
    args: &[std::ffi::OsString],
) -> anyhow::Result<()> {
    let ctx = project_ctx(store)?;
    let mut pin = ctx.pin;
    if let Some(layer) = override_layer {
        // A one-off: resolve another layer for this invocation only. The
        // checked-in pin is not read past this point and never written.
        pin.layer = layer.parse()?;
        pin.digest = None;
    }
    let resolved = resolve(&pin, &ctx.store)?;
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
    // Runnered entries (portable wasm) execute through their runner — from
    // the SAME verified layer, never from PATH (REQ-RUNNER-001).
    let mut cmd = if let Some(contract) = resolved.runners.get(tool) {
        let Some((_, runner_path)) = resolved.tools.iter().find(|(n, _)| n == &contract.tool)
        else {
            bail!(
                "tool '{tool}' runs via '{runner}' but the layer does not expose it — refusing",
                runner = contract.tool
            );
        };
        let mut cmd = std::process::Command::new(runner_path);
        cmd.args(&contract.args).arg(path);
        for arg in args {
            if let Some(prefix) = &contract.arg_prefix {
                cmd.arg(prefix);
            }
            cmd.arg(arg);
        }
        cmd
    } else {
        let mut cmd = std::process::Command::new(path);
        cmd.args(args);
        cmd
    };
    cmd.env("VARVE_LAYER", resolved.layer.layer.to_string())
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

/// Resolve which installed layer an export targets, and verify it (trust
/// first: never export from an unverifiable layer). `layer` names one
/// explicitly; `None` defaults to the resolved project pin, so an export with
/// no `--layer` tracks the pin (REQ-EXPORT-SYNC-001). Returns the store the
/// layer lives in (realm-aware on the pin path) and the verified entry.
fn export_target(
    base: &Store,
    layer: Option<&str>,
) -> anyhow::Result<(Store, varve_core::store::InstalledLayer)> {
    match layer {
        Some(l) => {
            let verifier = trust_root()?;
            let wanted: varve_core::LayerId = l.parse()?;
            let entry = base
                .list()?
                .into_iter()
                .find(|e| e.layer == wanted)
                .with_context(|| format!("layer {l} is not installed — varve install it first"))?;
            varve_core::verify_installed(base, &entry, &verifier, &varve_core::host_platform())?;
            Ok((base.clone(), entry))
        }
        None => {
            let ctx = project_ctx(base)?;
            let verifier = ctx_verifier(&ctx)?;
            let resolved = varve_core::resolve(&ctx.pin, &ctx.store)?;
            varve_core::verify_installed(
                &ctx.store,
                &resolved.layer,
                &verifier,
                &varve_core::host_platform(),
            )?;
            Ok((ctx.store, resolved.layer))
        }
    }
}

/// Bind an export directory to the layer that produced it: write a
/// `.varve-export.json` stamp (REQ-EXPORT-SYNC-001) so `varve verify --export`
/// can later catch a stale export whose pin has moved on.
fn write_export_stamp(
    out: &std::path::Path,
    entry: &varve_core::store::InstalledLayer,
    kind: &str,
) -> anyhow::Result<()> {
    let stamp = varve_core::exportstamp::ExportStamp {
        layer: entry.layer.to_string(),
        manifest_digest: entry.digest.clone(),
        kind: kind.to_string(),
    };
    varve_core::exportstamp::write_stamp(out, &stamp)?;
    println!(
        "stamped {} — export bound to layer {} ({}); `varve verify --export {}` checks it",
        out.join(varve_core::exportstamp::STAMP_FILE).display(),
        entry.layer,
        entry.digest,
        out.display(),
    );
    Ok(())
}

fn export_bazel(store: &Store, layer: Option<&str>, out: &std::path::Path) -> anyhow::Result<()> {
    let (_store, entry) = export_target(store, layer)?;
    let payload = std::fs::read(entry.root.join("layer.json"))?;
    let manifest = varve_core::LayerManifest::parse(&payload)?;
    let export = varve_core::bazel::export(&manifest);
    std::fs::create_dir_all(out)?;
    for (tool, json) in &export.registries {
        let path = out.join(format!("{tool}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(json)?)?;
        println!("wrote {}", path.display());
    }
    for (tool, platform, reason) in &export.skipped {
        eprintln!("skipped {tool} ({platform}): {reason}");
    }
    if export.registries.is_empty() {
        bail!(
            "nothing exported — no entry in layer {} carries source provenance",
            entry.layer
        );
    }
    write_export_stamp(out, &entry, "bazel-registry")?;
    Ok(())
}

/// Collect the verified `crate`-kind entries of an already-verified installed
/// layer as CrateEntry values — the shared front-half of every Cargo-facing
/// export. The layer was verified by `export_target`; each blob is still
/// re-hashed against its signed digest before it can leave the store.
fn collect_verified_crates(
    store: &Store,
    entry: &varve_core::store::InstalledLayer,
) -> anyhow::Result<Vec<varve_core::crateexport::CrateEntry>> {
    let payload = std::fs::read(entry.root.join("layer.json"))?;
    let manifest = varve_core::LayerManifest::parse(&payload)?;

    let mut crates = Vec::new();
    for e in &manifest.entries {
        if e.kind().map_err(|err| anyhow::anyhow!(err.to_string()))?
            != varve_core::PayloadKind::Crate
        {
            continue;
        }
        let name = e
            .annotations
            .get("eu.pulseengine.tool")
            .context("crate entry missing its name annotation")?;
        let version = e
            .annotations
            .get("eu.pulseengine.tool.version")
            .context("crate entry missing its version annotation")?;
        let cksum = e
            .digest
            .strip_prefix("sha256:")
            .with_context(|| format!("crate '{name}' digest is not sha256:<hex>"))?
            .to_string();
        let bytes_path = store
            .tool_path(entry, name)
            .with_context(|| format!("crate '{name}' blob is not present in the store"))?;
        let bytes = std::fs::read(&bytes_path)?;
        // Defense in depth: re-hash the on-disk bytes against the signed digest
        // ourselves, regardless of platform filtering, so what we export is the
        // exact bytes the trust root anchored.
        if varve_core::manifest_digest(&bytes) != e.digest {
            bail!(
                "crate '{name}' on-disk bytes do not match the signed digest {}",
                e.digest
            );
        }
        crates.push(varve_core::crateexport::CrateEntry {
            name: name.clone(),
            version: version.clone(),
            cksum,
            bytes,
        });
    }
    if crates.is_empty() {
        bail!(
            "nothing exported — layer {} carries no `crate` entries",
            entry.layer
        );
    }
    Ok(crates)
}

fn sbom_cmd(
    store: &Store,
    layer: Option<&str>,
    format: &str,
    out: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let format: varve_core::sbom::SbomFormat =
        format.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    // Trust first: an SBOM for a layer we cannot verify would describe bytes
    // nobody vouched for — worse than none, because it looks authoritative.
    let (_store, entry) = export_target(store, layer)?;
    let payload = std::fs::read(entry.root.join("layer.json"))?;
    let manifest = varve_core::LayerManifest::parse(&payload)?;
    let doc = varve_core::sbom::emit(&manifest, &entry.digest, format);
    match out {
        Some(path) => {
            std::fs::write(path, &doc)
                .with_context(|| format!("cannot write {}", path.display()))?;
            // Count what was WRITTEN, from the document itself — not what we
            // expected to write. A count taken from the input can disagree
            // with the file just produced, which is exactly the kind of small
            // lie an SBOM must not tell.
            let written = serde_json::from_str::<serde_json::Value>(&doc)
                .ok()
                .and_then(|v| v["components"].as_array().map(|a| a.len()))
                .unwrap_or_default();
            println!(
                "wrote an SBOM for layer {} ({written} component(s), from {} signed entries) to \
                 {} — transcribed from the signed manifest, not scanned",
                entry.layer,
                manifest.entries.len(),
                path.display()
            );
        }
        None => println!("{doc}"),
    }
    Ok(())
}

fn export_cargo(store: &Store, layer: Option<&str>, out: &std::path::Path) -> anyhow::Result<()> {
    let (store, entry) = export_target(store, layer)?;
    let crates = collect_verified_crates(&store, &entry)?;
    let registry_dir = out.join("registry");
    let n = varve_core::crateexport::export_local_registry(&crates, &registry_dir)?;
    let cargo_dir = out.join(".cargo");
    std::fs::create_dir_all(&cargo_dir)?;
    let config = cargo_dir.join("config.toml");
    std::fs::write(
        &config,
        varve_core::crateexport::cargo_config_toml(&registry_dir),
    )?;
    println!(
        "exported {n} verified crate(s) to a local registry at {} — copy {} into \
         .cargo/config.toml and `cargo build --offline`",
        registry_dir.display(),
        config.display()
    );
    write_export_stamp(out, &entry, "cargo")?;
    Ok(())
}

fn export_bazel_distdir(
    store: &Store,
    layer: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let (store, entry) = export_target(store, layer)?;
    let crates = collect_verified_crates(&store, &entry)?;
    let n = varve_core::crateexport::export_distdir(&crates, out)?;
    println!(
        "wrote {n} verified .crate tarball(s) to the Bazel distdir {} — with a pre-generated \
         crate_universe output, `bazel build --distdir={}` resolves them offline by sha256",
        out.display(),
        out.display()
    );
    write_export_stamp(out, &entry, "bazel-distdir")?;
    Ok(())
}

fn export_crates_vendor(
    store: &Store,
    layer: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let (store, entry) = export_target(store, layer)?;
    let crates = collect_verified_crates(&store, &entry)?;
    let vendor_dir = out.join("vendor");
    let n = varve_core::crateexport::export_vendor_dir(&crates, &vendor_dir)?;
    let cargo_dir = out.join(".cargo");
    std::fs::create_dir_all(&cargo_dir)?;
    let config = cargo_dir.join("config.toml");
    std::fs::write(
        &config,
        varve_core::crateexport::vendored_config_toml(&vendor_dir),
    )?;
    println!(
        "vendored {n} verified crate(s) to {} — a cargo-vendor tree bare Cargo and Corrosion \
         build against offline; copy {} into .cargo/config.toml (rules_rust needs BUILD files \
         on top — not yet emitted, REQ-VENDOR-002)",
        vendor_dir.display(),
        config.display()
    );
    write_export_stamp(out, &entry, "crates-vendor")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn deposit_cmd(
    spec: Option<&std::path::Path>,
    layer: Option<&str>,
    channel: Option<&str>,
    counter: Option<u64>,
    issued_at: &str,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    tools: &[String],
) -> anyhow::Result<()> {
    if let Some(spec_path) = spec {
        let text = std::fs::read_to_string(spec_path)
            .with_context(|| format!("cannot read spec {}", spec_path.display()))?;
        let file_spec = varve_core::parse_deposit_spec(&text)?;
        let base = spec_path.parent().unwrap_or(std::path::Path::new("."));
        let mut deposit_tools = Vec::new();
        for tool in file_spec.tools {
            let path = base.join(&tool.path);
            let bytes = std::fs::read(&path)
                .with_context(|| format!("cannot read tool binary {}", path.display()))?;
            let kind = tool
                .kind
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|e: varve_core::UnknownKind| anyhow::anyhow!(e.to_string()))?;
            deposit_tools.push(varve_core::DepositTool {
                name: tool.name,
                version: tool.version,
                platform: tool.platform,
                bytes,
                source: tool.source,
                runner: tool.runner,
                kind,
            });
        }
        return run_deposit(
            &file_spec.layer,
            &file_spec.channel,
            file_spec.counter,
            issued_at,
            key,
            key_id,
            out,
            deposit_tools,
        );
    }
    let (layer, channel, counter) = (
        layer.context("--layer required without --spec")?,
        channel.context("--channel required without --spec")?,
        counter.context("--counter required without --spec")?,
    );
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
            source: None,
            runner: None,
            kind: None,
        });
    }
    run_deposit(
        layer,
        channel,
        counter,
        issued_at,
        key,
        key_id,
        out,
        deposit_tools,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_deposit(
    layer: &str,
    channel: &str,
    counter: u64,
    issued_at: &str,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    deposit_tools: Vec<varve_core::DepositTool>,
) -> anyhow::Result<()> {
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

/// Per-project context (REQ-REALM-001): when the pin names a realm, that
/// realm's trust root and store namespace are AUTHORITATIVE — the ambient
/// environment cannot substitute either. Realmless pins keep the legacy
/// layout and the env-configured trust root.
struct ProjectCtx {
    pin: Pin,
    store: Store,
    realm: Option<varve_core::Realm>,
}

fn project_ctx(base: &Store) -> anyhow::Result<ProjectCtx> {
    let pin = load_pin()?;
    match &pin.realm {
        Some(name) => {
            let cwd = std::env::current_dir().context("cannot determine working directory")?;
            let realm = varve_core::resolve_realm(&cwd, name)?;
            let store = Store::at(realm.effective_root(base.root()));
            Ok(ProjectCtx {
                pin,
                store,
                realm: Some(realm),
            })
        }
        None => Ok(ProjectCtx {
            pin,
            store: base.clone(),
            realm: None,
        }),
    }
}

fn ctx_root_bytes(ctx: &ProjectCtx) -> anyhow::Result<Vec<u8>> {
    match &ctx.realm {
        Some(realm) => Ok(realm.trust_root.clone()),
        None => trust_root_bytes(),
    }
}

fn ctx_verifier(ctx: &ProjectCtx) -> anyhow::Result<varve_core::PinnedKeyVerifier> {
    varve_core::PinnedKeyVerifier::from_public_key_bytes(&ctx_root_bytes(ctx)?)
        .map_err(|e| anyhow::anyhow!("{e}"))
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
            "no trust root configured.\n\
             \n\
             The zero-config path is a realm: add `realm = \"pulseengine\"` to your \
             varve.toml and commit a varve-realms.toml naming the registry and trust \
             root — then no environment variable is needed and the realm's root is \
             authoritative. The canonical file ships as `varve-realms.toml` with each \
             release (and at pulseengine/varve/trust-roots/).\n\
             \n\
             Or, without a realm, point VARVE_TRUST_ROOT at the published root key \
             (`rolling.pub`, a release asset). See the Getting started section of the \
             README."
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

fn install(store: &Store, from: Option<&str>, platform: Option<String>) -> anyhow::Result<()> {
    let platform = platform.unwrap_or_else(varve_core::host_platform);
    let ctx = project_ctx(store)?;
    let from = match (from, &ctx.realm) {
        (Some(explicit), _) => explicit.to_string(),
        (None, Some(realm)) => realm.registry.clone(),
        (None, None) => {
            bail!("no source: pass --from, or name a realm in the pin so its registry applies")
        }
    };
    let from = from.as_str();
    let pin = &ctx.pin;
    let verifier = ctx_verifier(&ctx)?;
    let store = &ctx.store;
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
    let outcome = varve_core::install(pin, source, &verifier, store, &mut marks, &policy)?;
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

    // Auto-cache a baseline line-status the source carries beside the layer
    // (DD-008, REQ-STATUS-DIST-001), so `varve status` works with zero extra
    // steps after any install — a local oci-layout OR a registry (oci://)
    // pull (varve#34). Verified against the same realm/trust root; a bad,
    // stale, or unfetchable one is a note, never fatal to an otherwise-good
    // install. The consumer still owns freshness via `varve status --from-file`.
    let line = pin.layer.line().clone();
    let layer_ref = match &pin.digest {
        Some(digest) => varve_core::LayerRef::Digest(digest.clone()),
        None => varve_core::LayerRef::Name(pin.layer.clone()),
    };
    let root_pk = ctx_root_bytes(&ctx)?;
    match varve_core::cache_baseline_line_status(source, &layer_ref, &line, &root_pk, store.root())
    {
        Ok(Some(counter)) => {
            println!("cached baseline line-status #{counter} for line {line}");
        }
        Ok(None) => {}
        Err(e) => eprintln!("note: layer carried a line-status but it was not cached: {e}"),
    }
    Ok(())
}

fn verify(store: &Store, all: bool, exports: &[PathBuf]) -> anyhow::Result<()> {
    let ctx = project_ctx(store)?;
    let verifier = ctx_verifier(&ctx)?;
    let store = &ctx.store;
    let layers = if all {
        store.list()?
    } else {
        vec![varve_core::resolve(&ctx.pin, store)?.layer]
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
    if !exports.is_empty() {
        let current = varve_core::resolve(&ctx.pin, store)?.layer.digest;
        verify_exports(&current, exports)?;
    }
    Ok(())
}

/// Check committed export directories against the current pin's manifest digest
/// (REQ-EXPORT-SYNC-001). A stamp that names a different layer than the pin now
/// resolves is stale; an absent or malformed stamp is not a verified export.
/// Any of these fails the command — the whole point is a loud CI gate.
fn verify_exports(current_digest: &str, exports: &[PathBuf]) -> anyhow::Result<()> {
    use varve_core::exportstamp::{ExportStatus, read_stamp, status};
    let mut stale = Vec::new();
    for dir in exports {
        let stamp = read_stamp(dir)?;
        match status(&stamp, current_digest) {
            ExportStatus::Current => println!(
                "export {} — fresh: bound to layer {} ({})",
                dir.display(),
                stamp.layer,
                stamp.kind
            ),
            ExportStatus::Stale { stamped, current } => {
                eprintln!(
                    "export {} — STALE: stamped from layer {} ({stamped}); the pin now \
                     resolves {current}. Re-run the export against the current pin.",
                    dir.display(),
                    stamp.layer
                );
                stale.push(dir.display().to_string());
            }
        }
    }
    if !stale.is_empty() {
        bail!(
            "{} stale export(s) diverged from the pin (REQ-EXPORT-SYNC-001): {}",
            stale.len(),
            stale.join(", ")
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
    let ctx = project_ctx(store)?;
    let resolved = resolve(&ctx.pin, &ctx.store)?;
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

#[cfg(test)]
mod dispatch_tests {
    use super::dispatch_tool_name;
    use std::ffi::OsStr;

    // rivet: verifies REQ-SHIM-002
    #[test]
    fn varve_invoked_as_itself_is_not_a_dispatch() {
        for own in ["varve", "/usr/local/bin/varve", "varve.exe"] {
            assert_eq!(
                dispatch_tool_name(Some(OsStr::new(own))),
                None,
                "{own} must run the CLI, not dispatch"
            );
        }
        assert_eq!(dispatch_tool_name(None), None);
    }

    // rivet: verifies REQ-SHIM-002
    #[test]
    fn a_shim_name_is_the_file_name_only() {
        assert_eq!(
            dispatch_tool_name(Some(OsStr::new("/home/u/.varve/shims/synth"))),
            Some("synth".into())
        );
        assert_eq!(
            dispatch_tool_name(Some(OsStr::new("rivet"))),
            Some("rivet".into())
        );
        // Windows shims are copies named `<tool>.exe`.
        assert_eq!(
            dispatch_tool_name(Some(OsStr::new("synth.exe"))),
            Some("synth".into())
        );
    }

    // rivet: verifies REQ-SHIM-002
    #[test]
    fn a_hostile_argv0_cannot_smuggle_a_path() {
        // argv[0] is caller-controlled: traversal and separators are refused
        // rather than turned into a lookup. (`file_name` already strips the
        // directory; these assert the remaining cases fail closed.)
        for hostile in ["..", ".", ""] {
            assert_eq!(
                dispatch_tool_name(Some(OsStr::new(hostile))),
                None,
                "{hostile:?} must not name a tool"
            );
        }
        // A traversal path yields its final component, never a path.
        let got = dispatch_tool_name(Some(OsStr::new("../../etc/passwd")));
        assert_eq!(got, Some("passwd".into()));
        assert!(!got.unwrap().contains('/'));
    }
}
