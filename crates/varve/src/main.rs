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
mod exit;
mod inspect;

use exit::Outcome;

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
        /// Tool name, e.g. `synth` — or realm-qualified, e.g.
        /// `bytecodealliance/wasm-tools`, to ask about one specific provider
        /// where two realms of the composition ship the same name.
        tool: String,
    },
    /// Layers present in the local core.
    List,
    /// What is actually IN a layer: every payload's name, version, kind and
    /// platform, whether varve DISPATCHES it or merely HOLDS it, and every
    /// layer of the composition it came from (REQ-INSPECT-001).
    ///
    /// `list` prints layer ids and `sbom` collapses every non-tool payload to a
    /// CycloneDX `library`; neither answers "what is in here". Offline: the
    /// store already holds the answer, and the layer is re-verified before any
    /// of it is printed.
    Inspect {
        /// Layer to inspect, e.g. `2026.08.0`. Defaults to the resolved pin.
        #[arg(long)]
        layer: Option<String>,
        /// Machine-readable output (see `varve docs inspect` for the shape).
        #[arg(long)]
        json: bool,
    },
    /// The exit-code contract every varve command obeys — what a pipeline
    /// gates on (REQ-CIGATE-001). Also `varve docs exit-codes`.
    ExitCodes {
        /// Machine-readable: `{"codes":[{"code","name","meaning","commands"}]}`.
        #[arg(long)]
        json: bool,
    },
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
    /// Re-check the pinned layer offline: retained signature, the signed
    /// digest of every entry FOR THIS PLATFORM, each composed layer, the
    /// line's anti-rollback mark, and PATH shadowing. Entries for other
    /// platforms and files the manifest does not name are NOT checked — see
    /// `varve docs verify`.
    Verify {
        /// Verify every installed layer instead of only the pinned one.
        #[arg(long)]
        all: bool,
        /// Also check a project's Cargo lockfile against the pinned layer's
        /// `crate` entries: a package the layer pins must resolve to the same
        /// version and bytes, or verify fails (REQ-LOCKPIN-001). varve cannot
        /// intercept a build — this is asserted agreement, not dispatch.
        #[arg(long = "lockfile", value_name = "FILE")]
        lockfile: Option<PathBuf>,
        /// Also check a committed export directory against the current pin: its
        /// `.varve-export.json` stamp must name the layer the pin resolves to,
        /// or verify fails (REQ-EXPORT-SYNC-001). Repeatable; run it in CI so a
        /// stale vendored tree cannot slip through.
        #[arg(long = "export", value_name = "DIR")]
        export: Vec<PathBuf>,
    },
    /// Extract the core: export an installed layer as a directory-shaped
    /// OCI image layout — the offline artifact of record.
    ///
    /// The archive carries ONE platform's payloads: it exports what this
    /// machine installed, and `varve install` fetches only its own platform's
    /// bytes. A mixed air-gapped site needs one archive per platform, each made
    /// on (or installed for) that platform.
    Archive {
        /// Layer to export, e.g. `2026.07.0`.
        layer: String,
        /// Destination directory for the oci-layout.
        dest: PathBuf,
        /// The platform this core was installed for (target triple) — the one
        /// whose payloads the archive will carry. Defaults to this machine;
        /// pass it when the core was laid down with `varve install --platform`.
        #[arg(long, value_name = "TRIPLE")]
        platform: Option<String>,
        /// Overwrite a destination that already carries referrers, destroying
        /// them (REQ-NODESTROY-001). Without this, archiving over a layout
        /// that holds a line-status or attestations is REFUSED.
        #[arg(long)]
        force: bool,
        /// Archive even though this core cached no baseline line-status — the
        /// consumer's `varve status` will then fail for as long as they hold
        /// the archive, and a yank can never reach them (REQ-NOSILENT-001).
        #[arg(long)]
        allow_no_status: bool,
    },
    /// Dispatch a tool from the pinned layer, with the layer identity in the
    /// environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance
    /// tooling can record which qualified set produced the output.
    Run {
        /// One-off layer override — runs another installed layer WITHOUT
        /// touching the checked-in pin.
        #[arg(long, value_name = "LAYER")]
        varve: Option<String>,
        /// Tool and its arguments, after `--`. The tool may be realm-qualified
        /// (`bytecodealliance/wasm-tools`) to reach one specific provider where
        /// two realms of the composition ship the same name. `OsString`, so an
        /// argument that is not valid UTF-8 reaches the tool byte-for-byte
        /// instead of being lossily rewritten (unix arguments are arbitrary
        /// bytes).
        #[arg(trailing_var_arg = true, required = true)]
        tool_and_args: Vec<std::ffi::OsString>,
    },
    /// Mint a signing key and its public half — the value a realm pins as
    /// `trust-root` (REQ-KEYGEN-001). Without this an organisation cannot
    /// stand up its own realm at all: nothing else in varve emits a public key.
    Keygen {
        /// Where to write the signing key (128 hex characters). Keep it secret.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Where to write the public half (64 hex characters). Safe to publish;
        /// this is what consumers pin.
        #[arg(long = "pub", value_name = "FILE")]
        public: Option<PathBuf>,
    },
    /// Print the public half of an existing signing key, in exactly the form a
    /// realm's `trust-root` accepts. Refuses a key whose halves disagree.
    Pubkey {
        /// The signing key file.
        key: PathBuf,
    },
    /// (CI) Translate a realm's `layer.toml` into the environment the layer
    /// assembler reads (REQ-LAYERREPO-001). This is what lets a realm's
    /// contents live in the realm's OWN repository — bumping a tool becomes a
    /// one-line reviewed diff there, not a commit to the tool that signs it.
    ///
    /// Prints `KEY=value` lines for `$GITHUB_ENV`. It reads no network, writes
    /// no files, and touches no key.
    LayerSpec {
        /// The realm's layer manifest.
        #[arg(long, value_name = "FILE", default_value = "layer.toml")]
        manifest: PathBuf,
        /// Machine-readable output (see `varve docs layer-spec`).
        #[arg(long)]
        json: bool,
    },
    /// (CI) Assemble and SIGN a layer — the only way a layer comes into being.
    /// Writes an OCI image layout directory, the same shape `archive` produces.
    /// It does NOT publish: varve runs no server and pushes nothing, by design
    /// (README, "No server of our own"). See `varve docs deploy` for the push.
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
        /// Signing key file: 128 hex characters — a 32-byte ed25519 seed
        /// followed by its 32-byte public key. Mint one with `varve keygen`.
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
        /// Machine-readable result on stdout. A pipeline needs the layer's
        /// manifest digest; before this it had to scrape it out of a prose
        /// sentence (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
        /// Overwrite an `--out` that already carries referrers, destroying
        /// them. Without this, depositing into a used layout is REFUSED
        /// (REQ-NODESTROY-001) — it used to drop the line-status, line-index
        /// and attestations and report success.
        #[arg(long)]
        force: bool,
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
    /// Lay the layer's verified `vsix` entries out as
    /// `publisher.name-version.vsix` files, so `code --install-extension
    /// <file>` installs an editor extension whose bytes varve signed rather
    /// than whatever the marketplace serves today (REQ-VSIX-001).
    ExportVsix {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output directory for the `.vsix` files.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Unpack and RELOCATE the layer's verified `sdk` tree into a directory
    /// you can source (REQ-SDK-001 clause 3). The store keeps the archive
    /// exactly as its producer signed it; the usable tree lives here, with the
    /// build-time prefix patched to `--out` the way Yocto's own
    /// `relocate_sdk.py` and `toolchain-shar-relocate.sh` do it.
    ///
    /// An SDK's interpreter path is patched IN PLACE into a fixed-size field,
    /// so it can only move to a path NO LONGER than the one it was built for —
    /// a destination that does not fit is refused BEFORE anything is written.
    ExportSdk {
        /// Layer to export, e.g. `2026.08.0`. Defaults to the resolved
        /// project pin, so the export tracks the pin (REQ-EXPORT-SYNC-001).
        #[arg(long)]
        layer: Option<String>,
        /// Output directory — the path the tree is RELOCATED to, and therefore
        /// the path patched into its binaries. Must be at most as long as the
        /// prefix the SDK was built for.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Which `sdk` payload to export, when the layer carries more than one.
        /// One destination is patched into ONE tree, so a layer with several is
        /// ambiguous rather than a batch.
        #[arg(long, value_name = "NAME")]
        select: Option<String>,
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
    ///
    /// EXITS 3 WHEN THE PINNED LAYER IS YANKED — a signed yank exists to stop
    /// a build, so a pipeline gates on the exit code and never on stdout.
    /// See `varve docs exit-codes`.
    Status {
        /// Ingest a status envelope first: verify, cache (monotonic), then
        /// report. Without it, report from the local cache.
        #[arg(long = "from-file", value_name = "ENVELOPE")]
        from_file: Option<PathBuf>,
        /// Machine-readable report on stdout. The exit code still carries the
        /// verdict; this carries the detail.
        #[arg(long)]
        json: bool,
    },
    /// (CI) Sign a statement binding an attestation to a layer: "this digest,
    /// of this kind, from this producer, accompanies this layer"
    /// (REQ-ATTEST-001). varve vouches for the ASSOCIATION and the bytes'
    /// integrity — never for what the producer claimed.
    SignAttestation {
        /// Layer the attestation accompanies. Defaults to the resolved pin.
        #[arg(long)]
        layer: Option<String>,
        /// What the document is: sbom | provenance | audit | vex | qualification.
        #[arg(long)]
        kind: String,
        /// The attestation bytes to bind (carried verbatim, never rewritten).
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Who produced the underlying claim, e.g. `adacore`, `cargo-vet`.
        #[arg(long, default_value = "varve")]
        producer: String,
        /// Signing key file: 128 hex characters — a 32-byte ed25519 seed
        /// followed by its 32-byte public key. Mint one with `varve keygen`.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        /// Where to write the signed statement.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// (CI) Also ATTACH the statement and the attestation bytes to a
        /// deposit layout as referrer artifacts, so the evidence travels with
        /// the layer through a registry push, an `archive`, and an offline
        /// install (REQ-ATTEST-002). Without this the statement exists and
        /// reaches nobody — the mirror-boundary gap where bandersnatch,
        /// Verdaccio and every github.com-hosted BCR attestation drop the
        /// evidence and no error says so.
        #[arg(long = "attach-to", value_name = "DIR")]
        attach_to: Option<PathBuf>,
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
    },
    /// Check that an attestation belongs to the pinned layer: verify the
    /// statement against the trust root, then re-hash the carried bytes and
    /// confirm the layer it names is the one resolved here (REQ-ATTEST-001).
    CheckAttestation {
        /// The signed statement (DSSE envelope) produced by sign-attestation.
        #[arg(long, value_name = "FILE")]
        statement: PathBuf,
        /// The attestation bytes the statement describes.
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// (CI) Validate and sign a line-status document into a DSSE envelope.
    SignStatus {
        /// The status document JSON (see docs: line, counter, issued-at,
        /// support-until, yanked, known-problems).
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Signing key file: 128 hex characters — a 32-byte ed25519 seed
        /// followed by its 32-byte public key. Mint one with `varve keygen`.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
        /// The realm's signed line-index envelope (from `varve sign-index`).
        /// Without it the `affected` and yank ids can only be checked for
        /// SHAPE, and sign-status says which check it did not perform
        /// (REQ-ADVISORY-002).
        #[arg(long, value_name = "ENVELOPE")]
        index: Option<PathBuf>,
        /// Directories holding this line's oci-layouts (what `varve deposit
        /// --out` wrote, or a directory of them). The producer's own layers
        /// are the listing that needs no network and no published index —
        /// `signed-index` is false by default (DD-023). Repeatable.
        #[arg(long = "layouts", value_name = "DIR")]
        layouts: Vec<PathBuf>,
        /// Sign an advisory naming a layer that is not deposited yet.
        #[arg(long)]
        force: bool,
    },
    /// (CI) Validate and sign a line-index document — the realm's statement of
    /// which layers a line contains (REQ-INDEXAUTH-001). Without one, the
    /// listing a consumer resolves against is the registry's unauthenticated
    /// `/tags/list`, and a host that HIDES a layer is undetectable: every
    /// artifact it does serve still verifies.
    SignIndex {
        /// The index document JSON (line, counter, issued-at, layers[] of
        /// layer/digest/channel/counter). See `varve docs sign-index`.
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
        /// Signing key file: 128 hex characters — a 32-byte ed25519 seed
        /// followed by its 32-byte public key. Mint one with `varve keygen`.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
    },
    /// (CI) Attach a signed line-index envelope to a deposit layout, so an
    /// offline consumer of a realm declaring `signed-index = true` can obtain
    /// it (REQ-INDEXAUTH-001). On a registry the same envelope is pushed under
    /// the `line-index-<line>` tag — see `varve docs attach-index`.
    AttachIndex {
        /// The oci-layout directory produced by `varve deposit`.
        #[arg(long, value_name = "DIR")]
        layout: PathBuf,
        /// The signed line-index DSSE envelope (from `varve sign-index`).
        #[arg(long, value_name = "ENVELOPE")]
        index: PathBuf,
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
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
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
        /// Attach an advisory naming a layer this line does not (yet) have.
        /// Without this the attach is REFUSED, because an advisory whose
        /// `affected` id names nothing can never fire (REQ-ADVISORY-002).
        #[arg(long)]
        force: bool,
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
        /// Signing key file: 128 hex characters — a 32-byte ed25519 seed
        /// followed by its 32-byte public key. Mint one with `varve keygen`.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        #[arg(long, default_value = "varve-root-1")]
        key_id: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Machine-readable result on stdout (REQ-CIGATE-001).
        #[arg(long)]
        json: bool,
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

/// The one place a varve process turns an answer into an exit status
/// (REQ-CIGATE-001). Every code comes from `exit::Outcome`, which is also what
/// `varve exit-codes` prints and what the `exit-codes` docs topic is generated
/// from — so the contract cannot be documented in one place and implemented in
/// another.
fn main() -> ExitCode {
    match run() {
        Ok(outcome) => ExitCode::from(outcome.code()),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(Outcome::Error.code())
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

fn run() -> anyhow::Result<Outcome> {
    // Invoked under another name? Then this binary IS the shim: dispatch.
    let mut args = std::env::args_os();
    let argv0 = args.next();
    if let Some(tool) = dispatch_tool_name(argv0.as_deref()) {
        let store = Store::at(store_root()?);
        // Arguments pass through as OsString: a shim must hand the tool the
        // exact bytes the caller typed, and unix arguments are arbitrary bytes.
        let rest: Vec<std::ffi::OsString> = args.collect();
        run_tool(&store, None, &tool, &rest)?;
        return Ok(Outcome::Ok);
    }
    let cli = Cli::parse();
    let store = Store::at(store_root()?);
    // Two commands report a VERDICT rather than merely succeeding or failing —
    // a yanked layer and an empty search are ANSWERS, and their exit code is
    // the answer (REQ-CIGATE-001). They write it here; every other command
    // succeeds as `Ok` or fails as `Error`.
    let mut outcome = Outcome::Ok;
    match cli.command {
        Cmd::Which { tool } => which(&store, &tool),
        Cmd::List => list(&store),
        Cmd::Install { from, platform } => install(&store, from.as_deref(), platform),
        Cmd::Verify {
            all,
            export,
            lockfile,
        } => verify(&store, all, &export, lockfile.as_deref()),
        Cmd::Archive {
            layer,
            dest,
            platform,
            force,
            allow_no_status,
        } => archive(&store, &layer, &dest, platform, force, allow_no_status),
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
            json,
            force,
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
            json,
            force,
        ),
        Cmd::ExportBazel { layer, out } => export_bazel(&store, layer.as_deref(), &out),
        Cmd::ExportCargo { layer, out } => export_cargo(&store, layer.as_deref(), &out),
        Cmd::ExportCratesVendor { layer, out } => {
            export_crates_vendor(&store, layer.as_deref(), &out)
        }
        Cmd::ExportBazelDistdir { layer, out } => {
            export_bazel_distdir(&store, layer.as_deref(), &out)
        }
        Cmd::ExportVsix { layer, out } => export_vsix(&store, layer.as_deref(), &out),
        Cmd::ExportSdk { layer, out, select } => {
            export_sdk(&store, layer.as_deref(), &out, select.as_deref())
        }
        Cmd::Sbom { layer, format, out } => {
            sbom_cmd(&store, layer.as_deref(), &format, out.as_deref())
        }
        Cmd::Status { from_file, json } => {
            status(&store, from_file.as_deref(), json).map(|o| outcome = o)
        }
        Cmd::SignStatus {
            file,
            key,
            key_id,
            out,
            json,
            index,
            layouts,
            force,
        } => sign_status(
            &file,
            &key,
            &key_id,
            &out,
            json,
            index.as_deref(),
            &layouts,
            force,
        ),
        Cmd::Keygen { out, public } => keygen(&out, public.as_deref()),
        Cmd::Pubkey { key } => pubkey(&key),
        Cmd::LayerSpec { manifest, json } => layer_spec(&manifest, json),
        Cmd::SignAttestation {
            layer,
            kind,
            file,
            producer,
            key,
            key_id,
            out,
            attach_to,
            json,
        } => sign_attestation(
            &store,
            layer.as_deref(),
            &kind,
            &file,
            &producer,
            &key,
            &key_id,
            &out,
            attach_to.as_deref(),
            json,
        ),
        Cmd::CheckAttestation { statement, file } => check_attestation(&store, &statement, &file),
        Cmd::AttachStatus {
            layout,
            status,
            json,
            force,
        } => attach_status(&layout, &status, json, force),
        Cmd::SignIndex {
            file,
            key,
            key_id,
            out,
            json,
        } => sign_index(&file, &key, &key_id, &out, json),
        Cmd::AttachIndex {
            layout,
            index,
            json,
        } => attach_index(&layout, &index, json),
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
            json,
        } => sign_sums(&sums, &key, &key_id, &out, json),
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
        )
        .map(|o| outcome = o),
        Cmd::ExitCodes { json } => {
            if json {
                println!("{}", exit::render_json());
            } else {
                print!("{}", exit::render_text());
            }
            Ok(())
        }
        Cmd::Inspect { layer, json } => inspect::run(&store, layer.as_deref(), json),
    }?;
    Ok(outcome)
}

/// Report a command's result to whoever asked: the prose a person reads, or
/// the JSON a pipeline parses — never both, because a pipeline reads stdout and
/// two documents on one stream is not a document.
///
/// Every command tagged `(CI)` in `--help` takes `--json` and reports through
/// here (REQ-CIGATE-001). Before this, a pipeline that needed a layer's
/// manifest digest had to scrape it out of an English sentence, and every
/// wording change was a silent breaking change to somebody's CI.
///
/// The shape is a compatibility promise, so it is deliberately flat and
/// self-describing: a `command` field naming the subcommand, then that
/// command's own facts as named scalars. Paths are reported exactly as varve
/// was given them.
fn report(json: bool, human: &str, machine: serde_json::Value) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&machine).expect("report serialises")
        );
    } else {
        println!("{human}");
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

/// `varve env` — the whole environment in one command (REQ-EXPORTDECL-001
/// clause 4), not just the shims.
///
/// A project that declares a sourced export needs TWO things entered, in an
/// order that inverts what the file says: sourcing a script PREPENDS its bin to
/// PATH, so whatever is sourced LAST wins. `varve_core::env_lines` owns that
/// inversion — emitting the declarations in file order would produce exactly
/// the PATH the project said it did not want, and `verify` would then report
/// the shadowing the project had declared away.
///
/// The shims are emitted INLINE rather than as `. "$VARVE_ROOT/env"` because
/// that file is written by `shim install`; the fragment is byte-identical to
/// its contents, so the position — which is the part that matters — is the
/// same either way, and `eval "$(varve env)"` keeps working before any shim
/// has been installed.
fn print_env(store: &Store, shell: &str) -> anyhow::Result<()> {
    let shim_dir = store.root().join("shims");
    let env_file = store.root().join("env");
    // The PIN, not the whole project context: `env` needs the declarations and
    // the directory they are relative to, and nothing else. Reading it through
    // `project_ctx` would make entering an environment depend on the realm
    // resolving — and a realms file that cannot be read would then silently
    // drop the declared SDK, which is the accepted-ignored-and-believed shape
    // clause 4 exists to refuse.
    //
    // Outside a project there is no pin at all: the shims are the whole answer,
    // exactly as before. A pin that EXISTS and does not parse is an error, not
    // a fallback — `eval "$(varve env)"` must not quietly give you half an
    // environment because varve.toml has a typo in it.
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    let pin = match discover::find_pin(&cwd) {
        Some(_) => Some(load_pin()?),
        None => None,
    };
    let sourced: Vec<&varve_core::ExportDecl> = pin
        .as_ref()
        .map(|(p, _)| p.exports.iter().filter(|d| d.env.is_some()).collect())
        .unwrap_or_default();
    match shell {
        "sh" | "bash" | "zsh" => {
            let Some((pin, root)) = pin.as_ref().filter(|_| !sourced.is_empty()) else {
                print!("{}", env_script_sh(&shim_dir));
                return Ok(());
            };
            for line in varve_core::env_lines(pin, root, Some(&env_file)) {
                // The shims, inline: the sourced scripts must land around this
                // exact position, which is why the line is REPLACED rather than
                // appended somewhere convenient.
                if line == format!(". \"{}\"", env_file.display()) {
                    print!("{}", env_script_sh(&shim_dir));
                } else {
                    println!("{line}");
                }
            }
        }
        "fish" => {
            // A sourced export's script is the producer's POSIX sh
            // `environment-setup-*`; fish cannot source it, and printing the
            // shim line alone would hand back an environment that silently
            // lacks the SDK the project declared.
            if let Some(first) = sourced.first() {
                bail!(
                    "this project declares a sourced export ({} at {}), and its environment \
                     script is POSIX sh — fish cannot source it, and emitting only the shim \
                     line would give you an environment missing the very thing varve.toml \
                     declares. Enter it from sh, bash or zsh: `eval \"$(varve env)\"`.",
                    first.kind,
                    first.out
                );
            }
            println!(
                "if not contains \"{dir}\" $PATH\n    set -gx PATH \"{dir}\" $PATH\nend",
                dir = shim_dir.display()
            );
        }
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
    json: bool,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(sums).with_context(|| format!("cannot read {}", sums.display()))?;
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    // Refuse a key that cannot produce verifiable signatures BEFORE signing.
    // varve used to accept 64 bytes of entropy here and emit a signed layer no
    // trust root could ever verify, exit 0 (REQ-PRODUCER-001).
    let sk = varve_core::keys::check_keypair(&hex_key, &key.display().to_string())?;
    let envelope = varve_core::sign_release_sums(&bytes, &sk, key_id)?;
    std::fs::write(out, envelope).with_context(|| format!("cannot write {}", out.display()))?;
    report(
        json,
        &format!("signed release sums -> {}", out.display()),
        serde_json::json!({
            "command": "sign-sums",
            "sums": sums.display().to_string(),
            "sums_digest": varve_core::manifest_digest(&bytes),
            "key_id": key_id,
            "out": out.display().to_string(),
        }),
    );
    Ok(())
}

/// `varve status` — and, since v0.28.0, a GATE.
///
/// BREAKING (REQ-CIGATE-001): a yanked layer exits 3, not 0. Signing a yank
/// exists to stop a build; while this command exited 0 the only way to act on
/// one was to grep stdout for the word YANKED, which two personas of a
/// ten-persona audit independently failed to do — and a gate nobody can write
/// is not a gate. The report itself is unchanged and still goes to stdout, so a
/// script that only reads output keeps working; a script that checks `$?` now
/// gets the answer.
fn status(
    store: &Store,
    from_file: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<Outcome> {
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
    let verdict = doc.report_for(&pin.layer);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": "status",
                "layer": pin.layer.to_string(),
                "line": line.to_string(),
                "status_counter": doc.counter,
                "yanked": verdict.yanked_reason.is_some(),
                "yanked_reason": verdict.yanked_reason,
                "support_until": verdict.support_until,
                "known_problems": verdict.problems_total,
                "known_problems_with_workaround": verdict.problems_with_workaround,
                "exit_code": if verdict.yanked_reason.is_some() {
                    Outcome::Yanked.code()
                } else {
                    Outcome::Ok.code()
                },
            }))
            .expect("status report serialises")
        );
    } else {
        println!(
            "layer {} (line {line}, status document #{})",
            pin.layer, doc.counter
        );
        match &verdict.yanked_reason {
            Some(reason) => println!("  YANKED: {reason}"),
            None => println!("  not yanked"),
        }
        match &verdict.support_until {
            Some(until) => println!("  supported until {until}"),
            None => println!("  no stated support window"),
        }
        println!(
            "  {} known problem(s) affect this layer, {} with workarounds",
            verdict.problems_total, verdict.problems_with_workaround
        );
    }
    // The verdict IS the exit code (REQ-CIGATE-001). Note it is not an error:
    // stderr stays empty and the report above is complete, because varve
    // answered the question correctly — the answer is just one that stops a
    // build.
    Ok(match verdict.yanked_reason {
        Some(_) => Outcome::Yanked,
        None => Outcome::Ok,
    })
}

fn attach_status(
    layout: &std::path::Path,
    status: &std::path::Path,
    json: bool,
    force: bool,
) -> anyhow::Result<()> {
    let envelope = std::fs::read(status)
        .with_context(|| format!("cannot read status envelope {}", status.display()))?;
    // REQ-ADVISORY-002: where the layout carries a line-index, the `affected`
    // ids are checked against the layers the line actually has. `check.note`
    // says which check ran — and, when no listing was in reach, which one did
    // NOT. Printing it is clause 3: a partial check must not read as a
    // complete one.
    let (line, counter, check) =
        varve_core::attach_status_envelope_to_layout_checked(layout, &envelope, force)?;
    report(
        json,
        &format!(
            "attached baseline line-status #{counter} for line {line} to {}\n  {}",
            layout.display(),
            check.note
        ),
        serde_json::json!({
            "command": "attach-status",
            "line": line.to_string(),
            "counter": counter,
            "layout": layout.display().to_string(),
            "existence_checked": check.existence_checked,
            "note": check.note,
        }),
    );
    Ok(())
}

fn attach_index(
    layout: &std::path::Path,
    index: &std::path::Path,
    json: bool,
) -> anyhow::Result<()> {
    let envelope = std::fs::read(index)
        .with_context(|| format!("cannot read index envelope {}", index.display()))?;
    let (line, counter) = varve_core::attach_index_envelope_to_layout(layout, &envelope)?;
    report(
        json,
        &format!(
            "attached signed line-index #{counter} for line {line} to {}",
            layout.display()
        ),
        serde_json::json!({
            "command": "attach-index",
            "line": line.to_string(),
            "counter": counter,
            "layout": layout.display().to_string(),
        }),
    );
    Ok(())
}

fn sign_index(
    file: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    json: bool,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(file)
        .with_context(|| format!("cannot read index document {}", file.display()))?;
    // Validate through the typed model before signing: an index is the
    // document a consumer refuses installs on the strength of, so CI must not
    // be able to sign a malformed one and discover it at the far end.
    let doc: varve_core::LineIndex =
        serde_json::from_slice(&bytes).context("index document does not match the schema")?;
    // The line must be a real line, not merely a string that round-trips —
    // an index for "twenty twenty six" verifies fine and matches nothing.
    doc.line()?;
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    // Refuse a key that cannot produce verifiable signatures BEFORE signing,
    // as every other producing path does (REQ-PRODUCER-001).
    let sk = varve_core::keys::check_keypair(&hex_key, &key.display().to_string())?;
    let envelope = doc.sign(&sk, key_id)?;
    std::fs::write(out, envelope)
        .with_context(|| format!("cannot write envelope {}", out.display()))?;
    report(
        json,
        &format!(
            "signed line-index #{} for line {} ({} layer(s)) -> {}",
            doc.counter,
            doc.line,
            doc.layers.len(),
            out.display()
        ),
        serde_json::json!({
            "command": "sign-index",
            "line": doc.line,
            "counter": doc.counter,
            "layers": doc.layers.len(),
            "key_id": key_id,
            "out": out.display().to_string(),
        }),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_status(
    file: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    json: bool,
    index: Option<&std::path::Path>,
    layouts: &[PathBuf],
    force: bool,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(file)
        .with_context(|| format!("cannot read status document {}", file.display()))?;
    // Validate through the typed model before signing: CI must not be able
    // to sign a malformed advisory.
    let doc: varve_core::LineStatus =
        serde_json::from_slice(&bytes).context("status document does not match the schema")?;
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    // Refuse a key that cannot produce verifiable signatures BEFORE signing.
    // varve used to accept 64 bytes of entropy here and emit a signed layer no
    // trust root could ever verify, exit 0 (REQ-PRODUCER-001).
    let sk = varve_core::keys::check_keypair(&hex_key, &key.display().to_string())?;
    // REQ-ADVISORY-002: a typo in an `affected` layer id used to sign cleanly,
    // and the advisory then never fired for anyone — producer sees success,
    // consumer sees nothing, the yank silently does not exist. Shape is always
    // checked. EXISTENCE is checked only where a listing of the line is in
    // reach, and where it is not, `check.note` says so rather than letting a
    // partial check read as a complete one.
    let known = match index {
        Some(path) => {
            let env = std::fs::read(path)
                .with_context(|| format!("cannot read line-index envelope {}", path.display()))?;
            varve_core::known_layers_from_index(&env, &sk[32..])?
        }
        // The producer's own layouts: no network, no published index. This is
        // the path that actually runs for most realms (DD-023 clause 5).
        None if !layouts.is_empty() => varve_core::known_layers_in_layout_dirs(layouts, &doc.line),
        None => varve_core::KnownLayers::unknown(
            "no listing of this line was supplied — pass `--layouts <DIR>` (the directory \
             `varve deposit --out` wrote, or one holding several) to check the `affected` \
             and yank ids against the layers you actually deposited, or `--index \
             <envelope>` if this realm publishes a signed line-index",
        ),
    };
    let (envelope, check) = doc.sign_against(&known, force, &sk, key_id)?;
    std::fs::write(out, envelope)
        .with_context(|| format!("cannot write envelope {}", out.display()))?;
    report(
        json,
        &format!(
            "signed line-status #{} for line {} -> {}\n  {}",
            doc.counter,
            doc.line,
            out.display(),
            check.note
        ),
        serde_json::json!({
            "command": "sign-status",
            "line": doc.line,
            "counter": doc.counter,
            "yanked": doc.yanked.keys().collect::<Vec<_>>(),
            "known_problems": doc.known_problems.len(),
            "existence_checked": check.existence_checked,
            "note": check.note,
            "key_id": key_id,
            "out": out.display().to_string(),
        }),
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
) -> anyhow::Result<Outcome> {
    use clap::CommandFactory;
    let json = match format {
        "text" => false,
        "json" => true,
        other => bail!("unknown --format '{other}' (expected `text` or `json`)"),
    };
    // `varve docs check --coverage` (or --coverage) — the mechanical invariant.
    if coverage || topic == Some("check") {
        let gaps = docs::coverage_gaps(&Cli::command());
        // Subcommand presence is not the whole contract. Two audits found the
        // docs unusable for FILES and TASKS while this check reported green,
        // because a file format is not a subcommand and neither is a task
        // (REQ-DOCS-003).
        let missing_topics = docs::missing_required_topics();
        let bare_topics = docs::topics_without_examples();
        if gaps.is_empty() && missing_topics.is_empty() && bare_topics.is_empty() {
            println!(
                "docs coverage: OK — {} subcommands documented, {} workflow topic(s) present, \
                 {} topic(s) carry a worked example",
                Cli::command().get_subcommands().count(),
                docs::REQUIRED_TOPICS.len(),
                docs::TOPICS_NEEDING_EXAMPLES.len()
            );
            return Ok(Outcome::Ok);
        }
        if !missing_topics.is_empty() {
            eprintln!(
                "docs coverage: {} workflow topic(s) missing — a user cannot do the job \
                 without them:",
                missing_topics.len()
            );
            for m in &missing_topics {
                eprintln!("  {m}");
            }
        }
        if !bare_topics.is_empty() {
            eprintln!(
                "docs coverage: {} topic(s) must SHOW a literal example, not describe one:",
                bare_topics.len()
            );
            for b in &bare_topics {
                eprintln!("  {b}");
            }
        }
        if gaps.is_empty() {
            if strict {
                bail!(
                    "documentation gaps (REQ-DOCS-003): {} missing topic(s), {} without an \
                     example",
                    missing_topics.len(),
                    bare_topics.len()
                );
            }
            return Ok(Outcome::Ok);
        }
        eprintln!("docs coverage: {} subcommand(s) undocumented:", gaps.len());
        for g in &gaps {
            eprintln!("  {g}");
        }
        if strict {
            bail!(
                "undocumented subcommands (REQ-DOCS-001): {}{}",
                gaps.join(", "),
                if missing_topics.is_empty() && bare_topics.is_empty() {
                    String::new()
                } else {
                    format!(
                        " — plus {} missing workflow topic(s) and {} without an example \
                         (REQ-DOCS-003)",
                        missing_topics.len(),
                        bare_topics.len()
                    )
                }
            );
        }
        return Ok(Outcome::Ok);
    }
    if let Some(q) = grep {
        let hits = docs::grep(q);
        // A search that matched nothing EXITS NON-ZERO (REQ-CIGATE-001). It
        // used to print one prose line and exit 0, so a docs check could not
        // gate on the docs — `varve docs --grep "exit code"` returned nothing
        // across all fifty topics, quietly, successfully.
        //
        // It is code 4, not 1: nothing failed. The search ran and the answer is
        // empty, which is a result a pipeline branches on and not an incident
        // it reports.
        if hits.is_empty() {
            if json {
                println!("[]");
            } else {
                println!("no topic matches '{q}'");
            }
            return Ok(Outcome::NoMatch);
        }
        if json {
            let arr: Vec<_> = hits
                .iter()
                .map(|(slug, line)| {
                    serde_json::json!({
                        "slug": slug,
                        "title": docs::find(slug).map(|t| t.title),
                        "line": line,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&arr).expect("grep hits serialise")
            );
        } else {
            for (slug, line) in hits {
                println!("{slug}: {line}");
            }
        }
        return Ok(Outcome::Ok);
    }
    if list || topic.is_none() {
        if json {
            println!("{}", docs::render_json(None));
        } else {
            print!("{}", docs::render_list());
        }
        return Ok(Outcome::Ok);
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
    Ok(Outcome::Ok)
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

/// Resolve a `run`/`which` argument to (bare tool name, binary path).
///
/// A BARE argument dispatches through the pin's one choice per name — exactly
/// one entry exists, whatever the composition holds (REQ-REALM2-001 clause 4c).
/// A `realm/tool` argument reaches one specific provider, INCLUDING the one the
/// pin did not choose (clause 4b): "compare our fork against upstream" is a
/// real workflow, and losing the other binary entirely would be a worse answer
/// than the refusal this feature replaces.
fn dispatch_target<'a>(
    resolved: &'a varve_core::Resolved,
    arg: &str,
) -> Option<(&'a str, &'a std::path::Path)> {
    if arg.contains('/') {
        return resolved
            .qualified
            .iter()
            .find(|(provider, _)| provider.qualified().as_deref() == Some(arg))
            .map(|(provider, path)| (provider.tool.as_str(), path.as_path()));
    }
    resolved
        .tools
        .iter()
        .find(|(name, _)| name == arg)
        .map(|(name, path)| (name.as_str(), path.as_path()))
}

/// Every address this pin answers to: the bare names, plus the realm-qualified
/// form of any name more than one layer of the composition provides. An error
/// listing only bare names would hide the very binary clause 4b keeps alive.
fn addressable(resolved: &varve_core::Resolved) -> String {
    let mut names: Vec<String> = resolved.tools.iter().map(|(n, _)| n.clone()).collect();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (provider, _) in &resolved.qualified {
        *counts.entry(provider.tool.as_str()).or_default() += 1;
    }
    for (provider, _) in &resolved.qualified {
        if counts.get(provider.tool.as_str()).copied().unwrap_or(0) > 1
            && let Some(q) = provider.qualified()
        {
            names.push(q);
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        "(nothing)".to_string()
    } else {
        names.join(", ")
    }
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
    let Some((tool, path)) = dispatch_target(&resolved, tool) else {
        // The same correction `which` carries: the layer HOLDS a `wit`, `crate`
        // or `vsix` payload, it just does not dispatch one (REQ-INSPECT-001
        // clause 3). "not part of layer" sends the reader to re-deposit
        // something that is already there.
        if let Some((kind, version, in_layer)) = held_payload(&ctx.store, &resolved.layer, tool) {
            bail!(
                "'{tool}' is a HELD `{kind}` payload{version} of layer {in_layer}, not a \
                 dispatched tool — varve cannot exec it. Only a `tool` is dispatched by name. \
                 Run `varve inspect` to see every payload, or the matching `varve export-*` \
                 to materialise this one.",
                version = match version {
                    Some(v) => format!(" ({v})"),
                    None => String::new(),
                },
            );
        }
        bail!(
            "tool '{tool}' is not part of layer {} — it exposes: {}. `varve inspect` lists \
             every payload, dispatched and held.",
            resolved.layer.layer,
            addressable(&resolved)
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
/// The verified root of an export: which store the layer lives in, the layer,
/// and the trust root that vouched for it. The verifier travels with the target
/// because an export must follow the layer's COMPOSITION
/// (REQ-COMPOSEEXPORT-001), and each included layer is checked against its own
/// realm's root, falling back to this one where an include names no realm.
struct ExportTarget {
    store: Store,
    entry: varve_core::store::InstalledLayer,
    verifier: varve_core::PinnedKeyVerifier,
    /// The realm whose root vouched for the root layer, named for messages.
    realm: String,
}

fn export_target(base: &Store, layer: Option<&str>) -> anyhow::Result<ExportTarget> {
    match layer {
        Some(l) => {
            // Search the PROJECT'S store, not the top-level core. Realms
            // partition the core, so an explicit --layer used to miss a layer
            // the same project's `which` resolves — reported as both "no trust
            // root configured" (when one was) and "layer X is not installed"
            // (when it was). This is the README's headline example
            // (REQ-STORE-001).
            let (store, verifier, realm) = match project_ctx(base) {
                Ok(ctx) => {
                    let v = ctx_verifier(&ctx)?;
                    let realm = ctx_realm_name(&ctx);
                    (ctx.store, v, realm)
                }
                // Outside a project there is no realm: the top-level core and
                // the environment's trust root are the only answer available.
                Err(_) => (
                    base.clone(),
                    trust_root()?,
                    "the environment's trust root".to_string(),
                ),
            };
            let wanted: varve_core::LayerId = l.parse()?;
            let entry = store
                .list()?
                .into_iter()
                .find(|e| e.layer == wanted)
                .with_context(|| format!("layer {l} is not installed — varve install it first"))?;
            varve_core::verify_installed(&store, &entry, &verifier, &varve_core::host_platform())?;
            Ok(ExportTarget {
                store,
                entry,
                verifier,
                realm,
            })
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
            Ok(ExportTarget {
                realm: ctx_realm_name(&ctx),
                store: ctx.store,
                entry: resolved.layer,
                verifier,
            })
        }
    }
}

/// How to name the realm that vouches for a project's own layers, in a message
/// a reader can act on.
fn ctx_realm_name(ctx: &ProjectCtx) -> String {
    match &ctx.realm {
        Some(r) => r.name.clone(),
        None => "this project's own trust root".to_string(),
    }
}

/// One layer of a composition, VERIFIED against the trust root of the realm
/// that vouches for it (REQ-COMPOSEEXPORT-001 clause 1).
struct ComposedLayer {
    /// The store partition the layer lives in — a cross-realm include lives
    /// under the INCLUDED realm's fingerprint, not the including project's.
    store: Store,
    entry: varve_core::store::InstalledLayer,
    /// The realm that vouched for it, for the collision message.
    realm: String,
}

/// Every layer an export must cover: the root plus everything it composes,
/// root first, each verified against its own realm's root.
///
/// varve#79: `resolve()` already unions composed TOOLS so `which`/`run` see
/// them, and `verify` already checks each included layer — but every export
/// adapter read ONE `layer.json`, so an extender composing pulseengine's layer
/// got only their own crates and no error at all. Trust does not widen here:
/// each layer is checked against the root of the realm the include names, and
/// a layer that is not installed is an error naming it (clause 3), never a
/// quietly shorter export.
fn composition_for_export(target: &ExportTarget) -> anyhow::Result<Vec<ComposedLayer>> {
    let mut out = vec![ComposedLayer {
        store: target.store.clone(),
        entry: target.entry.clone(),
        realm: target.realm.clone(),
    }];
    let mut ancestors = vec![target.entry.digest.clone()];
    walk_composition(
        &target.store,
        &target.entry,
        &target.verifier,
        &target.realm,
        &mut ancestors,
        &mut out,
    )?;
    Ok(out)
}

/// The recursive half of `composition_for_export`. Bounded and cycle-guarded
/// for the same reason `verify` is: "refused" and "followed until the process
/// aborts" are not the same answer.
///
/// `ancestors` is a PATH, pushed and popped — a digest reappearing on its own
/// path is a cycle, while a digest reachable by two paths is a DIAMOND (two
/// layers sharing a base), the most ordinary composition there is. Conflating
/// the two is the bug `compose::walk` was fixed for; this walker must not
/// reintroduce it.
fn walk_composition(
    store: &Store,
    layer: &varve_core::store::InstalledLayer,
    own_verifier: &varve_core::PinnedKeyVerifier,
    own_realm: &str,
    ancestors: &mut Vec<String>,
    out: &mut Vec<ComposedLayer>,
) -> anyhow::Result<()> {
    if ancestors.len() > varve_core::compose::MAX_DEPTH {
        bail!(
            "composition is more than {} layers deep while collecting an export — refusing to \
             walk further",
            varve_core::compose::MAX_DEPTH
        );
    }
    let Ok(bytes) = std::fs::read(layer.root.join("layer.json")) else {
        return Ok(());
    };
    let view = varve_core::compose::view(&bytes)?;
    if view.includes.is_empty() {
        return Ok(());
    }
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    for inc in &view.includes {
        if ancestors.contains(&inc.digest) {
            bail!(
                "composition cycle while collecting an export: layer {} ({}) includes {} , \
                 which is already on its own path — refusing to follow it",
                layer.layer,
                layer.digest,
                inc.digest
            );
        }
        // Clause 3: an export that cannot follow the composition SAYS SO. A
        // missing include is an error naming it and its corrective install,
        // not a directory that is quietly missing that layer's crates.
        let Some((owner, entry)) = store.find_anywhere(&inc.digest)? else {
            bail!(
                "layer {} composes {}, which is not installed — this export would silently \
                 omit its payloads. `varve install` it, then re-run the export \
                 (REQ-COMPOSEEXPORT-001 clause 3)",
                layer.layer,
                inc.layer.clone().unwrap_or_else(|| inc.digest.clone())
            );
        };
        // A layer reachable by two paths is exported once, not refused.
        if out.iter().any(|c| c.entry.digest == entry.digest) {
            continue;
        }
        // Whose root vouches for this layer? The include names a realm, and
        // that realm's root is authoritative for it — not ours.
        let named_realm = match &inc.realm {
            Some(name) => {
                let realm = varve_core::resolve_realm(&cwd, name).with_context(|| {
                    format!(
                        "layer {} composes a layer from realm '{name}', but that realm is not \
                         defined here — add it to varve-realms.toml so its trust root can \
                         verify what it vouches for",
                        layer.layer
                    )
                })?;
                Some((
                    varve_core::PinnedKeyVerifier::from_public_key_bytes(&realm.trust_root)
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                    name.clone(),
                ))
            }
            None => None,
        };
        let (verifier, realm) = match &named_realm {
            Some((v, name)) => (v, name.as_str()),
            None => (own_verifier, own_realm),
        };
        varve_core::verify_installed(&owner, &entry, verifier, &varve_core::host_platform())
            .with_context(|| {
                format!(
                    "composed layer {} failed verification against realm '{realm}' — refusing \
                     to export payloads varve cannot vouch for. If the included layer comes \
                     from a DIFFERENT realm, this is the expected result of an `[[include]]` \
                     with no `realm =`",
                    entry.layer
                )
            })?;
        out.push(ComposedLayer {
            store: owner.clone(),
            entry: entry.clone(),
            realm: realm.to_string(),
        });
        ancestors.push(entry.digest.clone());
        walk_composition(&owner, &entry, verifier, realm, ancestors, out)?;
        ancestors.pop();
    }
    Ok(())
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
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    // One registry per TOOL, unioned across the composition. A tool name is
    // dispatchable, so the tool rule applies here rather than the payload rule
    // (REQ-COMPOSEEXPORT-001 clause 2): two layers claiming one name is
    // ambiguous unless they agree byte for byte.
    let mut registries: std::collections::BTreeMap<String, (serde_json::Value, String)> =
        std::collections::BTreeMap::new();
    for l in &layers {
        let payload = std::fs::read(l.entry.root.join("layer.json"))?;
        let manifest = varve_core::LayerManifest::parse(&payload)?;
        let export = varve_core::bazel::export(&manifest);
        for (tool, json) in export.registries {
            if let Some((first, first_realm)) = registries.get(&tool)
                && first != &json
            {
                bail!(
                    "tool '{tool}' is described differently by two layers in this composition \
                     (realm '{first_realm}' and realm '{}') — refusing to choose which \
                     checksum registry is the real one",
                    l.realm
                );
            }
            registries.insert(tool, (json, l.realm.clone()));
        }
        for (tool, platform, reason) in &export.skipped {
            eprintln!("skipped {tool} ({platform}): {reason}");
        }
    }
    std::fs::create_dir_all(out)?;
    for (tool, (json, _)) in &registries {
        let path = out.join(format!("{tool}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(json)?)?;
        println!("wrote {}", path.display());
    }
    if registries.is_empty() {
        bail!(
            "nothing exported — no entry in layer {} (or the {} layer(s) it composes) carries \
             source provenance",
            target.entry.layer,
            layers.len() - 1
        );
    }
    write_export_stamp(out, &target.entry, "bazel-registry")?;
    Ok(())
}

/// One payload lifted out of a verified layer, ready for an export adapter.
struct VerifiedPayload {
    name: String,
    version: String,
    /// The SIGNED digest, `sha256:<hex>`, re-checked against these bytes.
    digest: String,
    bytes: Vec<u8>,
    /// The entry's signed annotations, carried through so an adapter can read
    /// the producer's declarations rather than guess them. `export-sdk` needs
    /// `eu.pulseengine.varve.sdk.prefix` (REQ-SDK-001 clause 4), and a budget
    /// recovered from anywhere but the signature would not be attributable.
    annotations: std::collections::BTreeMap<String, String>,
}

impl VerifiedPayload {
    /// One signed annotation, by name.
    fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }
}

/// Collect the entries of one KIND out of ONE already-verified installed layer.
/// The shared front-half of every export adapter: the layer was verified by
/// `export_target` (or, for a composed layer, against its own realm's root),
/// and each blob is still re-hashed against its signed digest before it can
/// leave the store. Shared so the `crate` and `vsix` paths cannot drift apart
/// on the part that matters — which bytes are allowed out.
fn payloads_of_layer(
    store: &Store,
    entry: &varve_core::store::InstalledLayer,
    want: varve_core::PayloadKind,
) -> anyhow::Result<Vec<VerifiedPayload>> {
    let payload = std::fs::read(entry.root.join("layer.json"))?;
    let manifest = varve_core::LayerManifest::parse(&payload)?;
    let kind = want.as_str();

    let mut found = Vec::new();
    let host = varve_core::host_platform();
    for e in &manifest.entries {
        if e.kind().map_err(|err| anyhow::anyhow!(err.to_string()))? != want {
            continue;
        }
        // Only the payloads THIS host has. `install` platform-filters what it
        // lays down, so walking every platform's entry meant resolving a
        // foreign entry to the one on-disk file — the payload path is
        // name/version and carries no platform — and then comparing the host's
        // bytes against that entry's signed digest. The mismatch was real and
        // the conclusion was wrong: it reported tampering for a payload that
        // was simply built for another machine. Latent for every per-platform
        // non-tool payload; found by depositing spar's per-platform .vsix set.
        if !varve_core::platform::entry_matches(
            e.annotations
                .get(varve_core::platform::ANN_PLATFORM)
                .map(String::as_str),
            &host,
        ) {
            continue;
        }
        let name = e
            .annotations
            .get("eu.pulseengine.tool")
            .with_context(|| format!("{kind} entry missing its name annotation"))?;
        let version = e
            .annotations
            .get("eu.pulseengine.tool.version")
            .with_context(|| format!("{kind} entry missing its version annotation"))?;
        // Locate by ENTRY, not by name: a layer may hold several versions of
        // one payload, each under its own path, and `serde@1.0.200` must export
        // its OWN bytes rather than whichever version landed last
        // (REQ-STORE-002 clause 5).
        let bytes_path = store.entry_path(entry, e).with_context(|| {
            format!("{kind} '{name}' version {version} is not present in the store")
        })?;
        let bytes = std::fs::read(&bytes_path)?;
        // Defense in depth: re-hash the on-disk bytes against the signed digest
        // ourselves, regardless of platform filtering, so what we export is the
        // exact bytes the trust root anchored.
        if varve_core::manifest_digest(&bytes) != e.digest {
            bail!(
                "{kind} '{name}' version {version} on-disk bytes do not match the signed \
                 digest {}",
                e.digest
            );
        }
        found.push(VerifiedPayload {
            name: name.clone(),
            version: version.clone(),
            digest: e.digest.clone(),
            bytes,
            annotations: e.annotations.clone(),
        });
    }
    Ok(found)
}

/// Collect the entries of one KIND out of EVERY layer in the composition
/// (REQ-COMPOSEEXPORT-001 clause 1), applying the payload collision rule —
/// which is not the tool rule (clause 2).
fn collect_verified_payloads(
    layers: &[ComposedLayer],
    want: varve_core::PayloadKind,
) -> anyhow::Result<Vec<VerifiedPayload>> {
    let kind = want.as_str();
    let mut offered = Vec::new();
    for l in layers {
        for p in payloads_of_layer(&l.store, &l.entry, want)? {
            offered.push((
                varve_core::compose::PayloadOrigin {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    digest: p.digest.clone(),
                    realm: l.realm.clone(),
                    layer: l.entry.layer.to_string(),
                },
                p,
            ));
        }
    }
    let kept =
        varve_core::compose::union_payloads(offered).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if kept.is_empty() {
        let root = &layers[0].entry;
        if layers.len() > 1 {
            bail!(
                "nothing exported — layer {} and the {} layer(s) it composes carry no `{kind}` \
                 entries",
                root.layer,
                layers.len() - 1
            );
        }
        bail!(
            "nothing exported — layer {} carries no `{kind}` entries",
            root.layer
        );
    }
    Ok(kept.into_iter().map(|(_, p)| p).collect())
}

/// Collect the verified `crate`-kind entries of a whole composition as
/// CrateEntry values — the shared front-half of every Cargo-facing export.
fn collect_verified_crates(
    layers: &[ComposedLayer],
) -> anyhow::Result<Vec<varve_core::crateexport::CrateEntry>> {
    let mut crates = Vec::new();
    for p in collect_verified_payloads(layers, varve_core::PayloadKind::Crate)? {
        let cksum = p
            .digest
            .strip_prefix("sha256:")
            .with_context(|| format!("crate '{}' digest is not sha256:<hex>", p.name))?
            .to_string();
        crates.push(varve_core::crateexport::CrateEntry {
            name: p.name,
            version: p.version,
            cksum,
            bytes: p.bytes,
        });
    }
    Ok(crates)
}

/// One line telling the reader how many layers an export actually covered
/// (REQ-COMPOSEEXPORT-001 clause 3). A composed export that says nothing is
/// indistinguishable from an export that silently followed only the root.
fn report_composition(layers: &[ComposedLayer]) {
    if layers.len() < 2 {
        return;
    }
    println!("following the composition: {} layers —", layers.len());
    for l in layers {
        println!(
            "  {} {} (verified against realm '{}')",
            l.entry.layer, l.entry.digest, l.realm
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn keygen(out: &std::path::Path, public: Option<&std::path::Path>) -> anyhow::Result<()> {
    // Refuse to clobber: a signing key is not something to overwrite by accident.
    if out.exists() {
        bail!(
            "{} already exists — refusing to overwrite a signing key. Move it aside first.",
            out.display()
        );
    }
    if let Some(p) = public
        && p.exists()
    {
        bail!(
            "{} already exists — refusing to overwrite a published trust root. \
             Re-print it instead with `varve pubkey <key>`, or choose another path.",
            p.display()
        );
    }
    let (secret, pub_hex) = varve_core::keys::generate();

    std::fs::write(out, format!("{secret}\n"))
        .with_context(|| format!("cannot write {}", out.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner-only from the moment it exists.
        std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600))?;
    }
    match public {
        Some(p) => {
            std::fs::write(p, format!("{pub_hex}\n"))
                .with_context(|| format!("cannot write {}", p.display()))?;
            println!(
                "signing key -> {} (KEEP SECRET, mode 0600)\npublic half -> {}\n\n\
                 Consumers pin the public half as a realm's trust-root:\n\n  \
                 [realm.<your-realm>]\n  registry   = \"oci://<your registry>\"\n  \
                 trust-root = \"{pub_hex}\"\n\n\
                 Sign layers with: varve deposit --key {} …",
                out.display(),
                p.display(),
                out.display()
            );
        }
        None => {
            println!(
                "signing key -> {} (KEEP SECRET, mode 0600)\n\n\
                 Its public half — what consumers pin as a realm's trust-root:\n\n  {pub_hex}\n\n\
                 Re-print it any time with: varve pubkey {}",
                out.display(),
                out.display()
            );
        }
    }
    Ok(())
}

fn pubkey(key: &std::path::Path) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    let public = varve_core::keys::public_from_secret(&text, &key.display().to_string())?;
    // Bare on stdout, so it composes: trust-root = "$(varve pubkey root.key)"
    println!("{public}");
    Ok(())
}

/// `layer.toml` → the assembler's environment (REQ-LAYERREPO-001).
///
/// Nothing here is trusted work: the output is consumed by the assembler, which
/// verifies every byte it downloads regardless of what named it. What this must
/// not do is translate a manifest INEXACTLY — a dropped tool or a truncated
/// version produces a layer that signs and verifies while carrying the wrong
/// contents, so `layerspec` refuses rather than approximates.
fn layer_spec(manifest: &std::path::Path, json: bool) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(manifest).with_context(|| {
        format!(
            "cannot read layer manifest {}. This is the realm's own \
             `layer.toml` — see `varve docs layer-repo`.",
            manifest.display()
        )
    })?;
    let parsed = varve_core::layerspec::parse_layer_manifest(&text)
        .with_context(|| format!("in {}", manifest.display()))?;
    let env = varve_core::layerspec::assembler_env(&parsed)
        .with_context(|| format!("in {}", manifest.display()))?;
    if json {
        // The same values, as an object. `layer-spec` is tagged (CI), and a
        // pipeline must never have to scrape prose to drive one
        // (REQ-CIGATE-001 clause 2) — even when the prose is already
        // KEY=value, since that shape exists for `$GITHUB_ENV`, not for
        // programs.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "tarball_tools": env.layer_tools,
                "wsc_version": env.wsc_version,
                "vsix_packages": env.vsix_packages,
                "realm": env.realm,
                "channel": env.channel,
                "registry": env.registry,
                "varve_version": env.varve_version,
            }))?
        );
    } else {
        print!("{}", env.render());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_attestation(
    store: &Store,
    layer: Option<&str>,
    kind: &str,
    file: &std::path::Path,
    producer: &str,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
    attach_to: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<()> {
    let kind: varve_core::attest::AttestationKind = kind.parse()?;
    // Trust first, as everywhere: binding an attestation to a layer we cannot
    // verify would assert an association we have no basis for.
    let entry = export_target(store, layer)?.entry;
    let bytes = std::fs::read(file)
        .with_context(|| format!("cannot read attestation {}", file.display()))?;
    let st = varve_core::attest::statement(
        &entry.layer.to_string(),
        &entry.digest,
        kind,
        &bytes,
        producer,
    );
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    // Refuse a key that cannot produce verifiable signatures BEFORE signing.
    // varve used to accept 64 bytes of entropy here and emit a signed layer no
    // trust root could ever verify, exit 0 (REQ-PRODUCER-001).
    let sk = varve_core::keys::check_keypair(&hex_key, &key.display().to_string())?;
    let envelope = varve_core::attest::sign(&st, &sk, key_id)?;
    std::fs::write(out, &envelope).with_context(|| format!("cannot write {}", out.display()))?;
    // Carriage (REQ-ATTEST-002): both blobs go into the layout as referrer
    // entries — the statement AND the attested bytes verbatim. Carrying only
    // the statement would put a claim on the far side of the air gap with
    // nothing to check it against.
    if let Some(layout) = attach_to {
        varve_core::attestcarry::attach(layout, envelope.as_bytes(), &bytes).with_context(
            || {
                format!(
                    "cannot attach the attestation to layout {}",
                    layout.display()
                )
            },
        )?;
    }
    let mut human = format!(
        "signed a {kind} attestation statement by {producer} -> {out}\n\
         \u{20}\u{20}attestation digest : {adigest}\n\
         \u{20}\u{20}bound to layer     : {layer} ({ldigest})\n\
         varve vouches that these bytes accompany this layer; what {producer} claims is \
         {producer}'s to prove.",
        out = out.display(),
        adigest = st.digest,
        layer = entry.layer,
        ldigest = st.layer_manifest_digest,
    );
    if let Some(layout) = attach_to {
        human.push_str(&format!(
            "\nattached to layout {} as referrer artifacts — the statement AND the bytes, so it \
             travels with the layer through a registry push, `varve archive`, and an offline \
             install",
            layout.display()
        ));
    }
    report(
        json,
        &human,
        serde_json::json!({
            "command": "sign-attestation",
            "kind": kind.to_string(),
            "producer": producer,
            "attestation_digest": st.digest,
            "layer": entry.layer.to_string(),
            "layer_manifest_digest": st.layer_manifest_digest,
            "key_id": key_id,
            "out": out.display().to_string(),
            "attached_to": attach_to.map(|l| l.display().to_string()),
        }),
    );
    Ok(())
}

fn check_attestation(
    store: &Store,
    statement: &std::path::Path,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let ctx = project_ctx(store)?;
    let root = ctx_root_bytes(&ctx)?;
    // VERIFY THE LAYER, not just the statement. Clean-room review found this
    // reporting "attestation OK" over a tampered tool binary and a forged
    // layer.json — states `varve verify` rejects. Both values this command
    // then prints and joins on (the layer identity and its digest) are local
    // labels: InstalledLayer.digest is the store DIRECTORY NAME and .layer is
    // parsed from layer.json, neither authenticated until verify_installed
    // re-checks the retained envelope. This is the command a disconnected
    // consumer runs; it must not be the one that trusts unverified local state.
    let entry = export_target(store, None)?.entry;
    let envelope = std::fs::read(statement)
        .with_context(|| format!("cannot read statement {}", statement.display()))?;
    let bytes = std::fs::read(file)
        .with_context(|| format!("cannot read attestation {}", file.display()))?;
    // 1. The statement must verify against the pinned root — offline.
    let st = varve_core::attest::verify_statement(&envelope, &root)?;
    // 2. …and it must actually describe THESE bytes and THIS layer.
    varve_core::attest::check(&st, &bytes, &entry.digest, &entry.layer.to_string())?;
    println!(
        "attestation OK: a {kind} document produced by {producer}, {n} bytes\n\
         \u{20}\u{20}attestation digest : {adigest}\n\
         \u{20}\u{20}bound to layer     : {layer} ({ldigest})\n\
         note: varve verified the ASSOCIATION and the bytes' integrity, and re-verified the \
         layer itself. Any claim {producer} makes INSIDE the document is verified with \
         {producer}'s own key, not this one.",
        kind = st.kind,
        producer = st.producer,
        n = bytes.len(),
        adigest = st.digest,
        layer = entry.layer,
        ldigest = st.layer_manifest_digest,
    );
    Ok(())
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
    let entry = export_target(store, layer)?.entry;
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

/// An export directory, created if needed, resolved to an absolute path for
/// the MESSAGES varve prints — a line telling the reader where the export went
/// has to be pasteable from another shell.
///
/// Nothing absolute reaches the generated `.cargo/config.toml` any more: Cargo
/// resolves a relative `local-registry` against the directory that holds
/// `.cargo/`, so the export carries a bare subdirectory name and two exports of
/// one layer are byte-identical (REQ-REPRO-001 clause 1).
fn absolute_export_dir(out: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    out.canonicalize()
        .with_context(|| format!("cannot resolve {} to an absolute path", out.display()))
}

fn export_cargo(store: &Store, layer: Option<&str>, out: &std::path::Path) -> anyhow::Result<()> {
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    let out = &absolute_export_dir(out)?;
    let crates = collect_verified_crates(&layers)?;
    let registry_dir = out.join(varve_core::crateexport::REGISTRY_SUBDIR);
    let n = varve_core::crateexport::export_local_registry(&crates, &registry_dir)?;
    let cargo_dir = out.join(".cargo");
    std::fs::create_dir_all(&cargo_dir)?;
    let config = cargo_dir.join("config.toml");
    std::fs::write(
        &config,
        varve_core::crateexport::cargo_config_toml(varve_core::crateexport::REGISTRY_SUBDIR),
    )?;
    println!(
        "exported {n} verified crate(s) to a local registry at {} — the generated {} names \
         `{}` RELATIVE to {}, which is where Cargo resolves it from, so export straight into \
         your project root (`--out .`) or copy the whole directory; then `cargo build --offline`",
        registry_dir.display(),
        config.display(),
        varve_core::crateexport::REGISTRY_SUBDIR,
        out.display(),
    );
    // REQ-NOSILENT-001 clause 2. Until v0.27.0 the index carried "deps":[] and
    // "features":{} for every crate, and the worst observed outcome was a
    // build that exits 0 having compiled everything featureless — not a
    // failure anyone would notice. That is fixed, but the index is only ever
    // as good as what each `.crate` declares, and a registry index cannot
    // express everything a vendor directory can. Say which one is stronger,
    // on every run, rather than closing with an instruction to run the very
    // build that can succeed while being wrong.
    println!(
        "  the index is derived from each .crate's own Cargo.toml. If a build resolves \
         differently than you expect, `varve export-crates-vendor` sidesteps index \
         resolution entirely by vendoring the sources — it is the stronger of the two."
    );
    write_export_stamp(out, &target.entry, "cargo")?;
    Ok(())
}

fn export_bazel_distdir(
    store: &Store,
    layer: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    let crates = collect_verified_crates(&layers)?;
    let n = varve_core::crateexport::export_distdir(&crates, out)?;
    println!(
        "wrote {n} verified .crate tarball(s) to the Bazel distdir {} — with a pre-generated \
         crate_universe output, `bazel build --distdir={}` resolves them offline by sha256",
        out.display(),
        out.display()
    );
    write_export_stamp(out, &target.entry, "bazel-distdir")?;
    Ok(())
}

/// `varve export-vsix --out D` (REQ-VSIX-001 clause 3): lay the layer's
/// verified `.vsix` files out under names `code --install-extension` consumes
/// directly, and stamp the directory so `varve verify --export D` catches the
/// pin moving on without the export.
fn export_vsix(store: &Store, layer: Option<&str>, out: &std::path::Path) -> anyhow::Result<()> {
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    // Absolute, because the whole point of the printed line is that it can be
    // pasted into a different shell in a different directory.
    let out = &absolute_export_dir(out)?;
    let extensions: Vec<varve_core::VsixEntry> =
        collect_verified_payloads(&layers, varve_core::PayloadKind::Vsix)?
            .into_iter()
            .map(|p| varve_core::VsixEntry {
                name: p.name,
                version: p.version,
                bytes: p.bytes,
            })
            .collect();
    let n = varve_core::export_vsix(&extensions, out)?;
    println!(
        "exported {n} verified VS Code extension(s) to {} — install them with:",
        out.display()
    );
    // Every file, named: an extension is installed one at a time, and the
    // reader needs the exact argument, not a glob they have to expand.
    for e in &extensions {
        println!(
            "  code --install-extension {}",
            out.join(varve_core::vsixexport::vsix_file_name(&e.name, &e.version))
                .display()
        );
    }
    write_export_stamp(out, &target.entry, "vsix")?;
    Ok(())
}

/// `varve export-sdk --out D` (REQ-SDK-001 clause 3): materialise the layer's
/// verified tree payload under D, relocated from the prefix its producer signed
/// to D itself, and stamp the directory so `varve verify` catches the pin moving
/// on without the export.
///
/// The relocation budget comes from the SIGNED annotation, never from the
/// archive's contents or from a flag: a consumer able to name a longer prefix
/// could talk varve into patching a path that does not fit the interpreter
/// field, which is a tree of binaries that fail to exec with no explanation.
fn export_sdk(
    store: &Store,
    layer: Option<&str>,
    out: &std::path::Path,
    select: Option<&str>,
) -> anyhow::Result<()> {
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    let mut trees = collect_verified_payloads(&layers, varve_core::PayloadKind::Sdk)?;
    if let Some(name) = select {
        trees.retain(|p| p.name == name);
        if trees.is_empty() {
            bail!(
                "layer {} carries no `sdk` payload named '{name}'",
                target.entry.layer
            );
        }
    }
    // One destination is patched into ONE tree. Two trees relocated into the
    // same directory would overwrite each other's files and produce a hybrid
    // that hashes to nothing anyone signed, so ambiguity is refused BY NAME —
    // with the flag that resolves it, because a refusal without a fix is a
    // dead end.
    if trees.len() > 1 {
        let names: Vec<String> = trees
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        bail!(
            "layer {} carries {} `sdk` payloads ({}) and an export relocates ONE tree into \
             --out: the destination path is patched into the binaries, so two of them in one \
             directory would overwrite each other. Name the one you want with \
             `--select <NAME>`.",
            target.entry.layer,
            trees.len(),
            names.join(", ")
        );
    }
    let tree = trees.remove(0);
    // The budget, from inside the signature (clause 4). `collect_verified_payloads`
    // hands back bytes; the prefix is an annotation of the manifest ENTRY, which
    // is why the payload carries its annotations through.
    let built_prefix = tree
        .annotation(varve_core::ANN_SDK_PREFIX)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{}", varve_core::SdkExportError::NoBuiltPrefix))
        .with_context(|| {
            format!(
                "sdk '{}' version {} in layer {}",
                tree.name, tree.version, target.entry.layer
            )
        })?;
    // Absolute, because the destination is PATCHED INTO the SDK's binaries: a
    // relative one would resolve against whatever directory a compiler happens
    // to run in.
    let out = &absolute_export_dir(out)?;
    let report = varve_core::export_sdk(&tree.bytes, &built_prefix, out)?;
    println!(
        "exported sdk {}@{} to {} — {} dir(s), {} file(s), {} symlink(s); relocated from {} \
         ({} field(s) patched in place, {} text substitution(s), {} symlink(s) re-pointed)",
        tree.name,
        tree.version,
        out.display(),
        report.dirs,
        report.files,
        report.symlinks,
        built_prefix,
        report.patched_fields,
        report.substitutions,
        report.relocated_symlinks,
    );
    println!(
        "the store keeps the signed archive untouched — what is here is DERIVED and \
         deliberately outside the trust path (REQ-SDK-001 clause 2)"
    );
    // Exactly `ExportKind::Sdk`, not the string "sdk" spelled again: a
    // declaration in varve.toml is compared against this stamp, and a
    // mismatch reports the declared export as never produced at all.
    write_export_stamp(out, &target.entry, varve_core::ExportKind::Sdk.as_str())?;
    Ok(())
}

fn export_crates_vendor(
    store: &Store,
    layer: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let target = export_target(store, layer)?;
    let layers = composition_for_export(&target)?;
    report_composition(&layers);
    let out = &absolute_export_dir(out)?;
    let crates = collect_verified_crates(&layers)?;
    let vendor_dir = out.join(varve_core::crateexport::VENDOR_SUBDIR);
    let n = varve_core::crateexport::export_vendor_dir(&crates, &vendor_dir)?;
    let cargo_dir = out.join(".cargo");
    std::fs::create_dir_all(&cargo_dir)?;
    let config = cargo_dir.join("config.toml");
    std::fs::write(
        &config,
        varve_core::crateexport::vendored_config_toml(varve_core::crateexport::VENDOR_SUBDIR),
    )?;
    println!(
        "vendored {n} verified crate(s) to {} — a cargo-vendor tree bare Cargo and Corrosion \
         build against offline; the generated {} names `{}` RELATIVE to {}, so export straight \
         into your project root (`--out .`) or copy the whole directory (rules_rust needs BUILD \
         files on top — not yet emitted, REQ-VENDOR-002)",
        vendor_dir.display(),
        config.display(),
        varve_core::crateexport::VENDOR_SUBDIR,
        out.display(),
    );
    write_export_stamp(out, &target.entry, "crates-vendor")?;
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
    json: bool,
    force: bool,
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
                sdk_prefix: tool.sdk_prefix,
            });
        }
        let includes = file_spec
            .includes
            .into_iter()
            .map(|i| varve_core::deposit::DepositInclude {
                digest: i.digest,
                realm: i.realm,
                layer: i.layer,
            })
            .collect();
        return run_deposit(
            &file_spec.layer,
            &file_spec.channel,
            file_spec.counter,
            issued_at,
            key,
            key_id,
            out,
            deposit_tools,
            includes,
            json,
            force,
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
            sdk_prefix: None,
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
        // Composition is expressed in a spec file's [[include]] tables; the
        // individual flags deliberately do not grow a way to say it.
        Vec::new(),
        json,
        force,
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
    includes: Vec<varve_core::deposit::DepositInclude>,
    json: bool,
    force: bool,
) -> anyhow::Result<()> {
    // `deposit` writes an oci-layout DIRECTORY. A registry-shaped --out used to
    // report success while creating a local directory literally named
    // `./oci:/ghcr.io/...` (REQ-PRODUCER-001).
    let out_str = out.to_string_lossy();
    if let Some(scheme) = out_str.split_once("://").map(|(s, _)| s.to_string()) {
        bail!(
            "--out {out_str} looks like a {scheme} registry reference, but deposit writes a \
             LOCAL oci-layout directory. Deposit to a directory, then push that directory to \
             the registry with your OCI client (e.g. `oras cp --from-oci-layout <dir>:<tag> \
             {out_str}`)."
        );
    }
    let hex_key = std::fs::read_to_string(key)
        .with_context(|| format!("cannot read signing key {}", key.display()))?;
    // Refuse a key that cannot produce verifiable signatures BEFORE signing.
    // varve used to accept 64 bytes of entropy here and emit a signed layer no
    // trust root could ever verify, exit 0 (REQ-PRODUCER-001).
    let sk = varve_core::keys::check_keypair(&hex_key, &key.display().to_string())?;
    let spec = varve_core::DepositSpec {
        includes,
        layer: layer.parse()?,
        channel: channel.to_string(),
        counter,
        issued_at: issued_at.to_string(),
        tools: deposit_tools,
    };
    let entries = spec.tools.len();
    let includes = spec.includes.len();
    let channel = spec.channel.clone();
    let issued_at = spec.issued_at.clone();
    // REQ-NODESTROY-001: refuses by default when `out` already carries
    // referrers. `--force` is the deliberate override, and the refusal names
    // it — so the flag has to exist, or the message is telling the operator to
    // run something clap will reject.
    let outcome = varve_core::deposit_with_options(
        &spec,
        &sk,
        key_id,
        out,
        &varve_core::DepositOptions { force },
    )?;
    report(
        json,
        &format!(
            "deposited layer {} (counter {}) {} at {}",
            outcome.layer,
            outcome.counter,
            outcome.digest,
            out.display()
        ),
        // `manifest_digest` is the field a pipeline came here for: it is what
        // a pin records, what a `[[include]]` names, and what an attestation
        // binds to. It used to be recoverable only by cutting an English
        // sentence apart on spaces.
        serde_json::json!({
            "command": "deposit",
            "layer": outcome.layer.to_string(),
            "channel": channel,
            "counter": outcome.counter,
            "issued_at": issued_at,
            "manifest_digest": outcome.digest,
            "entries": entries,
            "includes": includes,
            "key_id": key_id,
            "out": out.display().to_string(),
        }),
    );
    Ok(())
}

fn archive(
    store: &Store,
    layer: &str,
    dest: &std::path::Path,
    platform: Option<String>,
    force: bool,
    allow_no_status: bool,
) -> anyhow::Result<()> {
    let platform = platform.unwrap_or_else(varve_core::host_platform);
    // Use the PROJECT'S store. `archive` filtered the ambient top-level core,
    // so for a realm-pinned layer it reported "not installed" while `list`,
    // `verify`, `which`, `run` and `sbom` all resolved it — and its corrective
    // advice (`varve install`) was a no-op loop. That takes out the offline
    // path, which is varve's whole thesis (REQ-STORE-001).
    let store = match project_ctx(store) {
        Ok(ctx) => ctx.store,
        Err(_) => store.clone(),
    };
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
    let summary = varve_core::export_archive_with_options(
        &store,
        &entry,
        dest,
        &platform,
        &varve_core::ArchiveOptions {
            force,
            allow_no_status,
        },
    )?;
    println!(
        "archived layer {} {} as oci-layout at {}",
        entry.layer,
        entry.digest,
        dest.display()
    );
    // What crossed, and what did not. An archive holds one platform's payloads
    // because that is all this machine installed, and an operator carrying this
    // media to a mixed site has to learn that BEFORE they travel, not from a
    // failed install on the far side of the gap (varve#80).
    println!(
        "  {} payload{} for {}",
        summary.archived,
        if summary.archived == 1 { "" } else { "s" },
        summary.platform
    );
    if !summary.omitted.is_empty() {
        let total: usize = summary.omitted.values().sum();
        let detail = summary
            .omitted
            .iter()
            .map(|(p, n)| format!("{p} ({n})"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {total} entr{} omitted — this core holds no payload for them: {detail}\n  \
             this archive installs on {} only; for another platform, install and archive the \
             layer there.",
            if total == 1 { "y" } else { "ies" },
            summary.platform
        );
    }
    // REQ-NOSILENT-001 clause 1: loud, on stderr, and it names the consequence
    // rather than the condition. `archive` was already verbose about omitted
    // PLATFORM payloads and silent about this — the inconsistency that hid it.
    if summary.baseline_missing {
        eprintln!(
            "warning: this core cached no baseline line-status for line {}, so the archive \
             carries none. Every consumer of it gets a permanently failing `varve status` and \
             no yank can ever reach them — and an air-gapped consumer cannot ask a registry \
             instead. Install from a source that carries the baseline (a registry, or a layout \
             with one attached) and archive again. Pass --allow-no-status to silence this if \
             you are shipping an archive that is not meant to receive advisories.",
            entry.layer.line()
        );
    }
    Ok(())
}

/// Per-project context (REQ-REALM-001): when the pin names a realm, that
/// realm's trust root and store namespace are AUTHORITATIVE — the ambient
/// environment cannot substitute either. Realmless pins keep the legacy
/// layout and the env-configured trust root.
struct ProjectCtx {
    pin: Pin,
    /// The directory holding `varve.toml` — what every declared export
    /// destination is relative to (REQ-EXPORTDECL-001 clause 2).
    root: PathBuf,
    store: Store,
    realm: Option<varve_core::Realm>,
}

fn project_ctx(base: &Store) -> anyhow::Result<ProjectCtx> {
    let (pin, root) = load_pin()?;
    match &pin.realm {
        Some(name) => {
            let cwd = std::env::current_dir().context("cannot determine working directory")?;
            let realm = varve_core::resolve_realm(&cwd, name)?;
            let store = Store::at(realm.effective_root(base.root()));
            Ok(ProjectCtx {
                pin,
                root,
                store,
                realm: Some(realm),
            })
        }
        None => Ok(ProjectCtx {
            pin,
            root,
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
                // Tell the layout which platform we want, so a payload it does
                // not carry is reported as the single-platform archive it is
                // rather than as a bare missing digest (varve#80).
                Box::new(varve_core::OciLayoutSource::at(path).for_platform(&platform))
            } else {
                Box::new(varve_core::DirSource::at(path))
            }
        };
    let source = &*source;
    let mut marks = varve_core::HighWaterMarks::load(store.root())?;
    let now = today_rfc3339();
    // The realm's line-index obligation (REQ-INDEXAUTH-001). The realm is
    // where every other trust question is settled, so it is where this one is
    // read: its name for the error, its trust root as the ONLY key an index
    // may verify against, and its `signed-index` declaration deciding whether
    // absence is fatal (clause 5). A realmless pin gets `None` — there is then
    // no root that could have signed an index, so there is nothing to check
    // and nothing that could be hidden from a check that cannot exist.
    let index = ctx.realm.as_ref().map(|realm| varve_core::IndexPolicy {
        realm: &realm.name,
        root_public_key: &realm.trust_root,
        required: realm.signed_index,
    });
    let policy = varve_core::InstallPolicy {
        index,
        now: &now,
        staleness_threshold_days: 90,
        platform: &platform,
    };
    let outcome = varve_core::install(pin, source, &verifier, store, &mut marks, &policy)?;
    // Clause 4: REPORT what the realm asserts the line contains, beside what
    // this install accepted. Reported and NOT enforced, deliberately — raising
    // the anti-rollback mark to the newest counter that merely EXISTS would
    // make a deliberately-pinned older layer uninstallable the moment the realm
    // publishes a newer one, which breaks frozen toolchains to defend against
    // an attack varve does not have (a consumer naming an exact layer cannot be
    // tricked by a withheld newer one). What they CANNOT do is see it — so it
    // is said out loud here.
    if let Some(high_water) = outcome.index_high_water {
        let realm = ctx.realm.as_ref().map(|r| r.name.as_str()).unwrap_or("-");
        println!(
            "  realm '{realm}' signed index for line {}: greatest counter {high_water}; this \
             install accepted counter {} (reported, not enforced — your pin stays installable)",
            pin.layer.line(),
            outcome.counter
        );
    }
    if let Some(age) = outcome.staleness_days {
        eprintln!(
            "warning: layer {} was issued {age} days ago — check whether a newer deposit of \
             its line exists",
            outcome.layer
        );
    }
    // Carriage, reported at the moment the evidence crosses the boundary
    // (REQ-ATTEST-002). `varve verify` is what says whether each still binds;
    // this only says what travelled, so a consumer downstream of a mirror can
    // see a drop instead of inferring it from silence.
    if outcome.attestations_carried > 0 {
        println!(
            "  carried {} attestation(s) with the layer — `varve verify` reports what each \
             claims and whether it still binds",
            outcome.attestations_carried
        );
    }
    if let Some(note) = &outcome.attestation_note {
        eprintln!(
            "warning: layer {} carried attestations that did not survive the trip: {note}",
            outcome.layer
        );
    }

    // A composed layer is only usable once EVERYTHING it composes is installed
    // — transitively (REQ-NOSILENT-001 clause 4). install exited 0 on a
    // composition `verify` rejects, so `run` then executed a tool from an
    // unverified included layer, and the error the user eventually hit named
    // `varve install`, which cannot take a layer or a digest, so following it
    // was a no-op loop.
    //
    // The check used to look only at the root's OWN includes, so a chain
    // root -> mid -> leaf with `leaf` missing passed: root's direct includes
    // were all present. `verify` walks the whole graph and rejects it at depth
    // 2, while `docs verify` promises "the CI gate and the install agree".
    // They now reach the same verdict.
    let mut composed_count = 0usize;
    if let Some(entry) = ctx.store.get(&outcome.digest)? {
        let mut missing: Vec<String> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut queue: Vec<varve_core::store::InstalledLayer> = vec![entry];
        let mut depth = 0usize;
        while let Some(current) = queue.pop() {
            depth += 1;
            if depth > varve_core::compose::MAX_DEPTH * 4 {
                break;
            }
            let Ok(bytes) = std::fs::read(current.root.join("layer.json")) else {
                continue;
            };
            let Ok(view) = varve_core::compose::view(&bytes) else {
                continue;
            };
            for inc in &view.includes {
                if !seen.insert(inc.digest.clone()) {
                    continue;
                }
                composed_count += 1;
                match ctx.store.find_anywhere(&inc.digest)? {
                    Some((_, found)) => queue.push(found),
                    None => {
                        // Name the realm too: "install it" is not actionable
                        // without knowing WHOSE layer it is, and a consumer
                        // composing two realms cannot tell them apart by id.
                        let name = inc.layer.clone().unwrap_or_else(|| inc.digest.clone());
                        missing.push(match &inc.realm {
                            Some(r) => format!("{name} (realm '{r}')"),
                            None => name,
                        });
                    }
                }
            }
        }
        if !missing.is_empty() {
            // Clause 3: REFUSE BEFORE claiming success. This used to print
            // "installed layer X" and THEN error, leaving a layer in
            // `varve list` that no other command would touch.
            bail!(
                "layer {} composes {} layer(s) that are not installed: {}.\n\
                 Install each first — a composed layer names what it needs by digest, \
                 but does not fetch it. `install` resolves THIS project's pin, so \
                 pointing --from at the other source is not enough: give the included \
                 layer its own pin (a directory whose varve.toml names that realm, \
                 channel and layer), run `varve install` there, then re-run this one. \
                 Both land in the same store. The list above is TRANSITIVE — a layer \
                 named here may be one this layer composes only indirectly. \
                 See `varve docs composition`.",
                outcome.layer,
                missing.len(),
                missing.join(", ")
            );
        }
    }
    println!(
        "installed layer {} (counter {}) {}",
        outcome.layer, outcome.counter, outcome.digest
    );
    if composed_count > 0 {
        println!(
            "  composes {composed_count} installed layer(s), transitively — `varve verify` \
             checks each against its own realm's trust root"
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

fn verify(
    store: &Store,
    all: bool,
    exports: &[PathBuf],
    lockfile: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let ctx = project_ctx(store)?;
    let verifier = ctx_verifier(&ctx)?;
    let store = &ctx.store;
    if all {
        // REQ-VERIFYALL-001: EVERY partition, each layer against ITS OWN
        // realm's root. `--help` has always promised "every installed layer";
        // this used to list only the pinned realm's partition, so a tampered
        // layer in another realm passed with exit 0 (varve#84). The realm
        // boundary is preserved in WHICH KEY verifies WHAT, not in what gets
        // looked at.
        return verify_every_partition(&ctx);
    }
    let layers = vec![varve_core::resolve(&ctx.pin, store)?.layer];
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
        report_attestations(&ctx, &layer)?;
        // A composition is only as trustworthy as every layer in it. Verifying
        // the root alone left an UNSIGNED included layer dispatching while
        // verify reported OK (found by clean-room review) — the included
        // layer's tools are on PATH exactly like the root's.
        verify_composition(&ctx, store, &layer)?;
    }
    // DECLARED exports first, and without being told (REQ-EXPORTDECL-001
    // clause 3). `--export DIR` below stays for a directory nobody has declared
    // yet; a declared one is checked whether or not anyone remembers it, which
    // is the whole difference between a gate and a habit.
    verify_declared_exports(&ctx, store)?;
    if !exports.is_empty() {
        let current = varve_core::resolve(&ctx.pin, store)?.layer.digest;
        verify_exports(&current, exports)?;
    }
    if let Some(path) = lockfile {
        verify_lockfile(&ctx, path)?;
    }
    // A verified layer that PATH does not actually reach is the gap between
    // what is signed and what executes — the one varve exists to close. verify
    // is where environment drift belongs (the precedent REQ-EXPORT-SYNC-001
    // set for stale exports), so this fails rather than warns (varve#66).
    verify_no_shadowing(&ctx, store)?;
    // varve#76: verify claimed to be "the install-time verdict, repeated
    // offline" and was not — the install-time verdict includes anti-rollback
    // and verify's did not, so a pin downgraded to an already-installed older
    // layer verified clean, exit 0. The docs tell people to run verify in CI
    // AS THE GATE, so the downgrade passed the gate. Per-line offline
    // anti-rollback is varve's most defensible property; the command a
    // consumer runs to check it must check it.
    verify_no_rollback(&ctx, store)?;
    Ok(())
}

/// `varve verify --all` (REQ-VERIFYALL-001): walk EVERY partition in the store.
///
/// Three properties this must have, each of which the old version lacked:
///   * every realm partition is walked, not only the pinned project's;
///   * each layer is checked against the root of the realm that OWNS its
///     partition — using the pinned project's root for another realm's layer
///     would be trust widening, the precise thing realms exist to prevent;
///   * every failure is reported, with layer id AND path, and the scope
///     actually covered is printed. It was fail-fast and in one observed run
///     the only layer id on screen belonged to a different, healthy layer.
fn verify_every_partition(ctx: &ProjectCtx) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    // fingerprint -> (realm name, verifier). A partition whose realm is not
    // defined here cannot be checked, and is REPORTED rather than skipped: an
    // unverifiable layer sitting in the store is what this command is for.
    let mut by_fp: std::collections::BTreeMap<String, (String, varve_core::PinnedKeyVerifier)> =
        std::collections::BTreeMap::new();
    for name in varve_core::realm::realm_names(&cwd).unwrap_or_default() {
        if let Ok(realm) = varve_core::resolve_realm(&cwd, &name)
            && let Ok(v) = varve_core::PinnedKeyVerifier::from_public_key_bytes(&realm.trust_root)
        {
            by_fp.insert(realm.fingerprint(), (name, v));
        }
    }

    // The pin's own root, for the top-level (non-realm) partition.
    let own = ctx_verifier(ctx)?;
    let host = varve_core::host_platform();
    let mut failures: Vec<String> = Vec::new();
    let mut checked_layers = 0usize;
    let mut total_layers = 0usize;
    let mut partitions_seen = 0usize;

    for (fp, part) in ctx.store.partitions() {
        let layers = part.list().unwrap_or_default();
        if layers.is_empty() {
            continue;
        }
        partitions_seen += 1;
        // Whose root speaks for this partition?
        let chosen = match &fp {
            Some(fp) => by_fp.get(fp).map(|(n, v)| (n.clone(), v)),
            // The top-level core is not realm-scoped: the pin's own root.
            None => Some(("(no realm)".to_string(), &own)),
        };
        for layer in layers {
            total_layers += 1;
            let Some((realm_name, verifier)) = &chosen else {
                failures.push(format!(
                    "layer {} ({}) sits in realm partition {} which varve-realms.toml does not \
                     define — nothing here can vouch for it. Add that realm, or remove the \
                     partition; an unverifiable layer in the store is exactly what `--all` is \
                     for.\n    at {}",
                    layer.layer,
                    layer.digest,
                    fp.clone().unwrap_or_default(),
                    layer.root.display()
                ));
                continue;
            };
            match varve_core::verify_installed(&part, &layer, *verifier, &host) {
                Ok(n) => {
                    checked_layers += 1;
                    println!(
                        "layer {} {} [realm {realm_name}] verified: signature OK, {n} tool(s) \
                         match their signed digests",
                        layer.layer, layer.digest
                    );
                }
                Err(e) => failures.push(format!(
                    "layer {} ({}) in realm {realm_name} FAILED: {e}\n    at {}",
                    layer.layer,
                    layer.digest,
                    layer.root.display()
                )),
            }
        }
    }

    if total_layers == 0 {
        bail!("nothing to verify — no layers installed");
    }
    // The scope, always — so a future regression that narrows what `--all`
    // covers shows up in the output instead of passing quietly.
    println!(
        "checked {checked_layers} of {total_layers} layer(s) across {partitions_seen} partition(s)"
    );
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  {f}");
        }
        bail!(
            "{} of {} installed layer(s) did not verify — see `varve docs recovery`",
            failures.len(),
            total_layers
        );
    }
    Ok(())
}

/// Fail when the layer the PIN resolves to sits below its line's high-water
/// mark (varve#76).
///
/// Scoped to the resolved layer deliberately. An older layer merely PRESENT in
/// the store is not a danger — a consumer may keep one around — but the layer
/// the pin dispatches being stale is precisely the attack anti-rollback
/// exists to stop. Checking every installed layer would fail on legitimately
/// retained ones, and a check that fires on correct setups is one people
/// switch off (the REQ-SHADOW-001 lesson).
fn verify_no_rollback(ctx: &ProjectCtx, store: &Store) -> anyhow::Result<()> {
    let resolved = varve_core::resolve(&ctx.pin, store)?;
    let payload = std::fs::read(resolved.layer.root.join("layer.json"))?;
    let manifest = varve_core::LayerManifest::parse(&payload)?;
    let marks = varve_core::HighWaterMarks::load(store.root())?;
    if let varve_core::RollbackVerdict::Rollback {
        line,
        presented,
        high_water,
    } = marks.check(&manifest)
    {
        bail!(
            "the layer verifies, but the pin resolves to a STALE layer: {} presents counter \
             {presented} while the {line} line's high-water mark is {high_water}. A \
             validly-signed older layer is exactly what anti-rollback exists to refuse — \
             `install` would have refused this. Move the pin forward, or if you are \
             deliberately going back, see `varve docs recovery`.",
            manifest.layer
        );
    }
    Ok(())
}

/// Report the attestations a verified layer carries (REQ-ATTEST-002): what
/// each claims, who produced it, and whether it STILL binds to this layer and
/// these bytes under the trust root.
///
/// REPORTING, not refusal, and that is a decision rather than an omission. An
/// attestation that no longer binds is evidence about the evidence — the
/// consumer must see it — but a layer whose own signature and digests are good
/// is still a good layer. Failing `verify` on a third party's stale audit would
/// make varve's verdict depend on someone else's release cadence, in the one
/// tool whose purpose is frozen toolchains.
///
/// Called only AFTER `verify_installed` has re-checked the retained envelope:
/// the layer's name and digest are local labels until then, and joining an
/// attestation onto unverified labels is the defect clean-room review already
/// found in `check-attestation`.
fn report_attestations(ctx: &ProjectCtx, layer: &varve_core::InstalledLayer) -> anyhow::Result<()> {
    let root = ctx_root_bytes(ctx)?;
    let reports = match varve_core::attestcarry::report_installed(
        &layer.root,
        &layer.layer.to_string(),
        &layer.digest,
        &root,
    ) {
        Ok(reports) => reports,
        // A broken attestation store is surfaced, never fatal — same rule as
        // the binding verdict itself.
        Err(e) => {
            eprintln!("note: attestations carried by layer {} : {e}", layer.layer);
            return Ok(());
        }
    };
    if reports.is_empty() {
        return Ok(());
    }
    println!("  carries {} attestation(s):", reports.len());
    for r in &reports {
        if r.binds {
            println!(
                "    {kind} by {producer}: binds to this layer (varve vouches for the \
                 association and the bytes' integrity — what {producer} CLAIMS is verified \
                 with {producer}'s own key)",
                kind = r.kind,
                producer = r.producer,
            );
        } else {
            println!(
                "    {kind} by {producer}: DOES NOT BIND — {reason}",
                kind = r.kind,
                producer = r.producer,
                reason = r.reason.as_deref().unwrap_or("unknown"),
            );
        }
    }
    Ok(())
}

/// Fail when PATH would run a different binary than the pin dispatches
/// (REQ-SHADOW-001 clause 3) — unless the project DECLARED that it would
/// (REQ-EXPORTDECL-001 clause 5).
///
/// A sourced SDK prepends its own bin to PATH, so its compiler shadows the
/// shims by construction. Whether that is a hijack or the entire point depends
/// on what the pin declared, and the declaration is why there are three
/// verdicts rather than two: `before-shims` is expected and must not fail —
/// a check that fires on the setup the project deliberately configured is one
/// people switch off, which is worse than not checking — while `after-shims`
/// means the declaration and the actual PATH disagree, a real fault with a
/// precise fix rather than the generic hijack report.
fn verify_no_shadowing(ctx: &ProjectCtx, store: &Store) -> anyhow::Result<()> {
    let resolved = varve_core::resolve(&ctx.pin, store)?;
    let path_var = std::env::var_os("PATH");
    // Our own binary: a shim is a symlink to VARVE, so reaching varve is the
    // supported route, not a conflict.
    let me = std::env::current_exe().ok();
    let mut shadowed = Vec::new();
    for (name, path) in &resolved.tools {
        if let varve_core::shadow::Shadowing::Shadowed { found } =
            varve_core::shadow::check(path_var.as_deref(), name, path, me.as_deref())
        {
            match varve_core::classify_shadowing(&ctx.pin, &ctx.root, &found) {
                varve_core::ShadowDeclaration::Expected(decl) => {
                    println!(
                        "note: {name} resolves to {} — inside the {} export declared \
                         `before-shims` in varve.toml, so this environment's own tool winning \
                         is what the project asked for, not a hijack",
                        found.display(),
                        decl.out
                    );
                }
                varve_core::ShadowDeclaration::ContradictsDeclaration(decl) => {
                    shadowed.push(format!(
                        "{name}: PATH resolves it to {}, inside the {} export at {} — but \
                         varve.toml declares that export `after-shims`, i.e. that varve's \
                         pinned tools win. The declaration and PATH disagree: either source \
                         {} BEFORE varve's env (so the shims land ahead of it — \
                         `varve env` emits exactly that order), or change the declaration to \
                         `path = \"before-shims\"` if this environment is meant to win.",
                        found.display(),
                        decl.kind,
                        decl.out,
                        decl.env
                            .as_ref()
                            .map(|e| e.script.clone())
                            .unwrap_or_default(),
                    ));
                }
                varve_core::ShadowDeclaration::Undeclared => {
                    shadowed.push(varve_core::shadow::describe(name, path, &found));
                }
            }
        }
    }
    if shadowed.is_empty() {
        return Ok(());
    }
    bail!(
        "the layer verifies, but {} of its tool(s) are not what your PATH runs \
         (REQ-SHADOW-001):\n\n{}",
        shadowed.len(),
        shadowed.join("\n\n")
    );
}

/// Check a project's lockfile against the pinned layer's `crate` entries
/// (REQ-LOCKPIN-001). Packages the layer does not pin are ignored — the layer
/// never claimed to cover every dependency.
fn verify_lockfile(ctx: &ProjectCtx, path: &std::path::Path) -> anyhow::Result<()> {
    let resolved = varve_core::resolve(&ctx.pin, &ctx.store)?;
    // READ THE LOCKFILE FIRST. An earlier version checked the layer's crates
    // before opening the file, so `--lockfile /does/not/exist` printed
    // "pins no crates — nothing to check" and exited 0 — naming a path it had
    // never opened. A gate that cannot fail is not a gate, and this one is sold
    // as the CI check for REQ-LOCKPIN-001.
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read lockfile {}", path.display()))?;
    let locked = varve_core::lockpin::parse_lockfile(&text, &path.display().to_string())?;

    // Only a layer that genuinely pins nothing may pass quietly, and it says
    // plainly that the check asserted nothing rather than implying agreement.
    // The composition, not just the root: a lockfile checked against one
    // layer of a composition silently asserts nothing about the crates the
    // INCLUDED layers pin, which is varve#79 wearing a different hat.
    let target = ExportTarget {
        store: ctx.store.clone(),
        entry: resolved.layer.clone(),
        verifier: ctx_verifier(ctx)?,
        realm: ctx_realm_name(ctx),
    };
    let layers = composition_for_export(&target)?;
    let crates = match collect_verified_crates(&layers) {
        Ok(c) => c,
        Err(e) if e.to_string().contains("carries no `crate` entries") => {
            println!(
                "lockfile {}: parsed {} package(s); layer {} pins no crates, so this check \
                 asserted nothing",
                path.display(),
                locked.len(),
                resolved.layer.layer
            );
            return Ok(());
        }
        Err(e) => {
            return Err(e).context(
                "cannot read the pinned layer's crates, so the lockfile CANNOT be checked \
                 — refusing to report agreement",
            );
        }
    };
    let found = varve_core::lockpin::disagreements(&crates, &locked);
    if found.is_empty() {
        println!(
            "lockfile {} agrees with layer {} ({} pinned crate(s) checked against {} package(s))",
            path.display(),
            resolved.layer.layer,
            crates.len(),
            locked.len()
        );
        return Ok(());
    }
    for d in &found {
        eprintln!("  {d}");
    }
    bail!(
        "{} package(s) in {} disagree with layer {} (REQ-LOCKPIN-001) — re-resolve against the \
         pinned layer, or move the pin",
        found.len(),
        path.display(),
        resolved.layer.layer
    );
}

/// Verify every layer a composition includes, each against ITS OWN realm's
/// trust root (REQ-COMPOSE-001). The including layer's root does not speak for
/// another realm — that separation is the whole reason composition exists
/// rather than merging tools into one layer.
fn verify_composition(
    ctx: &ProjectCtx,
    store: &Store,
    layer: &varve_core::store::InstalledLayer,
) -> anyhow::Result<()> {
    let mut ancestors = Vec::new();
    let mut verified = std::collections::BTreeSet::new();
    verify_composition_inner(ctx, store, layer, &mut ancestors, &mut verified)
}

/// The recursive half, carrying the ancestor path. The guards are NOT optional:
/// without them `verify --all` walked a self-referencing store entry until the
/// stack was exhausted and the process aborted (found by re-verification).
/// Resolution refuses such a graph, so verify must reach the same verdict —
/// "refused" and "followed until it crashes" are not the same answer, least of
/// all in the command whose job is to inspect adversarial store state.
///
/// `ancestors` is a PATH — pushed on the way down and popped on the way back up
/// — and `verified` is a separate set of layers already checked. Conflating the
/// two is the bug this function shipped with from v0.23.0 until v0.27.0: a
/// single insert-only set meant a DIAMOND (two layers sharing a base, the most
/// ordinary composition there is) was reported as a cycle, so `varve verify`
/// exited 1 on a store that `install`, `run`, `which` and every export handled
/// correctly. `compose::walk` had already been fixed for exactly this; this is
/// an independent reimplementation that kept the bug, and `walk_composition`
/// carries a comment warning against reintroducing it. It was found by a
/// persona audit driving the real binary — the two CLI tests below are the
/// regression proof.
fn verify_composition_inner(
    ctx: &ProjectCtx,
    store: &Store,
    layer: &varve_core::store::InstalledLayer,
    ancestors: &mut Vec<String>,
    verified: &mut std::collections::BTreeSet<String>,
) -> anyhow::Result<()> {
    if ancestors.contains(&layer.digest) {
        bail!(
            "composition cycle while verifying: layer {} ({}) reappears on its own path — \
             refusing to follow it",
            layer.layer,
            layer.digest
        );
    }
    // Already checked by another path through the graph. Its signature does not
    // become less valid for being reachable twice, and re-verifying it would
    // print the same line again (it did).
    if !verified.insert(layer.digest.clone()) {
        return Ok(());
    }
    if ancestors.len() > varve_core::compose::MAX_DEPTH {
        bail!(
            "composition is more than {} layers deep while verifying — refusing to walk further",
            varve_core::compose::MAX_DEPTH
        );
    }
    ancestors.push(layer.digest.clone());
    let result = verify_composition_includes(ctx, store, layer, ancestors, verified);
    ancestors.pop();
    result
}

/// The body of the walk, split out so the caller can pop `ancestors` on every
/// path out of it — including the error paths. A `?` that skipped the pop would
/// leave a stale ancestor behind and turn a later sibling into a false cycle.
fn verify_composition_includes(
    ctx: &ProjectCtx,
    store: &Store,
    layer: &varve_core::store::InstalledLayer,
    ancestors: &mut Vec<String>,
    verified: &mut std::collections::BTreeSet<String>,
) -> anyhow::Result<()> {
    let Ok(bytes) = std::fs::read(layer.root.join("layer.json")) else {
        return Ok(());
    };
    let view = varve_core::compose::view(&bytes)?;
    if view.includes.is_empty() {
        return Ok(());
    }
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    for inc in &view.includes {
        let Some((owner, entry)) = store.find_anywhere(&inc.digest)? else {
            bail!(
                "layer {} composes {}, which is not installed — `varve install` it, then re-verify",
                layer.layer,
                inc.layer.clone().unwrap_or_else(|| inc.digest.clone())
            );
        };
        // Whose root vouches for this layer? The include names a realm, and
        // that realm's root is authoritative for it — not ours.
        let verifier = match &inc.realm {
            Some(name) => {
                let realm = varve_core::resolve_realm(&cwd, name).with_context(|| {
                    format!(
                        "layer {} composes a layer from realm '{name}', but that realm is not                          defined here — add it to varve-realms.toml so its trust root can                          verify what it vouches for",
                        layer.layer
                    )
                })?;
                varve_core::PinnedKeyVerifier::from_public_key_bytes(&realm.trust_root)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            }
            // No realm named: the including layer's own root applies.
            None => ctx_verifier(ctx)?,
        };
        // How the root was chosen, in words a reader can act on. `<including
        // layer's>` used to leak into BOTH messages verbatim — an unrendered
        // template placeholder in the output of the command whose whole job is
        // to be believed (varve#78).
        let vouched_by = match &inc.realm {
            Some(name) => format!("realm '{name}'"),
            None => "this project's own trust root (the include names no realm)".to_string(),
        };
        let checked =
            varve_core::verify_installed(store, &entry, &verifier, &varve_core::host_platform())
                .with_context(|| {
                    let mut msg = format!(
                        "composed layer {} failed verification against {vouched_by}",
                        entry.layer
                    );
                    // The commonest cause is not tampering. An `[[include]]`
                    // with no `realm` is checked against the PIN's root, so a
                    // layer another realm signed — the entire point of
                    // composition — is accused of a bad signature. Say so, or
                    // the reader goes hunting for an attacker.
                    if inc.realm.is_none() {
                        msg.push_str(
                            ". If the included layer comes from a DIFFERENT realm, this is the \
                             expected result of an `[[include]]` with no `realm =` — its own \
                             realm's root is the one that vouches for it. Add `realm` to the \
                             include and re-deposit; the annotation is inside the signed payload, \
                             so it cannot be added afterwards",
                        );
                    }
                    msg
                })?;
        println!(
            "  composes {} {} — verified against {vouched_by}: {checked} tool(s) match",
            entry.layer, entry.digest,
        );
        // Composition is a graph: verify what this layer composes too, on a
        // path that remembers where it has been.
        verify_composition_inner(ctx, &owner, &entry, ancestors, verified)?;
    }
    Ok(())
}

/// The subcommand that PRODUCES a declared export kind.
///
/// Not `format!("export-{kind}")`: `bazel-registry` is produced by
/// `varve export-bazel`, so the obvious spelling would print a command that
/// does not exist in the message whose only job is telling the reader what to
/// run. `docs_names_the_producing_command_for_every_export_kind` asserts each
/// of these against the real subcommand list.
fn producing_command(kind: varve_core::ExportKind) -> &'static str {
    match kind {
        varve_core::ExportKind::Cargo => "export-cargo",
        varve_core::ExportKind::CratesVendor => "export-crates-vendor",
        varve_core::ExportKind::BazelRegistry => "export-bazel",
        varve_core::ExportKind::BazelDistdir => "export-bazel-distdir",
        varve_core::ExportKind::Vsix => "export-vsix",
        varve_core::ExportKind::Sdk => "export-sdk",
    }
}

/// Check every export the PIN declares, without being told to
/// (REQ-EXPORTDECL-001 clause 3).
///
/// `--export DIR` catches a stale export only for a directory someone
/// remembered to name, so the set of checked exports lived in a CI script or a
/// shell history rather than in the repository. Declared means checked: each
/// `[[export]]` is looked at on every `verify`, and anything but `Current`
/// fails. A declared directory that is ABSENT is a failure and not a warning —
/// "I forgot to generate it" and "it is stale" are the same severity to anyone
/// relying on the export.
fn verify_declared_exports(ctx: &ProjectCtx, store: &Store) -> anyhow::Result<()> {
    if ctx.pin.exports.is_empty() {
        return Ok(());
    }
    let current = varve_core::resolve(&ctx.pin, store)?.layer.digest;
    let mut faults = Vec::new();
    for decl in &ctx.pin.exports {
        let dir = decl.dir(&ctx.root);
        let status = varve_core::check_declared_export(decl, &ctx.root, &current);
        match status {
            varve_core::DeclaredExportStatus::Current => println!(
                "declared export {} ({}) — fresh: bound to the layer the pin resolves",
                dir.display(),
                decl.kind
            ),
            varve_core::DeclaredExportStatus::Missing => faults.push(format!(
                "{} ({}) — MISSING: varve.toml declares this export and there is no \
                 .varve-export.json in it. Generate it with `varve {} --out {}`.",
                dir.display(),
                decl.kind,
                producing_command(decl.kind),
                decl.out
            )),
            varve_core::DeclaredExportStatus::Stale { stamped, current } => faults.push(format!(
                "{} ({}) — STALE: stamped from {stamped}; the pin now resolves {current}. \
                 Re-run the export against the current pin.",
                dir.display(),
                decl.kind
            )),
            varve_core::DeclaredExportStatus::KindMismatch { declared, stamped } => {
                faults.push(format!(
                    "{} — DECLARED as a {declared} export but stamped {stamped}: the declared \
                     export was never produced there, and the {stamped} export's freshness says \
                     nothing about it",
                    dir.display()
                ))
            }
            varve_core::DeclaredExportStatus::Unreadable(why) => faults.push(format!(
                "{} ({}) — UNREADABLE stamp: {why}. Re-running the export is not the fix for a \
                 permissions fault or a truncated file.",
                dir.display(),
                decl.kind
            )),
        }
    }
    if !faults.is_empty() {
        bail!(
            "{} declared export(s) in {} are not current (REQ-EXPORTDECL-001):\n\n{}",
            faults.len(),
            ctx.root.join(varve_core::discover::PIN_FILE).display(),
            faults.join("\n\n")
        );
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

/// The pin, and the directory that holds it — the PROJECT ROOT.
///
/// The root is not a convenience: every `[[export]]` destination and every
/// `[export.env]` script is declared RELATIVE to it (REQ-EXPORTDECL-001
/// clause 2), so resolving one against the working directory instead would make
/// `varve verify` pass or fail depending on which subdirectory it was run from.
fn load_pin() -> anyhow::Result<(Pin, PathBuf)> {
    let cwd = std::env::current_dir().context("cannot determine working directory")?;
    let Some(path) = discover::find_pin(&cwd) else {
        bail!(
            "no varve.toml found walking up from {} — this project has no pinned layer. \
             Create varve.toml next to your rust-toolchain.toml to pin one.",
            cwd.display()
        );
    };
    let root = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((Pin::load(&path)?, root))
}

fn which(store: &Store, tool: &str) -> anyhow::Result<()> {
    let ctx = project_ctx(store)?;
    let resolved = resolve(&ctx.pin, &ctx.store)?;
    let asked = tool.to_string();
    let Some((tool, path)) = dispatch_target(&resolved, tool) else {
        // "is not part of layer" was FALSE for a held payload: the layer holds
        // it, verifies it, and hands it to an export adapter — it is simply not
        // DISPATCHED by name (REQ-INSPECT-001 clause 3). Saying a `wit` package
        // is not in the layer sends the reader to re-deposit something that is
        // already there.
        if let Some((kind, version, in_layer)) = held_payload(&ctx.store, &resolved.layer, tool) {
            bail!(
                "'{tool}' is a HELD `{kind}` payload{version} of layer {in_layer}, not a \
                 dispatched tool — varve stores and verifies it but does not put it on PATH. \
                 Only a `tool` is dispatched by name. Run `varve inspect` to see every \
                 payload, or the matching `varve export-*` to materialise this one.",
                version = match version {
                    Some(v) => format!(" ({v})"),
                    None => String::new(),
                },
            );
        }
        bail!(
            "tool '{tool}' is not part of layer {} as pinned here — the pin exposes: {}. \
             `varve inspect` lists every payload, dispatched and held.",
            resolved.layer.layer,
            addressable(&resolved)
        );
    };
    // STDOUT is the dispatched path, unchanged, so scripts that capture it
    // keep working (REQ-SHADOW-001 clause 2).
    println!("{}", path.display());
    println!(
        "layer {} ({}) {}",
        resolved.layer.layer, resolved.layer.channel, resolved.layer.digest
    );
    // The line above names the layer the PIN resolves to, which for a composed
    // tool is not the layer that owns the binary (`docs composition` says so).
    // Someone who ASKED qualified is asking precisely about a provider, so name
    // it — a third line, because the first two are what scripts capture.
    if asked.contains('/')
        && let Some((provider, _)) = resolved
            .qualified
            .iter()
            .find(|(p, _)| p.qualified().as_deref() == Some(asked.as_str()))
    {
        println!(
            "provided by realm '{}' layer {} {}",
            provider.realm, provider.layer, provider.digest
        );
    }
    // …but the answer to "which binary runs here" is false if PATH disagrees,
    // and that is the README's own words for this command (varve#66).
    let me = std::env::current_exe().ok();
    if let varve_core::shadow::Shadowing::Shadowed { found } = varve_core::shadow::check(
        std::env::var_os("PATH").as_deref(),
        tool,
        path,
        me.as_deref(),
    ) {
        // …and a declared sourced export is not a hijack (REQ-EXPORTDECL-001
        // clause 5). `verify` consults the declaration, so this must too, or
        // the two commands contradict each other on one PATH.
        match varve_core::classify_shadowing(&ctx.pin, &ctx.root, &found) {
            varve_core::ShadowDeclaration::Expected(decl) => eprintln!(
                "note: {} comes from the {} export declared `before-shims` in varve.toml",
                found.display(),
                decl.out
            ),
            _ => eprintln!(
                "warning: {}",
                varve_core::shadow::describe(tool, path, &found)
            ),
        }
    }
    Ok(())
}

fn list(store: &Store) -> anyhow::Result<()> {
    // Walk the top-level core AND every realm partition. Realms partition the
    // core by trust-root fingerprint, so listing only the top level made
    // realm-installed layers invisible: `list` printed "no layers installed"
    // with exit 0 immediately after a successful install, contradicted a second
    // later by verify, which, run and sbom (REQ-STORE-001). A command that
    // reports what is installed must not depend on which realm you happen to
    // be standing in.
    let mut rows: Vec<(String, varve_core::store::InstalledLayer)> = store
        .list()?
        .into_iter()
        .map(|e| (String::new(), e))
        .collect();

    let realms_dir = store.root().join("realms");
    if let Ok(entries) = std::fs::read_dir(&realms_dir) {
        let mut partitions: Vec<std::path::PathBuf> =
            entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        partitions.sort();
        for part in partitions {
            let Some(fingerprint) = part.file_name().map(|f| f.to_string_lossy().into_owned())
            else {
                continue;
            };
            // Name the realm where the project can tell us; otherwise the
            // fingerprint, which is at least unambiguous.
            let label = realm_name_for(&fingerprint).unwrap_or(fingerprint);
            for entry in Store::at(&part).list().unwrap_or_default() {
                rows.push((label.clone(), entry));
            }
        }
    }

    if rows.is_empty() {
        println!("no layers installed in {}", store.root().display());
        return Ok(());
    }
    for (realm, entry) in rows {
        if realm.is_empty() {
            println!("{}  {}  {}", entry.layer, entry.channel, entry.digest);
        } else {
            println!(
                "{}  {}  {}  realm={realm}",
                entry.layer, entry.channel, entry.digest
            );
        }
    }
    Ok(())
}

/// Does this layer — or anything it composes — HOLD a payload of that name, one
/// varve stores and verifies but does not dispatch (REQ-INSPECT-001 clause 3)?
/// Returns its kind, version and the layer it is in.
///
/// Read from the SIGNED manifests rather than from `resolve()`, which unions
/// only the DISPATCHABLE entries — that is precisely why a held payload was
/// invisible to every "is it in the layer?" question varve asked, and why
/// `which` reported a `wit` package as "not part of layer".
///
/// The composition is followed for the same reason `resolve` follows it: a
/// composed layer's payloads are part of what the pin delivers, so a held
/// payload one layer down is just as present as one in the root. The first
/// version of this looked only at the root and a CLI test caught it.
///
/// Best effort by design — it only ever improves an error message. A manifest
/// that cannot be read, an include that is not installed, or a cycle all end
/// the walk and fall back to the generic refusal, rather than replacing one
/// failure with a different one. It asserts no trust it has not got: `which`
/// does not verify signatures at all, and this claims only that a name appears
/// in a manifest already reached through the pinned layer's own signed
/// `[[include]]` chain.
fn held_payload(
    store: &Store,
    layer: &varve_core::store::InstalledLayer,
    name: &str,
) -> Option<(String, Option<String>, String)> {
    let mut queue = vec![layer.clone()];
    let mut seen: Vec<String> = vec![layer.digest.clone()];
    while let Some(current) = queue.pop() {
        if seen.len() > varve_core::compose::MAX_DEPTH {
            return None;
        }
        let Ok(bytes) = std::fs::read(current.root.join("layer.json")) else {
            continue;
        };
        let Ok(manifest) = varve_core::LayerManifest::parse(&bytes) else {
            continue;
        };
        let hit = manifest.entries.iter().find_map(|e| {
            if e.annotations.get("eu.pulseengine.tool").map(String::as_str) != Some(name) {
                return None;
            }
            // A dispatchable entry is not held — if we are here at all it did
            // not resolve, and the generic message is the honest one.
            let kind = match e.kind() {
                Ok(k) if k.is_dispatchable() => return None,
                Ok(k) => k.as_str().to_string(),
                Err(varve_core::UnknownKind(raw)) => raw,
            };
            Some((
                kind,
                e.annotations.get("eu.pulseengine.tool.version").cloned(),
                current.layer.to_string(),
            ))
        });
        if hit.is_some() {
            return hit;
        }
        let Ok(view) = varve_core::compose::view(&bytes) else {
            continue;
        };
        for inc in &view.includes {
            if seen.contains(&inc.digest) {
                continue;
            }
            seen.push(inc.digest.clone());
            if let Ok(Some((_, entry))) = store.find_anywhere(&inc.digest) {
                queue.push(entry);
            }
        }
    }
    None
}

/// The realm name for a store-partition fingerprint, when this project's
/// realms file defines one that matches. Best effort: a fingerprint with no
/// local definition is still listed, under its fingerprint.
fn realm_name_for(fingerprint: &str) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let names = varve_core::realm::realm_names(&cwd).ok()?;
    for name in names {
        if let Ok(realm) = varve_core::resolve_realm(&cwd, &name)
            && realm.fingerprint() == fingerprint
        {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod cli_contract_tests {
    use clap::CommandFactory;

    /// Every subcommand whose help text tags it `(CI)`.
    fn ci_marked() -> Vec<String> {
        super::Cli::command()
            .get_subcommands()
            .filter(|c| {
                let about = c.get_about().map(|a| a.to_string()).unwrap_or_default();
                let long = c
                    .get_long_about()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                // The tag is on the SUBCOMMAND, not on a flag inside it:
                // `sign-attestation --attach-to` is documented "(CI)" too, and
                // matching that would count a command twice.
                about.trim_start().starts_with("(CI)") || long.trim_start().starts_with("(CI)")
            })
            .map(|c| c.get_name().to_string())
            .collect()
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn every_ci_marked_subcommand_offers_json() {
        // Clause 2, checked against clap rather than against a list somebody
        // maintains by hand. A command that GAINS the `(CI)` tag and not the
        // flag fails here — which is the only way "every (CI) command offers
        // --json" stays true after this release.
        let marked = ci_marked();
        assert!(
            marked.len() >= 7,
            "only {} subcommand(s) are tagged (CI); the producer pipeline has seven — this \
             check is reading the wrong thing: {marked:?}",
            marked.len()
        );
        let cmd = super::Cli::command();
        let mut without: Vec<&str> = Vec::new();
        for name in &marked {
            let sub = cmd
                .get_subcommands()
                .find(|c| c.get_name() == name)
                .expect("the subcommand exists");
            if !sub.get_arguments().any(|a| a.get_long() == Some("json")) {
                without.push(name);
            }
        }
        assert!(
            without.is_empty(),
            "these commands are tagged (CI) and offer no --json, so a pipeline must scrape \
             their prose (REQ-CIGATE-001 clause 2): {without:?}"
        );
    }

    // rivet: verifies REQ-CIGATE-001
    #[test]
    fn the_ci_tag_check_can_actually_find_a_command() {
        // The gate above asserts an EMPTY result over a set it computes itself.
        // If `ci_marked` silently returned nothing — a clap upgrade moving the
        // doc comment from `about` to `long_about` would do it — the assertion
        // would pass while checking nothing. Name the commands it must find.
        let marked = ci_marked();
        for expected in [
            "deposit",
            "sign-attestation",
            "sign-status",
            "sign-index",
            "attach-index",
            "attach-status",
            "sign-sums",
        ] {
            assert!(
                marked.iter().any(|m| m == expected),
                "`{expected}` is tagged (CI) in --help and the tag scan does not see it: \
                 {marked:?}"
            );
        }
    }

    // rivet: verifies REQ-INSPECT-001
    #[test]
    fn inspect_is_a_real_subcommand_with_json() {
        let cmd = super::Cli::command();
        let sub = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "inspect")
            .expect("REQ-INSPECT-001 needs a command, not a flag on an existing one");
        assert!(sub.get_arguments().any(|a| a.get_long() == Some("json")));
        assert!(sub.get_arguments().any(|a| a.get_long() == Some("layer")));
    }
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
