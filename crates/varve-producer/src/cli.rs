//! The producer's command line, defined in the LIBRARY rather than the binary.
//!
//! Not a tidiness move. `docs check --coverage` enumerates the subcommands and
//! asserts each has a topic (REQ-PRODUCERDOCS-001), and the gate's kill
//! criteria are `--workspace --lib` — a CLI defined in `main.rs` cannot be
//! enumerated by a lib test, so the invariant could not be asserted where it
//! runs. Moving it here is what makes the documentation gate mechanical
//! instead of a habit.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "varve-producer", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
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
    /// Which pinned payloads have a newer upstream release (REQ-SCAN-001)?
    ///
    /// Reads pins from the realm manifest and nowhere else. The scanner this
    /// replaces read them out of a workflow file and broke silently when the
    /// realm moved — a second place the realm is defined is a place the two
    /// disagree.
    ///
    /// An upstream that cannot be ASKED is an error, never "nothing moved": a
    /// realm that stops receiving releases while every check stays green is the
    /// failure nobody notices.
    Scan {
        #[arg(long, default_value = "layer.toml")]
        manifest: std::path::PathBuf,
        /// Machine-readable result on stdout — the only consumer is a gate.
        #[arg(long)]
        format: Option<String>,
    },
    /// Embedded, queryable documentation (offline).
    ///
    /// `docs` lists topics; `docs <topic>` shows one; `docs check --coverage`
    /// asserts every subcommand is documented (REQ-PRODUCERDOCS-001).
    Docs {
        /// A topic slug, or `check` to run the coverage invariant.
        topic: Option<String>,
        /// Search across all topics.
        #[arg(long, value_name = "QUERY")]
        grep: Option<String>,
        /// (check) Report subcommands lacking a topic.
        #[arg(long)]
        coverage: bool,
        /// (check --coverage) Exit non-zero if any subcommand is undocumented.
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        format: Option<String>,
    },
    /// What layer id and counter should the next deposit use (REQ-SCAN-001)?
    ///
    /// Read out of the PUBLISHED record, never guessed. Nobody types a layer id
    /// any more, and one that is wrong is unrecoverable: varve has neither
    /// revocation nor deletion, so a spent id is spent.
    NextLayer {
        /// Destination repository, e.g. `ghcr.io/pulseengine/layers`.
        #[arg(long)]
        repo: String,
        /// The release line. Defaults to the current UTC `YYYY.MM`.
        #[arg(long)]
        line: Option<String>,
        #[arg(long)]
        format: Option<String>,
    },
    /// Ask the destination registry whether this layer id is already
    /// published, and refuse to replace it with different bytes
    /// (REQ-IMMUTABLE-001).
    ///
    /// Run this BEFORE pushing. `varve deposit` cannot do it: it contacts no
    /// network by design, and spending that property to fix a publisher's bug
    /// would be a bad trade.
    PublishCheck {
        /// Destination repository, e.g. `ghcr.io/pulseengine/varve-layers`.
        #[arg(long)]
        repo: String,
        /// The layer id being published, e.g. `2026.09.1`.
        #[arg(long)]
        layer: String,
        /// The manifest digest about to be pushed, as `varve deposit --json`
        /// reports it.
        #[arg(long)]
        digest: String,
        /// Replace a DIFFERENT already-published layer under this id.
        ///
        /// Only correct when nobody has consumed the published layer: it does
        /// not retract what anyone already resolved, and any pin naming this
        /// layer without a digest breaks. Prefer publishing a new layer id —
        /// the counter exists so a correction is a new layer, not a rewritten
        /// one.
        #[arg(long = "replace-published")]
        replace_published: bool,
        /// Machine-readable result.
        #[arg(long = "format", value_name = "FORMAT")]
        format: Option<String>,
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
        /// The payload's own version — what `%V` expands to, e.g. `0.2.2`.
        #[arg(long)]
        version: String,
        /// The release TAG, when it differs from the version (a hub such as
        /// `pulseengine/jess`). What `%R` expands to. Defaults to `--version`.
        #[arg(long)]
        release: Option<String>,
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
