//! The command line, in the LIBRARY rather than the binary.
//!
//! Same move varve-producer made: a `Cli` inside `main.rs` cannot be reached
//! by `--lib` tests, and the documentation gate has to enumerate the real CLI
//! rather than a copy of it. Keeping it here means the gate tests what ships.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "varve-serve",
    version,
    about = "Read the documentation a varve layer carries, straight out of the verified store",
    long_about = "Serves the documentation the pinned layer carries, read from the verified \
                  store rather than from a copy on disk.\n\nA tree document generally fetches \
                  assets at runtime and browsers block that under file://, so opening an \
                  exported index.html directly loses diagrams and search with no error. This \
                  serves it over http://127.0.0.1 instead.\n\nWith one document no selector is \
                  needed."
)]
pub struct Cli {
    /// Which document, when the layer carries more than one.
    #[arg(long, value_name = "NAME")]
    pub select: Option<String>,
    /// Port to listen on. 0 picks a free one and prints it.
    #[arg(long, default_value_t = 7777)]
    pub port: u16,
    /// Layer to read, e.g. `2026.09.3`. Defaults to the resolved project pin.
    #[arg(long)]
    pub layer: Option<String>,
    /// Print what would be served and exit, without listening.
    ///
    /// The gate-friendly form: CI can assert a layer's documentation is
    /// readable without leaving a process bound to a port.
    #[arg(long)]
    pub check: bool,
    /// Show documentation for this program.
    #[arg(long, value_name = "TOPIC", num_args = 0..=1, default_missing_value = "")]
    pub docs: Option<String>,
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

/// How `context` and `ask` print.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Markdown, for reading.
    Md,
    /// JSON, for a program.
    Json,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Print an orientation for the pin: what it holds and where to look.
    ///
    /// For an agent told to "check in here". It lists the pinned tools (what
    /// each prints about itself, read from the verified binary), the payloads
    /// held, the documentation carried, and the one command to run first,
    /// `varve-serve ask`. Metadata and topic names only, never documentation
    /// text. With no verified layer it prints nothing and exits non-zero.
    Context {
        /// `md` (default) or `json`.
        #[arg(long, value_enum, default_value_t = Format::Md)]
        format: Format,
    },
    /// Ask one narrow question and get pointers, not text.
    ///
    /// Searches documentation pages, every tool's subcommands and overview,
    /// the text of built-in docs topics, and varve's own commands. Each hit
    /// names the exact command that shows the whole page or topic.
    Ask {
        /// The question, in a few words.
        #[arg(required = true, num_args = 1.., value_name = "WORDS")]
        words: Vec<String>,
        /// `md` (default) or `json`.
        #[arg(long, value_enum, default_value_t = Format::Md)]
        format: Format,
        /// The most hits to print.
        #[arg(long, default_value_t = crate::ask::DEFAULT_LIMIT)]
        limit: usize,
    },
    /// Show one page of a verified documentation payload, as text.
    ///
    /// The command an `ask` hit prints in its `read` line.
    Page {
        /// The documentation payload, by name.
        doc: String,
        /// The member path inside it.
        path: String,
    },
}
