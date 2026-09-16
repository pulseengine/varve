//! The command line, in the LIBRARY rather than the binary.
//!
//! Same move varve-producer made: a `Cli` inside `main.rs` cannot be reached
//! by `--lib` tests, and the documentation gate has to enumerate the real CLI
//! rather than a copy of it. Keeping it here means the gate tests what ships.

use clap::Parser;

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
}
