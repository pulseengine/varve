//! The viewer's logic, as a library.
//!
//! `main.rs` is deliberately thin. Everything with a decision in it lives
//! here, because the mutation gate's kill criteria are `--workspace --lib`:
//! logic inside a binary crate cannot be reached by any lib test, so gating it
//! would report survivors nothing could ever kill.
//!
//! That matters more for this program than for most. `http.rs` is the only
//! file in the workspace that parses input arriving over a socket, and a
//! mutant that makes it answer a `POST`, or resolve a path it should not, is
//! exactly the kind nobody notices by reading.

pub mod cli;
pub mod docs;
pub mod http;
