//! The producer half of the varve pipeline (REQ-PRODUCER-002).
//!
//! Assembling a layer means fetching upstream releases, establishing what
//! vouched for each one, staging the payloads, and handing a deposit spec to
//! `varve-core`. That work used to be ~3.5k lines of bash, and every defect it
//! had was a string-handling defect invisible until a real registry was
//! involved. It lives here so those parts are pure functions with tests.
//!
//! This is a LIBRARY plus a thin binary on purpose: the logic is testable
//! without a process, and the binary is the seam where external services
//! (`gh`, `cosign`, `oras`) are invoked.

pub mod advisory;
pub mod advisorywatch;
pub mod apply;
pub mod asset;
pub mod attestation;
pub mod binfmt;
pub mod carryforward;
pub mod cli;
pub mod cvss;
pub mod deposit;
pub mod docs;
pub mod extract;
pub mod forge;
pub mod gh;
pub mod immutable;
pub mod ingest;
pub mod nextlayer;
pub mod orchestrate;
pub mod pgpsums;
pub mod plan;
pub mod registry;
pub mod scan;
pub mod source;
pub mod spec;
pub mod stage;
pub mod statusdraft;
pub mod sums;
/// A per-run scratch directory for tests (#246).
///
/// Tests used to derive scratch paths from a FIXED name in the shared temp
/// directory and `remove_dir_all` them on entry, so two concurrent runs of the
/// same test binary (two mutation shards on one host) deleted each other's
/// staged files. Every scratch is now its own `tempfile::TempDir`: unique per
/// call, removed on drop, and never wiped by anyone else.
#[cfg(test)]
pub(crate) mod testscratch {
    use std::path::Path;

    /// A unique scratch directory that lives as long as this value does.
    pub struct Scratch(tempfile::TempDir);

    impl Scratch {
        /// `tag` only makes a leftover directory recognisable; uniqueness comes
        /// from `tempfile`, not from the tag.
        pub fn new(tag: &str) -> Self {
            Scratch(
                tempfile::Builder::new()
                    .prefix(&format!("varve-{tag}-"))
                    .tempdir()
                    .expect("scratch"),
            )
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            self.0.path()
        }
    }

    impl AsRef<Path> for Scratch {
        fn as_ref(&self) -> &Path {
            self.0.path()
        }
    }
}
