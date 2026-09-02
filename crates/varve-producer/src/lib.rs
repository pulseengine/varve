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

pub mod asset;
pub mod attestation;
pub mod binfmt;
pub mod carryforward;
pub mod extract;
pub mod forge;
pub mod gh;
pub mod ingest;
pub mod plan;
pub mod spec;
pub mod sums;
