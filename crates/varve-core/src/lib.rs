//! Layer manifests, resolution, the core store, and verification wiring.
//!
//! `varve` reads two manifests and must never conflate them:
//!
//! * **the pin** (`varve.toml`) — human-written, checked into a consuming repo,
//!   naming the layer that project is frozen on;
//! * **the layer manifest** — CI-written, signed, immutable, describing exactly
//!   what a layer contains.
//!
//! The pin is a preference; the layer manifest is evidence.
//!
//! # The invariant
//!
//! Where bytes come from is pluggable — a public registry, a private one, an
//! archived core. **Whether they are accepted is not.** Signature and digest
//! verification run against the PulseEngine trust root on every path, and
//! swapping the source must not change any verdict. A source that could
//! influence acceptance would have joined the trusted base.
//!
//! See `docs/manifest-format.md`. Nothing here is implemented yet.

#![forbid(unsafe_code)]

pub mod discover;
pub mod layer;
pub mod pin;
pub mod resolve;
pub mod store;

pub use layer::{LayerId, LayerIdError, Line};
pub use pin::{Channel, Pin, PinError};
pub use resolve::{ResolveError, Resolved, resolve};
pub use store::{InstalledLayer, Store, StoreError, manifest_digest};
