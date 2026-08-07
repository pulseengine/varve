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

pub mod archive;
pub mod deposit;
pub mod discover;
pub mod install;
pub mod layer;
pub mod manifest;
pub mod pin;
pub mod resolve;
pub mod reverify;
pub mod rollback;
pub mod source;
pub mod store;
pub mod verify;

pub use archive::{ArchiveError, OciLayoutSource, export as export_archive};
pub use deposit::{DepositError, DepositOutcome, DepositSpec, DepositTool, deposit};
pub use install::{
    InstallError, InstallOutcome, InstallPolicy, ManifestVerifier, VerifyError, install,
};
pub use layer::{LayerId, LayerIdError, Line};
pub use manifest::{LayerManifest, ManifestError};
pub use pin::{Channel, Pin, PinError};
pub use resolve::{ResolveError, Resolved, resolve};
pub use reverify::{ReverifyError, verify_installed};
pub use rollback::{HighWaterMarks, RollbackError, RollbackVerdict, staleness_warning};
pub use source::{DirSource, LayerRef, LayerSource, MemorySource, SourceError};
pub use store::{InstalledLayer, Store, StoreError, manifest_digest};
pub use verify::{
    LAYER_PAYLOAD_TYPE, PinnedKeyVerifier, generate_root_keypair, sign_layer_manifest,
};
