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
pub mod attest;
pub mod attestcarry;
pub mod bazel;
pub mod compose;
pub mod crateexport;
pub mod deposit;
pub mod discover;
pub mod exportstamp;
pub mod install;
pub mod keys;
pub mod kind;
pub mod layer;
pub mod lineindex;
pub mod linestatus;
pub mod lockpin;
pub mod manifest;
pub mod pin;
pub mod platform;
pub mod realm;
pub mod registry;
pub mod resolve;
pub mod reverify;
pub mod rollback;
pub mod sbom;
pub mod selfverify;
pub mod shadow;
pub mod source;
pub mod store;
pub mod update;
pub mod verify;
pub mod vsixexport;

pub use archive::{ArchiveError, ExportSummary, OciLayoutSource, export as export_archive};
pub use deposit::{
    DepositError, DepositFileSpec, DepositOutcome, DepositSpec, DepositTool, RunnerSpec,
    ToolSource, deposit, parse_deposit_spec,
};
pub use install::{
    InstallError, InstallOutcome, InstallPolicy, ManifestVerifier, VerifyError, install,
};
pub use kind::{ANN_KIND, PayloadKind, UnknownKind};
pub use layer::{LayerId, LayerIdError, Line};
pub use lineindex::{
    IndexCache, IndexError, IndexPolicy, IndexedLayer, LineIndex,
    attach_envelope_to_layout as attach_index_envelope_to_layout,
    attach_to_layout as attach_index_to_layout, read_from_layout as read_index_from_layout,
};
pub use linestatus::{
    KnownProblem, LayerStatusReport, LineStatus, LineStatusError, StatusCache,
    attach_envelope_to_layout as attach_status_envelope_to_layout,
    attach_to_layout as attach_status_to_layout,
    cache_baseline_from_source as cache_baseline_line_status,
    read_any_from_layout as read_any_status_from_layout,
    read_from_layout as read_status_from_layout,
};
pub use manifest::{LayerManifest, ManifestError};
pub use pin::{Channel, Pin, PinError};
pub use platform::host_platform;
pub use realm::{Realm, RealmError, resolve_realm};
pub use registry::{RegistryRef, RegistrySource};
pub use resolve::{ResolveError, Resolved, RunnerContract, resolve};
pub use reverify::{ReverifyError, verify_installed};
pub use rollback::{HighWaterMarks, RollbackError, RollbackVerdict, staleness_warning};
pub use selfverify::{
    RELEASE_SUMS_PAYLOAD_TYPE, SelfVerifyError, sign_release_sums, verify_release_file,
};
pub use source::{DirSource, LayerRef, LayerSource, MemorySource, SourceError};
pub use store::{InstalledLayer, Store, StoreError, manifest_digest};
pub use verify::{
    LAYER_PAYLOAD_TYPE, PinnedKeyVerifier, generate_root_keypair, sign_layer_manifest,
};
pub use vsixexport::{VsixEntry, VsixExportError, export_vsix};
