//! Payload kinds (REQ-KIND-001) — what a layer entry *is*.
//!
//! A tool binary is just bytes with an exec bit; a crate, a WIT package, a
//! Zephyr module, an SDK, a wasm component are also just bytes. The kind
//! selects which export adapter and store layout apply — it does NOT change
//! how bytes are verified (every kind is a signed digest checked against the
//! trust root, exactly as a tool binary is; DD-003).
//!
//! Back-compat: an entry with no kind annotation is a `tool` (pre-kind layers,
//! as an unstamped platform means any-platform). An *unknown* kind is a hard
//! error WHERE THE KIND IS ACTED ON — `collect_verified_crates` refuses to
//! export a payload it cannot classify, rather than mishandle it.
//!
//! Scope, stated precisely because an earlier version of this comment claimed
//! more than the code does: `install` and `verify_installed` do NOT consult the
//! kind. They check the signed digest of every entry, which is what makes the
//! bytes trustworthy, and that check is kind-independent by design (DD-003). So
//! a layer deposited by a newer varve, carrying a kind this build has never
//! heard of, installs and verifies normally; only the adapters that must DO
//! something kind-specific refuse it. Consumers of `kind()` must therefore
//! handle `Err` on real installed layers — `sbom` labels such an entry rather
//! than dropping it. Whether install should refuse outright is tracked in
//! varve#49.

use std::fmt;
use std::str::FromStr;

/// The annotation carrying an entry's payload kind.
pub const ANN_KIND: &str = "eu.pulseengine.varve.kind";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PayloadKind {
    /// An executable dispatched by `varve run` / shims (the original kind).
    #[default]
    Tool,
    /// A Rust `.crate` tarball, consumed via `export-cargo`.
    Crate,
    /// A WIT interface package (`wit/` + `wit/deps/`).
    Wit,
    /// A Zephyr module directory (`zephyr/module.yml`).
    ZephyrModule,
    /// A C/C++ SDK tree (headers + libs + a cmake package).
    Sdk,
    /// A WebAssembly component.
    WasmComponent,
    /// Another LAYER, composed into this one (REQ-COMPOSE-001). The digest is
    /// that layer's signed manifest; it is not a blob to lay down.
    Layer,
}

impl PayloadKind {
    /// The canonical wire string, as written in the signed annotation.
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadKind::Tool => "tool",
            PayloadKind::Crate => "crate",
            PayloadKind::Wit => "wit",
            PayloadKind::ZephyrModule => "zephyr-module",
            PayloadKind::Sdk => "sdk",
            PayloadKind::WasmComponent => "wasm-component",
            PayloadKind::Layer => "layer",
        }
    }
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unrecognised payload kind — varve refuses it rather than guess.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown payload kind '{0}': this varve does not know how to handle it \
     (expected one of tool, crate, wit, zephyr-module, sdk, wasm-component)"
)]
pub struct UnknownKind(pub String);

impl FromStr for PayloadKind {
    type Err = UnknownKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tool" => Ok(PayloadKind::Tool),
            "crate" => Ok(PayloadKind::Crate),
            "wit" => Ok(PayloadKind::Wit),
            "zephyr-module" => Ok(PayloadKind::ZephyrModule),
            "sdk" => Ok(PayloadKind::Sdk),
            "wasm-component" => Ok(PayloadKind::WasmComponent),
            "layer" => Ok(PayloadKind::Layer),
            other => Err(UnknownKind(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-KIND-001
    #[test]
    fn every_kind_round_trips_through_its_wire_string() {
        for k in [
            PayloadKind::Tool,
            PayloadKind::Crate,
            PayloadKind::Wit,
            PayloadKind::ZephyrModule,
            PayloadKind::Sdk,
            PayloadKind::WasmComponent,
        ] {
            assert_eq!(k.as_str().parse::<PayloadKind>().unwrap(), k);
        }
    }

    // rivet: verifies REQ-KIND-001
    #[test]
    fn an_unknown_kind_is_refused_not_guessed() {
        let err = "quantum-blob".parse::<PayloadKind>().unwrap_err();
        assert_eq!(err, UnknownKind("quantum-blob".into()));
    }

    // rivet: verifies REQ-KIND-001
    #[test]
    fn the_default_kind_is_tool_for_back_compat() {
        assert_eq!(PayloadKind::default(), PayloadKind::Tool);
    }
}
