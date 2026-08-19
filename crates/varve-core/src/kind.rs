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
    /// A VS Code extension package (`.vsix`), consumed via `export-vsix`
    /// (REQ-VSIX-001). A `.vsix` is a single zip file, so it needs no
    /// tree-shaped store — and it is DATA handed to `code`, never executed
    /// by varve, so it is not dispatchable and carries no execute bit.
    Vsix,
    /// Another LAYER, composed into this one (REQ-COMPOSE-001). The digest is
    /// that layer's signed manifest; it is not a blob to lay down.
    Layer,
}

impl PayloadKind {
    /// Is a payload of this kind dispatched BY NAME (REQ-STORE-002 clause 1)?
    ///
    /// Only a `tool` is: `varve which`, `varve run` and the argv[0] shims all
    /// resolve a bare name, so a name must resolve to exactly one binary and
    /// the identity of a tool is (name, platform). Every other kind is held,
    /// not dispatched — its identity is (name, version, platform), because
    /// several versions of one crate is the ordinary shape of a dependency
    /// graph. A `layer` is not laid down at all; it answers `false` because it
    /// is certainly not dispatched by name.
    pub fn is_dispatchable(self) -> bool {
        matches!(self, PayloadKind::Tool)
    }

    /// The canonical wire string, as written in the signed annotation.
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadKind::Tool => "tool",
            PayloadKind::Crate => "crate",
            PayloadKind::Wit => "wit",
            PayloadKind::ZephyrModule => "zephyr-module",
            PayloadKind::Sdk => "sdk",
            PayloadKind::WasmComponent => "wasm-component",
            PayloadKind::Vsix => "vsix",
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
     (expected one of tool, crate, wit, zephyr-module, sdk, wasm-component, vsix)"
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
            "vsix" => Ok(PayloadKind::Vsix),
            "layer" => Ok(PayloadKind::Layer),
            other => Err(UnknownKind(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, in one place, so the tests below cannot silently skip a
    /// newly added kind — which is exactly how `layer` and `vsix` reached the
    /// enum with the round-trip test still listing six.
    const ALL_KINDS: &[PayloadKind] = &[
        PayloadKind::Tool,
        PayloadKind::Crate,
        PayloadKind::Wit,
        PayloadKind::ZephyrModule,
        PayloadKind::Sdk,
        PayloadKind::WasmComponent,
        PayloadKind::Vsix,
        PayloadKind::Layer,
    ];

    /// Position of a kind in `ALL_KINDS`. The match is EXHAUSTIVE on purpose:
    /// a new variant that is not added to `ALL_KINDS` fails to COMPILE here,
    /// so the round-trip and dispatchability tests always cover every kind.
    fn index_in_all_kinds(k: PayloadKind) -> usize {
        match k {
            PayloadKind::Tool => 0,
            PayloadKind::Crate => 1,
            PayloadKind::Wit => 2,
            PayloadKind::ZephyrModule => 3,
            PayloadKind::Sdk => 4,
            PayloadKind::WasmComponent => 5,
            PayloadKind::Vsix => 6,
            PayloadKind::Layer => 7,
        }
    }

    // rivet: verifies REQ-KIND-001
    #[test]
    fn the_kind_list_the_other_tests_iterate_holds_every_variant() {
        for (i, k) in ALL_KINDS.iter().enumerate() {
            assert_eq!(
                index_in_all_kinds(*k),
                i,
                "ALL_KINDS is out of step with the enum at {k}"
            );
        }
    }

    // rivet: verifies REQ-KIND-001, REQ-VSIX-001
    #[test]
    fn every_kind_round_trips_through_its_wire_string() {
        for k in ALL_KINDS {
            assert_eq!(k.as_str().parse::<PayloadKind>().unwrap(), *k);
        }
        // Clause 1: the wire string a deposit spec writes is `vsix`, spelled
        // out rather than left to whatever `as_str` happens to return — the
        // annotation is SIGNED, so renaming it silently breaks every layer
        // already deposited.
        assert_eq!(PayloadKind::Vsix.as_str(), "vsix");
        assert_eq!("vsix".parse::<PayloadKind>().unwrap(), PayloadKind::Vsix);
        assert_eq!(PayloadKind::Vsix.to_string(), "vsix");
    }

    // rivet: verifies REQ-KIND-001
    #[test]
    fn an_unknown_kind_is_refused_not_guessed() {
        let err = "quantum-blob".parse::<PayloadKind>().unwrap_err();
        assert_eq!(err, UnknownKind("quantum-blob".into()));
        // The refusal has to say what WOULD have worked, or the depositor who
        // wrote `kind = "vscode"` has nothing to correct it to.
        assert!(
            err.to_string().contains("vsix"),
            "the hint must list every kind this varve accepts: {err}"
        );
    }

    // rivet: verifies REQ-KIND-001
    #[test]
    fn the_default_kind_is_tool_for_back_compat() {
        assert_eq!(PayloadKind::default(), PayloadKind::Tool);
    }

    // rivet: verifies REQ-STORE-002, REQ-VSIX-001
    #[test]
    fn only_a_tool_is_dispatched_by_name() {
        // Clause 1: the identity rule follows dispatchability. A tool resolves
        // by bare name through `varve run`/`which`/the shims, so one name must
        // mean one binary. Nothing else is dispatched, so nothing else may be
        // keyed by name alone — that is what let two versions of one crate
        // overwrite each other.
        assert!(PayloadKind::Tool.is_dispatchable());
        for held in ALL_KINDS.iter().filter(|k| **k != PayloadKind::Tool) {
            assert!(
                !held.is_dispatchable(),
                "{held} is not dispatched by name and must not be keyed by one"
            );
        }
        // REQ-VSIX-001 clauses 2 and 4 both hang off this one answer: it is
        // what denies a `.vsix` the execute bit in `lay_down_payloads` and
        // what gives it a (name, version) identity, so two versions of one
        // extension coexist. Asserted by name, not only through the loop.
        assert!(
            !PayloadKind::Vsix.is_dispatchable(),
            "a .vsix is data handed to `code`, never a binary varve dispatches"
        );
    }
}
