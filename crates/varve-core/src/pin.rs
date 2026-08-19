//! The pin — `varve.toml`, the human-written half of the two manifests.
//!
//! Checked into the consuming repo, discovered by walking up from the working
//! directory, reviewed like code. It names the layer a project is frozen on;
//! it is a *preference*, where the layer manifest is *evidence*. Conflating
//! the two is how toolchains drift (see `docs/manifest-format.md`).
//!
//! Parsing is strict: unknown keys, a missing patch component, or a malformed
//! digest are hard errors carrying corrective guidance — a qualified pin that
//! half-parses is worse than one that fails loudly.
//!
//! The pin also declares the project's EXPORTS (REQ-EXPORTDECL-001). The pin
//! says which layer a project consumes; an `[[export]]` entry says HOW it
//! consumes it. They belong in one file because `verify` already reads it: a
//! second discovery path is a second thing to get wrong, and an export that
//! lives only in a CI script is an export nothing ever checks.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::layer::{LayerId, LayerIdError};

/// The release channel a pin selects.
///
/// `qualified` names a line with a stated support window and qualification
/// evidence attached; `rolling` has neither and may move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Qualified,
    Rolling,
}

impl Channel {
    /// The wire string, matching the signed manifest annotation and the pin.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Qualified => "qualified",
            Channel::Rolling => "rolling",
        }
    }
}

impl std::str::FromStr for Channel {
    type Err = ();
    /// The SAME vocabulary a pin accepts, exposed so the produce side can
    /// refuse a channel no pin could ever name (REQ-PRODUCER-001). Deriving
    /// both from one enum is what keeps them from drifting apart.
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "qualified" => Ok(Channel::Qualified),
            "rolling" => Ok(Channel::Rolling),
            _ => Err(()),
        }
    }
}

/// Which export adapter an `[[export]]` entry names (REQ-EXPORTDECL-001
/// clause 2).
///
/// The wire strings are exactly the ones the adapters already write into
/// `.varve-export.json`, so a declaration and the stamp it is checked against
/// are comparable without a translation table — a table is a place for the two
/// to drift, and drift here would make `verify` pass on a directory produced by
/// a different adapter entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExportKind {
    Cargo,
    CratesVendor,
    BazelRegistry,
    BazelDistdir,
    Vsix,
    Sdk,
}

impl ExportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportKind::Cargo => "cargo",
            ExportKind::CratesVendor => "crates-vendor",
            ExportKind::BazelRegistry => "bazel-registry",
            ExportKind::BazelDistdir => "bazel-distdir",
            ExportKind::Vsix => "vsix",
            ExportKind::Sdk => "sdk",
        }
    }

    /// Is this payload CONSUMED by entering an environment rather than by
    /// pointing at a path (clause 4)?
    ///
    /// A Yocto SDK is sourced: `environment-setup-*` sets CC, SYSROOT and
    /// CFLAGS and prepends its own bin to PATH. A local Cargo registry or a
    /// distdir is not — a config file points at it. Only a sourced export may
    /// carry an `[export.env]`, because on anything else the block would be
    /// accepted, ignored, and believed.
    pub fn is_sourced(self) -> bool {
        matches!(self, ExportKind::Sdk)
    }

    /// Every kind, for diagnostics that must say what WOULD have worked.
    pub const ALL: &'static [ExportKind] = &[
        ExportKind::Cargo,
        ExportKind::CratesVendor,
        ExportKind::BazelRegistry,
        ExportKind::BazelDistdir,
        ExportKind::Vsix,
        ExportKind::Sdk,
    ];
}

impl std::fmt::Display for ExportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ExportKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        ExportKind::ALL
            .iter()
            .find(|k| k.as_str() == s)
            .copied()
            .ok_or(())
    }
}

/// Where a sourced environment sits relative to varve's shims on PATH
/// (clause 5).
///
/// This is not bookkeeping. An SDK's `environment-setup-*` PREPENDS its own bin
/// to PATH, which shadows the shims — precisely the condition REQ-SHADOW-001
/// detects. Undeclared, `verify` either catches a genuine hijack or fires on a
/// legitimate setup, and the spurious failure is the worse of the two: a check
/// that cries wolf is a check people switch off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimOrder {
    /// The environment's bin comes FIRST: its compiler wins over the pinned
    /// one, and the project has said so on purpose.
    BeforeShims,
    /// varve's shims come first: the pinned tools win, and anything of theirs
    /// resolving into this export contradicts the declaration.
    AfterShims,
}

impl ShimOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            ShimOrder::BeforeShims => "before-shims",
            ShimOrder::AfterShims => "after-shims",
        }
    }
}

impl FromStr for ShimOrder {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "before-shims" => Ok(ShimOrder::BeforeShims),
            "after-shims" => Ok(ShimOrder::AfterShims),
            _ => Err(()),
        }
    }
}

/// How a sourced export's environment is entered (clauses 4 and 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEnv {
    /// The script to source, relative to the export's `out` directory.
    pub script: String,
    /// Where it sits relative to varve's shims once sourced.
    pub path: ShimOrder,
}

/// One declared export: the adapter, the destination, optionally a subset of
/// the layer, and — for a sourced payload — how its environment is entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDecl {
    pub kind: ExportKind,
    /// Destination, relative to the directory holding `varve.toml`.
    pub out: String,
    /// A SUBSET of the layer's payloads by name. `None` means all of them —
    /// a project exporting one extension or three crates into a dedicated
    /// area is the ordinary case, not a special one (clause 2).
    pub select: Option<Vec<String>>,
    pub env: Option<ExportEnv>,
}

impl ExportDecl {
    /// The absolute destination, resolved against the directory holding
    /// `varve.toml`. Relative in the file so the declaration travels with the
    /// repository; absolute here because everything downstream — the stamp, the
    /// SDK relocation budget, the PATH comparison — needs a real path.
    pub fn dir(&self, project_root: &Path) -> PathBuf {
        project_root.join(&self.out)
    }

    /// The script `varve env` sources for this export, if it has one.
    pub fn env_script(&self, project_root: &Path) -> Option<PathBuf> {
        self.env
            .as_ref()
            .map(|e| self.dir(project_root).join(&e.script))
    }
}

/// A parsed, validated pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Optional trust universe (REQ-REALM-001). When named, the realm's
    /// registry and trust root are AUTHORITATIVE for this project.
    pub realm: Option<String>,
    pub channel: Channel,
    pub layer: LayerId,
    /// Optional exact manifest digest. When present it wins over the name:
    /// a name resolving to a different digest is a hard failure (DD-005's
    /// lever available at the pin level).
    pub digest: Option<String>,
    /// Optional restriction to a subset of the layer's tools. `None` means
    /// every tool in the layer.
    pub tools: Option<Vec<String>>,
    /// The exports this project declares (REQ-EXPORTDECL-001). Declared means
    /// checked: `verify` looks at every one of these without being told.
    pub exports: Vec<ExportDecl>,
}

/// Why a pin failed to parse or validate.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("failed to read {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: not valid varve.toml")]
    Toml {
        path: String,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("{path}: manifest-version {found} is not supported (this varve understands version 1)")]
    UnsupportedManifestVersion { path: String, found: i64 },
    // Display carries only the location; the cause prints once via the
    // #[source] chain (varve#7 — the anyhow alternate formatter was
    // printing it twice).
    #[error("{path}: invalid layer identifier")]
    Layer {
        path: String,
        #[source]
        source: LayerIdError,
    },
    #[error(
        "{path}: digest '{found}' is not a valid digest: expected 'sha256:' followed by 64 hex characters"
    )]
    MalformedDigest { path: String, found: String },
    #[error(
        "{path}: tool name {name:?} is not a plain name — a tool is looked up INSIDE \
         the pinned layer, so a path would resolve outside it. Name the tool only, \
         e.g. tools = [\"rivet\"]."
    )]
    ToolNameIsAPath { path: String, name: String },
    #[error("{path}: tools list is present but empty — omit it to select every tool in the layer")]
    EmptyTools { path: String },
    #[error(
        "{path}: export kind {kind:?} is not one this varve can produce — expected one of {expected}"
    )]
    UnknownExportKind {
        path: String,
        kind: String,
        expected: String,
    },
    #[error(
        "{path}: export destination {out:?} is not usable ({why}) — an export directory is \
         RELATIVE to the directory holding varve.toml, so the declaration travels with the \
         repository and means the same thing on every machine"
    )]
    ExportOutEscapes {
        path: String,
        out: String,
        why: String,
    },
    #[error(
        "{path}: exports {first:?} and {second:?} both write to {out:?} — the second would \
         overwrite the first's stamp, and `verify` would then check one export twice while \
         never checking the other at all"
    )]
    DuplicateExportOut {
        path: String,
        out: String,
        first: String,
        second: String,
    },
    #[error(
        "{path}: export to {out:?} has an empty select list — omit it to export the whole layer"
    )]
    EmptyExportSelect { path: String, out: String },
    #[error(
        "{path}: export to {out:?} selects {name:?}, which is not a plain payload name — a \
         selection indexes the VERIFIED layer, so a path would reach outside it"
    )]
    ExportSelectIsAPath {
        path: String,
        out: String,
        name: String,
    },
    #[error(
        "{path}: export to {out:?} is a {kind} export, which is consumed by POINTING at it, not \
         by sourcing it — an [export.env] here would be accepted, ignored, and believed. Only \
         these kinds are entered as an environment: {sourced}"
    )]
    ExportEnvNotSourced {
        path: String,
        out: String,
        kind: String,
        sourced: String,
    },
    #[error(
        "{path}: export to {out:?} declares an environment but not where it sits relative to \
         varve's shims. Add `path = \"before-shims\"` if this environment's bin is meant to win \
         on PATH, or `path = \"after-shims\"` if varve's pinned tools are. Undeclared, `verify` \
         cannot tell a legitimate sourced SDK from a hijacked PATH (REQ-SHADOW-001), and \
         guessing wrong either misses a real one or cries wolf on a correct setup"
    )]
    ExportEnvNeedsShimOrder { path: String, out: String },
    #[error(
        "{path}: export to {out:?} declares path = {found:?} — expected \"before-shims\" or \
         \"after-shims\""
    )]
    UnknownShimOrder {
        path: String,
        out: String,
        found: String,
    },
    #[error(
        "{path}: export to {out:?} sources {script:?}, which is not usable ({why}) — the script \
         is relative to the export directory, and it must stay inside it"
    )]
    ExportScriptEscapes {
        path: String,
        out: String,
        script: String,
        why: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPin {
    #[serde(rename = "manifest-version")]
    manifest_version: i64,
    toolchain: RawToolchain,
    /// `[[export]]` entries, in declaration order.
    #[serde(default, rename = "export")]
    exports: Vec<RawExport>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    kind: String,
    out: String,
    select: Option<Vec<String>>,
    env: Option<RawExportEnv>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExportEnv {
    script: String,
    /// Kept as `Option<String>` rather than a required typed field so the
    /// refusal can explain WHY the answer is needed. Serde's own "missing field
    /// `path`" is true and useless: the reader has to know that omitting it
    /// makes `verify` guess between a legitimate SDK and a hijack.
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolchain {
    #[serde(default)]
    realm: Option<String>,
    channel: Channel,
    layer: String,
    digest: Option<String>,
    tools: Option<Vec<String>>,
}

impl Pin {
    /// Parse and validate pin content. `origin` names the source (a path, in
    /// diagnostics) — errors must tell the reader *which* file is wrong.
    pub fn parse(content: &str, origin: &str) -> Result<Self, PinError> {
        let raw: RawPin = toml::from_str(content).map_err(|source| PinError::Toml {
            path: origin.to_string(),
            source: Box::new(source),
        })?;
        if raw.manifest_version != 1 {
            return Err(PinError::UnsupportedManifestVersion {
                path: origin.to_string(),
                found: raw.manifest_version,
            });
        }
        let layer = LayerId::from_str(&raw.toolchain.layer).map_err(|source| PinError::Layer {
            path: origin.to_string(),
            source,
        })?;
        if let Some(digest) = &raw.toolchain.digest {
            let hex = digest
                .strip_prefix("sha256:")
                .ok_or_else(|| PinError::MalformedDigest {
                    path: origin.to_string(),
                    found: digest.clone(),
                })?;
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(PinError::MalformedDigest {
                    path: origin.to_string(),
                    found: digest.clone(),
                });
            }
        }
        if let Some(tools) = &raw.toolchain.tools {
            if tools.is_empty() {
                return Err(PinError::EmptyTools {
                    path: origin.to_string(),
                });
            }
            // A tool name indexes the verified layer's `bin/`. `Path::join`
            // with an absolute path REPLACES the base, and `..` walks out of
            // it, so anything but a plain name would escape the layer — the
            // opposite of "a pin resolves exactly or the command fails".
            for name in tools {
                let plain = !name.is_empty()
                    && name != "."
                    && name != ".."
                    && !name.contains('/')
                    && !name.contains('\\')
                    && !name.contains('\0');
                if !plain {
                    return Err(PinError::ToolNameIsAPath {
                        path: origin.to_string(),
                        name: name.clone(),
                    });
                }
            }
        }
        let exports = parse_exports(&raw.exports, origin)?;
        Ok(Pin {
            realm: raw.toolchain.realm,
            channel: raw.toolchain.channel,
            layer,
            digest: raw.toolchain.digest,
            tools: raw.toolchain.tools,
            exports,
        })
    }

    /// Read and parse a pin file from disk.
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let content = std::fs::read_to_string(path).map_err(|source| PinError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&content, &path.display().to_string())
    }
}

/// Is this a relative path that stays inside its base? Returns the fault, or
/// `None` when it is usable.
///
/// The rule the whole file already applies to a tool name, applied to a
/// directory: an absolute path REPLACES the base in `Path::join`, and `..`
/// walks out of it, so either would let a declaration written in a repository
/// address something outside the checkout.
fn contained_relative_fault(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("empty".into());
    }
    if value.starts_with('/') || value.starts_with('\\') || value.contains(':') {
        return Some("absolute".into());
    }
    if value.contains('\0') {
        return Some("contains a NUL".into());
    }
    for component in value.split(['/', '\\']) {
        if component == ".." {
            return Some("climbs out with '..'".into());
        }
    }
    if value.split(['/', '\\']).all(|c| c.is_empty() || c == ".") {
        return Some("names no directory".into());
    }
    None
}

/// Validate the declared exports as a set (REQ-EXPORTDECL-001 clauses 1, 2, 4
/// and 5). Nothing here is best-effort: an entry that cannot be acted on is a
/// hard failure, because the whole point of declaring an export is that
/// something checks it.
fn parse_exports(raw: &[RawExport], origin: &str) -> Result<Vec<ExportDecl>, PinError> {
    let mut decls: Vec<ExportDecl> = Vec::with_capacity(raw.len());
    for e in raw {
        let kind = ExportKind::from_str(&e.kind).map_err(|()| PinError::UnknownExportKind {
            path: origin.to_string(),
            kind: e.kind.clone(),
            expected: ExportKind::ALL
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })?;
        if let Some(why) = contained_relative_fault(&e.out) {
            return Err(PinError::ExportOutEscapes {
                path: origin.to_string(),
                out: e.out.clone(),
                why,
            });
        }
        if let Some(first) = decls.iter().find(|d| d.out == e.out) {
            return Err(PinError::DuplicateExportOut {
                path: origin.to_string(),
                out: e.out.clone(),
                first: first.kind.to_string(),
                second: kind.to_string(),
            });
        }
        if let Some(select) = &e.select {
            if select.is_empty() {
                return Err(PinError::EmptyExportSelect {
                    path: origin.to_string(),
                    out: e.out.clone(),
                });
            }
            for name in select {
                let plain = !name.is_empty()
                    && name != "."
                    && name != ".."
                    && !name.contains('/')
                    && !name.contains('\\')
                    && !name.contains('\0');
                if !plain {
                    return Err(PinError::ExportSelectIsAPath {
                        path: origin.to_string(),
                        out: e.out.clone(),
                        name: name.clone(),
                    });
                }
            }
        }
        let env = match &e.env {
            None => None,
            Some(raw_env) => {
                if !kind.is_sourced() {
                    return Err(PinError::ExportEnvNotSourced {
                        path: origin.to_string(),
                        out: e.out.clone(),
                        kind: kind.to_string(),
                        sourced: ExportKind::ALL
                            .iter()
                            .filter(|k| k.is_sourced())
                            .map(|k| k.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    });
                }
                if let Some(why) = contained_relative_fault(&raw_env.script) {
                    return Err(PinError::ExportScriptEscapes {
                        path: origin.to_string(),
                        out: e.out.clone(),
                        script: raw_env.script.clone(),
                        why,
                    });
                }
                // Clause 5: this is REQUIRED, not defaulted. A default would be
                // a guess about PATH order made on the project's behalf, and
                // being wrong in either direction is what this clause exists to
                // prevent.
                let Some(order) = &raw_env.path else {
                    return Err(PinError::ExportEnvNeedsShimOrder {
                        path: origin.to_string(),
                        out: e.out.clone(),
                    });
                };
                let path = ShimOrder::from_str(order).map_err(|()| PinError::UnknownShimOrder {
                    path: origin.to_string(),
                    out: e.out.clone(),
                    found: order.clone(),
                })?;
                Some(ExportEnv {
                    script: raw_env.script.clone(),
                    path,
                })
            }
        };
        decls.push(ExportDecl {
            kind,
            out: e.out.clone(),
            select: e.select.clone(),
            env,
        });
    }
    Ok(decls)
}

/// The verdict for ONE declared export (clause 3).
#[derive(Debug, PartialEq, Eq)]
pub enum DeclaredExportStatus {
    /// The stamp names the layer the pin resolves to, by the declared adapter.
    Current,
    /// The declared directory carries no stamp — never generated, deleted, or
    /// not a varve export at all.
    ///
    /// This is a FAILURE, not a warning. "I forgot to generate it" and "it is
    /// stale" are the same severity to anyone relying on the export, and
    /// distinguishing them mainly helps the person who made the mistake.
    Missing,
    /// The stamp was produced from a different layer than the pin now resolves.
    Stale { stamped: String, current: String },
    /// The directory was produced by a DIFFERENT adapter than the one declared.
    /// A `cargo` declaration checked against a `vsix` stamp would otherwise
    /// pass on freshness while the declared thing was never produced at all.
    KindMismatch { declared: String, stamped: String },
    /// The stamp exists but could not be read or parsed. Distinct from
    /// `Missing`, because "re-run the export" is not the fix for a permissions
    /// fault or a truncated file.
    Unreadable(String),
}

impl DeclaredExportStatus {
    pub fn is_current(&self) -> bool {
        matches!(self, DeclaredExportStatus::Current)
    }
}

/// Check one declared export against the layer the pin currently resolves to.
///
/// `verify` runs this over EVERY declared export without being asked — that is
/// the whole of clause 3. `--export <DIR>` remains for a directory nobody has
/// declared yet; a declared one is checked whether or not anyone remembers it.
pub fn check_declared_export(
    decl: &ExportDecl,
    project_root: &Path,
    current_manifest_digest: &str,
) -> DeclaredExportStatus {
    use crate::exportstamp::{ExportStampError, ExportStatus, read_stamp, status};
    let dir = decl.dir(project_root);
    match read_stamp(&dir) {
        Err(ExportStampError::Missing(_)) => DeclaredExportStatus::Missing,
        Err(other) => DeclaredExportStatus::Unreadable(other.to_string()),
        Ok(stamp) => {
            if stamp.kind != decl.kind.as_str() {
                return DeclaredExportStatus::KindMismatch {
                    declared: decl.kind.as_str().to_string(),
                    stamped: stamp.kind,
                };
            }
            match status(&stamp, current_manifest_digest) {
                ExportStatus::Current => DeclaredExportStatus::Current,
                ExportStatus::Stale { stamped, current } => {
                    DeclaredExportStatus::Stale { stamped, current }
                }
            }
        }
    }
}

/// Shell lines that enter every declared environment AND varve's shims in one
/// go (clause 4).
///
/// The ordering is the part worth reading twice, because it INVERTS. Sourcing a
/// script PREPENDS its bin to PATH, so whatever is sourced LAST ends up first
/// on PATH and wins. An export declared `before-shims` — its compiler is meant
/// to win — must therefore be sourced AFTER the shims, and one declared
/// `after-shims` must be sourced BEFORE them. Emitting them in declaration
/// order would produce exactly the PATH the project said it did not want, and
/// `verify` would then report the shadowing the project had declared away.
pub fn env_lines(pin: &Pin, project_root: &Path, shim_env: Option<&Path>) -> Vec<String> {
    let mut lines = Vec::new();
    let sourced = |order: ShimOrder, lines: &mut Vec<String>| {
        for decl in pin
            .exports
            .iter()
            .filter(|d| d.env.as_ref().is_some_and(|e| e.path == order))
        {
            if let Some(script) = decl.env_script(project_root) {
                lines.push(format!(
                    "# {} export {} — declared {} (REQ-EXPORTDECL-001 clause 5)",
                    decl.kind,
                    decl.out,
                    order.as_str()
                ));
                lines.push(format!(". \"{}\"", script.display()));
            }
        }
    };
    // Sourced FIRST so the shims, sourced after, land ahead of them on PATH.
    sourced(ShimOrder::AfterShims, &mut lines);
    if let Some(env) = shim_env {
        lines.push("# varve's shims".to_string());
        lines.push(format!(". \"{}\"", env.display()));
    }
    // Sourced LAST so this environment's bin lands ahead of the shims — which
    // is what `before-shims` asked for.
    sourced(ShimOrder::BeforeShims, &mut lines);
    lines
}

/// What a declared export says about a binary PATH resolves ahead of a shim
/// (clause 5).
#[derive(Debug, PartialEq, Eq)]
pub enum ShadowDeclaration<'a> {
    /// Inside an export declared to sit BEFORE the shims. Expected, and
    /// `verify` must not fail on it — a check that fires on the setup the
    /// project deliberately configured is one people switch off.
    Expected(&'a ExportDecl),
    /// Inside an export declared to sit AFTER the shims. The declaration and
    /// the actual PATH disagree, which is a real fault with a precise fix —
    /// and a far better message than the generic hijack report.
    ContradictsDeclaration(&'a ExportDecl),
    /// Inside no declared export: the ordinary hijack REQ-SHADOW-001 is for.
    Undeclared,
}

/// Is `path` inside `dir`? Canonicalised where both exist, because an export
/// directory reached through a symlinked checkout is the same directory, and
/// lexically otherwise — a declared export that has not been generated yet
/// cannot be canonicalised and must still be recognisable.
fn is_within(dir: &Path, path: &Path) -> bool {
    let real = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    path.starts_with(dir) || real(path).starts_with(real(dir))
}

/// Classify a shadowing binary against the project's declared exports.
///
/// An SDK's `environment-setup-*` prepends its own bin to PATH, so its compiler
/// shadows varve's shims. Whether that is a hijack or the point depends entirely
/// on what the project declared — which is why clause 5 makes the declaration
/// mandatory rather than inferred.
pub fn classify_shadowing<'a>(
    pin: &'a Pin,
    project_root: &Path,
    found: &Path,
) -> ShadowDeclaration<'a> {
    for decl in &pin.exports {
        let Some(env) = &decl.env else {
            // An export nobody sources puts nothing on PATH, so a binary found
            // inside one is not explained by it.
            continue;
        };
        if is_within(&decl.dir(project_root), found) {
            return match env.path {
                ShimOrder::BeforeShims => ShadowDeclaration::Expected(decl),
                ShimOrder::AfterShims => ShadowDeclaration::ContradictsDeclaration(decl),
            };
        }
    }
    ShadowDeclaration::Undeclared
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.07.0"
digest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
tools   = ["rivet", "synth"]
"#;

    // rivet: verifies REQ-PIN-001
    #[test]
    fn parses_a_complete_pin() {
        let pin = Pin::parse(FULL, "varve.toml").unwrap();
        assert_eq!(pin.channel, Channel::Qualified);
        assert_eq!(pin.layer, LayerId::from_str("2026.07.0").unwrap());
        assert_eq!(
            pin.digest.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            pin.tools.as_deref(),
            Some(&["rivet".to_string(), "synth".to_string()][..])
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn digest_and_tools_are_optional() {
        let pin = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.08.0\"\n",
            "varve.toml",
        )
        .unwrap();
        assert_eq!(pin.channel, Channel::Rolling);
        assert_eq!(pin.digest, None);
        assert_eq!(pin.tools, None);
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unsupported_manifest_version() {
        let err = Pin::parse(
            "manifest-version = 2\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::UnsupportedManifestVersion { found: 2, .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-PATCH-001
    #[test]
    fn rejects_two_part_layer_with_the_grammar_guidance() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07\"\n",
            "varve.toml",
        )
        .unwrap_err();
        let PinError::Layer { source, .. } = &err else {
            panic!("got: {err}");
        };
        assert!(matches!(source, LayerIdError::MissingPatch(_)));
        // The guidance lives in the SOURCE (printed once via the chain).
        assert!(
            source.to_string().contains("three-part"),
            "the chain must teach the grammar: {source}"
        );
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unknown_keys_instead_of_ignoring_them() {
        let err = Pin::parse(
            "manifest-version = 1\nsurprise = true\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::Toml { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_unknown_channel() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"latest\"\nlayer = \"2026.07.0\"\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::Toml { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_malformed_digest() {
        // Includes a wrong-length PURE-HEX digest: length and charset are
        // independent checks and each must reject alone.
        for bad in [
            "sha256:short",
            "md5:aaaa",
            "aaaaaaaa",
            "sha256:GGGG",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let toml = format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ndigest = \"{bad}\"\n"
            );
            let err = Pin::parse(&toml, "varve.toml").unwrap_err();
            assert!(
                matches!(err, PinError::MalformedDigest { .. }),
                "input {bad:?} got: {err}"
            );
        }
    }

    // rivet: verifies REQ-PIN-002
    #[test]
    fn rejects_a_tool_name_that_is_a_path() {
        // A tool name is looked up INSIDE the verified layer. `Path::join`
        // with an absolute path REPLACES the base, so an unchecked name would
        // resolve outside the layer entirely — exactly the "never falls back
        // to binaries on PATH" guarantee the docs make. Fail closed here.
        for hostile in [
            "/usr/bin/id",
            "../../usr/bin/id",
            "sub/dir",
            "..",
            ".",
            "",
            "C:\\Windows\\system32\\cmd.exe",
        ] {
            let content = format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"{}\"]\n",
                hostile.replace('\\', "\\\\")
            );
            assert!(
                Pin::parse(&content, "varve.toml").is_err(),
                "tool name {hostile:?} must be refused — it escapes the layer"
            );
        }
        // Ordinary names still parse.
        let ok = "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = [\"rivet\", \"synth-c\", \"cargo_x\"]\n";
        assert!(Pin::parse(ok, "varve.toml").is_ok());
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn rejects_empty_tools_list() {
        let err = Pin::parse(
            "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.07.0\"\ntools = []\n",
            "varve.toml",
        )
        .unwrap_err();
        assert!(matches!(err, PinError::EmptyTools { .. }), "got: {err}");
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn errors_name_the_offending_file() {
        let err = Pin::parse("nonsense", "proj/sub/varve.toml").unwrap_err();
        assert!(
            err.to_string().contains("proj/sub/varve.toml"),
            "diagnostic must carry the path: {err}"
        );
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::exportstamp::{ExportStamp, write_stamp};

    const HEAD: &str =
        "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"2026.08.0\"\n";

    fn parse(exports: &str) -> Result<Pin, PinError> {
        Pin::parse(&format!("{HEAD}{exports}"), "varve.toml")
    }

    /// A project declaring the five adapters that exist plus the sourced one
    /// this release adds — the shape a real repository would carry.
    const DECLARED: &str = r#"
[[export]]
kind = "cargo"
out  = "vendor/registry"

[[export]]
kind = "vsix"
out  = ".vscode/varve-extensions"
select = ["rust-lang.rust-analyzer", "vadimcn.vscode-lldb"]

[[export]]
kind = "sdk"
out  = "toolchains/poky"
select = ["poky-cortexa53"]

[export.env]
script = "environment-setup-cortexa53-poky-linux"
path   = "before-shims"
"#;

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_project_declares_its_exports_in_the_pin_it_already_has() {
        // Clause 1: one file, and `verify` already reads it. The set of exports
        // used to live in a CI script or a shell history, which is why an
        // export nobody named never went stale — nothing looked at it.
        let pin = parse(DECLARED).unwrap();
        assert_eq!(pin.exports.len(), 3);
        assert_eq!(pin.exports[0].kind, ExportKind::Cargo);
        assert_eq!(pin.exports[0].out, "vendor/registry");
        assert_eq!(
            pin.exports[0].select, None,
            "no subset means the whole layer"
        );
        assert_eq!(pin.exports[0].env, None);

        // Clause 2: the adapter, the destination, and a SUBSET of the layer.
        assert_eq!(pin.exports[1].kind, ExportKind::Vsix);
        assert_eq!(
            pin.exports[1].select.as_deref(),
            Some(
                &[
                    "rust-lang.rust-analyzer".to_string(),
                    "vadimcn.vscode-lldb".to_string()
                ][..]
            )
        );

        // Clauses 4 and 5 on the sourced one.
        let sdk = &pin.exports[2];
        assert_eq!(sdk.kind, ExportKind::Sdk);
        let env = sdk.env.as_ref().expect("an sdk is entered, not pointed at");
        assert_eq!(env.script, "environment-setup-cortexa53-poky-linux");
        assert_eq!(env.path, ShimOrder::BeforeShims);

        // Declared relative, resolved absolute against the pin's directory, so
        // the file means the same thing on every machine.
        let root = Path::new("/repo");
        assert_eq!(sdk.dir(root), Path::new("/repo/toolchains/poky"));
        assert_eq!(
            sdk.env_script(root).unwrap(),
            Path::new("/repo/toolchains/poky/environment-setup-cortexa53-poky-linux")
        );
        assert_eq!(pin.exports[0].env_script(root), None);

        // A pin with no exports is still a pin: this is additive, and every
        // varve.toml already in the world has none.
        assert!(Pin::parse(HEAD, "varve.toml").unwrap().exports.is_empty());
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn the_declared_kind_is_one_varve_can_actually_produce() {
        // An adapter varve does not have is a declaration nothing will ever
        // satisfy — and, worse, one `verify` would have to skip, which is the
        // "only checks what it is told about" failure this requirement exists
        // to close.
        let err = parse("[[export]]\nkind = \"npm\"\nout = \"x\"\n").unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, PinError::UnknownExportKind { .. }), "{msg}");
        for known in ExportKind::ALL {
            assert!(
                msg.contains(known.as_str()),
                "the refusal must list {known}, or the author has nothing to correct to: {msg}"
            );
        }
        // Every kind's wire string is the one the adapters already stamp, so a
        // declaration and a stamp compare directly.
        for (kind, wire) in [
            (ExportKind::Cargo, "cargo"),
            (ExportKind::CratesVendor, "crates-vendor"),
            (ExportKind::BazelRegistry, "bazel-registry"),
            (ExportKind::BazelDistdir, "bazel-distdir"),
            (ExportKind::Vsix, "vsix"),
            (ExportKind::Sdk, "sdk"),
        ] {
            assert_eq!(kind.as_str(), wire);
            assert_eq!(ExportKind::from_str(wire).unwrap(), kind);
        }
        assert_eq!(ExportKind::ALL.len(), 6, "ALL must list every variant");
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_destination_that_leaves_the_repository_is_refused() {
        // The declaration is checked into a repository and resolved against the
        // directory holding varve.toml. An absolute path REPLACES that base and
        // `..` walks out of it, so either would let a committed file address
        // something outside the checkout — and `verify` would then report on a
        // directory nobody reviewing the pin could see.
        for bad in [
            "/etc",
            "../outside",
            "a/../../outside",
            "",
            ".",
            "./",
            "C:\\x",
        ] {
            let err = parse(&format!(
                "[[export]]\nkind = \"cargo\"\nout = \"{}\"\n",
                bad.replace('\\', "\\\\")
            ))
            .unwrap_err();
            assert!(
                matches!(err, PinError::ExportOutEscapes { .. }),
                "out {bad:?} must be refused, got: {err}"
            );
        }
        for good in ["vendor", "vendor/registry", "a/b/c"] {
            assert!(
                parse(&format!("[[export]]\nkind = \"cargo\"\nout = \"{good}\"\n")).is_ok(),
                "{good} is an ordinary export directory"
            );
        }
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn two_exports_may_not_share_one_directory() {
        // Each adapter writes ONE `.varve-export.json`. Two into one directory
        // means the second overwrites the first's stamp, after which `verify`
        // checks one export twice and the other never — a gate that reports
        // green on something it has not looked at.
        let err = parse(
            "[[export]]\nkind = \"cargo\"\nout = \"vendor\"\n\
             [[export]]\nkind = \"vsix\"\nout = \"vendor\"\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::DuplicateExportOut { .. }),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("cargo") && msg.contains("vsix"),
            "names both: {msg}"
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn a_subset_selection_names_payloads_not_paths() {
        // Clause 2's subset indexes the VERIFIED layer, exactly as `tools` does
        // in the toolchain block, so the same rule applies: a name, never a
        // path, or the selection resolves outside the layer.
        for bad in ["../evil", "a/b", "", ".", "..", "a\\b"] {
            let err = parse(&format!(
                "[[export]]\nkind = \"cargo\"\nout = \"v\"\nselect = [\"{}\"]\n",
                bad.replace('\\', "\\\\")
            ))
            .unwrap_err();
            assert!(
                matches!(err, PinError::ExportSelectIsAPath { .. }),
                "select {bad:?} must be refused, got: {err}"
            );
        }
        // Present but empty is a mistake with a specific correction: omitting
        // the key means the whole layer, so an empty list can only be a typo.
        let err = parse("[[export]]\nkind = \"cargo\"\nout = \"v\"\nselect = []\n").unwrap_err();
        assert!(
            matches!(err, PinError::EmptyExportSelect { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn an_environment_must_say_where_it_sits_relative_to_the_shims() {
        // Clause 5, and the reason these two requirements ship together. An
        // SDK's environment-setup prepends its own bin to PATH and shadows
        // varve's shims — the exact condition REQ-SHADOW-001 detects. Left
        // undeclared, `verify` must either miss a genuine hijack or fire on a
        // legitimate setup, and the spurious failure is worse: a check that
        // cries wolf is a check people switch off.
        let err = parse(
            "[[export]]\nkind = \"sdk\"\nout = \"t\"\n[export.env]\nscript = \"env-setup\"\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::ExportEnvNeedsShimOrder { .. }),
            "got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("before-shims"), "offers the answers: {msg}");
        assert!(msg.contains("after-shims"), "offers the answers: {msg}");
        assert!(
            msg.contains("REQ-SHADOW-001"),
            "says WHY it is needed, not just that it is: {msg}"
        );

        // Both answers parse, and nothing else does.
        for (value, want) in [
            ("before-shims", ShimOrder::BeforeShims),
            ("after-shims", ShimOrder::AfterShims),
        ] {
            let pin = parse(&format!(
                "[[export]]\nkind = \"sdk\"\nout = \"t\"\n[export.env]\nscript = \"e\"\npath = \"{value}\"\n"
            ))
            .unwrap();
            assert_eq!(pin.exports[0].env.as_ref().unwrap().path, want);
            assert_eq!(want.as_str(), value);
        }
        let err = parse(
            "[[export]]\nkind = \"sdk\"\nout = \"t\"\n[export.env]\nscript = \"e\"\npath = \"first\"\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::UnknownShimOrder { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn only_an_export_that_is_sourced_may_declare_an_environment() {
        // Clause 4 distinguishes a payload ENTERED as an environment from one
        // POINTED at. A local Cargo registry is pointed at by a config file; an
        // `[export.env]` on it would be accepted, ignored, and believed.
        let err = parse(
            "[[export]]\nkind = \"cargo\"\nout = \"v\"\n[export.env]\nscript = \"e\"\npath = \"after-shims\"\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::ExportEnvNotSourced { .. }),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("sdk"),
            "names what IS sourced: {err}"
        );
        assert!(ExportKind::Sdk.is_sourced());
        for pointed in ExportKind::ALL.iter().filter(|k| **k != ExportKind::Sdk) {
            assert!(
                !pointed.is_sourced(),
                "{pointed} is consumed by pointing at it, not by sourcing it"
            );
        }
        // …and the script itself must stay inside the export directory.
        let err = parse(
            "[[export]]\nkind = \"sdk\"\nout = \"t\"\n[export.env]\nscript = \"../../etc/profile\"\npath = \"after-shims\"\n",
        )
        .unwrap_err();
        assert!(
            matches!(err, PinError::ExportScriptEscapes { .. }),
            "got: {err}"
        );
    }

    fn stamped(dir: &std::path::Path, kind: &str, digest: &str) {
        write_stamp(
            dir,
            &ExportStamp {
                layer: "2026.08.0".into(),
                manifest_digest: digest.into(),
                kind: kind.into(),
            },
        )
        .unwrap();
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn every_declared_export_is_checked_and_an_absent_one_fails() {
        // Clause 3. Declared means checked — no `--export` argument, no CI
        // script listing directories. And "I forgot to generate it" and "it is
        // stale" are the same severity to anyone relying on the export, so a
        // missing directory FAILS rather than warns.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pin = parse(DECLARED).unwrap();
        let current = "sha256:aaaa";

        // Nothing generated yet: every declared export fails, none is skipped.
        for decl in &pin.exports {
            assert_eq!(
                check_declared_export(decl, root, current),
                DeclaredExportStatus::Missing,
                "{} must fail while it does not exist",
                decl.out
            );
        }

        // Generated against the current pin: fresh.
        for decl in &pin.exports {
            stamped(&decl.dir(root), decl.kind.as_str(), current);
            let got = check_declared_export(decl, root, current);
            assert!(
                got.is_current(),
                "{} should be fresh, got {got:?}",
                decl.out
            );
        }

        // The pin moves on and the exports do not.
        let moved = "sha256:bbbb";
        assert_eq!(
            check_declared_export(&pin.exports[0], root, moved),
            DeclaredExportStatus::Stale {
                stamped: current.into(),
                current: moved.into(),
            }
        );

        // A directory produced by a DIFFERENT adapter is not the declared
        // export, however fresh its stamp is — the declared thing was never
        // produced at all.
        let vsix = &pin.exports[1];
        stamped(&vsix.dir(root), "cargo", current);
        assert_eq!(
            check_declared_export(vsix, root, current),
            DeclaredExportStatus::KindMismatch {
                declared: "vsix".into(),
                stamped: "cargo".into(),
            }
        );

        // A stamp that exists but is unreadable is its own verdict: "re-run the
        // export" is not the fix for a truncated file.
        let cargo = &pin.exports[0];
        std::fs::write(
            cargo.dir(root).join(crate::exportstamp::STAMP_FILE),
            b"{not json",
        )
        .unwrap();
        assert!(matches!(
            check_declared_export(cargo, root, current),
            DeclaredExportStatus::Unreadable(_)
        ));
    }

    // rivet: verifies REQ-EXPORTDECL-001, REQ-SHADOW-001
    #[test]
    fn a_declared_sdk_environment_is_not_reported_as_a_hijack() {
        // Clause 5's payoff. The SDK's `aarch64-poky-linux-gcc` really is ahead
        // of varve's shims on PATH — the project said so. Reporting that as a
        // hijack is the cry-wolf failure; reporting an UNdeclared one as fine
        // is the miss. The declaration is what tells them apart.
        let root = Path::new("/repo");
        let pin = parse(DECLARED).unwrap();
        let sdk_gcc = Path::new("/repo/toolchains/poky/sysroots/x86_64/usr/bin/gcc");
        match classify_shadowing(&pin, root, sdk_gcc) {
            ShadowDeclaration::Expected(d) => assert_eq!(d.out, "toolchains/poky"),
            other => panic!("a declared before-shims SDK must be expected, got {other:?}"),
        }

        // Anywhere else is the ordinary hijack REQ-SHADOW-001 exists for — a
        // distro gcc, a `cargo install`ed tool, a stale shim directory.
        assert_eq!(
            classify_shadowing(&pin, root, Path::new("/usr/local/bin/gcc")),
            ShadowDeclaration::Undeclared
        );
        // …and so is a binary inside an export that is not sourced at all: a
        // vendor directory puts nothing on PATH, so it explains nothing.
        assert_eq!(
            classify_shadowing(&pin, root, Path::new("/repo/vendor/registry/gcc")),
            ShadowDeclaration::Undeclared
        );

        // Declared the OTHER way, the same binary is a real fault: the project
        // said varve's tools win and PATH says otherwise. Distinct verdict,
        // because the fix is distinct — fix PATH, or fix the declaration.
        let after = parse(
            "[[export]]\nkind = \"sdk\"\nout = \"toolchains/poky\"\n[export.env]\nscript = \"e\"\npath = \"after-shims\"\n",
        )
        .unwrap();
        match classify_shadowing(&after, root, sdk_gcc) {
            ShadowDeclaration::ContradictsDeclaration(d) => {
                assert_eq!(d.out, "toolchains/poky")
            }
            other => panic!("expected ContradictsDeclaration, got {other:?}"),
        }
    }

    // rivet: verifies REQ-EXPORTDECL-001
    #[test]
    fn one_command_sources_the_whole_environment_in_the_declared_path_order() {
        // Clause 4, and the ordering INVERTS — which is the whole reason this
        // is computed rather than written by hand. Sourcing a script PREPENDS
        // its bin to PATH, so whatever is sourced LAST wins. An export declared
        // `before-shims` must therefore be sourced AFTER the shims; emitting
        // them in declaration order would produce exactly the PATH the project
        // said it did not want, and `verify` would then flag it.
        let root = Path::new("/repo");
        let shim_env = Path::new("/home/u/.varve/env");
        let pin = parse(
            "[[export]]\nkind = \"cargo\"\nout = \"vendor\"\n\
             [[export]]\nkind = \"sdk\"\nout = \"early\"\n\
             [export.env]\nscript = \"env-setup-early\"\npath = \"before-shims\"\n\
             [[export]]\nkind = \"sdk\"\nout = \"late\"\n\
             [export.env]\nscript = \"env-setup-late\"\npath = \"after-shims\"\n",
        )
        .unwrap();
        let sourced: Vec<String> = env_lines(&pin, root, Some(shim_env))
            .into_iter()
            .filter(|l| l.starts_with(". "))
            .collect();
        assert_eq!(
            sourced,
            vec![
                ". \"/repo/late/env-setup-late\"".to_string(),
                ". \"/home/u/.varve/env\"".to_string(),
                ". \"/repo/early/env-setup-early\"".to_string(),
            ],
            "after-shims is sourced FIRST so the shims land ahead of it"
        );
        // A cargo export contributes nothing: it is pointed at, not entered.
        assert!(
            !env_lines(&pin, root, Some(shim_env))
                .join("\n")
                .contains("vendor")
        );
        // Without a shim env there is still an environment to enter.
        let no_shims: Vec<String> = env_lines(&pin, root, None)
            .into_iter()
            .filter(|l| l.starts_with(". "))
            .collect();
        assert_eq!(no_shims.len(), 2);
        assert!(!no_shims.iter().any(|l| l.contains(".varve/env")));
    }
}
