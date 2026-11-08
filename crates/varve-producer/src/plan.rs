//! From a realm's manifest to the work a deposit has to do
//! (REQ-PRODUCER-002, REQ-REALM2-002).
//!
//! This is where the port stops being a translation and starts being an
//! improvement. The shell pipeline could not read `layer.toml`; it read three
//! environment variables — `TARBALL_TOOLS`, `WSC_VERSION`, `VSIX_PACKAGES` —
//! encoded as space-separated entries of colon-separated fields. That encoding
//! is why `varve-core::layerspec` has to refuse a version containing a space,
//! why the opt-in reasons need a heredoc, and why one whole class of tests
//! exists.
//!
//! Here the manifest is read directly. There is no encoding, so there is
//! nothing for a separator to corrupt.
//!
//! It also removes a hard limit rather than working around one. The shell
//! carried exactly ONE raw-per-platform tool, because that layout lived in a
//! variable called `WSC_VERSION` that named a specific tool in a specific
//! repository. The `bytecodealliance` realm needs three — `wac`, `wkg` and
//! `wrpc` — and could not be assembled at all. Here `layout` is a property of
//! a tool, so three is not a special case; it is just three.

use crate::asset::{self, TemplateError};
use varve_core::layerspec::{
    DocsFormat, LayerManifest, ManifestCrate, ManifestDocs, ManifestTool, ManifestVsix,
};

/// What kind of payload a plan item produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// A binary inside a per-platform archive.
    Tarball,
    /// A bare per-platform binary, no archive.
    RawPerPlatform,
    /// A VS Code extension package.
    Vsix,
    /// A TREE: the archive is the payload (REQ-SDKDEPOSIT-001). Not mined for
    /// a binary, not architecture-checked as though it were one.
    Sdk,
    /// A language toolchain (REQ-TOOLCHAIN-001). The archive is the payload,
    /// as for `Sdk` — and unlike `Sdk` it carries NO relocation prefix,
    /// because a toolchain is laid down and pointed at rather than patched.
    /// Keeping it a separate variant is what stops `check_sdk_prefixes`
    /// demanding a prefix this kind must never have.
    Toolchain,
    /// Documentation the layer carries for the versions it pins
    /// (REQ-LAYERDOCS-001). HELD, never dispatched — it is data, like a
    /// `vsix`, and varve does not render it.
    ///
    /// One manifest kind, two storage shapes, decided by the declared format:
    /// `html` and `rustdoc` are TREES (a site is not one file), while `pdf`,
    /// `markdown` and `reqif` are single files. The format decides it, not
    /// the extension of whatever the upstream happened to name the asset.
    Docs(DocsFormat),
    /// A Rust `.crate`, stored exactly as the release published it
    /// (REQ-CRATEPAYLOAD-001). HELD, never dispatched; never unpacked, because
    /// its sha256 is the `cksum` a Cargo registry index records for it.
    Crate,
    /// A Zephyr module TREE (REQ-ZMODEXPORT-001): the archive is the payload,
    /// stored as published, and must contain `zephyr/module.yml`. HELD, never
    /// dispatched; platform-independent, because source is the same on every
    /// machine.
    ZephyrModule,
}

impl PayloadKind {
    /// The kind `varve deposit` signs for this payload, or `None` for a tool.
    ///
    /// Exhaustive on purpose. This used to be an inline match ending in
    /// `_ => None`, so a document was deposited with no kind at all — signed
    /// as a TOOL — and `export-docs` found nothing in a layer that carried
    /// one. A new kind now fails to compile here instead of shipping unlabelled.
    pub fn deposit_kind(self) -> Option<&'static str> {
        match self {
            PayloadKind::Tarball | PayloadKind::RawPerPlatform => None,
            PayloadKind::Vsix => Some("vsix"),
            PayloadKind::Sdk => Some("sdk"),
            PayloadKind::Toolchain => Some("toolchain"),
            PayloadKind::Docs(_) => Some("docs"),
            PayloadKind::Crate => Some("crate"),
            PayloadKind::ZephyrModule => Some("zephyr-module"),
        }
    }
}

/// One asset to fetch, verify and stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPlan {
    /// The name the payload is deposited under, and dispatched by.
    pub name: String,
    /// `owner/repo` the release comes from.
    pub repo: String,
    /// What the payload IS — the number it answers to, and the one signed
    /// into the layer.
    pub version: String,
    /// The release tag to ASK the forge for. Equal to `version` for almost
    /// every tool; different on a hub, where `pulseengine/jess` tags `v0.7.2`
    /// and ships `with-device` at `0.2.2` (REQ-PAYLOADID-001).
    pub release: String,
    /// The release asset, template already expanded.
    pub asset: String,
    /// `None` for a platform-independent payload.
    pub platform: Option<String>,
    /// Did the manifest NAME this asset, through `asset-for`, rather than
    /// leave it to the default template?
    ///
    /// The difference decides what a missing asset MEANS. A template-derived
    /// name that matches nothing is ordinary: upstream builds three platforms
    /// where the layer asks for four, and the layer omits the fourth (loom
    /// has done this for months). An asset the operator wrote out by hand and
    /// that does not exist is a MISTAKE — naming it was a claim that it is
    /// there. Layer 2026.09.18 shipped without a single Linux build of five
    /// tools because both read as the same note.
    pub named_explicitly: bool,
    pub kind: PayloadKind,
    /// Why this release is ingested with no proof, if it is.
    pub unverified_reason: Option<String>,
    /// A path that must exist inside an `sdk` payload once unpacked
    /// (REQ-SDKDEPOSIT-001 clause 5). `None` for every other kind.
    pub contains: Option<String>,
    /// The asset carrying this release's unsigned digest list, if it publishes
    /// one (REQ-UPSTREAMSUMS-001). A property of the RELEASE, so every payload
    /// from one release carries the same value.
    pub upstream_sums: Option<String>,
    /// The signed digest list this release is verified against, and the key
    /// that must have signed it (REQ-SIGNEDSUMS-001). A property of the
    /// RELEASE, like `upstream_sums`.
    pub pgp_sums: Option<PgpSumsPlan>,
    /// The label a human reads when choosing between documents. `None` for
    /// every kind but `docs`.
    pub title: Option<String>,
    /// The payload a document documents, by name. `None` for every kind but
    /// `docs`.
    pub documents: Option<String>,
    /// The pip requirement files of a `zephyr-module` the operator accepts
    /// (REQ-ZMODEXPORT-001 clause 5). `None` for every other kind.
    pub allow_pip: Option<Vec<String>>,
}

/// A release's PGP-signed digest list, as declared in the producer's input
/// (REQ-SIGNEDSUMS-001): where the list and its detached signature are, how
/// to read the list, and the pinned certificate that must have signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpSumsPlan {
    /// The release asset carrying the digest list, templates expanded.
    pub list: String,
    /// The release asset carrying the detached signature over `list`.
    pub signature: String,
    pub format: crate::pgpsums::ListFormat,
    /// The payload version and release tag the list must belong to. A
    /// signature says who published a list, not which release it is for.
    pub version: String,
    pub release: String,
    /// The OpenPGP certificate. Relative to the input file once
    /// [`anchor_key_files`] has run; read from disk at ingestion, and its
    /// absence is an error and never a weaker rung.
    pub key_file: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// `pgp-sums` without `pgp-key-file`: a signature with no pinned key to
    /// check it against verifies nothing.
    PgpSumsNeedsKey {
        tool: String,
    },
    /// A `pgp-*` field on an entry that declares no `pgp-sums`: read by
    /// nothing, and believed.
    PgpFieldWithoutSums {
        tool: String,
        field: &'static str,
    },
    /// `pgp-sums-format` names a format this producer does not read.
    PgpSumsFormatUnknown {
        tool: String,
        found: String,
    },
    /// Both a signed and an unsigned digest list: the unsigned one could never
    /// be consulted, because the signed rung either accepts or aborts.
    PgpSumsAndUpstreamSums {
        tool: String,
    },
    /// `pgp-sums` with an asset name that names no release: an older, validly
    /// signed list could stand in for this one.
    PgpSumsAssetNotVersioned {
        tool: String,
        asset: String,
    },
    /// The version or release the names expand with is a MOVING tag, so the
    /// expanded names are the same for every release.
    PgpSumsMovingTag {
        tool: String,
        what: &'static str,
        value: String,
    },
    /// Neither the list nor its signature carries the release, so the same
    /// two names would serve every release.
    PgpSumsListNotVersioned {
        tool: String,
        list: String,
        signature: String,
    },
    Template(TemplateError),
    /// Documentation describes the layer, not a machine, so a per-platform
    /// template would expand to several identical payloads under one name.
    DocsIsNotPerPlatform {
        name: String,
        asset: String,
    },
    /// A crate is platform-independent source; a per-platform template would
    /// expand to several payloads claiming one name and version.
    CrateIsNotPerPlatform {
        name: String,
        asset: String,
    },
    /// A Zephyr module is source: one tree for every platform.
    ZephyrIsNotPerPlatform {
        name: String,
        asset: String,
    },
    /// A `zephyr-module` names no asset, and none can be derived.
    ZephyrNeedsAsset {
        name: String,
    },
    /// An `sdk` or `toolchain` names no asset, and none can be derived.
    NeedsAsset {
        name: String,
        layout: String,
        /// The entry did name its files through `asset-for`, which does not
        /// substitute for `asset` on these layouts (#331).
        has_asset_for: bool,
    },
    /// `allow-pip` on an entry that is not a `zephyr-module`.
    AllowPipNotOnZephyrModule {
        tool: String,
    },
    /// A tool declares a layout this planner does not implement.
    UnknownLayout {
        tool: String,
        layout: String,
    },
    /// A tool restricts itself to a platform the layer does not declare.
    ///
    /// Refused rather than ignored. An ignored entry is indistinguishable from
    /// a typo, and the symptom would be a tool quietly missing from a signed
    /// layer — which is how layer 2026.09.18 shipped without a single Linux
    /// build of five tools.
    PlatformNotInLayer {
        tool: String,
        platform: String,
        declared: Vec<String>,
    },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Template(e) => write!(f, "{e}"),
            PlanError::PgpSumsNeedsKey { tool } => write!(
                f,
                "tool {tool:?} declares `pgp-sums` but no `pgp-key-file`. A \
                 signature is only evidence against a key the operator pinned: \
                 name the OpenPGP certificate, as a path relative to this file, \
                 e.g. pgp-key-file = \"keys/upstream.asc\". varve never fetches \
                 the key and never reads one from beside the artifact."
            ),
            PlanError::PgpFieldWithoutSums { tool, field } => write!(
                f,
                "tool {tool:?} sets `{field}` but declares no `pgp-sums`. \
                 Nothing would read it, and a pinned key that vouches for \
                 nothing looks like a verified release. Declare `pgp-sums`, or \
                 drop `{field}`."
            ),
            PlanError::PgpSumsFormatUnknown { tool, found } => write!(
                f,
                "tool {tool:?} declares pgp-sums-format = {found:?}. Known \
                 formats are \"sha256sums\" (the default) and \"rust-channel\"."
            ),
            PlanError::PgpSumsAssetNotVersioned { tool, asset } => write!(
                f,
                "tool {tool:?} declares `pgp-sums` with the asset name {asset:?}, which \
                 names no release (no `%V` or `%R`). A signed digest list proves who \
                 published it, not which release it is for: with a versionless asset name \
                 an OLDER, validly signed list and its older assets could be served in \
                 place of this release and be recorded as it. Put `%V` or `%R` in the \
                 asset name so the list must name this release's files."
            ),
            PlanError::PgpSumsMovingTag { tool, what, value } => write!(
                f,
                "tool {tool:?} declares `pgp-sums` with the {what} {value:?}, which names no \
                 particular release (a moving tag such as latest, nightly, stable or main, or \
                 a token with no leading digit). The asset names built from it are identical \
                 for every release, so an OLDER validly signed list and its older assets \
                 would stand in for this one. Declare a {what} that starts with a digit — a \
                 version such as 1.2.3 or a date such as 2026-10-01."
            ),
            PlanError::PgpSumsListNotVersioned {
                tool,
                list,
                signature,
            } => write!(
                f,
                "tool {tool:?} declares `pgp-sums` with the list {list:?} and signature \
                 {signature:?}, and neither names a release (no `%V` or `%R`). The same two \
                 names would serve every release, so a list from another release could be \
                 served in place of this one's. Put `%V` or `%R` in the list or signature name."
            ),
            PlanError::PgpSumsAndUpstreamSums { tool } => write!(
                f,
                "tool {tool:?} declares both `pgp-sums` and `upstream-sums`. \
                 The signed list either verifies or aborts the run; it never \
                 falls through to an unsigned one, so `upstream-sums` could \
                 never be consulted. Drop it."
            ),
            PlanError::PlatformNotInLayer {
                tool,
                platform,
                declared,
            } => write!(
                f,
                "tool {tool:?} restricts itself to platform {platform:?}, which \
                 this layer does not declare.\n  declared: {}\n\
                 Refusing rather than ignoring it: an ignored entry reads \
                 exactly like a typo, and the symptom is a tool quietly \
                 missing from a signed layer.",
                declared.join(", ")
            ),
            PlanError::DocsIsNotPerPlatform { name, asset } => write!(
                f,
                "docs {name:?} uses a per-platform template {asset:?}. \
                 Documentation describes the LAYER, not a machine — the same \
                 pages are true on every platform — so a `%T` here would \
                 deposit several identical payloads under one name and make \
                 `varve export-docs {name}` ambiguous. Name the asset without \
                 a platform placeholder."
            ),
            PlanError::CrateIsNotPerPlatform { name, asset } => write!(
                f,
                "crate {name:?} uses a per-platform template {asset:?}. A \
                 `.crate` is source — the same bytes on every platform, and \
                 the same `cksum` in the registry index — so a platform \
                 placeholder here would deposit several payloads under one \
                 name and version. Name the asset without one."
            ),
            PlanError::ZephyrIsNotPerPlatform { name, asset } => write!(
                f,
                "zephyr-module {name:?} uses a per-platform template {asset:?}. A \
                 module is source — the same tree on every platform — so a platform \
                 placeholder here would deposit several payloads under one name and \
                 version. Name the asset without one."
            ),
            PlanError::ZephyrNeedsAsset { name } => write!(
                f,
                "zephyr-module {name:?} names no `asset`. The archive's name is the \
                 upstream's and cannot be derived from the module's name, so the \
                 manifest states it, e.g. asset = \"{name}-%V.tar.gz\"."
            ),
            PlanError::NeedsAsset {
                name,
                layout,
                has_asset_for: true,
            } => write!(
                f,
                "{layout} {name:?} sets `asset-for` but no `asset`. On a {layout} \
                 layout `asset-for` does not substitute for `asset`: an `asset` \
                 template is still required, since the archive's name is the \
                 upstream's and cannot be derived from the entry's name, e.g. \
                 asset = \"{name}-%V.tar.gz\"."
            ),
            PlanError::NeedsAsset { name, layout, .. } => write!(
                f,
                "{layout} {name:?} names no `asset`. The archive's name is the \
                 upstream's and cannot be derived from the entry's name, so the \
                 manifest states it, e.g. asset = \"{name}-%V.tar.gz\"."
            ),
            PlanError::AllowPipNotOnZephyrModule { tool } => write!(
                f,
                "tool {tool:?} sets `allow-pip`, and only an entry with \
                 layout = \"zephyr-module\" has pip requirement files to accept. \
                 Left in place it would be read by nothing and believed. Drop it, \
                 or make this entry a zephyr-module."
            ),
            PlanError::UnknownLayout { tool, layout } => write!(
                f,
                "tool {tool:?} declares layout = {layout:?}. Known layouts are \
                 \"tarball\" (a per-platform archive) and \"raw-per-platform\" \
                 (a bare per-platform binary)."
            ),
        }
    }
}

impl std::error::Error for PlanError {}

impl From<TemplateError> for PlanError {
    fn from(e: TemplateError) -> Self {
        PlanError::Template(e)
    }
}

fn repo_of(tool_repo: &Option<String>, name: &str) -> String {
    match tool_repo {
        Some(r) => r.clone(),
        None => format!("pulseengine/{name}"),
    }
}

/// The asset template a tool uses, defaulted per layout.
///
/// A raw-per-platform tool has no archive to name, so its default is the tool
/// name plus the platform — the shape `wsc-linux-x86_64` and
/// `wac-cli-aarch64-apple-darwin` both follow once a template is given.
fn template_of(t: &ManifestTool, kind: PayloadKind) -> String {
    if let Some(a) = &t.asset {
        return a.clone();
    }
    match kind {
        PayloadKind::Tarball => asset::default_tarball_template(&t.name, &t.version),
        PayloadKind::RawPerPlatform => format!("{}-%T", t.name),
        PayloadKind::Vsix => unreachable!("a vsix carries its template"),
        // An SDK's asset name is never derivable: sdk-ng spells it
        // `toolchain_gnu_<host>_<target>.tar.xz`, wasi-sdk spells it
        // `wasi-sdk-34.0-arm64-linux.tar.gz`. Neither follows from the tool
        // name, so the manifest states it and `plan` refuses without one.
        PayloadKind::Sdk => unreachable!("an sdk carries its template"),
        // Nor is a toolchain's: upstream Rust spells it
        // `rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz`, with the
        // component name and the version in it and neither derivable
        // from the payload name. The manifest states it.
        PayloadKind::Toolchain => unreachable!("a toolchain carries its template"),
        PayloadKind::Docs(_) => unreachable!("a docs entry carries its template"),
        PayloadKind::Crate => unreachable!("a crate is planned by plan_crate"),
        // The tree's name is the upstream's, like an sdk's: not derivable.
        PayloadKind::ZephyrModule => unreachable!("a zephyr-module carries its template"),
    }
}

fn kind_of(t: &ManifestTool) -> Result<PayloadKind, PlanError> {
    match t.layout.as_deref() {
        None | Some("tarball") => Ok(PayloadKind::Tarball),
        Some("raw-per-platform") => Ok(PayloadKind::RawPerPlatform),
        Some("sdk") => Ok(PayloadKind::Sdk),
        Some("toolchain") => Ok(PayloadKind::Toolchain),
        Some("zephyr-module") => Ok(PayloadKind::ZephyrModule),
        Some(other) => Err(PlanError::UnknownLayout {
            tool: t.name.clone(),
            layout: other.to_string(),
        }),
    }
}

/// The signed-digest-list declaration of one tool, validated (REQ-SIGNEDSUMS-001).
///
/// `pgp-sums`, `pgp-sums-signature`, `pgp-sums-format` and `pgp-key-file` are
/// ONE declaration: the first and the last are required together, and the two
/// in between are meaningless without them. Anything else is refused here, at
/// plan time, because half of it is a proof nobody can check.
///
/// The signature defaults to the list's name plus `.asc`, which is the
/// convention (`SHA256SUMS` / `SHA256SUMS.asc`, and Rust's
/// `channel-rust-stable.toml` / `.toml.asc`). The format defaults to
/// `sha256sums`.
fn pgp_plan(
    t: &ManifestTool,
    release: &str,
    kind: PayloadKind,
) -> Result<Option<PgpSumsPlan>, PlanError> {
    let Some(list) = &t.pgp_sums else {
        let stray = [
            ("pgp-sums-signature", t.pgp_sums_signature.is_some()),
            ("pgp-sums-format", t.pgp_sums_format.is_some()),
            ("pgp-key-file", t.pgp_key_file.is_some()),
        ];
        if let Some((field, _)) = stray.into_iter().find(|(_, set)| *set) {
            return Err(PlanError::PgpFieldWithoutSums {
                tool: t.name.clone(),
                field,
            });
        }
        return Ok(None);
    };
    let Some(key_file) = &t.pgp_key_file else {
        return Err(PlanError::PgpSumsNeedsKey {
            tool: t.name.clone(),
        });
    };
    if t.upstream_sums.is_some() {
        return Err(PlanError::PgpSumsAndUpstreamSums {
            tool: t.name.clone(),
        });
    }
    let format = match &t.pgp_sums_format {
        None => crate::pgpsums::ListFormat::default(),
        Some(f) => {
            crate::pgpsums::ListFormat::parse(f).ok_or_else(|| PlanError::PgpSumsFormatUnknown {
                tool: t.name.clone(),
                found: f.clone(),
            })?
        }
    };
    // A signed list proves who published it, not which release it is for.
    // With the sha256sums format the only thing tying the list to THIS release
    // is that every asset is looked up by a name that carries the release, so
    // a versionless name lets an older signed list and its older assets stand
    // in for it. (A Rust channel binds through its own version instead, and is
    // checked at ingestion.)
    //
    // But template TEXT proves nothing when the value it expands with is a
    // moving tag: `t-%V.tar.gz` with version `latest` is `t-latest.tar.gz` for
    // every release. So each placeholder a template uses must expand from a
    // value that names a release ([`names_a_release`]).
    let list_template = list.clone();
    let signature_template = t
        .pgp_sums_signature
        .clone()
        .unwrap_or_else(|| format!("{list_template}.asc"));
    if format == crate::pgpsums::ListFormat::Sha256Sums {
        let carries_release = |name: &str| name.contains("%V") || name.contains("%R");
        let expands_from_a_release = |name: &str| -> Result<(), PlanError> {
            if name.contains("%V") && !names_a_release(&t.version) {
                return Err(PlanError::PgpSumsMovingTag {
                    tool: t.name.clone(),
                    what: "version",
                    value: t.version.clone(),
                });
            }
            if name.contains("%R") && !names_a_release(release) {
                return Err(PlanError::PgpSumsMovingTag {
                    tool: t.name.clone(),
                    what: "release",
                    value: release.to_string(),
                });
            }
            Ok(())
        };
        // An entry with no `asset` takes the default tarball template, which
        // embeds the version literally.
        if let Some(a) = &t.asset {
            if !carries_release(a) {
                return Err(PlanError::PgpSumsAssetNotVersioned {
                    tool: t.name.clone(),
                    asset: a.clone(),
                });
            }
            expands_from_a_release(a)?;
        }
        if t.asset.is_none() {
            if kind != PayloadKind::Tarball {
                return Err(PlanError::PgpSumsAssetNotVersioned {
                    tool: t.name.clone(),
                    asset: template_of(t, kind),
                });
            }
            if !names_a_release(&t.version) {
                return Err(PlanError::PgpSumsMovingTag {
                    tool: t.name.clone(),
                    what: "version",
                    value: t.version.clone(),
                });
            }
        }
        for a in t.asset_for.values() {
            if !carries_release(a) {
                return Err(PlanError::PgpSumsAssetNotVersioned {
                    tool: t.name.clone(),
                    asset: a.clone(),
                });
            }
            expands_from_a_release(a)?;
        }
        // The list or its signature must carry the release as well, or two
        // fixed names serve every release.
        if !carries_release(&list_template) && !carries_release(&signature_template) {
            return Err(PlanError::PgpSumsListNotVersioned {
                tool: t.name.clone(),
                list: list_template,
                signature: signature_template,
            });
        }
        expands_from_a_release(&list_template)?;
        expands_from_a_release(&signature_template)?;
    }
    let list = asset::expand(&list_template, &t.version, release, None, None)?;
    let signature = match &t.pgp_sums_signature {
        Some(s) => asset::expand(s, &t.version, release, None, None)?,
        None => format!("{list}.asc"),
    };
    Ok(Some(PgpSumsPlan {
        list,
        signature,
        format,
        version: t.version.clone(),
        release: release.to_string(),
        key_file: std::path::PathBuf::from(key_file),
    }))
}

/// Words that name a CHANNEL rather than a release: what they point at changes.
/// As a suffix of a full version (`1.2.3-beta.1`) `beta` and `alpha` are
/// ordinary prerelease labels and pass; these do not, even as a suffix.
const MOVING_SUFFIXES: &[&str] = &[
    "latest", "rolling", "lts", "stable", "current", "head", "main", "master", "edge", "next",
    "canary",
];

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A segment that is a wildcard, or that fuses digits with a moving word
/// (`3lts`).
fn is_wildcard_or_fused(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    lower == "x"
        || lower == "*"
        || (segment.bytes().any(|b| b.is_ascii_digit())
            && MOVING_SUFFIXES.iter().any(|w| lower.contains(w)))
}

/// Does this version or release tag name exactly ONE release?
///
/// This is a NAME HEURISTIC, not a cryptographic binding: it keeps the names a
/// signed list is looked up under from being the same for every release, and a
/// publisher who reuses a numbered tag defeats it.
///
/// After one leading `v` the token must be either
/// * a full date, `YYYY-MM-DD` or `YYYY.MM.DD`; or
/// * at least two numeric dot-components (`1.2`, `1.2.3`), optionally followed
///   by a `-prerelease` or `+build` suffix.
///
/// Refused: a bare number (`1`, `2026`, `v4`), any `x`, `X` or `*` segment
/// (`3.x`, `1.*`), a component that is not all digits (`3lts`), an empty
/// suffix, and a suffix segment that is a moving word (`1.2.3-latest`,
/// `1.0-rolling`) or fuses one with digits (`1.2.3-3lts`). `beta`, `alpha`,
/// `rc` and `nightly` are prerelease labels and pass as a suffix of a full
/// version, never as the version.
pub fn names_a_release(token: &str) -> bool {
    let bare = token.strip_prefix('v').unwrap_or(token);
    if is_full_date(bare) {
        return true;
    }
    let (core, suffix) = match bare.find(['-', '+']) {
        Some(at) => (&bare[..at], Some(&bare[at + 1..])),
        None => (bare, None),
    };
    let components: Vec<&str> = core.split('.').collect();
    if components.len() < 2 || !components.iter().all(|c| is_digits(c)) {
        return false;
    }
    match suffix {
        None => true,
        Some(suffix) => {
            !suffix.is_empty()
                && suffix.split(['-', '.', '+', '_']).all(|segment| {
                    !segment.is_empty()
                        && !is_wildcard_or_fused(segment)
                        && !MOVING_SUFFIXES.contains(&segment.to_ascii_lowercase().as_str())
                })
        }
    }
}

/// `YYYY-MM-DD` or `YYYY.MM.DD`, digits only.
fn is_full_date(s: &str) -> bool {
    let sep = if s.contains('-') { '-' } else { '.' };
    let parts: Vec<&str> = s.split(sep).collect();
    matches!(parts.as_slice(), [y, m, d]
        if y.len() == 4 && m.len() == 2 && d.len() == 2
            && is_digits(y) && is_digits(m) && is_digits(d))
}

/// Resolve every `pgp-key-file` against the input file that named it.
///
/// The path in the input is relative to THAT file, so the planner (which has no
/// idea where the file lives) leaves it as written and the caller that read the
/// file anchors it here, once, before anything is ingested. A relative path
/// resolved against the working directory instead would make the same input
/// verify against a different key depending on where it was run from.
pub fn anchor_key_files(plans: &mut [PayloadPlan], input_file: &std::path::Path) {
    let base = match input_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    for plan in plans {
        if let Some(pgp) = &mut plan.pgp_sums {
            pgp.key_file = base.join(&pgp.key_file);
        }
    }
}

/// Expand one tool into one plan item per platform.
pub fn plan_tool(t: &ManifestTool, platforms: &[&str]) -> Result<Vec<PayloadPlan>, PlanError> {
    let kind = kind_of(t)?;
    // The pip opt-in belongs to a module and to nothing else; on any other
    // entry it would be dropped or signed, and believed either way.
    if t.allow_pip.is_some() && kind != PayloadKind::ZephyrModule {
        return Err(PlanError::AllowPipNotOnZephyrModule {
            tool: t.name.clone(),
        });
    }
    // A module's archive name is the upstream's and cannot be derived, so it
    // is stated, and a missing one is a refusal and not a panic.
    if kind == PayloadKind::ZephyrModule {
        match &t.asset {
            None => {
                return Err(PlanError::ZephyrNeedsAsset {
                    name: t.name.clone(),
                });
            }
            Some(a) if asset::is_per_platform(a) => {
                return Err(PlanError::ZephyrIsNotPerPlatform {
                    name: t.name.clone(),
                    asset: a.clone(),
                });
            }
            Some(_) => {}
        }
    }
    // Likewise an sdk's or a toolchain's: upstream's name, not derivable, so a
    // missing one is a refusal naming the entry and not a panic (#306).
    if t.asset.is_none() && matches!(kind, PayloadKind::Sdk | PayloadKind::Toolchain) {
        return Err(PlanError::NeedsAsset {
            name: t.name.clone(),
            layout: t.layout.clone().unwrap_or_default(),
            has_asset_for: !t.asset_for.is_empty(),
        });
    }
    let template = template_of(t, kind);
    let repo = repo_of(&t.repo, &t.name);
    // `binary` names the executable when it differs from the tool (kiln ships
    // kilnd); the payload is deposited under THAT name, which is what a
    // consumer dispatches.
    let name = t.binary.clone().unwrap_or_else(|| t.name.clone());
    // Absent `release`, the version serves as the tag — the ordinary case.
    let release = t.release.clone().unwrap_or_else(|| t.version.clone());
    let pgp_sums = pgp_plan(t, &release, kind)?;

    let mut out = Vec::new();
    if !asset::is_per_platform(&template) {
        out.push(PayloadPlan {
            name,
            repo,
            version: t.version.clone(),
            release: release.clone(),
            asset: asset::expand(&template, &t.version, &release, None, None)?,
            platform: None,
            // No `asset-for` on this path: either the payload is platform-
            // independent, or its kind carries no per-platform naming at all.
            named_explicitly: false,
            kind,
            unverified_reason: t.opt_in_reason(),
            contains: t.contains.clone(),
            upstream_sums: t.upstream_sums.clone(),
            pgp_sums: pgp_sums.clone(),
            title: None,
            documents: None,
            allow_pip: t.allow_pip.clone(),
        });
        return Ok(out);
    }
    // A tool may be carried for FEWER platforms than the layer declares, for
    // an upstream whose build for one cannot be a varve payload at all. Each
    // named platform must be one the layer declares, or it is refused: an
    // ignored name reads exactly like a typo (REQ-TOOLPLAT-001).
    let carried: Vec<&str> = match &t.platforms {
        None => platforms.to_vec(),
        Some(only) => {
            for want in only {
                if !platforms.contains(&want.as_str()) {
                    return Err(PlanError::PlatformNotInLayer {
                        tool: t.name.clone(),
                        platform: want.clone(),
                        declared: platforms.iter().map(|p| (*p).to_string()).collect(),
                    });
                }
            }
            // Filtered in the LAYER's order, not the manifest's, so a payload
            // list does not change shape with the order someone typed.
            platforms
                .iter()
                .copied()
                .filter(|p| only.iter().any(|w| w == p))
                .collect()
        }
    };
    for p in &carried {
        // An explicit name wins over the template. Some upstreams ship only a
        // musl Linux build, whose name no template can derive from a gnu
        // triple; naming the file is exact where inferring it would guess.
        //
        // The explicit name is ITSELF expanded, because the two cases differ.
        // `wac-cli-x86_64-unknown-linux-musl` carries no version and means
        // itself — expansion is a no-op. `synth-%V-x86_64-unknown-linux-musl
        // .tar.gz` does carry one, and freezing it here would break on the
        // realm's next unattended scan: the scanner bumps `version`, the
        // hardcoded asset still names the old release, and the deposit 404s
        // at 3am. An upstream that ships musl under a versioned name was
        // simply not expressible before this.
        let explicit = t.asset_for.get(*p);
        let asset = match explicit {
            Some(explicit) => asset::expand(explicit, &t.version, &release, Some(p), None)?,
            None => asset::expand(&template, &t.version, &release, Some(p), None)?,
        };
        out.push(PayloadPlan {
            name: name.clone(),
            repo: repo.clone(),
            version: t.version.clone(),
            release: release.clone(),
            asset,
            platform: Some((*p).to_string()),
            named_explicitly: explicit.is_some(),
            kind,
            unverified_reason: t.opt_in_reason(),
            contains: t.contains.clone(),
            upstream_sums: t.upstream_sums.clone(),
            pgp_sums: pgp_sums.clone(),
            title: None,
            documents: None,
            // A per-platform entry is never a module (refused above), so it
            // has no pip opt-in to carry.
            allow_pip: None,
        });
    }
    Ok(out)
}

/// Expand one extension entry.
pub fn plan_vsix(v: &ManifestVsix, platforms: &[&str]) -> Result<Vec<PayloadPlan>, PlanError> {
    let repo = repo_of(&v.repo, &v.name);
    let mut out = Vec::new();
    if !asset::is_per_platform(&v.asset) {
        out.push(PayloadPlan {
            name: v.name.clone(),
            repo,
            version: v.version.clone(),
            release: v.version.clone(),
            asset: asset::expand(&v.asset, &v.version, &v.version, None, None)?,
            platform: None,
            // No `asset-for` on this path: either the payload is platform-
            // independent, or its kind carries no per-platform naming at all.
            named_explicitly: false,
            kind: PayloadKind::Vsix,
            unverified_reason: None,
            contains: None,
            upstream_sums: None,
            pgp_sums: None,
            title: None,
            documents: None,
            allow_pip: None,
        });
        return Ok(out);
    }
    for p in platforms {
        out.push(PayloadPlan {
            name: v.name.clone(),
            repo: repo.clone(),
            version: v.version.clone(),
            release: v.version.clone(),
            asset: asset::expand(&v.asset, &v.version, &v.version, Some(p), None)?,
            platform: Some((*p).to_string()),
            // No `asset-for` on this path: either the payload is platform-
            // independent, or its kind carries no per-platform naming at all.
            named_explicitly: false,
            kind: PayloadKind::Vsix,
            unverified_reason: None,
            contains: None,
            upstream_sums: None,
            pgp_sums: None,
            title: None,
            documents: None,
            allow_pip: None,
        });
    }
    Ok(out)
}

/// Expand one documentation entry.
///
/// Documentation is not built per platform — the same HTML describes the
/// layer on every machine — so unlike a tool or an extension there is no
/// platform loop here. A `%T` in the template would therefore expand to
/// nothing meaningful, and is refused rather than silently producing four
/// identical payloads.
pub fn plan_docs(d: &ManifestDocs) -> Result<Vec<PayloadPlan>, PlanError> {
    if asset::is_per_platform(&d.asset) {
        return Err(PlanError::DocsIsNotPerPlatform {
            name: d.name.clone(),
            asset: d.asset.clone(),
        });
    }
    let release = d.release.clone().unwrap_or_else(|| d.version.clone());
    Ok(vec![PayloadPlan {
        name: d.name.clone(),
        repo: repo_of(&d.repo, &d.name),
        version: d.version.clone(),
        release: release.clone(),
        asset: asset::expand(&d.asset, &d.version, &release, None, None)?,
        platform: None,
        // No `asset-for` on this path: either the payload is platform-
        // independent, or its kind carries no per-platform naming at all.
        named_explicitly: false,
        kind: PayloadKind::Docs(d.format),
        unverified_reason: None,
        // The declared entry point IS a shape check — `contains` already
        // means "a path that must exist inside this payload". Reusing it
        // makes `entry` verified at deposit rather than decorative: a
        // manifest that names an entry the payload does not have fails while
        // it can still be fixed, instead of being discovered by a reader
        // whose link 404s.
        contains: d.entry.clone(),
        upstream_sums: None,
        pgp_sums: None,
        title: d.title.clone(),
        documents: d.documents.clone(),
        allow_pip: None,
    }])
}

/// Expand one crate entry.
///
/// No platform loop, for the reason documentation has none: a `.crate` is the
/// same bytes everywhere. The default asset is what `cargo package` writes.
pub fn plan_crate(c: &ManifestCrate) -> Result<Vec<PayloadPlan>, PlanError> {
    let template = c
        .asset
        .clone()
        .unwrap_or_else(|| format!("{}-%V.crate", c.name));
    if asset::is_per_platform(&template) {
        return Err(PlanError::CrateIsNotPerPlatform {
            name: c.name.clone(),
            asset: template,
        });
    }
    let release = c.release.clone().unwrap_or_else(|| c.version.clone());
    Ok(vec![PayloadPlan {
        name: c.name.clone(),
        repo: repo_of(&c.repo, &c.name),
        version: c.version.clone(),
        release: release.clone(),
        asset: asset::expand(&template, &c.version, &release, None, None)?,
        platform: None,
        // No `asset-for` on this path: either the payload is platform-
        // independent, or its kind carries no per-platform naming at all.
        named_explicitly: false,
        kind: PayloadKind::Crate,
        unverified_reason: None,
        contains: None,
        upstream_sums: None,
        pgp_sums: None,
        title: None,
        documents: None,
        allow_pip: None,
    }])
}

/// The whole manifest as work items.
pub fn plan(m: &LayerManifest, platforms: &[&str]) -> Result<Vec<PayloadPlan>, PlanError> {
    let mut out = Vec::new();
    for t in &m.tools {
        out.extend(plan_tool(t, platforms)?);
    }
    for v in &m.vsix {
        out.extend(plan_vsix(v, platforms)?);
    }
    for d in &m.docs {
        out.extend(plan_docs(d)?);
    }
    for c in &m.crates {
        out.extend(plan_crate(c)?);
    }
    Ok(out)
}

/// Distinct releases the plan touches, in first-seen order.
///
/// The ingestion proof is established per RELEASE, not per payload: rivet and
/// spar each appear as a tool and an extension from one release, and verifying
/// twice is what killed the 2026.08.3 deposit.
pub fn releases(plans: &[PayloadPlan]) -> Vec<(String, String)> {
    let mut seen: Vec<(String, String)> = Vec::new();
    for p in plans {
        let key = (p.repo.clone(), p.release.clone());
        if !seen.contains(&key) {
            seen.push(key);
        }
    }
    seen
}

#[cfg(test)]
mod asset_for_template_tests {
    use super::*;

    fn manifest(asset_for: &[(&str, &str)]) -> varve_core::layerspec::LayerManifest {
        let entries = asset_for
            .iter()
            .map(|(k, v)| format!("\"{k}\" = \"{v}\""))
            .collect::<Vec<_>>()
            .join("\n");
        let text = format!(
            "[varve]\nversion = \"v0.39.0\"\n\n\
             [realm]\nname = \"r\"\nchannel = \"rolling\"\n\
             registry = \"oci://ghcr.io/o/r\"\n\n\
             [[tool]]\nname = \"synth\"\nversion = \"v0.74.0\"\n\
             [tool.asset-for]\n{entries}\n"
        );
        varve_core::layerspec::parse_layer_manifest(&text).expect("layer.toml")
    }

    /// An upstream that publishes musl under a VERSIONED name cannot be
    /// expressed by a literal `asset-for`: the realm's scanner bumps the
    /// version unattended, and a hardcoded `synth-v0.74.0-…-musl.tar.gz` then
    /// names a release that no longer exists. The failure is a 404 during an
    /// unattended deposit — the exact shape the scanner exists to avoid.
    ///
    /// The template language already knows how to write the version. The only
    /// thing missing was letting `asset-for` use it.
    ///
    /// `%R` and not `%V`: these upstreams put the RELEASE TAG in the asset
    /// name (`synth-v0.74.0-…`), and `%V` is the bare version (`0.74.0`).
    /// Checked against the real release listing rather than assumed — the
    /// first draft of this test asserted the wrong one.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_explicit_asset_may_be_a_template_so_it_survives_a_version_bump() {
        let m = manifest(&[
            (
                "x86_64-unknown-linux-gnu",
                "synth-%R-x86_64-unknown-linux-musl.tar.gz",
            ),
            (
                "aarch64-unknown-linux-gnu",
                "synth-%R-aarch64-unknown-linux-musl.tar.gz",
            ),
        ]);
        let plan = plan(
            &m,
            &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],
        )
        .expect("plans");
        let assets: Vec<&str> = plan.iter().map(|p| p.asset.as_str()).collect();
        assert_eq!(
            assets,
            vec![
                "synth-v0.74.0-x86_64-unknown-linux-musl.tar.gz",
                "synth-v0.74.0-aarch64-unknown-linux-musl.tar.gz",
            ],
            "a musl asset must be nameable without freezing the version into the manifest"
        );
    }

    /// Every asset-for entry that exists today is a plain file name, and must
    /// keep meaning exactly itself. Expansion has to be a no-op for them or
    /// this change breaks three realms quietly.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_literal_asset_name_still_means_itself() {
        let m = manifest(&[(
            "x86_64-unknown-linux-gnu",
            "wac-cli-x86_64-unknown-linux-musl",
        )]);
        let plan = plan(&m, &["x86_64-unknown-linux-gnu"]).expect("plans");
        assert_eq!(plan[0].asset, "wac-cli-x86_64-unknown-linux-musl");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_core::layerspec::parse_layer_manifest;

    const PLATFORMS: &[&str] = &["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"];

    fn manifest(tools: &str) -> LayerManifest {
        let text = format!(
            "[varve]\nversion = \"v0.29.0\"\n\n[realm]\nname = \"r\"\n\
             channel = \"rolling\"\nregistry = \"oci://x\"\n\n{tools}"
        );
        parse_layer_manifest(&text).expect("parses")
    }

    /// A tool carried for FEWER platforms than the layer declares.
    ///
    /// `WebAssembly/binaryen` 133 is why. Its Linux binaries are statically
    /// linked and stand alone; its macOS binaries are 1.7 MB stubs needing a
    /// 15 MB `@rpath/libbinaryen.dylib` at `@loader_path/../lib`. A varve
    /// `tool` payload is ONE executable, so a macOS payload would pass
    /// install AND verification and fail at the first exec — the worst shape
    /// of failure, because every check that could have caught it passes.
    ///
    /// Note what this is NOT: skipping an asset the release does not publish.
    /// binaryen DOES publish macOS assets. Expressing this by naming a file
    /// that is not there would make a 404 enact a policy.
    // rivet: verifies REQ-TOOLPLAT-001
    #[test]
    fn a_tool_is_carried_only_for_the_platforms_it_names() {
        let m = manifest(
            "[[tool]]\nname = \"wasm-opt\"\nrepo = \"WebAssembly/binaryen\"\n\
             version = \"133\"\nrelease = \"version_133\"\n\
             platforms = [\"x86_64-unknown-linux-gnu\"]\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 1, "one platform, not {}: {p:?}", PLATFORMS.len());
        assert_eq!(p[0].platform.as_deref(), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(p[0].name, "wasm-opt");
    }

    /// Absent, every platform the layer declares — the ordinary case, and the
    /// one a filter must not quietly narrow.
    // rivet: verifies REQ-TOOLPLAT-001
    #[test]
    fn a_tool_naming_no_platforms_is_carried_for_all_of_them() {
        let m = manifest("[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n");
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), PLATFORMS.len());
    }

    /// A platform the layer does not declare is a REFUSAL, not a no-op.
    ///
    /// This is the clause that matters. An ignored entry reads exactly like a
    /// typo, and its symptom is a tool quietly absent from a signed layer —
    /// how layer 2026.09.18 shipped without a single Linux build of five
    /// tools. A restriction that silently matches nothing would deposit a
    /// layer claiming a tool it does not carry.
    // rivet: verifies REQ-TOOLPLAT-001
    #[test]
    fn a_platform_the_layer_does_not_declare_is_refused_not_ignored() {
        let m = manifest(
            "[[tool]]\nname = \"wasm-opt\"\nrepo = \"WebAssembly/binaryen\"\n\
             version = \"133\"\nrelease = \"version_133\"\n\
             platforms = [\"x86_64-unknown-linux-musl\"]\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("a platform the layer never declared");
        assert!(
            matches!(
                &e,
                PlanError::PlatformNotInLayer { tool, platform, .. }
                    if tool == "wasm-opt" && platform == "x86_64-unknown-linux-musl"
            ),
            "{e:?}"
        );
        // The message must name what IS declared, or the operator cannot see
        // whether they mistyped the triple or the layer is missing it.
        assert!(e.to_string().contains("aarch64-apple-darwin"), "{e}");
    }

    /// The payload order follows the LAYER's platform order, not the order
    /// somebody happened to type into the manifest.
    // rivet: verifies REQ-TOOLPLAT-001
    #[test]
    fn the_carried_platforms_keep_the_layers_order() {
        let m = manifest(
            "[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\
             platforms = [\"x86_64-unknown-linux-gnu\", \"aarch64-apple-darwin\"]\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        let got: Vec<&str> = p.iter().filter_map(|x| x.platform.as_deref()).collect();
        assert_eq!(got, PLATFORMS, "reordered by the manifest: {got:?}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_tarball_tool_expands_to_one_item_per_platform() {
        let m = manifest("[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n");
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].asset, "rivet-v0.34.0-aarch64-apple-darwin.tar.gz");
        assert_eq!(p[0].repo, "pulseengine/rivet");
        assert_eq!(p[0].kind, PayloadKind::Tarball);
    }

    /// THE thing the shell could not do. `WSC_VERSION` was one variable naming
    /// one tool in one repository, so the bytecodealliance realm — which needs
    /// wac, wkg and wrpc — could not be assembled at all. Here layout is a
    /// property of a tool.
    // rivet: verifies REQ-REALM2-002
    #[test]
    fn three_raw_per_platform_tools_are_not_a_special_case() {
        let m = manifest(
            "[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.10.1\"\nlayout = \"raw-per-platform\"\nasset = \"wac-cli-%T\"\n\
             [[tool]]\nname = \"wkg\"\nrepo = \"bytecodealliance/wasm-pkg-tools\"\n\
             version = \"v0.16.1\"\nlayout = \"raw-per-platform\"\nasset = \"wkg-%T\"\n\
             [[tool]]\nname = \"wrpc\"\nrepo = \"bytecodealliance/wrpc\"\n\
             version = \"v0.17.0\"\nlayout = \"raw-per-platform\"\n\
             asset = \"wit-bindgen-wrpc-%T\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 6, "three tools x two platforms");
        let names: Vec<&str> = p.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"wac") && names.contains(&"wkg") && names.contains(&"wrpc"));
        assert!(p.iter().all(|x| x.kind == PayloadKind::RawPerPlatform));
        assert_eq!(p[0].asset, "wac-cli-aarch64-apple-darwin");
    }

    /// wac and wrpc ship only a musl Linux build. A static musl binary is the
    /// right payload for a gnu platform, but no template can derive
    /// `wac-cli-x86_64-unknown-linux-musl` from `x86_64-unknown-linux-gnu` —
    /// so the manifest names it. Found by checking a planned manifest against
    /// the real releases: four of twelve assets did not exist.
    // rivet: verifies REQ-REALM2-002
    #[test]
    fn a_platform_whose_asset_name_cannot_be_derived_is_named_explicitly() {
        let m = manifest(
            "[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.10.1\"\nlayout = \"raw-per-platform\"\n\
             asset = \"wac-cli-%T\"\n\
             [tool.asset-for]\n\
             \"x86_64-unknown-linux-gnu\" = \"wac-cli-x86_64-unknown-linux-musl\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        let linux = p
            .iter()
            .find(|x| x.platform.as_deref() == Some("x86_64-unknown-linux-gnu"));
        assert_eq!(
            linux.map(|x| x.asset.as_str()),
            Some("wac-cli-x86_64-unknown-linux-musl")
        );
        // The platform with no override still follows the template.
        let mac = p
            .iter()
            .find(|x| x.platform.as_deref() == Some("aarch64-apple-darwin"));
        assert_eq!(
            mac.map(|x| x.asset.as_str()),
            Some("wac-cli-aarch64-apple-darwin")
        );
    }

    /// The payload is deposited under the BINARY's name — kiln ships kilnd,
    /// and a consumer dispatches `kilnd`.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_differing_binary_name_is_what_the_payload_is_called() {
        let m = manifest("[[tool]]\nname = \"kiln\"\nversion = \"v0.4.4\"\nbinary = \"kilnd\"\n");
        let p = plan(&m, PLATFORMS).expect("plans");
        assert!(p.iter().all(|x| x.name == "kilnd"));
        // …but the ASSET still follows the tool's own name.
        assert!(p[0].asset.starts_with("kiln-v0.4.4-"), "{}", p[0].asset);
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_portable_vsix_is_planned_once_and_a_per_platform_one_per_platform() {
        let m = manifest(
            "[[tool]]\nname = \"t\"\nversion = \"v1\"\n\
             [[vsix]]\nname = \"rivet-sdlc\"\nrepo = \"pulseengine/rivet\"\n\
             version = \"v0.34.0\"\nasset = \"rivet-sdlc-%V.vsix\"\n\
             [[vsix]]\nname = \"spar-aadl\"\nrepo = \"pulseengine/spar\"\n\
             version = \"v0.40.0\"\nasset = \"spar-aadl-%P-%V.vsix\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        let sdlc: Vec<_> = p.iter().filter(|x| x.name == "rivet-sdlc").collect();
        let aadl: Vec<_> = p.iter().filter(|x| x.name == "spar-aadl").collect();
        assert_eq!(sdlc.len(), 1, "portable package planned once");
        assert_eq!(sdlc[0].platform, None);
        assert_eq!(aadl.len(), 2, "per-platform package planned per platform");
        assert_eq!(aadl[0].asset, "spar-aadl-darwin-arm64-0.40.0.vsix");
    }

    /// The opt-in reason travels with every payload of that release, because
    /// it is signed beside each of them.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unverified_reason_is_carried_onto_every_payload_of_that_release() {
        let m = manifest(
            "[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\nversion = \"v0.10.1\"\n\
             layout = \"raw-per-platform\"\nasset = \"wac-cli-%T\"\n\
             unverified-reason = \"v0.10.1 publishes nothing verifiable\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 2);
        assert!(p.iter().all(
            |x| x.unverified_reason.as_deref() == Some("v0.10.1 publishes nothing verifiable")
        ));
    }

    /// rivet appears as a tool AND an extension from one release. Verifying
    /// that release twice is what killed the 2026.08.3 deposit.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_release_reached_by_two_payloads_is_listed_once() {
        let m = manifest(
            "[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\
             [[vsix]]\nname = \"rivet-sdlc\"\nrepo = \"pulseengine/rivet\"\n\
             version = \"v0.34.0\"\nasset = \"rivet-sdlc-%V.vsix\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        let r = releases(&p);
        assert_eq!(
            r,
            vec![("pulseengine/rivet".to_string(), "v0.34.0".to_string())]
        );
    }

    /// varve has TWO assemblers for one job: `varve layer-spec`, which encodes
    /// a manifest into the environment the older shell assembler reads, and
    /// this planner, which `varve-producer` runs directly. They must resolve
    /// the same manifest to the same fetch tag.
    ///
    /// They did not. `layer-spec` implemented `release` fully — fetch tag AND
    /// the fifth positional field carrying the payload's own version — while
    /// `plan_tool` never read it. The capability was taught to the path being
    /// retired and not to the path in production, and nothing compared them,
    /// so the realm's own manifest was correct and the deposit still failed.
    ///
    /// Whichever assembler is retired first, disagreement between them is a
    /// defect while both ship.
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn both_assemblers_resolve_the_same_fetch_tag() {
        let m = manifest(
            "[[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.2\"\nrelease = \"v0.7.2\"\nbinary = \"with-device\"\n\
             asset = \"with-device-%V-%T.tar.gz\"\n",
        );
        let planned = plan(&m, PLATFORMS).expect("plans");
        let env = varve_core::layerspec::assembler_env(&m).expect("encodes");

        // `head:fetch_tag:binary:asset[:payload_version]`
        let entry = env
            .layer_tools
            .split_whitespace()
            .find(|e| e.contains("jess"))
            .expect("the hub entry is encoded");
        let fields: Vec<&str> = entry.split(':').collect();
        let encoded_tag = fields[1];

        assert_eq!(
            encoded_tag, planned[0].release,
            "the two assemblers disagree on the tag to fetch: layer-spec says \
             {encoded_tag}, the planner says {}",
            planned[0].release
        );
        assert_eq!(
            fields.last().copied(),
            Some(planned[0].version.trim_start_matches('v')),
            "and on the payload's own version"
        );
    }

    /// EVERY optional field on `ManifestTool` must reach the plan. The unit
    /// tests above all passed while `release` was parsed, documented with the
    /// exact failure it prevents, and read by NOTHING — so the deposit asked
    /// jess for a release tagged `0.2.2` and `with-device` stayed missing from
    /// the realm. A field the manifest accepts and the planner ignores is worse
    /// than one that does not exist: the operator writes it, the schema
    /// validates it, and the behaviour never changes.
    ///
    /// This sets every optional field to a distinctive value and asserts each
    /// one is observable in the resulting plan. Adding a field to
    /// `ManifestTool` without consuming it fails here.
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn no_optional_manifest_field_is_inert() {
        let m = manifest(
            "[[tool]]\nname = \"probe\"\nrepo = \"acme/hub\"\nbinary = \"probed\"\n\
             version = \"1.2.3\"\nrelease = \"v9.9.9\"\n\
             asset = \"probe-%V-%T.bin\"\nlayout = \"raw-per-platform\"\n\
             unverified-reason = \"v9.9.9 upstream publishes nothing\"\n\
             upstream-sums = \"sha256.sum\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        let f = p.first().expect("at least one payload");

        assert_eq!(f.repo, "acme/hub", "`repo` is inert");
        assert_eq!(f.name, "probed", "`binary` is inert");
        assert_eq!(f.version, "1.2.3", "`version` is inert");
        assert_eq!(f.release, "v9.9.9", "`release` is inert");
        assert!(f.asset.starts_with("probe-1.2.3-"), "`asset` is inert");
        assert_eq!(f.kind, PayloadKind::RawPerPlatform, "`layout` is inert");
        assert_eq!(
            f.unverified_reason.as_deref(),
            Some("v9.9.9 upstream publishes nothing"),
            "`unverified-reason` is inert"
        );
        assert_eq!(
            f.upstream_sums.as_deref(),
            Some("sha256.sum"),
            "`upstream-sums` is inert"
        );

        // `contains` and `asset-for` belong to layouts the entry above cannot
        // also be, so they are exercised on their own manifests.
        let sdk = manifest(
            "[[tool]]\nname = \"zsdk\"\nrepo = \"z/sdk\"\nversion = \"0.17.0\"\n\
             layout = \"sdk\"\nasset = \"zsdk-%V.tar.xz\"\ncontains = \"arm-zephyr-eabi\"\n",
        );
        let sp = plan(&sdk, PLATFORMS).expect("plans");
        assert_eq!(
            sp[0].contains.as_deref(),
            Some("arm-zephyr-eabi"),
            "`contains` is inert"
        );

        let explicit = manifest(
            "[[tool]]\nname = \"musl\"\nrepo = \"m/m\"\nversion = \"1.0.0\"\n\
             layout = \"raw-per-platform\"\nasset = \"m-%T\"\n\
             [tool.asset-for]\n\"x86_64-unknown-linux-gnu\" = \"m-musl\"\n",
        );
        let ep = plan(&explicit, PLATFORMS).expect("plans");
        assert!(
            ep.iter().any(|x| x.asset == "m-musl"),
            "`asset-for` is inert"
        );
    }

    /// Documentation is planned once, not once per platform: the same pages
    /// describe the layer on every machine.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn documentation_is_planned_once_not_per_platform() {
        let m = manifest(
            "[[docs]]\nname = \"traceability\"\nrepo = \"pulseengine/varve\"\n\
             version = \"v0.35.0\"\nformat = \"html\"\nentry = \"index.html\"\n\
             asset = \"varve-%V-traceability-html.tar.gz\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 1, "one payload, not one per platform");
        assert_eq!(p[0].platform, None);
        assert_eq!(p[0].asset, "varve-0.35.0-traceability-html.tar.gz");
        assert_eq!(p[0].kind, PayloadKind::Docs(DocsFormat::Html));
    }

    /// The declared entry point travels as the shape check, so a manifest
    /// naming an entry the payload lacks fails at deposit rather than at a
    /// reader's 404.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn the_declared_entry_point_becomes_the_shape_check() {
        let m = manifest(
            "[[docs]]\nname = \"api\"\nrepo = \"pulseengine/varve\"\n\
             version = \"v0.36.0\"\nformat = \"rustdoc\"\n\
             entry = \"varve_core/index.html\"\nasset = \"varve-core-%V-rustdoc.tar.gz\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p[0].contains.as_deref(), Some("varve_core/index.html"));
    }

    /// A `%T` in a docs template would deposit four identical payloads under
    /// one name and make `export-docs <name>` ambiguous.
    // rivet: verifies REQ-LAYERDOCS-001
    /// The default asset is what `cargo package` writes and what varve's own
    /// release uploads, and the release tag is asked for — not the bare
    /// version, which is no tag at all.
    // rivet: partially-verifies REQ-CRATEPAYLOAD-001
    #[test]
    fn a_crate_defaults_to_the_file_cargo_package_writes() {
        let m = manifest(
            "[[crate]]\nname = \"varve-core\"\nrepo = \"pulseengine/varve\"\n\
             version = \"0.36.0\"\nrelease = \"v0.36.0\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 1, "a crate is one payload, not one per platform");
        assert_eq!(p[0].kind, PayloadKind::Crate);
        assert_eq!(p[0].asset, "varve-core-0.36.0.crate");
        assert_eq!(p[0].release, "v0.36.0");
        assert_eq!(p[0].version, "0.36.0");
        assert_eq!(p[0].repo, "pulseengine/varve");
        assert_eq!(p[0].platform, None);
    }

    // rivet: partially-verifies REQ-CRATEPAYLOAD-001
    #[test]
    fn a_crate_without_a_release_asks_for_its_version() {
        let m = manifest("[[crate]]\nname = \"serde\"\nversion = \"1.0.0\"\n");
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p[0].release, "1.0.0");
        assert_eq!(p[0].repo, "pulseengine/serde");
    }

    // rivet: partially-verifies REQ-CRATEPAYLOAD-001
    #[test]
    fn a_per_platform_crate_template_is_refused() {
        let m = manifest(
            "[[crate]]\nname = \"varve-core\"\nversion = \"0.36.0\"\n\
             asset = \"varve-core-%V-%T.crate\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(e, PlanError::CrateIsNotPerPlatform { .. }),
            "{e:?}"
        );
        assert!(e.to_string().contains("varve-core"), "{e}");
    }

    /// Every planned kind is labelled the way `varve deposit` names it, parsed
    /// back by varve-core's own kind parser — so a producer label varve does
    /// not recognise fails here rather than at deposit.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn every_payload_kind_is_labelled_with_a_kind_varve_core_parses() {
        let all = [
            PayloadKind::Tarball,
            PayloadKind::RawPerPlatform,
            PayloadKind::Vsix,
            PayloadKind::Sdk,
            PayloadKind::Toolchain,
            PayloadKind::Docs(DocsFormat::Pdf),
            PayloadKind::Crate,
            PayloadKind::ZephyrModule,
        ];
        for k in all {
            let core = match k.deposit_kind() {
                None => varve_core::PayloadKind::Tool,
                Some(s) => s.parse().unwrap_or_else(|e| panic!("{k:?}: {e}")),
            };
            let want = match k {
                PayloadKind::Tarball | PayloadKind::RawPerPlatform => varve_core::PayloadKind::Tool,
                PayloadKind::Vsix => varve_core::PayloadKind::Vsix,
                PayloadKind::Sdk => varve_core::PayloadKind::Sdk,
                // A toolchain stages like an sdk and is SIGNED as itself. If
                // these two ever collapsed, a compiler would be annotated
                // `sdk` and `export-sdk` would try to relocate it.
                PayloadKind::Toolchain => varve_core::PayloadKind::Toolchain,
                PayloadKind::Docs(_) => varve_core::PayloadKind::Docs,
                PayloadKind::Crate => varve_core::PayloadKind::Crate,
                PayloadKind::ZephyrModule => varve_core::PayloadKind::ZephyrModule,
            };
            assert_eq!(core, want, "{k:?}");
        }
    }

    /// REQ-ZMODEXPORT-001. A Zephyr module is a tree: planned once, no
    /// platform, the archive is the payload, and the operator's pip opt-in
    /// reaches the plan rather than being parsed and dropped.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_zephyr_module_is_planned_once_and_carries_its_pip_opt_in() {
        let m = manifest(
            "[[tool]]\nname = \"gale\"\nrepo = \"pulseengine/gale\"\nversion = \"v0.1.0\"\n\
             layout = \"zephyr-module\"\nasset = \"gale-%V-module.tar.gz\"\n\
             allow-pip = [\"scripts/requirements.txt\"]\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 1, "a module is one payload, not one per platform");
        assert_eq!(p[0].kind, PayloadKind::ZephyrModule);
        assert_eq!(p[0].platform, None);
        assert_eq!(p[0].asset, "gale-0.1.0-module.tar.gz");
        assert_eq!(
            p[0].allow_pip.as_deref(),
            Some(&["scripts/requirements.txt".to_string()][..]),
            "`allow-pip` is inert"
        );
        assert_eq!(
            PayloadKind::ZephyrModule.deposit_kind(),
            Some("zephyr-module")
        );
        let bare = manifest(
            "[[tool]]\nname = \"gale\"\nversion = \"v0.1.0\"\nlayout = \"zephyr-module\"\n\
             asset = \"gale.tar.gz\"\n",
        );
        assert_eq!(plan(&bare, PLATFORMS).unwrap()[0].allow_pip, None);
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_per_platform_zephyr_module_template_is_refused() {
        let m = manifest(
            "[[tool]]\nname = \"gale\"\nversion = \"v0.1.0\"\nlayout = \"zephyr-module\"\n\
             asset = \"gale-%V-%T.tar.gz\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(e, PlanError::ZephyrIsNotPerPlatform { .. }),
            "{e:?}"
        );
        assert!(e.to_string().contains("gale"), "{e}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_zephyr_module_without_an_asset_is_refused_not_a_panic() {
        let m = manifest(
            "[[tool]]\nname = \"gale\"\nversion = \"v0.1.0\"\nlayout = \"zephyr-module\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::ZephyrNeedsAsset { name } if name == "gale"),
            "{e:?}"
        );
        assert!(e.to_string().contains("gale-%V.tar.gz"), "{e}");
    }

    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn an_sdk_without_an_asset_is_refused_not_a_panic() {
        let m = manifest("[[tool]]\nname = \"zsdk\"\nversion = \"0.17.0\"\nlayout = \"sdk\"\n");
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::NeedsAsset { name, layout, .. } if name == "zsdk" && layout == "sdk"),
            "{e:?}"
        );
        assert!(e.to_string().contains("zsdk"), "{e}");
        assert!(e.to_string().contains("zsdk-%V.tar.gz"), "{e}");
        assert!(!e.to_string().contains("asset-for"), "{e}");
    }

    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn an_sdk_with_only_asset_for_is_refused_and_told_asset_for_is_no_substitute() {
        let m = manifest(
            "[[tool]]\nname = \"zsdk\"\nversion = \"0.17.0\"\nlayout = \"sdk\"\n\
             [tool.asset-for]\n\"x86_64-unknown-linux-gnu\" = \"zsdk-linux.tar.xz\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::NeedsAsset { name, layout, .. } if name == "zsdk" && layout == "sdk"),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(text.contains("asset-for"), "{text}");
        assert!(text.contains("does not substitute"), "{text}");
        assert!(text.contains("zsdk-%V.tar.gz"), "{text}");
    }

    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn a_toolchain_with_only_asset_for_is_refused_and_told_asset_for_is_no_substitute() {
        let m = manifest(
            "[[tool]]\nname = \"rustc\"\nversion = \"1.98.1\"\nlayout = \"toolchain\"\n\
             [tool.asset-for]\n\"x86_64-unknown-linux-gnu\" = \"rustc-linux.tar.xz\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::NeedsAsset { name, layout, .. } if name == "rustc" && layout == "toolchain"),
            "{e:?}"
        );
        let text = e.to_string();
        assert!(text.contains("asset-for"), "{text}");
        assert!(text.contains("does not substitute"), "{text}");
    }

    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn a_toolchain_without_an_asset_is_refused_not_a_panic() {
        let m =
            manifest("[[tool]]\nname = \"rustc\"\nversion = \"1.98.1\"\nlayout = \"toolchain\"\n");
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::NeedsAsset { name, layout, .. } if name == "rustc" && layout == "toolchain"),
            "{e:?}"
        );
    }

    /// `allow-pip` on anything that is not a module would be signed or
    /// dropped, and believed either way.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn allow_pip_on_a_tool_that_is_not_a_zephyr_module_is_refused() {
        let m = manifest(
            "[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\nallow-pip = [\"a.txt\"]\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(
            matches!(&e, PlanError::AllowPipNotOnZephyrModule { tool } if tool == "rivet"),
            "{e:?}"
        );
        assert!(e.to_string().contains("zephyr-module"), "{e}");
    }

    #[test]
    fn a_per_platform_docs_template_is_refused() {
        let m = manifest(
            "[[docs]]\nname = \"book\"\nrepo = \"a/b\"\nversion = \"v1.0.0\"\n\
             format = \"html\"\nasset = \"book-%V-%T.tar.gz\"\n",
        );
        let e = plan(&m, PLATFORMS).expect_err("must refuse");
        assert!(matches!(e, PlanError::DocsIsNotPerPlatform { .. }), "{e:?}");
        assert!(e.to_string().contains("describes the LAYER"), "{e}");
    }

    /// A hub ships documentation too: the tag and the payload version differ,
    /// and the same rule applies as for a tool.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_docs_payload_honours_its_release_tag() {
        let m = manifest(
            "[[docs]]\nname = \"handbook\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.2\"\nrelease = \"v0.7.2\"\nformat = \"pdf\"\n\
             asset = \"handbook-%V.pdf\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p[0].release, "v0.7.2", "fetched by the tag");
        assert_eq!(p[0].version, "0.2.2", "signed as what it is");
        assert_eq!(p[0].asset, "handbook-0.2.2.pdf");
        assert_eq!(p[0].contains, None, "a pdf has no inside to check");
    }

    /// A HUB tags a release under one number and ships the payload under
    /// another. The tag is what GitHub is asked for; the version is what the
    /// binary answers and what gets signed into the layer. Conflating them
    /// dropped `with-device` out of the pulseengine realm entirely: the
    /// manifest gained a `release` field to say so, and NOTHING read it, so
    /// the 2026.09.3 deposit asked jess for a release tagged `0.2.2`.
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn a_hub_payload_is_fetched_by_its_release_tag_not_its_version() {
        let m = manifest(
            "[[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.2\"\nrelease = \"v0.7.2\"\n\
             asset = \"with-device-%V-%T.tar.gz\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert!(!p.is_empty());
        for x in &p {
            assert_eq!(x.release, "v0.7.2", "the tag GitHub is asked for");
            assert_eq!(x.version, "0.2.2", "what the payload IS, and is signed");
            assert!(
                x.asset.contains("with-device-0.2.2-"),
                "%V is the payload version, not the tag: {}",
                x.asset
            );
        }
        assert_eq!(
            releases(&p),
            vec![("pulseengine/jess".to_string(), "v0.7.2".to_string())],
            "the release fetched and verified is the TAG"
        );
    }

    /// Absent `release`, the version serves as the tag — the ordinary case for
    /// almost every tool, and it must not regress.
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn without_a_release_field_the_version_is_still_the_tag() {
        let m = manifest("[[tool]]\nname = \"rivet\"\nversion = \"v0.37.0\"\n");
        let p = plan(&m, PLATFORMS).expect("plans");
        assert!(!p.is_empty());
        for x in &p {
            assert_eq!(x.release, "v0.37.0");
            assert_eq!(x.version, "v0.37.0");
        }
    }

    /// `%R` is the tag as written. On a hub that is the RELEASE, not the
    /// payload version — an upstream that keeps the `v` in its asset names
    /// would otherwise get a name built from the wrong number entirely.
    // rivet: verifies REQ-PAYLOADID-001
    #[test]
    fn percent_r_on_a_hub_is_the_release_tag() {
        let m = manifest(
            "[[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.2\"\nrelease = \"v0.7.2\"\n\
             asset = \"wd-%R-%T.tar.gz\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert!(p[0].asset.starts_with("wd-v0.7.2-"), "{}", p[0].asset);
    }

    /// Distinct versions of one repo are distinct releases — the assembler
    /// refuses that case, and it must be able to SEE it first.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn one_repo_at_two_versions_is_two_releases() {
        let m = manifest(
            "[[tool]]\nname = \"rivet\"\nversion = \"v0.34.0\"\n\
             [[vsix]]\nname = \"rivet-sdlc\"\nrepo = \"pulseengine/rivet\"\n\
             version = \"v0.33.1\"\nasset = \"rivet-sdlc-%V.vsix\"\n",
        );
        let r = releases(&plan(&m, PLATFORMS).expect("plans"));
        assert_eq!(r.len(), 2);
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_unknown_layout_is_refused_naming_the_ones_that_work() {
        let m = manifest("[[tool]]\nname = \"t\"\nversion = \"v1\"\nlayout = \"zipfile\"\n");
        let err = plan(&m, PLATFORMS).expect_err("refuses");
        let msg = err.to_string();
        assert!(
            msg.contains("zipfile") && msg.contains("raw-per-platform"),
            "{msg}"
        );
    }

    /// A raw-per-platform tool with no explicit template still needs one, and
    /// the default has to vary by platform or every platform would fetch the
    /// same file.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_raw_tool_without_a_template_still_varies_by_platform() {
        let m = manifest(
            "[[tool]]\nname = \"thing\"\nversion = \"v1\"\nlayout = \"raw-per-platform\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 2);
        assert_ne!(
            p[0].asset, p[1].asset,
            "every platform fetched the same asset"
        );
        assert_eq!(p[0].asset, "thing-aarch64-apple-darwin");
    }

    // ------------------------------------------ pgp-sums (REQ-SIGNEDSUMS-001)

    const SIGNED_TOOL: &str = "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\n\
         asset = \"t-%V.tar.gz\"\n";

    fn signed(extra: &str) -> Result<Vec<PayloadPlan>, PlanError> {
        plan(&manifest(&format!("{SIGNED_TOOL}{extra}")), PLATFORMS)
    }

    /// Defaults: the signature is the list's name plus `.asc`, the format is
    /// sha256sums, and the key path is carried as written.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_pgp_sums_entry_plans_with_its_defaults() {
        let p = signed("pgp-sums = \"SUMS-%V\"\npgp-key-file = \"keys/up.asc\"\n").unwrap();
        let spec = p[0].pgp_sums.as_ref().expect("declared");
        assert_eq!(spec.list, "SUMS-1.0");
        assert_eq!(spec.signature, "SUMS-1.0.asc");
        assert_eq!(spec.format, crate::pgpsums::ListFormat::Sha256Sums);
        assert_eq!(spec.key_file, std::path::PathBuf::from("keys/up.asc"));
        // A property of the release: every platform's payload carries it.
        assert!(p.iter().all(|x| x.pgp_sums == p[0].pgp_sums));
    }

    /// Templates expand in the list and signature names; a stated signature
    /// and format are honoured.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_list_and_signature_names_are_templates_and_overridable() {
        let p = signed(
            "pgp-sums = \"sums-%V.txt\"\npgp-sums-signature = \"sums-%R.sig\"\n\
             pgp-sums-format = \"rust-channel\"\npgp-key-file = \"k.asc\"\n",
        )
        .unwrap();
        let spec = p[0].pgp_sums.as_ref().unwrap();
        // %V is the bare version, %R the release tag.
        assert_eq!(spec.list, "sums-1.0.txt");
        assert_eq!(spec.signature, "sums-v1.0.sig");
        assert_eq!(spec.format, crate::pgpsums::ListFormat::RustChannel);

        // Not stated: the default signature follows the EXPANDED list name.
        let p = signed("pgp-sums = \"sums-%V.txt\"\npgp-key-file = \"k.asc\"\n").unwrap();
        assert_eq!(
            p[0].pgp_sums.as_ref().unwrap().signature,
            "sums-1.0.txt.asc"
        );
    }

    /// `pgp-sums` without a key is a signature checked against nothing.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn pgp_sums_without_a_key_file_is_a_plan_error() {
        let err = signed("pgp-sums = \"SUMS-%V\"\n").expect_err("refuses");
        assert_eq!(
            err,
            PlanError::PgpSumsNeedsKey { tool: "t".into() },
            "{err}"
        );
        assert!(err.to_string().contains("pgp-key-file"), "{err}");
    }

    /// A key, a format or a signature with no list is read by nothing.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_pgp_field_without_pgp_sums_is_a_plan_error() {
        for (line, field) in [
            ("pgp-key-file = \"k.asc\"", "pgp-key-file"),
            ("pgp-sums-signature = \"x.sig\"", "pgp-sums-signature"),
            ("pgp-sums-format = \"rust-channel\"", "pgp-sums-format"),
        ] {
            let err = signed(&format!("{line}\n")).expect_err("refuses");
            assert_eq!(
                err,
                PlanError::PgpFieldWithoutSums {
                    tool: "t".into(),
                    field
                },
                "{line}"
            );
            assert!(err.to_string().contains(field), "{err}");
        }
    }

    /// An unknown format is refused, naming the ones that work.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_unknown_pgp_sums_format_is_a_plan_error() {
        let err =
            signed("pgp-sums = \"S-%V\"\npgp-key-file = \"k.asc\"\npgp-sums-format = \"yaml\"\n")
                .expect_err("refuses");
        assert!(
            matches!(&err, PlanError::PgpSumsFormatUnknown { found, .. } if found == "yaml"),
            "{err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("sha256sums") && msg.contains("rust-channel"),
            "{msg}"
        );
    }

    /// Both lists on one entry: the unsigned one could never be consulted.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_signed_and_an_unsigned_list_on_one_entry_is_a_plan_error() {
        let err = signed(
            "pgp-sums = \"S-%V\"\npgp-key-file = \"k.asc\"\nupstream-sums = \"sha256.sum\"\n",
        )
        .expect_err("refuses");
        assert_eq!(err, PlanError::PgpSumsAndUpstreamSums { tool: "t".into() });
        assert!(err.to_string().contains("upstream-sums"), "{err}");
    }

    /// A per-platform list name would not be one list.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_per_platform_list_name_is_refused() {
        let err = signed("pgp-sums = \"sums-%V-%T.txt\"\npgp-key-file = \"k.asc\"\n")
            .expect_err("refuses");
        assert!(matches!(err, PlanError::Template(_)), "{err}");
    }

    /// An entry with only `upstream-sums` is untouched by the new fields.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn an_upstream_sums_entry_declares_no_pgp_plan() {
        let p = signed("upstream-sums = \"sha256.sum\"\n").unwrap();
        assert_eq!(p[0].pgp_sums, None);
        assert_eq!(p[0].upstream_sums.as_deref(), Some("sha256.sum"));
    }

    /// The key path is relative to the input file, not to where the producer
    /// was started.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn key_files_are_anchored_to_the_input_file() {
        let mut p = signed("pgp-sums = \"S-%V\"\npgp-key-file = \"keys/up.asc\"\n").unwrap();
        anchor_key_files(&mut p, std::path::Path::new("realm/layer.toml"));
        assert_eq!(
            p[0].pgp_sums.as_ref().unwrap().key_file,
            std::path::PathBuf::from("realm/keys/up.asc")
        );
        // A bare file name has no directory to anchor to: the current one.
        let mut p = signed("pgp-sums = \"S-%V\"\npgp-key-file = \"up.asc\"\n").unwrap();
        anchor_key_files(&mut p, std::path::Path::new("layer.toml"));
        assert_eq!(
            p[0].pgp_sums.as_ref().unwrap().key_file,
            std::path::PathBuf::from("./up.asc")
        );
        // Plans that declare nothing are left alone.
        let mut p = signed("").unwrap();
        anchor_key_files(&mut p, std::path::Path::new("realm/layer.toml"));
        assert_eq!(p[0].pgp_sums, None);
    }

    /// A toolchain entry for the Rust channel plans with the channel format,
    /// one asset per platform, and the one list shared by all of them.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_rust_toolchain_entry_plans_with_the_rust_channel_format() {
        let m = manifest(
            "[[tool]]\nname = \"rust\"\nrepo = \"o/rust-mirror\"\nversion = \"1.98.1\"\n\
             layout = \"toolchain\"\nasset = \"rustc-%V-%T.tar.xz\"\n\
             pgp-sums = \"channel-rust-stable.toml\"\n\
             pgp-sums-format = \"rust-channel\"\n\
             pgp-key-file = \"keys/rust-release.asc\"\n",
        );
        let p = plan(&m, PLATFORMS).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].kind, PayloadKind::Toolchain);
        let spec = p[0].pgp_sums.as_ref().expect("declared");
        assert_eq!(spec.format, crate::pgpsums::ListFormat::RustChannel);
        assert_eq!(spec.list, "channel-rust-stable.toml");
        assert_eq!(spec.signature, "channel-rust-stable.toml.asc");
        assert_eq!(p[0].pgp_sums, p[1].pgp_sums);
        assert_ne!(p[0].asset, p[1].asset);
    }

    /// REPLAY at plan time: a versionless asset name lets an older signed list
    /// stand in for this release.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn pgp_sums_with_a_versionless_asset_template_is_a_plan_error() {
        let err = plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nasset = \"t-%T.tar.gz\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect_err("refuses");
        assert!(
            matches!(&err, PlanError::PgpSumsAssetNotVersioned { asset, .. } if asset == "t-%T.tar.gz"),
            "{err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("older") && msg.contains("%V"), "{msg}");
    }

    /// Either placeholder binds the name to a release, and so does the default
    /// tarball template, which embeds the version.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_versioned_asset_template_is_accepted_with_pgp_sums() {
        for asset in ["t-%V-%T.tar.gz", "t-%R-%T.tar.gz"] {
            plan(
                &manifest(&format!(
                    "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nasset = \"{asset}\"\n\
                     pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n"
                )),
                PLATFORMS,
            )
            .unwrap_or_else(|e| panic!("{asset}: {e}"));
        }
        plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect("the default template embeds the version");
    }

    /// A raw-per-platform entry with no `asset` defaults to `<name>-%T`, which
    /// names no release.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_default_raw_template_names_no_release_and_is_refused_with_pgp_sums() {
        let err = plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nlayout = \"raw-per-platform\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect_err("refuses");
        assert!(
            matches!(&err, PlanError::PgpSumsAssetNotVersioned { asset, .. } if asset == "t-%T"),
            "{err}"
        );
    }

    /// An `asset-for` override is a name too, and each must be versioned.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_versionless_asset_for_name_is_a_plan_error_with_pgp_sums() {
        let err = plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nasset = \"t-%V-%T.tar.gz\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n\
                 [tool.asset-for]\naarch64-apple-darwin = \"t-darwin.tar.gz\"\n",
            ),
            PLATFORMS,
        )
        .expect_err("refuses");
        assert!(
            matches!(&err, PlanError::PgpSumsAssetNotVersioned { asset, .. } if asset == "t-darwin.tar.gz"),
            "{err}"
        );
    }

    /// The version rule is for the sha256sums format; a Rust channel binds
    /// through the manifest's own version, checked at ingestion.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_rust_channel_format_is_not_subject_to_the_template_rule() {
        plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"1.98.1\"\nlayout = \"toolchain\"\n\
                 asset = \"rustc.tar.xz\"\npgp-sums = \"c.toml\"\n\
                 pgp-sums-format = \"rust-channel\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect("plans");
    }

    fn signed_tool(
        version: &str,
        release: Option<&str>,
        asset: &str,
        extra: &str,
    ) -> Result<Vec<PayloadPlan>, PlanError> {
        let release = release
            .map(|r| format!("release = \"{r}\"\n"))
            .unwrap_or_default();
        plan(
            &manifest(&format!(
                "[[tool]]\nname = \"t\"\nversion = \"{version}\"\n{release}asset = \"{asset}\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n{extra}"
            )),
            PLATFORMS,
        )
    }

    /// MOVING TAGS: the expanded names are the same for every release, so the
    /// template text proves nothing. The rule: the version (or release) a
    /// template expands with must, after one leading `v`, START WITH A DIGIT
    /// and have no `-`/`.`/`_` separated segment that is a moving-tag word
    /// (latest, nightly, stable, beta, current, head, main, master, edge, dev,
    /// canary, snapshot).
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_moving_version_is_refused_with_pgp_sums() {
        for v in [
            "latest",
            "nightly",
            "stable",
            "main",
            "master",
            "edge",
            "current",
            "head",
            "dev",
            "Latest",
            "v-latest",
            "1.0-latest",
            "2026-10-01-nightly",
            "",
        ] {
            let err = signed_tool(v, None, "t-%V.tar.gz", "").expect_err(v);
            assert!(
                matches!(&err, PlanError::PgpSumsMovingTag { what: "version", value, .. } if value == v),
                "{v:?}: {err}"
            );
            assert!(err.to_string().contains("older"), "{err}");
        }
    }

    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_moving_release_is_refused_when_a_template_uses_it_and_ignored_when_none_does() {
        for r in ["latest", "nightly", "stable", "main"] {
            let err = signed_tool("1.2.3", Some(r), "t-%R.tar.gz", "").expect_err(r);
            assert!(
                matches!(&err, PlanError::PgpSumsMovingTag { what: "release", value, .. } if value == r),
                "{r}: {err}"
            );
        }
        // No template names the release, so its value binds nothing and is not judged.
        signed_tool("1.2.3", Some("latest"), "t-%V.tar.gz", "").expect("plans");
    }

    /// The default tarball template embeds the version literally, so the
    /// literal itself is what must name a release.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_default_tarball_template_of_a_moving_version_is_refused() {
        let err = plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"latest\"\n\
                 pgp-sums = \"SUMS-%V\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect_err("refuses");
        assert!(matches!(err, PlanError::PgpSumsMovingTag { .. }), "{err}");
    }

    /// Versions and dates that DO name a release are accepted.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn digit_led_versions_and_dates_are_accepted() {
        for v in [
            "v1.2.3",
            "1.2.3",
            "2026-10-01",
            "34.0",
            "1.0.0-rc.1",
            "v0.7.2",
        ] {
            signed_tool(v, None, "t-%V.tar.gz", "").unwrap_or_else(|e| panic!("{v}: {e}"));
        }
    }

    /// The list or the signature must carry the release, so two fixed names
    /// do not serve every release.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn a_list_and_signature_that_name_no_release_are_refused() {
        let err = plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nasset = \"t-%V.tar.gz\"\n\
                 pgp-sums = \"SHA256SUMS\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect_err("refuses");
        assert!(
            matches!(&err, PlanError::PgpSumsListNotVersioned { list, signature, .. }
                if list == "SHA256SUMS" && signature == "SHA256SUMS.asc"),
            "{err}"
        );
        // Either one carrying the release is enough.
        for (list, sig) in [("SHA256SUMS", "S-%V.asc"), ("S-%R", "SHA256SUMS.asc")] {
            plan(
                &manifest(&format!(
                    "[[tool]]\nname = \"t\"\nversion = \"v1.0\"\nasset = \"t-%V.tar.gz\"\n\
                     pgp-sums = \"{list}\"\npgp-sums-signature = \"{sig}\"\npgp-key-file = \"k.asc\"\n"
                )),
                PLATFORMS,
            )
            .unwrap_or_else(|e| panic!("{list} {sig}: {e}"));
        }
    }

    /// Neither new rule applies to the Rust channel, which binds through its
    /// own manifest.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn the_new_name_rules_do_not_apply_to_the_rust_channel_format() {
        plan(
            &manifest(
                "[[tool]]\nname = \"t\"\nversion = \"latest\"\nlayout = \"toolchain\"\n\
                 asset = \"rustc.tar.xz\"\npgp-sums = \"channel-rust-stable.toml\"\n\
                 pgp-sums-format = \"rust-channel\"\npgp-key-file = \"k.asc\"\n",
            ),
            PLATFORMS,
        )
        .expect("plans");
    }

    /// What may stand for "one release": a name heuristic, not a binding.
    // rivet: verifies REQ-SIGNEDSUMS-001
    #[test]
    fn only_a_token_that_names_exactly_one_release_passes() {
        for ok in [
            "1.2",
            "v1.2.3",
            "0.47.0",
            "1.98.1",
            "2026-11-08",
            "2026.11.08",
            "1.2.3-rc.1",
            "v1.0.0-beta.2",
            "1.0.0-beta1",
            "1.2.3+build5",
            "34.0",
            "0.7.2",
        ] {
            assert!(names_a_release(ok), "{ok:?} names one release");
        }
        for bad in [
            "1",
            "v4",
            "3.x",
            "2-lts",
            "1.x-rolling",
            "2026",
            "latest",
            "beta",
            "v",
            "",
            "1.*",
            "3lts",
            "1.X",
            "x",
            "*",
            "nightly",
            "main",
            "1.2.3-x",
            "1.2.3-",
            "1.2.3-latest",
            "1.2.3-3lts",
            "1.2.",
            ".1.2",
            "1..2",
            "2026-11",
            "2026-1-8",
            "2026-11-08-nightly",
            "next",
            "alpha",
            "lts",
            "rolling",
        ] {
            assert!(!names_a_release(bad), "{bad:?} must not pass");
        }
    }
}
