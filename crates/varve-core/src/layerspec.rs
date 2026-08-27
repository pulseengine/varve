//! `layer.toml` → assembler inputs (REQ-LAYERREPO-001).
//!
//! A realm's contents belong in the realm's own repository, not in varve's
//! workflow file: bumping `rivet` to v0.34.0 should be a one-line reviewed diff
//! in `pulseengine-layers`, not a commit to the tool that signs it. This module
//! is the adapter that makes that possible — it reads the manifest and produces
//! the environment `tools/build-deposit-spec.sh` already consumes.
//!
//! It lives HERE, next to the assembler it feeds, rather than in the layers
//! repository, because a realm running a *copy* of the assembler gets none of
//! the system testing varve does on it (REQ-PEL-ASSEMBLER-001). One writer, one
//! set of tests, every realm.
//!
//! ## Why this refuses so much
//!
//! The assembler's inputs are space-separated lists of colon-separated fields.
//! That encoding cannot represent a value containing a space or a colon, and
//! the shell will not complain — it will silently split one tool into two, or
//! truncate a version. A layer assembled from a mangled list is still signed,
//! still verifies, and carries the wrong bytes. So every field that lands in
//! the encoding is checked against the encoding's own alphabet BEFORE it gets
//! there, and anything the assembler cannot faithfully carry is an error rather
//! than a best-effort translation. This is the same reasoning that made
//! `UNVERIFIED_INGEST` line-separated instead of punctuation-separated.

use std::collections::BTreeSet;
use std::fmt;

/// The pinned varve release that builds this layer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VarvePin {
    pub version: String,
}

/// Which realm this layer belongs to, and where it is published.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRealm {
    pub name: String,
    pub channel: String,
    pub registry: String,
}

/// How a tool's release presents its binaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// One `.tar.gz` per target triple — the PulseEngine norm.
    Tarball,
    /// Bare per-platform binaries with no archive (sigil ships `wsc` this way).
    RawPerPlatform,
}

impl Layout {
    fn parse(s: &str) -> Option<Layout> {
        match s {
            "tarball" => Some(Layout::Tarball),
            "raw-per-platform" => Some(Layout::RawPerPlatform),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTool {
    pub name: String,
    pub version: String,
    /// `owner/repo`. Absent = `pulseengine/<name>`.
    #[serde(default)]
    pub repo: Option<String>,
    /// The executable's name, when it differs from the tool's (kiln ships
    /// `kilnd`). Absent = `<name>`.
    #[serde(default)]
    pub binary: Option<String>,
    /// Release asset name template; `%V` bare version, `%T` Rust target triple,
    /// `%U` short upstream platform tag. Absent = the assembler's default.
    #[serde(default)]
    pub asset: Option<String>,
    /// Absent = `tarball`.
    #[serde(default)]
    pub layout: Option<String>,
    /// Why this tool is ingested with NO proof of origin (REQ-INGEST-001
    /// clause 3). Present only for a release that offers neither a
    /// cosign-signed sums file nor a build attestation.
    ///
    /// The reason is not paperwork: it is signed into the layer and shown by
    /// `varve inspect`, so every consumer reads the operator's words next to
    /// the bytes they were written about. "We could not verify this" must
    /// never be the silent path, which is why the field carries prose rather
    /// than a boolean.
    #[serde(rename = "unverified-reason", default)]
    pub unverified_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestVsix {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub repo: Option<String>,
    /// Asset template; `%V` bare version, `%P` VS Code platform tag. A template
    /// with no `%P` is one portable package.
    pub asset: String,
}

/// The whole manifest. `deny_unknown_fields` throughout is load-bearing: a
/// mistyped `verison = "v0.34.0"` would otherwise leave the real `version`
/// missing or stale, and the layer would ship the wrong release under a good
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerManifest {
    pub varve: VarvePin,
    pub realm: ManifestRealm,
    #[serde(default, rename = "tool")]
    pub tools: Vec<ManifestTool>,
    #[serde(default, rename = "vsix")]
    pub vsix: Vec<ManifestVsix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerSpecError {
    /// The TOML did not parse, or carried a field the schema does not define.
    Parse(String),
    /// A value cannot survive the assembler's encoding.
    Unencodable {
        field: String,
        value: String,
        why: &'static str,
    },
    /// `layout = "..."` is not one the assembler implements.
    UnknownLayout { tool: String, layout: String },
    /// The assembler carries exactly one raw-per-platform tool, as
    /// `WSC_VERSION`. A second one has nowhere to go.
    ManyRawPerPlatform { first: String, second: String },
    /// The assembler's single raw-per-platform slot is not generic: it fetches
    /// `wsc` from `pulseengine/sigil`. Any other tool put in it becomes a
    /// request for the wrong tool from the wrong repository.
    RawPerPlatformNotWsc { tool: String, repo: String },
    /// The assembler hardcodes `pulseengine/` for extension repositories.
    VsixForeignOwner { name: String, repo: String },
    /// The assembler derives a tarball tool's identity from its REPOSITORY
    /// basename, so a manifest `name` that disagrees with it is discarded.
    RepoNameMismatch {
        name: String,
        repo: String,
        basename: String,
    },
    /// Two entries would land under one name.
    Duplicate { kind: &'static str, name: String },
    /// An opt-in that states no reason.
    UnverifiedWithoutReason { tool: String },
    /// Two tools from one repository disagree about why it is unverified.
    ConflictingReason {
        repo: String,
        first: String,
        second: String,
    },
    /// The manifest describes nothing to deposit.
    Empty,
}

impl fmt::Display for LayerSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerSpecError::Parse(e) => write!(f, "layer.toml does not parse: {e}"),
            LayerSpecError::Unencodable { field, value, why } => write!(
                f,
                "{field} = {value:?} cannot be passed to the assembler: {why}. \
                 The assembler reads space-separated entries of colon-separated \
                 fields, so such a value would be split or truncated silently \
                 and the layer would carry the wrong bytes under a good signature."
            ),
            LayerSpecError::UnknownLayout { tool, layout } => write!(
                f,
                "tool {tool:?} declares layout = {layout:?}, which varve does not \
                 implement. Use \"tarball\" (one .tar.gz per target triple) or \
                 \"raw-per-platform\" (bare per-platform binaries)."
            ),
            LayerSpecError::ManyRawPerPlatform { first, second } => write!(
                f,
                "tools {first:?} and {second:?} both declare \
                 layout = \"raw-per-platform\", and the assembler carries only \
                 one (as WSC_VERSION). Depositing would silently drop one of \
                 them. Teach the assembler a general raw-per-platform list \
                 before adding the second."
            ),
            LayerSpecError::RawPerPlatformNotWsc { tool, repo } => write!(
                f,
                "tool {tool:?} from {repo:?} declares \
                 layout = \"raw-per-platform\", but the assembler's only slot \
                 for that layout is hardcoded to fetch `wsc` from \
                 `pulseengine/sigil` — it would emit WSC_VERSION and download \
                 the wrong tool, from the wrong repository, at this tool's \
                 version, and deposit it under the wrong name. Teach the \
                 assembler a general raw-per-platform list before carrying \
                 this."
            ),
            LayerSpecError::VsixForeignOwner { name, repo } => write!(
                f,
                "vsix {name:?} names repo {repo:?}, but the assembler resolves \
                 extension repositories as pulseengine/<name> and would fetch \
                 the wrong release. Either publish it under pulseengine, or \
                 teach the assembler an owner field for extensions."
            ),
            LayerSpecError::RepoNameMismatch {
                name,
                repo,
                basename,
            } => write!(
                f,
                "tool {name:?} names repo {repo:?}, but the assembler takes a \
                 tarball tool's identity from the repository basename — it \
                 would download, name the payload, and default the asset \
                 template as {basename:?}, and {name:?} would mean nothing. A \
                 consumer asking for {name:?} would then find no such tool in \
                 a layer that deposited and verified. Rename the entry to \
                 {basename:?}, or set `binary` if only the executable differs."
            ),
            LayerSpecError::Duplicate { kind, name } => {
                write!(f, "two {kind} entries are both named {name:?}")
            }
            LayerSpecError::UnverifiedWithoutReason { tool } => write!(
                f,
                "tool {tool:?} sets an empty `unverified-reason`. \"We could \
                 not verify this\" must never be the silent path: the reason \
                 is what travels with the bytes into the signed layer, where \
                 every consumer reads it. Say why this is acceptable and what \
                 removes the need, or do not carry the tool."
            ),
            LayerSpecError::ConflictingReason {
                repo,
                first,
                second,
            } => write!(
                f,
                "two tools from {repo:?} give different reasons for ingesting \
                 it unverified:\n  {first:?}\n  {second:?}\nThe opt-in is per \
                 RELEASE, not per tool, so one of these would be recorded and \
                 the other silently discarded. Give the repository one reason."
            ),
            LayerSpecError::Empty => write!(
                f,
                "layer.toml declares no [[tool]] and no [[vsix]]: there is \
                 nothing to deposit. A layer with no payloads is signed, \
                 published, and useless."
            ),
        }
    }
}

impl std::error::Error for LayerSpecError {}

/// What the assembler needs in its environment, derived from the manifest.
///
/// Rendered as `KEY=value` lines so a workflow can append them to `$GITHUB_ENV`
/// — no `eval`, no quoting round-trip, and nothing that would let a manifest
/// value execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblerEnv {
    pub layer_tools: String,
    pub wsc_version: Option<String>,
    pub vsix_packages: String,
    pub realm: String,
    pub channel: String,
    pub registry: String,
    pub varve_version: String,
    /// `owner/repo=reason` lines for releases ingested with no proof.
    pub unverified_ingest: Vec<(String, String)>,
}

impl AssemblerEnv {
    /// `KEY=value` lines, newline-terminated, in a stable order.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("TARBALL_TOOLS={}\n", self.layer_tools));
        out.push_str(&format!(
            "WSC_VERSION={}\n",
            self.wsc_version.as_deref().unwrap_or("")
        ));
        out.push_str(&format!("VSIX_PACKAGES={}\n", self.vsix_packages));
        out.push_str(&format!("VARVE_REALM={}\n", self.realm));
        out.push_str(&format!("VARVE_CHANNEL={}\n", self.channel));
        out.push_str(&format!("VARVE_REGISTRY={}\n", self.registry));
        out.push_str(&format!("VARVE_VERSION={}\n", self.varve_version));
        // UNVERIFIED_INGEST is LINE-separated, because a reason is prose and
        // any punctuation separator can occur inside it — the assembler
        // documents that choice and the reason it made it. A `KEY=value` line
        // cannot carry newlines, so this uses $GITHUB_ENV's heredoc form.
        //
        // The delimiter is checked against the content rather than assumed: an
        // operator's reason that happened to contain the delimiter would end
        // the block early and inject whatever followed as further environment,
        // which is the shape of an actual injection rather than a typo.
        if !self.unverified_ingest.is_empty() {
            let body: String = self
                .unverified_ingest
                .iter()
                .map(|(repo, why)| format!("{repo}={why}\n"))
                .collect();
            let mut delim = String::from("VARVE_UNVERIFIED_EOF");
            while body.contains(&delim) {
                delim.push('_');
            }
            out.push_str(&format!("UNVERIFIED_INGEST<<{delim}\n{body}{delim}\n"));
        }
        out
    }
}

pub fn parse_layer_manifest(text: &str) -> Result<LayerManifest, LayerSpecError> {
    toml::from_str(text).map_err(|e| LayerSpecError::Parse(e.to_string()))
}

/// Reject anything the assembler's encoding cannot carry intact.
///
/// `%` is allowed: it is the asset templates' own metacharacter. `:` and
/// whitespace are the encoding's separators, and an empty value would collapse
/// a field position.
fn encodable(field: &str, value: &str) -> Result<(), LayerSpecError> {
    let unencodable = |why| LayerSpecError::Unencodable {
        field: field.to_string(),
        value: value.to_string(),
        why,
    };
    if value.is_empty() {
        return Err(unencodable("it is empty"));
    }
    if value.contains(':') {
        return Err(unencodable("it contains ':', which separates fields"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(unencodable(
            "it contains whitespace, which separates entries",
        ));
    }
    Ok(())
}

/// `owner/repo` → (owner, repo), defaulting the owner to `pulseengine`.
fn split_repo(repo: &str, default_name: &str) -> (String, String) {
    match repo.split_once('/') {
        Some((owner, name)) => (owner.to_string(), name.to_string()),
        None => ("pulseengine".to_string(), default_name.to_string()),
    }
}

pub fn assembler_env(m: &LayerManifest) -> Result<AssemblerEnv, LayerSpecError> {
    if m.tools.is_empty() && m.vsix.is_empty() {
        return Err(LayerSpecError::Empty);
    }
    encodable("realm.name", &m.realm.name)?;
    encodable("realm.channel", &m.realm.channel)?;
    encodable("varve.version", &m.varve.version)?;

    let mut unverified: Vec<(String, String)> = Vec::new();
    let mut tarballs: Vec<String> = Vec::new();
    let mut wsc_version: Option<String> = None;
    let mut raw_owner: Option<String> = None;
    let mut seen_tools: BTreeSet<&str> = BTreeSet::new();

    for t in &m.tools {
        encodable("tool.name", &t.name)?;
        encodable("tool.version", &t.version)?;
        if !seen_tools.insert(t.name.as_str()) {
            return Err(LayerSpecError::Duplicate {
                kind: "tool",
                name: t.name.clone(),
            });
        }
        let layout = match t.layout.as_deref() {
            None => Layout::Tarball,
            Some(s) => Layout::parse(s).ok_or_else(|| LayerSpecError::UnknownLayout {
                tool: t.name.clone(),
                layout: s.to_string(),
            })?,
        };
        // The opt-in is per RELEASE, so it is keyed by repository; two tools
        // from one repo must agree about why it is unverified, or one reason
        // would be recorded and the other silently dropped.
        if let Some(why) = &t.unverified_reason {
            let why = why.trim();
            if why.is_empty() {
                return Err(LayerSpecError::UnverifiedWithoutReason {
                    tool: t.name.clone(),
                });
            }
            let full = match &t.repo {
                Some(r) => r.clone(),
                None => format!("pulseengine/{}", t.name),
            };
            if let Some((_, prev)) = unverified.iter().find(|(r, _)| *r == full) {
                if prev != why {
                    return Err(LayerSpecError::ConflictingReason {
                        repo: full,
                        first: prev.clone(),
                        second: why.to_string(),
                    });
                }
            } else {
                unverified.push((full, why.to_string()));
            }
        }
        let (owner, repo_name) = match &t.repo {
            Some(r) => {
                encodable("tool.repo", r)?;
                split_repo(r, &t.name)
            }
            None => ("pulseengine".to_string(), t.name.clone()),
        };

        if layout == Layout::RawPerPlatform {
            if let Some(first) = &raw_owner {
                return Err(LayerSpecError::ManyRawPerPlatform {
                    first: first.clone(),
                    second: t.name.clone(),
                });
            }
            // The slot is not generic. `wsc` is what the assembler fetches,
            // from `pulseengine/sigil`; anything else silently becomes a
            // request for that tool at this tool's version.
            if t.name != "wsc" || owner != "pulseengine" || repo_name != "sigil" {
                return Err(LayerSpecError::RawPerPlatformNotWsc {
                    tool: t.name.clone(),
                    repo: format!("{owner}/{repo_name}"),
                });
            }
            raw_owner = Some(t.name.clone());
            wsc_version = Some(t.version.clone());
            continue;
        }

        // The assembler does `tool="${f_tool##*/}"` and then uses that name for
        // the payload, the extract directory and the default asset template. A
        // manifest whose `name` disagrees with the repository basename is
        // therefore not translated — it is DISCARDED, and the layer deposits a
        // payload under a name nobody asked for. `raw-per-platform` is exempt
        // because the assembler hardcodes that one pairing (`wsc` from
        // `pulseengine/sigil`) instead of deriving it.
        if repo_name != t.name {
            return Err(LayerSpecError::RepoNameMismatch {
                name: t.name.clone(),
                repo: t.repo.clone().unwrap_or_else(|| repo_name.clone()),
                basename: repo_name.clone(),
            });
        }

        // `[owner/]tool:version[:binary[:asset-template]]`. The owner prefix is
        // omitted when it is the default, so a manifest that names no repos
        // produces exactly the list the pre-migration workflow carried.
        // `repo_name == t.name` holds by the check above, so testing it here
        // too would be a condition no input could vary — cargo-mutants proved
        // it dead by flipping it and killing nothing.
        let head = if owner == "pulseengine" {
            t.name.clone()
        } else {
            format!("{owner}/{repo_name}")
        };
        let mut entry = format!("{head}:{}", t.version);
        // A template cannot be given without a binary: they are positional.
        match (&t.binary, &t.asset) {
            (None, None) => {}
            (Some(b), None) => {
                encodable("tool.binary", b)?;
                entry.push(':');
                entry.push_str(b);
            }
            (b, Some(a)) => {
                encodable("tool.asset", a)?;
                let bin = b.clone().unwrap_or_else(|| t.name.clone());
                encodable("tool.binary", &bin)?;
                entry.push(':');
                entry.push_str(&bin);
                entry.push(':');
                entry.push_str(a);
            }
        }
        tarballs.push(entry);
    }

    let mut vsix_entries: Vec<String> = Vec::new();
    let mut seen_vsix: BTreeSet<&str> = BTreeSet::new();
    for v in &m.vsix {
        encodable("vsix.name", &v.name)?;
        encodable("vsix.version", &v.version)?;
        encodable("vsix.asset", &v.asset)?;
        if !seen_vsix.insert(v.name.as_str()) {
            return Err(LayerSpecError::Duplicate {
                kind: "vsix",
                name: v.name.clone(),
            });
        }
        // The assembler builds `pulseengine/<repo_name>` itself, so a foreign
        // owner cannot be expressed — and quietly dropping the owner would
        // fetch a DIFFERENT repository's release of the same name.
        let repo_name = match &v.repo {
            Some(r) => {
                encodable("vsix.repo", r)?;
                let (owner, name) = split_repo(r, &v.name);
                if owner != "pulseengine" {
                    return Err(LayerSpecError::VsixForeignOwner {
                        name: v.name.clone(),
                        repo: r.clone(),
                    });
                }
                name
            }
            None => v.name.clone(),
        };
        vsix_entries.push(format!("{repo_name}:{}:{}:{}", v.version, v.name, v.asset));
    }

    Ok(AssemblerEnv {
        layer_tools: tarballs.join(" "),
        wsc_version,
        vsix_packages: vsix_entries.join(" "),
        realm: m.realm.name.clone(),
        channel: m.realm.channel.clone(),
        registry: m.realm.registry.clone(),
        varve_version: m.varve.version.clone(),
        unverified_ingest: unverified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manifest `pulseengine-layers` actually carries, trimmed to the
    /// shapes that differ from one another. Kept as one literal so the tests
    /// exercise a document that could really be committed, not a fragment.
    const REAL: &str = r#"
[varve]
version = "v0.28.0"

[realm]
name    = "pulseengine"
channel = "rolling"
registry = "oci://ghcr.io/pulseengine/varve/layers"

[[tool]]
name    = "rivet"
version = "v0.34.0"

[[tool]]
name    = "kiln"
version = "v0.4.4"
binary  = "kilnd"

[[tool]]
name    = "wsc"
repo    = "pulseengine/sigil"
version = "v0.11.0"
layout  = "raw-per-platform"

[[vsix]]
name    = "rivet-sdlc"
repo    = "pulseengine/rivet"
version = "v0.34.0"
asset   = "rivet-sdlc-%V.vsix"

[[vsix]]
name    = "spar-aadl"
repo    = "pulseengine/spar"
version = "v0.40.0"
asset   = "spar-aadl-%P-%V.vsix"
"#;

    fn env_of(text: &str) -> AssemblerEnv {
        assembler_env(&parse_layer_manifest(text).expect("parses")).expect("converts")
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_plain_tool_becomes_name_and_version() {
        assert!(env_of(REAL).layer_tools.starts_with("rivet:v0.34.0 "));
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_differing_binary_name_is_carried_as_the_third_field() {
        assert!(env_of(REAL).layer_tools.contains("kiln:v0.4.4:kilnd"));
    }

    /// The one raw-per-platform tool leaves TARBALL_TOOLS entirely — putting it
    /// there would have the assembler look for a tarball that does not exist.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn the_raw_per_platform_tool_becomes_wsc_version_and_not_a_tarball() {
        let e = env_of(REAL);
        assert_eq!(e.wsc_version.as_deref(), Some("v0.11.0"));
        assert!(!e.layer_tools.contains("wsc"), "{}", e.layer_tools);
        assert!(!e.layer_tools.contains("sigil"), "{}", e.layer_tools);
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn vsix_entries_drop_the_default_owner_the_assembler_re_adds() {
        let e = env_of(REAL);
        assert_eq!(
            e.vsix_packages,
            "rivet:v0.34.0:rivet-sdlc:rivet-sdlc-%V.vsix \
             spar:v0.40.0:spar-aadl:spar-aadl-%P-%V.vsix"
        );
    }

    /// The manifest is the only place a version is written, so a typo there
    /// must not be able to leave the real key at its previous value.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_mistyped_key_is_refused_rather_than_ignored() {
        let text = REAL.replace("name    = \"rivet\"", "nmae    = \"rivet\"");
        let err = parse_layer_manifest(&text).unwrap_err();
        assert!(
            matches!(&err, LayerSpecError::Parse(m) if m.contains("nmae")),
            "{err}"
        );
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn an_unknown_layout_is_refused_and_names_the_two_that_work() {
        let text = REAL.replace("raw-per-platform", "zipfile");
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("zipfile") && msg.contains("raw-per-platform"),
            "{msg}"
        );
    }

    /// The assembler has exactly one slot. A second raw-per-platform tool would
    /// otherwise be dropped from a layer that still signs and publishes.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_second_raw_per_platform_tool_is_refused_rather_than_dropped() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"other\"\nversion = \"v1.0.0\"\nlayout = \"raw-per-platform\"\n"
        );
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        assert_eq!(
            err,
            LayerSpecError::ManyRawPerPlatform {
                first: "wsc".into(),
                second: "other".into()
            }
        );
    }

    /// Found by actually trying to assemble a bytecodealliance manifest: the
    /// assembler's one raw-per-platform slot fetches `wsc` from
    /// `pulseengine/sigil`, so putting any other tool in it emitted
    /// WSC_VERSION = that tool's version and would have downloaded wsc at
    /// v0.10.1 — wrong tool, wrong repo, wrong version, deposited under the
    /// wrong name, silently.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_raw_per_platform_tool_that_is_not_wsc_is_refused() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.10.1\"\nlayout = \"raw-per-platform\"\n"
        );
        // The FIRST raw tool in REAL is wsc, so this trips the many-slot rule;
        // remove wsc to isolate the identity rule.
        let only = text.replace(
            "[[tool]]\nname    = \"wsc\"\nrepo    = \"pulseengine/sigil\"\nversion = \"v0.11.0\"\nlayout  = \"raw-per-platform\"\n",
            "",
        );
        assert!(!only.contains("wsc"), "the wsc block must be gone: {only}");
        let err = assembler_env(&parse_layer_manifest(&only).unwrap()).unwrap_err();
        assert_eq!(
            err,
            LayerSpecError::RawPerPlatformNotWsc {
                tool: "wac".into(),
                repo: "bytecodealliance/wac".into()
            },
            "{err}"
        );
        assert!(err.to_string().contains("wrong repository"), "{err}");
    }

    /// One wrong field is enough. The slot fetches `wsc` from
    /// `pulseengine/sigil`, so a tool that matches two of those three and
    /// misses the third still becomes a request for something else — and a
    /// test that only varies all three at once cannot tell the guard from a
    /// much weaker one. cargo-mutants proved that by narrowing it.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn the_wsc_slot_rejects_a_tool_that_differs_in_any_single_field() {
        let base = REAL.replace(
            "[[tool]]\nname    = \"wsc\"\nrepo    = \"pulseengine/sigil\"\nversion = \"v0.11.0\"\nlayout  = \"raw-per-platform\"\n",
            "",
        );
        for (name, repo, what) in [
            ("wsc", "acme/sigil", "a different OWNER"),
            ("wsc", "pulseengine/other", "a different REPOSITORY"),
            ("other", "pulseengine/sigil", "a different TOOL NAME"),
        ] {
            let text = format!(
                "{base}\n[[tool]]\nname = \"{name}\"\nrepo = \"{repo}\"\n\
                 version = \"v1.0.0\"\nlayout = \"raw-per-platform\"\n"
            );
            let err = assembler_env(&parse_layer_manifest(&text).unwrap()).expect_err(what);
            assert!(
                matches!(err, LayerSpecError::RawPerPlatformNotWsc { .. }),
                "{what} ({name} from {repo}) was not refused as a wsc-slot \
                 mismatch: {err:?}"
            );
        }
    }

    /// Dropping the owner would fetch pulseengine's release of the same name —
    /// a different repository's bytes, deposited under a good signature.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_foreign_owner_on_an_extension_is_refused() {
        let text = REAL.replace(
            "repo    = \"pulseengine/rivet\"",
            "repo    = \"acme/rivet\"",
        );
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        assert_eq!(
            err,
            LayerSpecError::VsixForeignOwner {
                name: "rivet-sdlc".into(),
                repo: "acme/rivet".into()
            }
        );
    }

    /// The encoding's separators cannot appear in the data. Both of these would
    /// be split by the shell rather than reported.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_value_carrying_a_separator_is_refused() {
        for (bad, why) in [("v1.0 rc1", "whitespace"), ("v1.0:rc1", "':'")] {
            let text = REAL.replace("v0.34.0\"\n\n[[tool]]", &format!("{bad}\"\n\n[[tool]]"));
            let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(why), "{bad}: {msg}");
        }
    }

    /// `tarball` is the default, but the docs say you may write it, so writing
    /// it must not be refused. cargo-mutants found this by deleting the match
    /// arm: every test used the default or `raw-per-platform`, so nothing
    /// noticed that spelling it out stopped working.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn an_explicit_tarball_layout_means_the_same_as_omitting_it() {
        let explicit = REAL.replace(
            "name    = \"rivet\"\nversion = \"v0.34.0\"",
            "name    = \"rivet\"\nversion = \"v0.34.0\"\nlayout  = \"tarball\"",
        );
        assert_ne!(explicit, REAL, "the fixture substitution must apply");
        assert_eq!(env_of(&explicit).layer_tools, env_of(REAL).layer_tools);
    }

    /// A foreign OWNER is fine — `bytecodealliance/wasm-tools` is the whole
    /// point of the second realm — as long as the basename still identifies
    /// the tool.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_foreign_owner_is_carried_as_a_qualified_repository() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"wasm-tools\"\nrepo = \"bytecodealliance/wasm-tools\"\nversion = \"v1.257.1\"\n"
        );
        assert!(
            env_of(&text)
                .layer_tools
                .contains("bytecodealliance/wasm-tools:v1.257.1"),
            "{}",
            env_of(&text).layer_tools
        );
    }

    /// The assembler names the payload from the repository basename, so a
    /// disagreeing `name` is discarded rather than translated — the layer would
    /// deposit and verify while carrying a tool under a name nobody asked for.
    /// cargo-mutants found this too: no fixture had a tarball tool whose repo
    /// basename differed, because the only differing repo was exempt.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_tool_whose_repo_basename_disagrees_with_its_name_is_refused() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"wsc2\"\nrepo = \"pulseengine/sigil\"\nversion = \"v0.11.0\"\n"
        );
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        assert_eq!(
            err,
            LayerSpecError::RepoNameMismatch {
                name: "wsc2".into(),
                repo: "pulseengine/sigil".into(),
                basename: "sigil".into(),
            },
            "{err}"
        );
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn two_tools_of_one_name_are_refused() {
        let text = format!("{REAL}\n[[tool]]\nname = \"rivet\"\nversion = \"v0.1.0\"\n");
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        assert_eq!(
            err,
            LayerSpecError::Duplicate {
                kind: "tool",
                name: "rivet".into()
            }
        );
    }

    /// A release offering neither mechanism can be carried only with a stated
    /// reason, and the reason is signed into the layer where every consumer
    /// reads it. It belongs in the manifest beside the tool it excuses, not in
    /// a workflow variable — split definitions are how versions drift (#106).
    // rivet: verifies REQ-LAYERADAPT-001
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn an_unverified_reason_reaches_the_assembler_intact() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.10.1\"\nunverified-reason = \"publishes no sums, no cosign \
             bundle and no attestation; tracked upstream, re-check each cut\"\n"
        );
        let env = env_of(&text);
        assert_eq!(env.unverified_ingest.len(), 1);
        assert_eq!(env.unverified_ingest[0].0, "bytecodealliance/wac");
        assert!(env.unverified_ingest[0].1.contains("re-check each cut"));

        // Rendered in $GITHUB_ENV's heredoc form, because the value is
        // line-separated and a KEY=value line cannot carry newlines.
        let r = env.render();
        assert!(r.contains("UNVERIFIED_INGEST<<"), "{r}");
        assert!(r.contains("bytecodealliance/wac=publishes no sums"), "{r}");
    }

    /// A reason containing the delimiter would end the heredoc early and let
    /// whatever followed be read as further environment. That is an injection,
    /// not a typo, so the delimiter is chosen against the content.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_reason_containing_the_delimiter_cannot_close_the_block_early() {
        let text = format!(
            "{REAL}\n[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.10.1\"\nunverified-reason = \"VARVE_UNVERIFIED_EOF\\nPATH=/evil\"\n"
        );
        let r = env_of(&text).render();
        let opened = r
            .lines()
            .find(|l| l.starts_with("UNVERIFIED_INGEST<<"))
            .expect("heredoc opened");
        let delim = opened.trim_start_matches("UNVERIFIED_INGEST<<");
        // The delimiter must not appear inside the body it delimits.
        let body = r.split(&format!("<<{delim}\n")).nth(1).expect("body");
        let body = body.split(&format!("\n{delim}")).next().expect("closes");
        assert!(
            !body.contains(delim),
            "delimiter occurs inside its own body"
        );
        assert!(
            body.contains("PATH=/evil"),
            "the reason must survive verbatim"
        );
    }

    /// "We could not verify this" must never be the silent path.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn an_empty_unverified_reason_is_refused() {
        for bad in ["\"\"", "\"   \""] {
            let text = format!(
                "{REAL}\n[[tool]]\nname = \"wac\"\nversion = \"v1\"\nunverified-reason = {bad}\n"
            );
            let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
            assert_eq!(
                err,
                LayerSpecError::UnverifiedWithoutReason { tool: "wac".into() },
                "{bad}"
            );
        }
    }

    /// The opt-in is per RELEASE. Two tools from one repository giving
    /// different reasons would record one and drop the other.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn two_tools_from_one_repo_must_agree_on_the_reason() {
        // `wsc` already comes from pulseengine/sigil as a raw-per-platform
        // tool, which is exempt from the basename rule; a tarball tool named
        // `sigil` from the same repo is the reachable way two payloads share
        // one release. Two tarball tools cannot, by construction.
        let text = REAL.replace(
            "layout  = \"raw-per-platform\"",
            "layout  = \"raw-per-platform\"\nunverified-reason = \"first\"",
        ) + "\n[[tool]]\nname = \"sigil\"\nrepo = \"pulseengine/sigil\"\nversion = \"v0.11.0\"\n\
             unverified-reason = \"second\"\n";
        let err = assembler_env(&parse_layer_manifest(&text).unwrap()).unwrap_err();
        assert!(
            matches!(err, LayerSpecError::ConflictingReason { .. }),
            "{err:?}"
        );
        // Agreeing is fine, and recorded once.
        let ok = text.replace("\"second\"", "\"first\"");
        assert_eq!(env_of(&ok).unverified_ingest.len(), 1);
    }

    /// A manifest with nothing unverified must not emit the variable at all —
    /// an empty opt-in list and an absent one are different statements.
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_manifest_with_nothing_unverified_emits_no_opt_in() {
        let r = env_of(REAL).render();
        assert!(!r.contains("UNVERIFIED_INGEST"), "{r}");
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_manifest_with_no_payloads_is_refused() {
        let text = "[varve]\nversion = \"v0.28.0\"\n\n[realm]\nname = \"p\"\nchannel = \"rolling\"\nregistry = \"oci://x\"\n";
        assert_eq!(
            assembler_env(&parse_layer_manifest(text).unwrap()).unwrap_err(),
            LayerSpecError::Empty
        );
    }

    /// VSIX_PACKAGES must be SET-but-empty rather than absent: the assembler
    /// distinguishes "this layer carries no extensions" from "someone forgot".
    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn a_layer_with_no_extensions_still_sets_the_variable() {
        let text = REAL
            .split("[[vsix]]")
            .next()
            .expect("has a tools section")
            .to_string();
        let rendered = env_of(&text).render();
        assert!(rendered.contains("\nVSIX_PACKAGES=\n"), "{rendered}");
    }

    // rivet: verifies REQ-LAYERADAPT-001
    #[test]
    fn render_emits_one_key_per_line_in_a_stable_order() {
        let rendered = env_of(REAL).render();
        let keys: Vec<&str> = rendered
            .lines()
            .map(|l| l.split('=').next().unwrap_or(""))
            .collect();
        assert_eq!(
            keys,
            [
                "TARBALL_TOOLS",
                "WSC_VERSION",
                "VSIX_PACKAGES",
                "VARVE_REALM",
                "VARVE_CHANNEL",
                "VARVE_REGISTRY",
                "VARVE_VERSION"
            ]
        );
    }
}
