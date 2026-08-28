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
use varve_core::layerspec::{LayerManifest, ManifestTool, ManifestVsix};

/// What kind of payload a plan item produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// A binary inside a per-platform archive.
    Tarball,
    /// A bare per-platform binary, no archive.
    RawPerPlatform,
    /// A VS Code extension package.
    Vsix,
}

/// One asset to fetch, verify and stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPlan {
    /// The name the payload is deposited under, and dispatched by.
    pub name: String,
    /// `owner/repo` the release comes from.
    pub repo: String,
    pub version: String,
    /// The release asset, template already expanded.
    pub asset: String,
    /// `None` for a platform-independent payload.
    pub platform: Option<String>,
    pub kind: PayloadKind,
    /// Why this release is ingested with no proof, if it is.
    pub unverified_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Template(TemplateError),
    /// A tool declares a layout this planner does not implement.
    UnknownLayout {
        tool: String,
        layout: String,
    },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Template(e) => write!(f, "{e}"),
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
    }
}

fn kind_of(t: &ManifestTool) -> Result<PayloadKind, PlanError> {
    match t.layout.as_deref() {
        None | Some("tarball") => Ok(PayloadKind::Tarball),
        Some("raw-per-platform") => Ok(PayloadKind::RawPerPlatform),
        Some(other) => Err(PlanError::UnknownLayout {
            tool: t.name.clone(),
            layout: other.to_string(),
        }),
    }
}

/// Expand one tool into one plan item per platform.
pub fn plan_tool(t: &ManifestTool, platforms: &[&str]) -> Result<Vec<PayloadPlan>, PlanError> {
    let kind = kind_of(t)?;
    let template = template_of(t, kind);
    let repo = repo_of(&t.repo, &t.name);
    // `binary` names the executable when it differs from the tool (kiln ships
    // kilnd); the payload is deposited under THAT name, which is what a
    // consumer dispatches.
    let name = t.binary.clone().unwrap_or_else(|| t.name.clone());

    let mut out = Vec::new();
    if !asset::is_per_platform(&template) {
        out.push(PayloadPlan {
            name,
            repo,
            version: t.version.clone(),
            asset: asset::expand(&template, &t.version, None, None)?,
            platform: None,
            kind,
            unverified_reason: t.unverified_reason.clone(),
        });
        return Ok(out);
    }
    for p in platforms {
        // An explicit name wins over the template. Some upstreams ship only a
        // musl Linux build, whose name no template can derive from a gnu
        // triple; naming the file is exact where inferring it would guess.
        let asset = match t.asset_for.get(*p) {
            Some(explicit) => explicit.clone(),
            None => asset::expand(&template, &t.version, Some(p), None)?,
        };
        out.push(PayloadPlan {
            name: name.clone(),
            repo: repo.clone(),
            version: t.version.clone(),
            asset,
            platform: Some((*p).to_string()),
            kind,
            unverified_reason: t.unverified_reason.clone(),
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
            asset: asset::expand(&v.asset, &v.version, None, None)?,
            platform: None,
            kind: PayloadKind::Vsix,
            unverified_reason: None,
        });
        return Ok(out);
    }
    for p in platforms {
        out.push(PayloadPlan {
            name: v.name.clone(),
            repo: repo.clone(),
            version: v.version.clone(),
            asset: asset::expand(&v.asset, &v.version, Some(p), None)?,
            platform: Some((*p).to_string()),
            kind: PayloadKind::Vsix,
            unverified_reason: None,
        });
    }
    Ok(out)
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
        let key = (p.repo.clone(), p.version.clone());
        if !seen.contains(&key) {
            seen.push(key);
        }
    }
    seen
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
             unverified-reason = \"publishes nothing verifiable\"\n",
        );
        let p = plan(&m, PLATFORMS).expect("plans");
        assert_eq!(p.len(), 2);
        assert!(
            p.iter()
                .all(|x| x.unverified_reason.as_deref() == Some("publishes nothing verifiable"))
        );
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
}
