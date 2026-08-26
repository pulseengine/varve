//! Which upstream asset becomes which payload (REQ-PRODUCER-002 clause 4).
//!
//! This is the logic that has actually failed in production, twice, and both
//! times silently:
//!
//! * a mistyped `%V` in an asset template matched nothing, so the tool was
//!   omitted from a layer that still assembled, signed and published. The
//!   layer claimed to carry a fork it did not carry.
//! * a repo appearing in both the tarball list and the extension list was
//!   verified twice, and the second `gh release download` refused to
//!   overwrite the sums file the first had fetched, killing the run mid-way.
//!
//! Neither is a subtle cryptographic failure. Both are string handling — and
//! in bash both were invisible until a real registry was involved. Here they
//! are pure functions over owned data, so a unit test is the whole story.

use std::fmt;

/// The Rust target triples a layer carries unless told otherwise.
pub const DEFAULT_PLATFORMS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
];

/// The short platform tags used OUTSIDE this organisation.
///
/// bytecodealliance names its assets `<tool>-<version>-aarch64-macos.tar.gz`,
/// not by Rust target triple, so ingesting a second realm needs the mapping
/// written down rather than assumed. Recorded from the live wasm-tools
/// v1.257.1 asset list on 2026-08-21.
pub fn upstream_platform_tag(triple: &str) -> Option<&'static str> {
    match triple {
        "aarch64-apple-darwin" => Some("aarch64-macos"),
        "x86_64-apple-darwin" => Some("x86_64-macos"),
        "aarch64-unknown-linux-gnu" => Some("aarch64-linux"),
        "x86_64-unknown-linux-gnu" => Some("x86_64-linux"),
        _ => None,
    }
}

/// A placeholder an asset template may carry.
///
/// Kept as an enum rather than a set of `str::replace` calls so that adding a
/// placeholder without teaching the expander about it cannot compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    /// `%V` — the bare version, leading `v` stripped.
    BareVersion,
    /// `%T` — the Rust target triple.
    Triple,
    /// `%U` — the short upstream platform tag.
    UpstreamTag,
    /// `%P` — the VS Code platform tag.
    VsCodePlatform,
}

impl Placeholder {
    pub fn token(self) -> &'static str {
        match self {
            Placeholder::BareVersion => "%V",
            Placeholder::Triple => "%T",
            Placeholder::UpstreamTag => "%U",
            Placeholder::VsCodePlatform => "%P",
        }
    }

    pub const ALL: &'static [Placeholder] = &[
        Placeholder::BareVersion,
        Placeholder::Triple,
        Placeholder::UpstreamTag,
        Placeholder::VsCodePlatform,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// A placeholder the expander does not implement — `%Q`, or a typo like
    /// `%v`. Refused rather than left in the string, because a template that
    /// keeps a literal `%v` matches no asset and the tool vanishes from the
    /// layer.
    UnknownPlaceholder { template: String, found: String },
    /// `%U` was used for a triple that has no recorded upstream tag.
    NoUpstreamTag { template: String, triple: String },
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::UnknownPlaceholder { template, found } => write!(
                f,
                "asset template {template:?} carries {found:?}, which is not a \
                 placeholder varve expands. Known: %V (bare version), %T (Rust \
                 target triple), %U (short upstream tag), %P (VS Code platform). \
                 An unexpanded placeholder matches no release asset, and the \
                 payload would be dropped from a layer that still signs."
            ),
            TemplateError::NoUpstreamTag { template, triple } => write!(
                f,
                "asset template {template:?} uses %U, but {triple:?} has no \
                 recorded upstream platform tag. Add it to \
                 `upstream_platform_tag` from the upstream's real asset list \
                 rather than guessing the spelling."
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Strip a single leading `v`, the way every release in this ecosystem spells
/// a tag. `v0.34.0` -> `0.34.0`; `0.34.0` is already bare.
pub fn bare_version(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

/// Expand an asset template for one platform.
///
/// `platform` is `None` for a platform-independent asset; a template that then
/// asks for `%T`/`%U`/`%P` is an error rather than a half-expanded string.
pub fn expand(
    template: &str,
    version: &str,
    platform: Option<&str>,
    vscode_platform: Option<&str>,
) -> Result<String, TemplateError> {
    // Reject unknown placeholders BEFORE substituting, so a typo cannot be
    // masked by a successful substitution elsewhere in the same template.
    //
    // No hand-rolled index arithmetic: the first version walked a byte cursor
    // and `cargo mutants` hung it by turning `i += 2` into `i *= 2`. The same
    // cursor also sliced `template[i..i + 2]`, which panics on a template
    // containing any multi-byte character. `match_indices` plus `chars()` has
    // neither failure mode by construction.
    for (idx, _) in template.match_indices('%') {
        let token: String = template[idx..].chars().take(2).collect();
        if !Placeholder::ALL.iter().any(|p| p.token() == token) {
            return Err(TemplateError::UnknownPlaceholder {
                template: template.to_string(),
                found: token,
            });
        }
    }

    let mut out = template.replace(Placeholder::BareVersion.token(), bare_version(version));
    if let Some(triple) = platform {
        out = out.replace(Placeholder::Triple.token(), triple);
        if out.contains(Placeholder::UpstreamTag.token()) {
            let tag =
                upstream_platform_tag(triple).ok_or_else(|| TemplateError::NoUpstreamTag {
                    template: template.to_string(),
                    triple: triple.to_string(),
                })?;
            out = out.replace(Placeholder::UpstreamTag.token(), tag);
        }
    }
    if let Some(p) = vscode_platform {
        out = out.replace(Placeholder::VsCodePlatform.token(), p);
    }
    Ok(out)
}

/// Does this template vary by platform at all?
///
/// A VS Code extension template with no `%P` is ONE portable package, and
/// expanding it per platform would download the same file four times and
/// deposit four identical payloads.
pub fn is_per_platform(template: &str) -> bool {
    template.contains(Placeholder::Triple.token())
        || template.contains(Placeholder::UpstreamTag.token())
        || template.contains(Placeholder::VsCodePlatform.token())
}

/// The default tarball asset template for a tool, matching what the shell
/// pipeline used: `<tool>-<version>-%T.tar.gz`, with the version as WRITTEN
/// (leading `v` kept), because that is how these releases name assets.
pub fn default_tarball_template(tool: &str, version: &str) -> String {
    format!("{tool}-{version}-%T.tar.gz")
}

/// What a tool matched across every platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub matched: Vec<(String, String)>,
    pub missing: Vec<String>,
}

/// Select the assets for one tool across `platforms`, given which asset names
/// the release actually publishes.
///
/// **A tool that matches NOTHING on any platform is an error, not a warning.**
/// That is the 2026.08.3 defect: a template that matched no asset produced a
/// layer silently missing a tool it claimed to carry. A tool missing on SOME
/// platforms is normal — not every upstream builds for every triple — and is
/// reported so the operator can see the shape of what shipped.
pub fn select(
    template: &str,
    version: &str,
    platforms: &[&str],
    available: &[String],
) -> Result<Selection, TemplateError> {
    let mut matched = Vec::new();
    let mut missing = Vec::new();
    if !is_per_platform(template) {
        let asset = expand(template, version, None, None)?;
        if available.iter().any(|a| a == &asset) {
            matched.push((String::new(), asset));
        } else {
            missing.push(asset);
        }
        return Ok(Selection { matched, missing });
    }
    for platform in platforms {
        let asset = expand(template, version, Some(platform), None)?;
        if available.iter().any(|a| a == &asset) {
            matched.push(((*platform).to_string(), asset));
        } else {
            missing.push(asset);
        }
    }
    Ok(Selection { matched, missing })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avail(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn bare_version_strips_one_leading_v_only() {
        assert_eq!(bare_version("v0.34.0"), "0.34.0");
        assert_eq!(bare_version("0.34.0"), "0.34.0");
        // Not a recursive strip: `vv1` is a real (if odd) tag, and eating both
        // would silently look for the wrong asset.
        assert_eq!(bare_version("vv1.0.0"), "v1.0.0");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_triple_template_expands_per_platform() {
        let got = expand(
            "wasm-tools-%V-%T.tar.gz",
            "v1.257.1",
            Some("aarch64-apple-darwin"),
            None,
        )
        .expect("expands");
        assert_eq!(got, "wasm-tools-1.257.1-aarch64-apple-darwin.tar.gz");
    }

    /// bytecodealliance names assets by short tag, not Rust triple. Getting
    /// this wrong is how a second realm silently ingests nothing.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_upstream_tag_uses_the_recorded_spelling_not_the_triple() {
        let got = expand(
            "wasm-tools-%V-%U.tar.gz",
            "v1.257.1",
            Some("aarch64-apple-darwin"),
            None,
        )
        .expect("expands");
        assert_eq!(got, "wasm-tools-1.257.1-aarch64-macos.tar.gz");
    }

    /// The 2026.08.3 defect, as a unit test: a typo'd placeholder must be
    /// REFUSED, not left in the string to match nothing.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_mistyped_placeholder_is_refused_rather_than_left_unexpanded() {
        let err = expand(
            "rivet-%v-%T.tar.gz",
            "v0.34.0",
            Some("x86_64-apple-darwin"),
            None,
        )
        .expect_err("must refuse");
        assert_eq!(
            err,
            TemplateError::UnknownPlaceholder {
                template: "rivet-%v-%T.tar.gz".into(),
                found: "%v".into()
            }
        );
        assert!(
            err.to_string().contains("matches no release asset"),
            "{err}"
        );
    }

    /// Every recorded mapping, not just one. These spellings come from a real
    /// upstream asset list; a single wrong tag omits that tool on exactly one
    /// platform, which is the quietest way this pipeline can fail.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn every_recorded_upstream_tag_is_pinned() {
        assert_eq!(
            upstream_platform_tag("aarch64-apple-darwin"),
            Some("aarch64-macos")
        );
        assert_eq!(
            upstream_platform_tag("x86_64-apple-darwin"),
            Some("x86_64-macos")
        );
        assert_eq!(
            upstream_platform_tag("aarch64-unknown-linux-gnu"),
            Some("aarch64-linux")
        );
        assert_eq!(
            upstream_platform_tag("x86_64-unknown-linux-gnu"),
            Some("x86_64-linux")
        );
        assert_eq!(upstream_platform_tag("riscv64-unknown-linux-gnu"), None);
        // Every default platform must HAVE a tag, or a %U template silently
        // cannot cover the set the layer claims to support.
        for p in DEFAULT_PLATFORMS {
            assert!(
                upstream_platform_tag(p).is_some(),
                "no upstream tag for {p}"
            );
        }
    }

    /// A template is a string from a manifest, so it can contain anything.
    /// The first expander sliced two bytes at a `%` and would panic here.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_multibyte_template_is_refused_not_panicked_on() {
        let err = expand("tool-%\u{00e9}-%V.tar.gz", "v1.0.0", None, None)
            .expect_err("must refuse, and must not panic");
        assert!(
            matches!(err, TemplateError::UnknownPlaceholder { .. }),
            "{err:?}"
        );
    }

    /// A bare trailing `%` has no placeholder after it.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_trailing_percent_is_refused() {
        let err = expand("tool-%V.tar.gz%", "v1.0.0", None, None).expect_err("must refuse");
        assert!(
            matches!(err, TemplateError::UnknownPlaceholder { .. }),
            "{err:?}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_unknown_upstream_triple_is_refused_rather_than_guessed() {
        let err = expand(
            "t-%U.tar.gz",
            "v1.0.0",
            Some("riscv64-unknown-linux-gnu"),
            None,
        )
        .expect_err("must refuse");
        assert!(
            matches!(err, TemplateError::NoUpstreamTag { .. }),
            "{err:?}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_template_without_a_platform_token_is_one_portable_package() {
        assert!(!is_per_platform("rivet-sdlc-%V.vsix"));
        assert!(is_per_platform("spar-aadl-%P-%V.vsix"));
        assert!(is_per_platform("t-%V-%T.tar.gz"));
        assert!(is_per_platform("t-%V-%U.tar.gz"));
    }

    /// A tool present on some platforms and absent on others is normal and
    /// must still ship what it has.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_partial_platform_match_ships_what_exists_and_reports_the_rest() {
        let sel = select(
            "rivet-v0.34.0-%T.tar.gz",
            "v0.34.0",
            &["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"],
            &avail(&["rivet-v0.34.0-aarch64-apple-darwin.tar.gz"]),
        )
        .expect("selects");
        assert_eq!(sel.matched.len(), 1);
        assert_eq!(
            sel.missing,
            vec!["rivet-v0.34.0-x86_64-unknown-linux-gnu.tar.gz"]
        );
    }

    /// The one that shipped a broken layer: nothing matched anywhere. The
    /// caller must be able to tell this from a partial match.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_tool_matching_nothing_anywhere_is_visible_as_an_empty_match() {
        let sel = select(
            "rivet-v9.9.9-%T.tar.gz",
            "v9.9.9",
            DEFAULT_PLATFORMS,
            &avail(&["rivet-v0.34.0-aarch64-apple-darwin.tar.gz"]),
        )
        .expect("selects");
        assert!(sel.matched.is_empty(), "{:?}", sel.matched);
        assert_eq!(sel.missing.len(), DEFAULT_PLATFORMS.len());
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_portable_package_is_selected_once_not_once_per_platform() {
        let sel = select(
            "rivet-sdlc-%V.vsix",
            "v0.34.0",
            DEFAULT_PLATFORMS,
            &avail(&["rivet-sdlc-0.34.0.vsix"]),
        )
        .expect("selects");
        assert_eq!(sel.matched.len(), 1, "{:?}", sel.matched);
        assert_eq!(sel.matched[0].1, "rivet-sdlc-0.34.0.vsix");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_default_template_matches_what_the_shell_pipeline_produced() {
        assert_eq!(
            default_tarball_template("rivet", "v0.34.0"),
            "rivet-v0.34.0-%T.tar.gz"
        );
    }
}
