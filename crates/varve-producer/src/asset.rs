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

/// The same host, OS FIRST — zephyrproject-rtos/sdk-ng's convention
/// (`toolchain_gnu_macos-aarch64_arm-zephyr-eabi.tar.xz`).
///
/// Derived by swapping [`upstream_platform_tag`]'s halves rather than by a
/// second table: two tables would be two places to add a platform, and the one
/// nobody remembers to update is the one that silently omits a payload.
pub fn host_platform_tag(triple: &str) -> Option<String> {
    let tag = upstream_platform_tag(triple)?;
    let (arch, os) = tag.split_once('-')?;
    Some(format!("{os}-{arch}"))
}

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

/// The platform tags VS Code uses for a per-platform extension package.
///
/// A different vocabulary again from both the Rust triple and the short
/// upstream tag, for the same four machines. Recorded rather than derived,
/// because a guessed spelling produces a template that matches nothing — and
/// this pipeline has already shipped a layer missing a payload that way.
pub fn vscode_platform_tag(triple: &str) -> Option<&'static str> {
    match triple {
        "aarch64-apple-darwin" => Some("darwin-arm64"),
        "x86_64-apple-darwin" => Some("darwin-x64"),
        "aarch64-unknown-linux-gnu" => Some("linux-arm64"),
        "x86_64-unknown-linux-gnu" => Some("linux-x64"),
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
    /// `%U` — the short upstream platform tag, ARCH FIRST: `aarch64-macos`.
    /// bytecodealliance spells its assets this way.
    UpstreamTag,
    /// `%H` — the same host, OS FIRST: `macos-aarch64`.
    ///
    /// Not a stylistic variant of `%U`. There is no single "upstream
    /// convention": bytecodealliance writes `aarch64-macos` and
    /// zephyrproject-rtos/sdk-ng writes `macos-aarch64`, and a template using
    /// the wrong one matches nothing. varve had only the first, which is why
    /// the first attempt to deposit a Zephyr SDK asked for
    /// `toolchain_gnu_aarch64-macos_arm-zephyr-eabi.tar.xz` against a release
    /// that publishes `toolchain_gnu_macos-aarch64_arm-zephyr-eabi.tar.xz`.
    HostTag,
    /// `%P` — the VS Code platform tag.
    VsCodePlatform,
    /// `%R` — the release tag exactly as the manifest writes it, leading `v`
    /// included. `%V` strips that `v`, and several upstreams keep it:
    /// `wasmtime-v48.0.1-aarch64-macos.tar.xz`. Without this a manifest has to
    /// hardcode the version inside the template, so a version bump edits two
    /// places and one of them eventually gets missed.
    ReleaseTag,
}

impl Placeholder {
    pub fn token(self) -> &'static str {
        match self {
            Placeholder::BareVersion => "%V",
            Placeholder::Triple => "%T",
            Placeholder::UpstreamTag => "%U",
            Placeholder::HostTag => "%H",
            Placeholder::VsCodePlatform => "%P",
            Placeholder::ReleaseTag => "%R",
        }
    }

    pub const ALL: &'static [Placeholder] = &[
        Placeholder::BareVersion,
        Placeholder::Triple,
        Placeholder::UpstreamTag,
        Placeholder::HostTag,
        Placeholder::VsCodePlatform,
        Placeholder::ReleaseTag,
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
    /// `%P` was used for a triple that has no recorded VS Code tag.
    NoVsCodeTag { template: String, triple: String },
    /// The template asks for a platform token and no platform was supplied.
    ///
    /// Returning the token unexpanded instead — as the first version of this
    /// function did — produces a name like `spar-aadl-%P-0.34.0.vsix`, which
    /// matches no asset. The payload then vanishes from a layer that still
    /// assembles, signs and publishes. That is the precise defect this module
    /// exists to prevent, so the half-expanded string must not be reachable.
    MissingPlatform { template: String, token: String },
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
            TemplateError::NoVsCodeTag { template, triple } => write!(
                f,
                "asset template {template:?} uses %P, but {triple:?} has no \
                 recorded VS Code platform tag. Add it to `vscode_platform_tag` \
                 from the marketplace's real package names rather than guessing \
                 the spelling."
            ),
            TemplateError::MissingPlatform { template, token } => write!(
                f,
                "asset template {template:?} asks for {token}, but no platform \
                 was supplied for this expansion. Leaving {token} in the name \
                 would produce an asset that matches nothing, and the payload \
                 would be dropped from a layer that still signs."
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
    release: &str,
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

    // `%R` is the RELEASE tag and `%V` the payload's own version. They are the
    // same string for almost every tool, and different on a hub: jess tags
    // `v0.7.2` and ships `with-device` at `0.2.2`. Deriving one from the other
    // is what left `with-device` unfetchable (REQ-PAYLOADID-001).
    let mut out = template
        .replace(Placeholder::ReleaseTag.token(), release)
        .replace(Placeholder::BareVersion.token(), bare_version(version));
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
        if out.contains(Placeholder::HostTag.token()) {
            let tag = host_platform_tag(triple).ok_or_else(|| TemplateError::NoUpstreamTag {
                template: template.to_string(),
                triple: triple.to_string(),
            })?;
            out = out.replace(Placeholder::HostTag.token(), &tag);
        }
        if out.contains(Placeholder::VsCodePlatform.token()) {
            // Derived from the triple unless the caller named one explicitly:
            // a per-platform extension is selected over the SAME four machines
            // as everything else, and requiring the caller to remember a third
            // vocabulary is exactly how %P went unexpanded in the first place.
            let tag = match vscode_platform {
                Some(p) => p.to_string(),
                None => vscode_platform_tag(triple)
                    .ok_or_else(|| TemplateError::NoVsCodeTag {
                        template: template.to_string(),
                        triple: triple.to_string(),
                    })?
                    .to_string(),
            };
            out = out.replace(Placeholder::VsCodePlatform.token(), &tag);
        }
    } else if let Some(p) = vscode_platform {
        out = out.replace(Placeholder::VsCodePlatform.token(), p);
    }

    // Anything still unexpanded would match no asset. Refusing here is what
    // makes this function's contract true rather than aspirational: the first
    // version documented this behaviour and returned Ok with the literal token.
    for ph in [
        Placeholder::Triple,
        Placeholder::UpstreamTag,
        Placeholder::VsCodePlatform,
    ] {
        if out.contains(ph.token()) {
            return Err(TemplateError::MissingPlatform {
                template: template.to_string(),
                token: ph.token().to_string(),
            });
        }
    }
    Ok(out)
}

/// Does this template vary by platform at all?
///
/// A VS Code extension template with no `%P` is ONE portable package, and
/// expanding it per platform would download the same file four times and
/// deposit four identical payloads.
pub fn is_per_platform(template: &str) -> bool {
    // Every placeholder that names a MACHINE must be listed here. A
    // per-platform token missing from this list does not fail loudly: the
    // template is treated as one portable asset, expanded once with no
    // platform, and the payload is reported absent — which is how adding %H
    // without touching this function made a correct Zephyr template match
    // nothing.
    template.contains(Placeholder::Triple.token())
        || template.contains(Placeholder::UpstreamTag.token())
        || template.contains(Placeholder::HostTag.token())
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
    release: &str,
    platforms: &[&str],
    available: &[String],
) -> Result<Selection, TemplateError> {
    let mut matched = Vec::new();
    let mut missing = Vec::new();
    if !is_per_platform(template) {
        let asset = expand(template, version, release, None, None)?;
        if available.iter().any(|a| a == &asset) {
            matched.push((String::new(), asset));
        } else {
            missing.push(asset);
        }
        return Ok(Selection { matched, missing });
    }
    for platform in platforms {
        let asset = expand(template, version, release, Some(platform), None)?;
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

    /// Several upstreams keep the `v` in their asset names —
    /// `wasmtime-v48.0.1-aarch64-macos.tar.xz`. Found by planning a real
    /// bytecodealliance manifest and checking every name against the release:
    /// four of twelve did not exist, and two of those were this.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_release_tag_is_available_as_written_not_only_bare() {
        assert_eq!(
            expand(
                "wasmtime-%R-%U.tar.xz",
                "v48.0.1",
                "v48.0.1",
                Some("aarch64-apple-darwin"),
                None
            )
            .expect("expands"),
            "wasmtime-v48.0.1-aarch64-macos.tar.xz"
        );
        // And the bare form still strips it.
        assert_eq!(
            expand("t-%V.tar.gz", "v48.0.1", "v48.0.1", None, None).expect("expands"),
            "t-48.0.1.tar.gz"
        );
    }

    /// A template using both must not leave a stray `v`: expanding %V first
    /// would turn "%R" into "v" + the already-substituted bare version.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_template_using_both_version_forms_expands_each_correctly() {
        assert_eq!(
            expand("x-%R-y-%V.tar.gz", "v1.2.3", "v1.2.3", None, None).expect("expands"),
            "x-v1.2.3-y-1.2.3.tar.gz"
        );
    }

    /// The defect a clean-room review found in this very module: `%P` was
    /// never substituted, so a real VSIX template expanded to a literal
    /// `spar-aadl-%P-0.34.0.vsix`, matched nothing on every platform, and the
    /// extension would have vanished from a layer that still signs. `select`
    /// passed `vscode_platform: None` and `expand` returned Ok with the token
    /// still in it.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_per_platform_vsix_template_selects_the_real_marketplace_names() {
        let sel = select(
            "spar-aadl-%P-%V.vsix",
            "v0.34.0",
            "v0.34.0",
            DEFAULT_PLATFORMS,
            &avail(&[
                "spar-aadl-darwin-arm64-0.34.0.vsix",
                "spar-aadl-linux-x64-0.34.0.vsix",
            ]),
        )
        .expect("selects");
        let names: Vec<&str> = sel.matched.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "spar-aadl-darwin-arm64-0.34.0.vsix",
                "spar-aadl-linux-x64-0.34.0.vsix"
            ],
            "matched={:?} missing={:?}",
            sel.matched,
            sel.missing
        );
        // And nothing may still carry the token.
        assert!(
            sel.matched.iter().all(|(_, n)| !n.contains('%'))
                && sel.missing.iter().all(|n| !n.contains('%')),
            "{sel:?}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn every_default_platform_has_a_vscode_tag() {
        assert_eq!(
            vscode_platform_tag("aarch64-apple-darwin"),
            Some("darwin-arm64")
        );
        assert_eq!(
            vscode_platform_tag("x86_64-apple-darwin"),
            Some("darwin-x64")
        );
        assert_eq!(
            vscode_platform_tag("aarch64-unknown-linux-gnu"),
            Some("linux-arm64")
        );
        assert_eq!(
            vscode_platform_tag("x86_64-unknown-linux-gnu"),
            Some("linux-x64")
        );
        assert_eq!(vscode_platform_tag("riscv64-unknown-linux-gnu"), None);
        for p in DEFAULT_PLATFORMS {
            assert!(vscode_platform_tag(p).is_some(), "no VS Code tag for {p}");
        }
    }

    /// The doc comment used to say this was an error and it was not: expand
    /// returned Ok with the literal token, which is the enabling mechanism for
    /// the bug above. A half-expanded name must be unreachable.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_platform_token_with_no_platform_is_refused_not_left_in_the_name() {
        for (template, token) in [
            ("t-%T.tar.gz", "%T"),
            ("t-%U.tar.gz", "%U"),
            ("t-%P.vsix", "%P"),
        ] {
            let err = expand(template, "v1.0.0", "v1.0.0", None, None).expect_err("must refuse");
            assert_eq!(
                err,
                TemplateError::MissingPlatform {
                    template: template.into(),
                    token: token.into()
                },
                "{template}"
            );
            assert!(err.to_string().contains("matches nothing"), "{err}");
        }
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_unknown_triple_for_a_vscode_template_is_refused_rather_than_guessed() {
        let err = expand(
            "t-%P.vsix",
            "v1.0.0",
            "v1.0.0",
            Some("riscv64-unknown-linux-gnu"),
            None,
        )
        .expect_err("must refuse");
        assert!(matches!(err, TemplateError::NoVsCodeTag { .. }), "{err:?}");
    }

    /// A template is a string from a manifest, so it can contain anything.
    /// The first expander sliced two bytes at a `%` and would panic here.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_multibyte_template_is_refused_not_panicked_on() {
        let err = expand("tool-%\u{00e9}-%V.tar.gz", "v1.0.0", "v1.0.0", None, None)
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
        let err =
            expand("tool-%V.tar.gz%", "v1.0.0", "v1.0.0", None, None).expect_err("must refuse");
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

#[cfg(test)]
mod host_tag_tests {
    use super::*;

    /// There is no single "upstream convention". bytecodealliance writes
    /// `aarch64-macos`; zephyrproject-rtos/sdk-ng writes `macos-aarch64`. A
    /// template using the wrong one matches nothing, which is how the first
    /// attempt to deposit a Zephyr SDK asked for
    /// `toolchain_gnu_aarch64-macos_arm-zephyr-eabi.tar.xz` against a release
    /// that publishes `toolchain_gnu_macos-aarch64_arm-zephyr-eabi.tar.xz`.
    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn the_two_upstream_host_conventions_are_both_available_and_differ() {
        for (triple, arch_first, os_first) in [
            ("aarch64-apple-darwin", "aarch64-macos", "macos-aarch64"),
            ("x86_64-apple-darwin", "x86_64-macos", "macos-x86_64"),
            (
                "aarch64-unknown-linux-gnu",
                "aarch64-linux",
                "linux-aarch64",
            ),
            ("x86_64-unknown-linux-gnu", "x86_64-linux", "linux-x86_64"),
        ] {
            assert_eq!(upstream_platform_tag(triple), Some(arch_first), "{triple}");
            assert_eq!(
                host_platform_tag(triple).as_deref(),
                Some(os_first),
                "{triple}"
            );
            assert_ne!(arch_first, os_first, "the conventions must actually differ");
        }
    }

    /// A template naming a MACHINE must be recognised as per-platform. A token
    /// missing from `is_per_platform` does not fail loudly — the template is
    /// expanded once with no platform and the payload reported absent, which
    /// is exactly what happened when %H was added without it.
    // rivet: verifies REQ-SDKDEPOSIT-001
    #[test]
    fn every_machine_naming_token_marks_a_template_per_platform() {
        for tok in ["%T", "%U", "%H", "%P"] {
            assert!(
                is_per_platform(&format!("tool-{tok}.tar.gz")),
                "{tok} does not mark a template per-platform"
            );
        }
        assert!(!is_per_platform("tool-%V.tar.gz"), "%V names no machine");
    }
}
