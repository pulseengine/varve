//! Which forge a release comes from (REQ-PRODUCER-002).
//!
//! The pipeline this replaces hardcoded `github.com` and
//! `token.actions.githubusercontent.com` in five places. That is fine right up
//! until someone runs varve inside an organisation whose code lives on GitHub
//! Enterprise Server — which is most organisations that would want a signed,
//! pinned toolchain in the first place. A supply-chain tool that only works
//! against one vendor's public host is not one an enterprise can adopt.
//!
//! So the host and its OIDC issuer are DATA, not string literals. The default
//! is github.com because that is where this organisation's code is; nothing
//! else assumes it.
//!
//! ## What is and is not verified here
//!
//! The GHES values below follow GitHub's documented scheme — Actions OIDC on
//! GHES issues tokens from `https://<host>/_services/token`, and `gh` targets
//! an instance through `GH_HOST`. **This has not been exercised against a real
//! GHES instance from this repository**, and `gh attestation verify`
//! availability differs by GHES version, so the build-provenance rung may be
//! unavailable there even when the cosign-sums rung works. That is stated
//! rather than assumed: a realm on GHES whose releases publish a
//! cosign-signed `SHA256SUMS.txt` uses rung 1 and does not depend on it.

use std::fmt;

/// A code-hosting instance a release can be ingested from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forge {
    /// Hostname, e.g. `github.com` or `ghe.example.com`. No scheme.
    pub host: String,
    /// The OIDC issuer whose tokens sign that forge's keyless certificates.
    pub oidc_issuer: String,
}

impl Default for Forge {
    fn default() -> Self {
        Forge::github_com()
    }
}

impl Forge {
    /// The public instance.
    pub fn github_com() -> Self {
        Forge {
            host: "github.com".into(),
            oidc_issuer: "https://token.actions.githubusercontent.com".into(),
        }
    }

    /// A GitHub Enterprise Server instance, using GitHub's documented scheme
    /// for Actions OIDC on GHES.
    pub fn enterprise(host: &str) -> Self {
        Forge {
            host: host.trim_end_matches('/').to_string(),
            oidc_issuer: format!("https://{}/_services/token", host.trim_end_matches('/')),
        }
    }

    /// Read the forge from the environment, the way `gh` itself does.
    ///
    /// `GH_HOST` targets an instance; `VARVE_OIDC_ISSUER` overrides the issuer
    /// for an instance that does not follow the default scheme, because
    /// guessing an issuer wrong means verifying a signature against the wrong
    /// authority — which fails closed, but confusingly.
    pub fn from_env(gh_host: Option<&str>, oidc_override: Option<&str>) -> Self {
        let mut forge = match gh_host.map(str::trim).filter(|h| !h.is_empty()) {
            None => Forge::github_com(),
            Some(h) if h.eq_ignore_ascii_case("github.com") => Forge::github_com(),
            Some(h) => Forge::enterprise(h),
        };
        if let Some(issuer) = oidc_override.map(str::trim).filter(|s| !s.is_empty()) {
            forge.oidc_issuer = issuer.to_string();
        }
        forge
    }

    /// `https://<host>/<owner>/<repo>/` — the certificate identity prefix a
    /// release's signing workflow must fall under.
    pub fn identity_prefix(&self, repo: &str) -> String {
        format!("https://{}/{}/", self.host, repo)
    }

    /// The certificate identity a release's signing workflow must have, as the
    /// anchored regexp `cosign verify-blob --certificate-identity-regexp` takes.
    ///
    /// `^https://<host>/<owner>/<repo>/\.github/workflows/[^@]+@refs/tags/<tag>$`
    ///
    /// A signature proves WHO signed, not which release it is for. The old
    /// pattern was the repository URL as an unanchored prefix, which accepted
    /// any workflow at any ref, so an older release's validly signed sums
    /// served under a newer tag verified. Pinning the ref to the release tag
    /// makes the certificate itself say which release it was issued for. The
    /// host, repository and tag are escaped: they are data, not pattern.
    pub fn identity_regexp(&self, repo: &str, release: &str) -> String {
        format!(
            "^https://{}/{}/\\.github/workflows/[^@]+@refs/tags/{}$",
            regex_escape(&self.host),
            regex_escape(repo),
            regex_escape(release)
        )
    }

    /// The identity [`Self::identity_regexp`] enforces, spelled for a reader
    /// and for the signed record: the path of the workflow is any file under
    /// `.github/workflows/` (`[^@]+`) and the ref is the release tag. Not
    /// escaped and not anchored; it begins `https://<host>/<owner>/`, so a
    /// reader that wants the owner finds it where it always was.
    pub fn identity_pattern(&self, repo: &str, release: &str) -> String {
        format!(
            "https://{}/{}/.github/workflows/[^@]+@refs/tags/{}",
            self.host, repo, release
        )
    }

    pub fn is_public_github(&self) -> bool {
        self.host == "github.com"
    }
}

/// Escape every regex metacharacter, the way Go's `regexp.QuoteMeta` does
/// (cosign is Go): `\.+*?()|[]{}^$`.
fn regex_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl fmt::Display for Forge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (OIDC {})", self.host, self.oidc_issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_default_is_public_github() {
        let f = Forge::default();
        assert_eq!(f.host, "github.com");
        assert_eq!(f.oidc_issuer, "https://token.actions.githubusercontent.com");
        assert!(f.is_public_github());
    }

    /// The whole point: an enterprise instance must not inherit github.com's
    /// issuer, or every signature would be checked against the wrong authority.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_enterprise_host_gets_its_own_issuer_not_githubs() {
        let f = Forge::enterprise("ghe.example.com");
        assert_eq!(f.oidc_issuer, "https://ghe.example.com/_services/token");
        assert!(!f.oidc_issuer.contains("githubusercontent"));
        assert!(!f.is_public_github());
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_identity_prefix_follows_the_host() {
        assert_eq!(
            Forge::github_com().identity_prefix("pulseengine/rivet"),
            "https://github.com/pulseengine/rivet/"
        );
        assert_eq!(
            Forge::enterprise("ghe.example.com").identity_prefix("acme/tool"),
            "https://ghe.example.com/acme/tool/"
        );
    }

    fn accepts(f: &Forge, repo: &str, release: &str, identity: &str) -> bool {
        regex::Regex::new(&f.identity_regexp(repo, release))
            .expect("the identity regexp compiles")
            .is_match(identity)
    }

    /// The recorded form (`identity_pattern`) and the enforced form
    /// (`identity_regexp`) are built separately, so they are tied here: a URI
    /// the recorded pattern describes is accepted by the enforced regexp, and
    /// another tag's URI and a branch URI are not.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_recorded_identity_pattern_describes_what_the_regexp_accepts() {
        for f in [Forge::github_com(), Forge::enterprise("ghe.example.com")] {
            let described = f
                .identity_pattern("acme/tool-x", "v1.2.3")
                .replace("[^@]+", "release.yml");
            assert!(
                accepts(&f, "acme/tool-x", "v1.2.3", &described),
                "{described}"
            );
            let other_tag = described.replace("v1.2.3", "v1.2.4");
            assert!(!accepts(&f, "acme/tool-x", "v1.2.3", &other_tag));
            let branch = described.replace("refs/tags/v1.2.3", "refs/heads/main");
            assert!(!accepts(&f, "acme/tool-x", "v1.2.3", &branch));
            let other_repo = described.replace("acme/tool-x", "acme/tool-y");
            assert!(!accepts(&f, "acme/tool-x", "v1.2.3", &other_repo));
        }
    }

    /// A certificate is accepted only when its workflow ran from THIS release's
    /// tag in THIS repository. Same repo and another tag, another repo and the
    /// same tag, and a branch are all refused.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn the_identity_is_pinned_to_the_release_tag_and_the_repository() {
        let f = Forge::github_com();
        let id = |repo: &str, r: &str| {
            format!("https://github.com/{repo}/.github/workflows/release.yml@{r}")
        };
        let ok = id("pulseengine/rivet", "refs/tags/v0.41.1");
        assert!(accepts(&f, "pulseengine/rivet", "v0.41.1", &ok), "same tag");
        // An older release's signature served under a newer tag.
        let older = id("pulseengine/rivet", "refs/tags/v0.41.0");
        assert!(!accepts(&f, "pulseengine/rivet", "v0.41.1", &older));
        // Another repository's workflow at the same tag.
        let other = id("pulseengine/spar", "refs/tags/v0.41.1");
        assert!(!accepts(&f, "pulseengine/rivet", "v0.41.1", &other));
        // A repository that merely starts with the same name.
        let longer = id("pulseengine/rivet-evil", "refs/tags/v0.41.1");
        assert!(!accepts(&f, "pulseengine/rivet", "v0.41.1", &longer));
        // A branch, and a tag that merely begins with the release.
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &id("pulseengine/rivet", "refs/heads/main")
        ));
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &id("pulseengine/rivet", "refs/tags/v0.41.10")
        ));
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &id("pulseengine/rivet", "refs/tags/xv0.41.1")
        ));
        // The dot in the tag is a dot, and the workflow must live under
        // .github/workflows of the repository.
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &id("pulseengine/rivet", "refs/tags/v0x41y1")
        ));
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            "https://github.com/pulseengine/rivet/other/release.yml@refs/tags/v0.41.1"
        ));
        // Another host.
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            "https://github.example.com/pulseengine/rivet/.github/workflows/release.yml@refs/tags/v0.41.1"
        ));
        // Nothing before or after the identity.
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &format!("x{ok}")
        ));
        assert!(!accepts(
            &f,
            "pulseengine/rivet",
            "v0.41.1",
            &format!("{ok}/")
        ));
    }

    /// The tag is DATA: regex metacharacters in it (`+` in build metadata, `.`)
    /// are matched literally.
    // rivet: verifies REQ-INGEST-001
    #[test]
    fn a_release_tag_with_regex_metacharacters_matches_only_itself() {
        let f = Forge::enterprise("ghe.example.com");
        let tag = "v1.0.0+b(1)[x]{2}|a*?^$";
        let ok = format!("https://ghe.example.com/a/b/.github/workflows/r.yml@refs/tags/{tag}");
        assert!(accepts(&f, "a/b", tag, &ok));
        assert!(!accepts(
            &f,
            "a/b",
            tag,
            "https://ghe.example.com/a/b/.github/workflows/r.yml@refs/tags/v1.0.0"
        ));
        // A dot in the HOST or repo is literal too.
        assert!(!accepts(
            &f,
            "a/b",
            "v1",
            "https://gheXexample.com/a/b/.github/workflows/r.yml@refs/tags/v1"
        ));
        assert!(!accepts(
            &f,
            "a.b/c",
            "v1",
            "https://ghe.example.com/aXb/c/.github/workflows/r.yml@refs/tags/v1"
        ));
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn gh_host_selects_the_instance_the_way_gh_does() {
        assert!(Forge::from_env(None, None).is_public_github());
        assert!(Forge::from_env(Some(""), None).is_public_github());
        // `gh` treats the public host case-insensitively; a "GitHub.com" value
        // must not be mistaken for an enterprise instance called GitHub.com.
        assert!(Forge::from_env(Some("GitHub.com"), None).is_public_github());
        assert_eq!(
            Forge::from_env(Some("ghe.example.com"), None).host,
            "ghe.example.com"
        );
    }

    /// An instance whose issuer does not follow the default scheme must be
    /// expressible, because guessing it wrong fails closed but confusingly.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_issuer_can_be_overridden_for_a_nonstandard_instance() {
        let f = Forge::from_env(
            Some("ghe.example.com"),
            Some("https://sso.example.com/oidc"),
        );
        assert_eq!(f.host, "ghe.example.com");
        assert_eq!(f.oidc_issuer, "https://sso.example.com/oidc");
    }

    /// The forge is printed when a run starts, so an operator can see which
    /// instance they are ingesting from before anything is signed. Both halves
    /// have to be there: the host alone does not say which authority verified.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn display_names_the_host_and_the_issuer() {
        let shown = Forge::enterprise("ghe.example.com").to_string();
        assert!(shown.contains("ghe.example.com"), "{shown}");
        assert!(
            shown.contains("https://ghe.example.com/_services/token"),
            "{shown}"
        );
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_trailing_slash_on_the_host_does_not_double_up() {
        let f = Forge::enterprise("ghe.example.com/");
        assert_eq!(f.host, "ghe.example.com");
        assert_eq!(f.oidc_issuer, "https://ghe.example.com/_services/token");
        assert_eq!(f.identity_prefix("a/b"), "https://ghe.example.com/a/b/");
    }
}
