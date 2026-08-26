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

    pub fn is_public_github(&self) -> bool {
        self.host == "github.com"
    }
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
