//! The public-registry source (REQ-REGISTRY-001, REQ-REGISTRY-002, DD-003).
//!
//! Pull over the OCI distribution API: challenge → token → manifest → blobs.
//! On a registry a layer is one OCI artifact manifest whose `layers[]` are
//! the DSSE envelope, the manifest payload, and the tool blobs, each
//! annotated; the tag is the layer name. Tags are mutable and therefore
//! DISCOVERY ONLY — everything this source returns passes the same pipeline
//! (signature against the trust root, payload digest, per-blob digests,
//! anti-rollback) as every other source. The registry decides availability;
//! it has no voice in acceptance.
//!
//! Pull-only by design: publishing happens in CI with standard tooling
//! (`oras push`), which never joins the client trust path.
//!
//! # Speaking the spec, not one registry's dialect (REQ-REGISTRY-002)
//!
//! The client makes the request first and lets the registry say how to
//! authenticate: a 401 carries `WWW-Authenticate: Bearer realm=…,service=…`
//! and the token is fetched from THAT realm. Nothing about the token endpoint
//! is guessed, because every registry puts it somewhere else — and a guessed
//! endpoint fails on public third-party registries too, not only private ones.
//!
//! ## Credential precedence (REQ-REGISTRY-002 clause 2)
//!
//! First match wins; a source that names a credential helper rather than a
//! credential is remembered only so the error can say so:
//!
//! 1. `$VARVE_REGISTRY_AUTH` — `username:password`, applied to the registry
//!    named in the `oci://` reference.
//! 2. `$DOCKER_CONFIG/config.json`
//! 3. `~/.docker/config.json`
//! 4. `$XDG_RUNTIME_DIR/containers/auth.json` (podman)
//!
//! Each file is read for its `auths` object only: the `auth` field is
//! base64 `username:password`, or `username`/`password` may appear directly.
//! varve does NOT execute `credsStore` / `credHelpers` credential helpers.
//! Sourcing a secret by exec'ing a PATH-resolved binary is the exact class of
//! trust REQ-SHADOW-001 exists because PATH does not deserve. Cloud registries
//! (ECR, GCP Artifact Registry, ACR) are therefore reached by handing varve the
//! credential — `VARVE_REGISTRY_AUTH="AWS:$(aws ecr get-login-password …)"` —
//! which is friction, and is the accepted price of running no external binary.
//!
//! The credential is sent as HTTP Basic to the TOKEN endpoint only, never to
//! the registry API, and never across a redirect (see `agent_config`).

use std::cell::{OnceCell, RefCell};
use std::path::PathBuf;

use crate::source::{LayerRef, LayerSource, SourceError};

/// artifactType of a layer artifact manifest on a registry.
pub const LAYER_ARTIFACT_TYPE: &str = "application/vnd.pulseengine.varve.layer.v1+json";
/// Annotation marking the envelope entry in `layers[]`.
pub const ANN_ROLE: &str = "eu.pulseengine.varve.role";
pub const ROLE_ENVELOPE: &str = "envelope";
pub const ROLE_PAYLOAD: &str = "payload";
/// The baseline line-status DSSE envelope carried beside a layer on the
/// registry (REQ-STATUS-DIST-001), so `varve status` works after an
/// `oci://` install with no local layout.
pub const ROLE_LINE_STATUS: &str = "line-status";
/// The realm's signed line-index envelope (REQ-INDEXAUTH-001), carried under
/// its own per-line tag rather than beside a layer: the index has to be
/// obtainable when the layer a consumer wants is precisely the one being
/// withheld, so it must not be reachable only THROUGH a layer.
pub const ROLE_LINE_INDEX: &str = "line-index";
/// A carried attestation's signed STATEMENT (REQ-ATTEST-002). Many per layer,
/// unlike line-status which is one per line — so these are found by scanning
/// all layers, not by taking the first match.
pub const ROLE_ATTESTATION_STATEMENT: &str = "attestation-statement";
/// The attested bytes travelling verbatim beside a statement. Linked back to
/// its statement by the `eu.pulseengine.varve.attests` annotation, so a layer
/// carrying several attestations cannot mix up which evidence belongs to which
/// claim.
pub const ROLE_ATTESTATION_BYTES: &str = "attestation-bytes";

/// Environment variable carrying `username:password` for the registry named
/// in the reference. The one credential route that runs no external binary.
pub const CREDENTIAL_ENV: &str = "VARVE_REGISTRY_AUTH";

/// Manifest media types varve will accept (REQ-REGISTRY-002 clause 4).
/// Offering only the OCI type makes every registry that serves the Docker
/// schema-2 type unreachable, which is most of the older estate.
pub const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

/// Tags requested per `/tags/list` page.
const TAGS_PAGE_SIZE: u32 = 100;
/// Hard bound on pages followed. A registry that keeps handing out
/// `Link: rel="next"` forever must stop the client, not spin it — and the
/// stop is an ERROR, never a short list, because a short list is precisely
/// the failure mode this bound exists to make impossible (varve#70).
const MAX_TAG_PAGES: usize = 64;

/// Tool binaries are tens of MB; ureq's 10 MiB default would reject them
/// (caught on the first real GHCR pull). 8 GiB is a sanity bound, not a
/// promise — digests still decide.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// A token response is JSON with one field. Nothing legitimate is large.
const MAX_TOKEN_BYTES: u64 = 1024 * 1024;

/// The digest of the first layer in an OCI artifact manifest carrying the
/// given `eu.pulseengine.varve.role` annotation, if present. Pure — the
/// unit-testable heart of registry blob discovery.
/// The tags of a repository that name layers of one line — what a registry is
/// willing to SERVE for that line, which is what omission is measured against
/// (REQ-INDEXAUTH-001 clause 3). Pure, so the filter is unit-testable: the
/// mutation gate runs `--lib`, and an over-eager filter here would report a
/// served layer as hidden and accuse an honest registry of tampering.
///
/// A tag that is not a canonical `YYYY.MM.P` cannot be a layer this line
/// contains — a signed index names layers by that grammar and nothing else —
/// so junk tags, other lines' layers, and the `line-index-*` tag carrying the
/// index itself are all excluded rather than reported as extra layers.
fn layers_of_line(tags: Vec<String>, line: &str) -> Vec<String> {
    tags.into_iter()
        .filter(|tag| {
            tag.parse::<crate::layer::LayerId>()
                .is_ok_and(|id| id.line().to_string() == line)
        })
        .collect()
}

fn layer_digest_for_role(manifest: &serde_json::Value, role: &str) -> Option<String> {
    manifest["layers"]
        .as_array()?
        .iter()
        .find(|l| l["annotations"][ANN_ROLE] == role)
        .and_then(|l| l["digest"].as_str())
        .map(str::to_string)
}

// ───────────────────────────── base64 ─────────────────────────────
// Hand-rolled rather than pulled in as a dependency: it is forty lines, it
// is on the credential path, and a dependency there is a dependency that can
// read secrets. Both directions are unit-tested and round-tripped.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64, tolerating absent padding and embedded newlines —
/// both occur in hand-edited docker configs. Any other stray byte is a
/// refusal, not a silent skip.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = ((acc << 6) | v) & 0x3_FFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ─────────────────────────── credentials ───────────────────────────

/// A username/password pair for one registry. Never `Debug`-printed in the
/// clear: `RegistrySource` derives `Debug`, and a derived `Debug` on a
/// credential is how secrets reach panic messages and logs.
#[derive(Clone, PartialEq, Eq)]
struct Credential {
    username: String,
    password: String,
    /// Human-readable provenance for error messages — a path or an env var
    /// NAME. Never the value.
    origin: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("origin", &self.origin)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credential {
    fn basic_header(&self) -> String {
        format!(
            "Basic {}",
            base64_encode(format!("{}:{}", self.username, self.password).as_bytes())
        )
    }
}

/// What a credential source had to say. The non-`Found` variants exist so a
/// 401 can explain WHICH kind of nothing varve had (REQ-REGISTRY-002
/// clause 5) instead of collapsing every case into a confusing downstream
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialLookup {
    Found(Credential),
    /// The config delegates this registry to a credential helper. varve does
    /// not execute it; the name travels only into the advice text.
    HelperOnly {
        helper: String,
        origin: String,
    },
    /// A credential was configured but cannot be read as one.
    Malformed {
        origin: String,
    },
    Absent,
}

/// Fold the configured sources in precedence order: the first usable
/// credential wins; failing that, the first source that had something to say
/// is kept so the error can say it.
fn first_usable(lookups: Vec<CredentialLookup>) -> CredentialLookup {
    let mut explanation = CredentialLookup::Absent;
    for lookup in lookups {
        match lookup {
            CredentialLookup::Found(_) => return lookup,
            CredentialLookup::Absent => {}
            other => {
                if matches!(explanation, CredentialLookup::Absent) {
                    explanation = other;
                }
            }
        }
    }
    explanation
}

/// `username:password` out of the environment variable's value.
fn credential_from_env_value(value: &str) -> CredentialLookup {
    let origin = format!("${CREDENTIAL_ENV}");
    // `$(aws ecr get-login-password)` and friends routinely arrive with a
    // trailing newline. Only line endings are trimmed — trimming spaces
    // would corrupt a password that legitimately ends in one.
    let value = value.trim_end_matches(['\n', '\r']);
    if value.is_empty() {
        return CredentialLookup::Absent;
    }
    match value.split_once(':') {
        Some((username, password)) if !username.is_empty() => CredentialLookup::Found(Credential {
            username: username.to_string(),
            password: password.to_string(),
            origin,
        }),
        _ => CredentialLookup::Malformed { origin },
    }
}

/// Decode a docker config `auth` field (base64 `username:password`).
fn decode_basic_auth(encoded: &str) -> Option<(String, String)> {
    let decoded = base64_decode(encoded.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    if username.is_empty() {
        return None;
    }
    Some((username.to_string(), password.to_string()))
}

/// Do a docker-config `auths` key and a registry host name refer to the same
/// registry? Keys are written with and without a scheme and with and without
/// a trailing path, and Docker Hub is spelled three different ways.
fn registry_key_matches(key: &str, registry: &str) -> bool {
    fn host(s: &str) -> String {
        let s = s
            .strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .unwrap_or(s);
        s.split('/').next().unwrap_or(s).to_ascii_lowercase()
    }
    const HUB: [&str; 3] = ["docker.io", "index.docker.io", "registry-1.docker.io"];
    let (key, registry) = (host(key), host(registry));
    key == registry || (HUB.contains(&key.as_str()) && HUB.contains(&registry.as_str()))
}

/// Read one docker/podman config for this registry. Pure over the parsed
/// JSON so the whole matrix — `auth`, plaintext `username`/`password`,
/// `credHelpers`, `credsStore`, absence — is unit-testable.
fn credential_from_docker_config(
    config: &serde_json::Value,
    registry: &str,
    origin: &str,
) -> CredentialLookup {
    if let Some(auths) = config["auths"].as_object()
        && let Some((_, entry)) = auths
            .iter()
            .find(|(k, _)| registry_key_matches(k, registry))
    {
        if let Some(auth) = entry["auth"].as_str().filter(|a| !a.is_empty()) {
            return match decode_basic_auth(auth) {
                Some((username, password)) => CredentialLookup::Found(Credential {
                    username,
                    password,
                    origin: origin.to_string(),
                }),
                None => CredentialLookup::Malformed {
                    origin: origin.to_string(),
                },
            };
        }
        if let (Some(username), Some(password)) =
            (entry["username"].as_str(), entry["password"].as_str())
            && !username.is_empty()
        {
            return CredentialLookup::Found(Credential {
                username: username.to_string(),
                password: password.to_string(),
                origin: origin.to_string(),
            });
        }
    }
    // No credential here — but the config may still explain where the user
    // thinks it is. varve will not run the helper; it will name it.
    if let Some(helpers) = config["credHelpers"].as_object()
        && let Some((_, helper)) = helpers
            .iter()
            .find(|(k, _)| registry_key_matches(k, registry))
        && let Some(helper) = helper.as_str().filter(|h| !h.is_empty())
    {
        return CredentialLookup::HelperOnly {
            helper: helper.to_string(),
            origin: origin.to_string(),
        };
    }
    if let Some(store) = config["credsStore"].as_str().filter(|s| !s.is_empty()) {
        return CredentialLookup::HelperOnly {
            helper: store.to_string(),
            origin: origin.to_string(),
        };
    }
    CredentialLookup::Absent
}

/// The config files consulted, in precedence order.
fn credential_config_paths() -> Vec<PathBuf> {
    let dir = |var: &str, tail: &str| -> Option<PathBuf> {
        let value = std::env::var(var).ok()?;
        if value.is_empty() {
            return None;
        }
        Some(PathBuf::from(value).join(tail))
    };
    [
        dir("DOCKER_CONFIG", "config.json"),
        dir("HOME", ".docker/config.json"),
        dir("XDG_RUNTIME_DIR", "containers/auth.json"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Read each path that exists and parses, in order. An unreadable or
/// unparseable config contributes nothing rather than failing the pull —
/// a broken docker config must not stop an anonymous install.
fn lookups_from_paths(paths: &[PathBuf], registry: &str) -> Vec<CredentialLookup> {
    paths
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let json = serde_json::from_str::<serde_json::Value>(&text).ok()?;
            Some(credential_from_docker_config(
                &json,
                registry,
                &path.display().to_string(),
            ))
        })
        .collect()
}

fn resolve_credential(registry: &str) -> CredentialLookup {
    let mut lookups = Vec::new();
    if let Ok(value) = std::env::var(CREDENTIAL_ENV) {
        lookups.push(credential_from_env_value(&value));
    }
    lookups.extend(lookups_from_paths(&credential_config_paths(), registry));
    first_usable(lookups)
}

/// What to tell the user when a registry refuses. Distinguishes "varve had
/// no credential" from "varve had one and it was refused" and names the fix
/// (REQ-REGISTRY-002 clause 5). Never contains the secret — only its origin.
fn credential_advice(lookup: &CredentialLookup, registry: &str, repository: &str) -> String {
    match lookup {
        CredentialLookup::Found(credential) => format!(
            "varve sent the credential from {} and the registry rejected it. Check that the \
             username is right and that it may pull {repository}.",
            credential.origin
        ),
        CredentialLookup::HelperOnly { helper, origin } => format!(
            "varve offered no credential: {origin} delegates {registry} to the credential helper \
             '{helper}', and varve does not execute credential helpers — sourcing a secret by \
             running a PATH-resolved binary is exactly the trust varve refuses (REQ-SHADOW-001). \
             Supply it directly instead: {CREDENTIAL_ENV}='<username>:<password>' (for ECR: \
             {CREDENTIAL_ENV}=\"AWS:$(aws ecr get-login-password --region <region>)\")."
        ),
        CredentialLookup::Malformed { origin } => format!(
            "varve offered no credential: {origin} is set but is not a `username:password` pair. \
             (varve does not log the value.)"
        ),
        CredentialLookup::Absent => format!(
            "varve offered no credential: set {CREDENTIAL_ENV}='<username>:<password>', or \
             `docker login {registry}` so the credential lands in the `auths` section of \
             ~/.docker/config.json — varve reads `auths`, and does not run credential helpers."
        ),
    }
}

// ──────────────────── WWW-Authenticate / token realm ────────────────────

/// The parts of a `WWW-Authenticate: Bearer …` challenge varve uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BearerChallenge {
    realm: Option<String>,
    service: Option<String>,
    scope: Option<String>,
}

/// Parse a Bearer challenge. Quoted values are honoured verbatim, which
/// matters: a scope is `repository:name:pull,push` and splitting the header
/// on commas would truncate it.
fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let header = header.trim();
    let (scheme, params) = match header.split_once(char::is_whitespace) {
        Some((scheme, params)) => (scheme, params),
        None => (header, ""),
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let chars: Vec<char> = params.chars().collect();
    let mut challenge = BearerChallenge::default();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && (chars[i] == ',' || chars[i].is_whitespace()) {
            i += 1;
        }
        let key_start = i;
        while i < chars.len() && chars[i] != '=' && chars[i] != ',' {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            break;
        }
        let key = chars[key_start..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_ascii_lowercase();
        i += 1;
        let value = if chars.get(i) == Some(&'"') {
            i += 1;
            let mut value = String::new();
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    value.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                value.push(chars[i]);
                i += 1;
            }
            value
        } else {
            let value_start = i;
            while i < chars.len() && chars[i] != ',' {
                i += 1;
            }
            chars[value_start..i]
                .iter()
                .collect::<String>()
                .trim()
                .to_string()
        };
        match key.as_str() {
            "realm" => challenge.realm = Some(value),
            "service" => challenge.service = Some(value),
            "scope" => challenge.scope = Some(value),
            _ => {}
        }
    }
    Some(challenge)
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The token URL the CHALLENGE names — never a guessed path. `default_scope`
/// covers registries that challenge without naming one.
fn token_url(challenge: &BearerChallenge, default_scope: &str) -> Option<String> {
    let realm = challenge.realm.as_deref()?.trim();
    if realm.is_empty() {
        return None;
    }
    let mut query = Vec::new();
    if let Some(service) = challenge.service.as_deref().filter(|s| !s.is_empty()) {
        query.push(format!("service={}", percent_encode(service)));
    }
    let scope = challenge
        .scope
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_scope);
    query.push(format!("scope={}", percent_encode(scope)));
    // Realms carry their own query string in the wild (GitLab's does).
    let separator = if realm.contains('?') { '&' } else { '?' };
    Some(format!("{realm}{separator}{}", query.join("&")))
}

/// May varve send a credential to this realm? The realm host CANNOT be
/// constrained — a different host is normal and correct (auth.docker.io for
/// registry-1.docker.io, gitlab.com/jwt/auth for registry.gitlab.com). The
/// SCHEME can: an https registry must not be able to talk varve into posting
/// a Basic credential over cleartext.
fn realm_is_acceptable(realm: &str, reference_scheme: &str) -> bool {
    if reference_scheme == "https" {
        realm.starts_with("https://")
    } else {
        realm.starts_with("http://") || realm.starts_with("https://")
    }
}

fn token_from_body(body: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    // `token` is the distribution spec's field; `access_token` is the OAuth2
    // spelling several registries answer with instead.
    json["token"]
        .as_str()
        .or_else(|| json["access_token"].as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

// ───────────────────────── tags/list pagination ─────────────────────────

/// The scheme+authority of a URL, for same-origin comparison.
fn origin_of(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after = &url[scheme_end + 3..];
    let authority_end = after.find('/').unwrap_or(after.len());
    Some(url[..scheme_end + 3 + authority_end].to_ascii_lowercase())
}

/// Resolve a `Link` target against the page it came from, refusing anything
/// that leaves the origin. A registry that could point `rel="next"` at
/// another host could harvest the bearer token varve is carrying.
fn resolve_next_url(base: &str, target: &str) -> Option<String> {
    let origin = origin_of(base)?;
    let absolute = if target.contains("://") {
        target.to_string()
    } else if let Some(path) = target.strip_prefix('/') {
        format!("{origin}/{path}")
    } else {
        let path_base = base.split(['?', '#']).next().unwrap_or(base);
        let cut = path_base.rfind('/')?;
        format!("{}/{target}", &path_base[..cut])
    };
    (origin_of(&absolute)? == origin).then_some(absolute)
}

/// The `rel="next"` target of a `Link` header, if any. Commas inside the
/// angle brackets belong to the URL, not to the header's list syntax.
fn parse_link_next(link: &str, current: &str) -> Option<String> {
    let mut segments = Vec::new();
    let mut current_segment = String::new();
    let mut depth = 0i32;
    for c in link.chars() {
        match c {
            '<' => {
                depth += 1;
                current_segment.push(c);
            }
            '>' => {
                depth -= 1;
                current_segment.push(c);
            }
            ',' if depth == 0 => segments.push(std::mem::take(&mut current_segment)),
            _ => current_segment.push(c),
        }
    }
    segments.push(current_segment);
    for segment in segments {
        let segment = segment.trim();
        let Some(open) = segment.find('<') else {
            continue;
        };
        let Some(close) = segment[open..].find('>').map(|i| open + i) else {
            continue;
        };
        let is_next = segment[close + 1..].split(';').any(|param| {
            param
                .split_once('=')
                .is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("rel") && rel_is_next(v))
        });
        if is_next {
            return resolve_next_url(current, segment[open + 1..close].trim());
        }
    }
    None
}

/// `rel="next"`, `rel=next`, and `rel="prev next"` all mean next.
fn rel_is_next(value: &str) -> bool {
    value
        .trim()
        .trim_matches('"')
        .split_whitespace()
        .any(|r| r.eq_ignore_ascii_case("next"))
}

/// The first `/tags/list` page URL. `?n=` is what makes a registry paginate
/// at all — without it many serve one implementation-defined page and the
/// client never learns there was more.
fn tags_first_page_url(base: &str) -> String {
    format!("{base}/tags/list?n={TAGS_PAGE_SIZE}")
}

/// The tags on one `/tags/list` page. `tags: null` is spec-legal and means
/// an empty page; anything that is not JSON is a transport failure, not an
/// empty repository.
fn tags_from_page(bytes: &[u8]) -> Result<Vec<String>, SourceError> {
    let json: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| SourceError::Transport(format!("tags/list: {e}")))?;
    Ok(json["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

// ───────────────────────────── the source ─────────────────────────────

/// An `oci://` reference: registry host + repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRef {
    pub registry: String,
    pub repository: String,
    /// http for the test double, https everywhere real. Never configurable
    /// from a pin — parsed from the explicit `--from` reference only.
    pub scheme: String,
}

impl RegistryRef {
    /// Parse `oci://ghcr.io/org/repo` (https) or `oci+http://host:port/repo`
    /// (test double / air-gapped mirror on a trusted network — acceptance is
    /// unaffected either way; transport privacy is not what the trust model
    /// rests on).
    pub fn parse(reference: &str) -> Result<Self, SourceError> {
        let (scheme, rest) = if let Some(rest) = reference.strip_prefix("oci://") {
            ("https", rest)
        } else if let Some(rest) = reference.strip_prefix("oci+http://") {
            ("http", rest)
        } else {
            return Err(SourceError::Transport(format!(
                "'{reference}' is not an oci:// reference"
            )));
        };
        let (registry, repository) = rest.split_once('/').ok_or_else(|| {
            SourceError::Transport(format!("'{reference}' has no repository path"))
        })?;
        if registry.is_empty() || repository.is_empty() {
            return Err(SourceError::Transport(format!(
                "'{reference}' has an empty registry or repository"
            )));
        }
        Ok(RegistryRef {
            registry: registry.to_string(),
            repository: repository.trim_end_matches('/').to_string(),
            scheme: scheme.to_string(),
        })
    }
}

/// The HTTP client configuration varve pulls with.
///
/// `redirect_auth_headers(Never)` is the load-bearing setting
/// (REQ-REGISTRY-002 clause 6): blob fetches redirect to CDNs, and a client
/// that carries `Authorization` across that redirect hands the registry
/// credential to a third party. `Never` is stricter than the requirement's
/// "not to a DIFFERENT host" — ureq offers only `Never` and `SameHost`, and
/// distribution-spec redirect targets carry their own credentials in the URL,
/// so the strict setting costs nothing. It is also ureq's current default;
/// stating it explicitly means a change of that default cannot silently
/// change varve's behaviour, and the unit test below fails if it does.
///
/// `http_status_as_error(false)` is required for clause 1: ureq's default
/// turns a 401 into an `Err` with the response — and therefore the
/// `WWW-Authenticate` challenge — discarded.
fn agent_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .http_status_as_error(false)
        .build()
}

/// One HTTP response, reduced to what the client reasons about.
struct Fetched {
    status: u16,
    bytes: Vec<u8>,
    link: Option<String>,
    challenge: Option<String>,
}

/// Pull-only OCI distribution client implementing `LayerSource`.
pub struct RegistrySource {
    reference: RegistryRef,
    agent: ureq::Agent,
    /// The bearer token the realm issued. A short-lived credential is still a
    /// credential — never derived into `Debug`.
    token: RefCell<Option<String>>,
    /// Resolved lazily: an anonymous pull from a public registry must not
    /// read the user's docker config at all.
    credential: OnceCell<CredentialLookup>,
}

impl std::fmt::Debug for RegistrySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrySource")
            .field("reference", &self.reference)
            .field(
                "token",
                &self
                    .token
                    .borrow()
                    .as_ref()
                    .map(|_| "<redacted bearer token>"),
            )
            .field("credential", &self.credential)
            .finish()
    }
}

impl RegistrySource {
    pub fn new(reference: RegistryRef) -> Self {
        RegistrySource {
            reference,
            agent: ureq::Agent::new_with_config(agent_config()),
            token: RefCell::new(None),
            credential: OnceCell::new(),
        }
    }

    pub fn parse(reference: &str) -> Result<Self, SourceError> {
        Ok(Self::new(RegistryRef::parse(reference)?))
    }

    /// Use this credential instead of consulting the environment. Sent as
    /// HTTP Basic to the token realm only.
    pub fn with_credential(self, username: &str, password: &str) -> Self {
        let _ = self.credential.set(CredentialLookup::Found(Credential {
            username: username.to_string(),
            password: password.to_string(),
            origin: "the credential supplied to RegistrySource::with_credential".to_string(),
        }));
        self
    }

    fn credential(&self) -> &CredentialLookup {
        self.credential
            .get_or_init(|| resolve_credential(&self.reference.registry))
    }

    fn base(&self) -> String {
        format!(
            "{}://{}/v2/{}",
            self.reference.scheme, self.reference.registry, self.reference.repository
        )
    }

    fn send(&self, url: &str, accept: &str, token: Option<&str>) -> Result<Fetched, SourceError> {
        let mut request = self.agent.get(url).header("Accept", accept);
        if let Some(token) = token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = request
            .call()
            .map_err(|e| SourceError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let link = header("link");
        let challenge = header("www-authenticate");
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_vec()
            .map_err(|e| SourceError::Transport(e.to_string()))?;
        Ok(Fetched {
            status,
            bytes,
            link,
            challenge,
        })
    }

    /// Ask the realm the CHALLENGE names for a token, sending the resolved
    /// credential as Basic if there is one.
    fn obtain_token(&self, challenge: &BearerChallenge) -> Result<String, SourceError> {
        let default_scope = format!("repository:{}:pull", self.reference.repository);
        let url = token_url(challenge, &default_scope).ok_or_else(|| {
            SourceError::Transport(format!(
                "{} demanded authentication but its WWW-Authenticate challenge names no realm, \
                 so varve has no token endpoint to ask",
                self.reference.registry
            ))
        })?;
        if !realm_is_acceptable(&url, &self.reference.scheme) {
            return Err(SourceError::Transport(format!(
                "{} is an https registry but points its token realm at {url}; varve will not \
                 send a credential over cleartext",
                self.reference.registry
            )));
        }
        let mut request = self.agent.get(&url).header("Accept", "application/json");
        if let CredentialLookup::Found(credential) = self.credential() {
            request = request.header("Authorization", &credential.basic_header());
        }
        let mut response = request
            .call()
            .map_err(|e| SourceError::Transport(format!("token request to {url} failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(self.auth_error(&format!("the token endpoint {url}"), status));
        }
        if !(200..300).contains(&status) {
            return Err(SourceError::Transport(format!(
                "token endpoint {url} returned HTTP {status}"
            )));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_TOKEN_BYTES)
            .read_to_string()
            .map_err(|e| SourceError::Transport(format!("token response: {e}")))?;
        token_from_body(&body).ok_or_else(|| {
            SourceError::Transport(format!(
                "token endpoint {url} answered HTTP {status} with no `token` field"
            ))
        })
    }

    /// A refusal, said out loud with the fix (clause 5) and never with the
    /// secret.
    fn auth_error(&self, what: &str, status: u16) -> SourceError {
        SourceError::Transport(format!(
            "{} refused access to {} at {what} (HTTP {status}). {}",
            self.reference.registry,
            self.reference.repository,
            credential_advice(
                self.credential(),
                &self.reference.registry,
                &self.reference.repository
            )
        ))
    }

    /// One GET, authenticating on demand: make the request, and if the
    /// registry answers 401, take the token endpoint from ITS challenge
    /// (REQ-REGISTRY-002 clause 1) rather than guessing a path.
    fn fetch(&self, url: &str, accept: &str) -> Result<Fetched, SourceError> {
        let cached = self.token.borrow().clone();
        let first = self.send(url, accept, cached.as_deref())?;
        if first.status != 401 {
            return Ok(first);
        }
        let challenge = first
            .challenge
            .as_deref()
            .and_then(parse_bearer_challenge)
            .ok_or_else(|| {
                SourceError::Transport(format!(
                    "{} answered HTTP 401 for {url} with no Bearer challenge varve could parse \
                     ({}), so there is no token endpoint to ask. {}",
                    self.reference.registry,
                    match &first.challenge {
                        Some(header) => format!("WWW-Authenticate: {header}"),
                        None => "no WWW-Authenticate header".to_string(),
                    },
                    credential_advice(
                        self.credential(),
                        &self.reference.registry,
                        &self.reference.repository
                    )
                ))
            })?;
        let token = self.obtain_token(&challenge)?;
        *self.token.borrow_mut() = Some(token.clone());
        let second = self.send(url, accept, Some(&token))?;
        if second.status == 401 {
            return Err(self.auth_error(url, second.status));
        }
        Ok(second)
    }

    /// `fetch` plus status interpretation: 404 is honest absence, every
    /// other non-2xx is transport trouble said out loud.
    fn get_checked(&self, url: &str, accept: &str) -> Result<Fetched, SourceError> {
        let fetched = self.fetch(url, accept)?;
        match fetched.status {
            200..=299 => Ok(fetched),
            404 => Err(SourceError::NotFound(url.to_string())),
            status => Err(SourceError::Transport(format!(
                "{url} returned HTTP {status}"
            ))),
        }
    }

    fn get(&self, url: &str, accept: &str) -> Result<Vec<u8>, SourceError> {
        Ok(self.get_checked(url, accept)?.bytes)
    }

    /// Fetch the OCI artifact manifest for a tag. Untrusted discovery: the
    /// pipeline re-verifies whatever blobs this points at.
    fn artifact_manifest_for_tag(&self, tag: &str) -> Result<serde_json::Value, SourceError> {
        let manifest_bytes =
            self.get(&format!("{}/manifests/{tag}", self.base()), MANIFEST_ACCEPT)?;
        serde_json::from_slice(&manifest_bytes)
            .map_err(|e| SourceError::Transport(format!("artifact manifest: {e}")))
    }

    /// The envelope blob a tag's artifact manifest references.
    fn envelope_for_tag(&self, tag: &str) -> Result<Vec<u8>, SourceError> {
        let manifest = self.artifact_manifest_for_tag(tag)?;
        let envelope_digest = layer_digest_for_role(&manifest, ROLE_ENVELOPE).ok_or_else(|| {
            SourceError::NotFound(format!("tag {tag} carries no varve envelope layer"))
        })?;
        self.fetch_blob(&envelope_digest)
    }

    /// The baseline line-status blob a tag's artifact manifest references,
    /// if any (REQ-STATUS-DIST-001). Absence is `Ok(None)`, not an error.
    fn line_status_for_tag(&self, tag: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let manifest = self.artifact_manifest_for_tag(tag)?;
        match layer_digest_for_role(&manifest, ROLE_LINE_STATUS) {
            Some(digest) => self.fetch_blob(&digest).map(Some),
            None => Ok(None),
        }
    }

    /// The realm's signed line-index envelope for a line, if this registry
    /// carries one (REQ-INDEXAUTH-001 clause 1). Absence — no such tag, or a
    /// tag carrying no index layer — is `Ok(None)`, never an error: whether
    /// absence is tolerable is the REALM's call (clause 5), settled in
    /// `lineindex::check`, and a registry must not get to decide it by
    /// answering 404. Opaque, untrusted bytes: the caller verifies them
    /// against the realm's root, and the registry is the party they constrain.
    fn line_index_for_tag(&self, tag: &str) -> Result<Option<Vec<u8>>, SourceError> {
        let manifest = match self.artifact_manifest_for_tag(tag) {
            Ok(manifest) => manifest,
            Err(SourceError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        match layer_digest_for_role(&manifest, ROLE_LINE_INDEX) {
            Some(digest) => self.fetch_blob(&digest).map(Some),
            None => Ok(None),
        }
    }

    /// Every attestation a tag's artifact manifest references
    /// (REQ-ATTEST-002). A statement whose bytes are absent from the manifest
    /// is an ERROR, not a skipped entry: evidence that did not travel is the
    /// thing this requirement exists to detect, and dropping it here would
    /// reproduce the mirror-boundary bug inside the code meant to catch it.
    fn attestations_for_tag(
        &self,
        tag: &str,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        let manifest = self.artifact_manifest_for_tag(tag)?;
        let Some(layers) = manifest["layers"].as_array() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for l in layers
            .iter()
            .filter(|l| l["annotations"][ANN_ROLE] == ROLE_ATTESTATION_STATEMENT)
        {
            let Some(st_digest) = l["digest"].as_str() else {
                continue;
            };
            let bytes_digest = layers
                .iter()
                .find(|b| {
                    b["annotations"][ANN_ROLE] == ROLE_ATTESTATION_BYTES
                        && b["annotations"][crate::attestcarry::ANN_STATEMENT] == *st_digest
                })
                .and_then(|b| b["digest"].as_str())
                .ok_or_else(|| {
                    SourceError::NotFound(format!(
                        "tag {tag} carries attestation statement {st_digest} but the manifest \
                         references no bytes for it — the claim travelled and the evidence \
                         did not"
                    ))
                })?;
            out.push(crate::attestcarry::CarriedAttestation {
                statement_digest: st_digest.to_string(),
                statement: self.fetch_blob(st_digest)?,
                bytes: self.fetch_blob(bytes_digest)?,
            });
        }
        // Deterministic, matching the layout and store readers — a report that
        // reshuffles between transports is a diff generator for anyone
        // recording verify output as evidence.
        out.sort_by(|a, b| a.statement_digest.cmp(&b.statement_digest));
        Ok(out)
    }

    /// Every tag in the repository, following `Link: rel="next"` to the end
    /// (REQ-REGISTRY-002 clause 3, varve#70).
    ///
    /// Three digest-pin paths enumerate tags. A truncated list does not
    /// merely lose tags — it makes a digest pin, a status baseline and the
    /// carried attestations all come back EMPTY, which is indistinguishable
    /// from legitimate absence. So exhaustion is the only acceptable outcome
    /// besides an error: running out of pages raises, it never returns short.
    fn tags(&self) -> Result<Vec<String>, SourceError> {
        let mut url = tags_first_page_url(&self.base());
        let mut out = Vec::new();
        for _ in 0..MAX_TAG_PAGES {
            let page = self.get_checked(&url, "application/json")?;
            out.extend(tags_from_page(&page.bytes)?);
            let next = page
                .link
                .as_deref()
                .and_then(|link| parse_link_next(link, &url));
            let Some(next) = next else {
                return Ok(out);
            };
            if next == url {
                return Err(SourceError::Transport(format!(
                    "{url} answered with a Link rel=\"next\" pointing at the page it came from; \
                     refusing to loop"
                )));
            }
            url = next;
        }
        Err(SourceError::Transport(format!(
            "{}/tags/list was still handing out `Link: rel=\"next\"` after {MAX_TAG_PAGES} pages. \
             varve stops rather than looping, and refuses to answer from a partial tag list — a \
             short list would silently turn a digest pin into 'not found'.",
            self.base()
        )))
    }
}

impl LayerSource for RegistrySource {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        match layer {
            LayerRef::Name(id) => self.envelope_for_tag(&id.to_string()),
            LayerRef::Digest(digest) => {
                // A pin's digest names the PAYLOAD, not any registry object;
                // tags are enumerated and each candidate's payload digest
                // compared. Discovery only — verification decides.
                for tag in self.tags()? {
                    if let Ok(envelope) = self.envelope_for_tag(&tag)
                        && let Ok(text) = std::str::from_utf8(&envelope)
                        && let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text)
                        && let Ok(payload) = env.payload_bytes()
                        && &crate::store::manifest_digest(&payload) == digest
                    {
                        return Ok(envelope);
                    }
                }
                Err(SourceError::NotFound(digest.clone()))
            }
        }
    }

    fn fetch_line_status(&self, layer: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
        // Resolve the tag whose artifact manifest carries the baseline.
        // A named pin maps straight to its tag; a digest pin is located by
        // the same tag scan fetch_manifest uses.
        match layer {
            LayerRef::Name(id) => self.line_status_for_tag(&id.to_string()),
            LayerRef::Digest(digest) => {
                for tag in self.tags()? {
                    if let Ok(envelope) = self.envelope_for_tag(&tag)
                        && let Ok(text) = std::str::from_utf8(&envelope)
                        && let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text)
                        && let Ok(payload) = env.payload_bytes()
                        && &crate::store::manifest_digest(&payload) == digest
                    {
                        return self.line_status_for_tag(&tag);
                    }
                }
                Ok(None)
            }
        }
    }

    fn fetch_line_index(&self, line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        self.line_index_for_tag(&crate::lineindex::index_tag(line))
    }

    fn served_layers(&self, line: &str) -> Result<Option<Vec<String>>, SourceError> {
        // A registry CAN enumerate, so it answers `Some(..)` — including
        // `Some(vec![])` when it serves nothing of this line, which against a
        // signed index means it is hiding everything. `None` here would mean
        // "cannot enumerate" and would switch clause 3 off for every registry.
        //
        // `tags()` raises rather than returning a short list, and that is
        // load-bearing here: a truncated page would look like a registry that
        // legitimately serves fewer layers, so omission detection would report
        // a hidden layer that is not hidden — or, worse, a hostile registry
        // could truncate its way to any listing it liked.
        Ok(Some(layers_of_line(self.tags()?, line)))
    }

    fn fetch_attestations(
        &self,
        layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        // Same tag resolution as the baseline: a named pin maps to its tag, a
        // digest pin is located by the tag scan. Untrusted bytes throughout —
        // the caller re-verifies every statement against the trust root, and
        // the registry is precisely the party this evidence constrains.
        match layer {
            LayerRef::Name(id) => self.attestations_for_tag(&id.to_string()),
            LayerRef::Digest(digest) => {
                for tag in self.tags()? {
                    if let Ok(envelope) = self.envelope_for_tag(&tag)
                        && let Ok(text) = std::str::from_utf8(&envelope)
                        && let Ok(env) = wsc::dsse::DsseEnvelope::from_json(text)
                        && let Ok(payload) = env.payload_bytes()
                        && &crate::store::manifest_digest(&payload) == digest
                    {
                        return self.attestations_for_tag(&tag);
                    }
                }
                Ok(Vec::new())
            }
        }
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        let bytes = self.get(
            &format!("{}/blobs/{digest}", self.base()),
            "application/octet-stream",
        )?;
        // Transport-level integrity: a registry answering a digest request
        // with other bytes is broken or hostile either way. The pipeline
        // re-checks against the SIGNED digests; this check just fails fast.
        if crate::store::manifest_digest(&bytes) != digest {
            return Err(SourceError::Transport(format!(
                "registry returned wrong bytes for {digest}"
            )));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-do-not-log";

    // rivet: verifies REQ-REGISTRY-001
    #[test]
    fn oci_references_parse_and_bad_ones_are_refused() {
        let r = RegistryRef::parse("oci://ghcr.io/pulseengine/layers").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "pulseengine/layers");
        assert_eq!(r.scheme, "https");
        let t = RegistryRef::parse("oci+http://127.0.0.1:5000/test/repo").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.registry, "127.0.0.1:5000");
        for bad in [
            "https://ghcr.io/x",
            "oci://",
            "oci://hostonly",
            "oci://host/",
        ] {
            assert!(RegistryRef::parse(bad).is_err(), "{bad} must not parse");
        }
    }

    // rivet: verifies REQ-STATUS-DIST-001
    #[test]
    fn a_role_annotated_layer_digest_is_found_and_absence_is_none() {
        let manifest = serde_json::json!({
            "layers": [
                {"digest": "sha256:aaa", "annotations": {ANN_ROLE: ROLE_ENVELOPE}},
                {"digest": "sha256:bbb", "annotations": {ANN_ROLE: ROLE_PAYLOAD}},
                {"digest": "sha256:ccc", "annotations": {ANN_ROLE: ROLE_LINE_STATUS}},
            ]
        });
        assert_eq!(
            layer_digest_for_role(&manifest, ROLE_LINE_STATUS),
            Some("sha256:ccc".to_string()),
            "the baseline line-status layer must be found by its role"
        );
        assert_eq!(
            layer_digest_for_role(&manifest, ROLE_ENVELOPE),
            Some("sha256:aaa".to_string())
        );
        // A manifest with no line-status layer yields None, not an error.
        let bare = serde_json::json!({
            "layers": [{"digest": "sha256:aaa", "annotations": {ANN_ROLE: ROLE_ENVELOPE}}]
        });
        assert_eq!(layer_digest_for_role(&bare, ROLE_LINE_STATUS), None);
        // Each signed document has its OWN role. Sharing one would let the
        // line-status blob be handed over where the index was asked for; the
        // payload-type check would then reject it, but only after the source
        // had chosen which document the consumer got (REQ-INDEXAUTH-001).
        assert_ne!(ROLE_LINE_INDEX, ROLE_LINE_STATUS);
        assert_eq!(layer_digest_for_role(&manifest, ROLE_LINE_INDEX), None);
        let indexed = serde_json::json!({
            "layers": [
                {"digest": "sha256:ccc", "annotations": {ANN_ROLE: ROLE_LINE_STATUS}},
                {"digest": "sha256:ddd", "annotations": {ANN_ROLE: ROLE_LINE_INDEX}},
            ]
        });
        assert_eq!(
            layer_digest_for_role(&indexed, ROLE_LINE_INDEX),
            Some("sha256:ddd".to_string())
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_registrys_listing_for_a_line_is_that_lines_layers_and_nothing_else() {
        // What `served_layers` answers with, and therefore what omission is
        // measured against (clause 3). Both directions matter and neither is
        // obvious: including a tag that is not a layer of this line would
        // let an index name it and be satisfied by junk, while EXCLUDING a
        // layer that is served would accuse an honest registry of hiding it.
        let tags = vec![
            "2026.08.0".to_string(),
            "2026.08.10".to_string(),
            "2026.09.0".to_string(),          // another line
            "line-index-2026.08".to_string(), // the index's own tag
            "latest".to_string(),             // a floating tag some pipeline pushed
            "2026.08.01".to_string(),         // non-canonical: leading zero
            "2026.08".to_string(),            // a line, not a layer
        ];
        assert_eq!(
            layers_of_line(tags.clone(), "2026.08"),
            vec!["2026.08.0".to_string(), "2026.08.10".to_string()],
        );
        assert_eq!(
            layers_of_line(tags, "2026.09"),
            vec!["2026.09.0".to_string()]
        );
        // A repository with no layer of this line enumerates EMPTY, which
        // against a signed index means it is hiding everything. That is a
        // different statement from "cannot enumerate", and the distinction is
        // the difference between catching a hostile registry and refusing
        // every air-gapped install.
        assert!(layers_of_line(vec!["latest".to_string()], "2026.08").is_empty());
    }

    // ─────────────── clause 1: the challenge, not a guess ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_bearer_challenge_yields_realm_service_and_scope() {
        let c = parse_bearer_challenge(
            r#"Bearer realm="https://auth.example.test/token",service="registry.example.test",scope="repository:org/repo:pull""#,
        )
        .expect("a Bearer challenge must parse");
        assert_eq!(c.realm.as_deref(), Some("https://auth.example.test/token"));
        assert_eq!(c.service.as_deref(), Some("registry.example.test"));
        assert_eq!(c.scope.as_deref(), Some("repository:org/repo:pull"));

        // A scope contains commas. Splitting the header on commas — the
        // obvious wrong implementation — truncates it to "repository:x:pull".
        let c =
            parse_bearer_challenge(r#"Bearer realm="https://a/t",scope="repository:x:pull,push""#)
                .unwrap();
        assert_eq!(
            c.scope.as_deref(),
            Some("repository:x:pull,push"),
            "a quoted scope must survive its own commas"
        );

        // Unquoted values, odd spacing, and a lowercase scheme are all legal.
        let c = parse_bearer_challenge("bearer realm=https://a/t, service=reg").unwrap();
        assert_eq!(c.realm.as_deref(), Some("https://a/t"));
        assert_eq!(c.service.as_deref(), Some("reg"));

        // A Basic challenge is not a Bearer challenge.
        assert_eq!(parse_bearer_challenge(r#"Basic realm="x""#), None);
        // A bare scheme parses to a challenge with no realm, which the caller
        // reports as "no token endpoint to ask" rather than guessing one.
        assert_eq!(
            parse_bearer_challenge("Bearer"),
            Some(BearerChallenge::default())
        );
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn the_token_url_comes_from_the_realm_the_registry_named() {
        let c = parse_bearer_challenge(
            r#"Bearer realm="https://auth.example.test/v1/token",service="reg.example.test""#,
        )
        .unwrap();
        let url = token_url(&c, "repository:fallback:pull").unwrap();
        assert!(
            url.starts_with("https://auth.example.test/v1/token?"),
            "the realm decides the endpoint, not a hardcoded /token: {url}"
        );
        assert!(url.contains("service=reg.example.test"), "{url}");
        assert!(
            url.contains("scope=repository%3Afallback%3Apull"),
            "an absent scope falls back to a pull scope for the repository: {url}"
        );

        // A realm that already carries a query string gets '&', not a second '?'.
        let c = parse_bearer_challenge(r#"Bearer realm="https://gl.test/jwt/auth?x=1""#).unwrap();
        let url = token_url(&c, "repository:r:pull").unwrap();
        assert!(url.starts_with("https://gl.test/jwt/auth?x=1&"), "{url}");
        assert_eq!(url.matches('?').count(), 1, "{url}");

        // No realm, no endpoint — and no guess.
        assert_eq!(token_url(&BearerChallenge::default(), "s"), None);
        assert_eq!(
            token_url(
                &BearerChallenge {
                    realm: Some("  ".into()),
                    ..Default::default()
                },
                "s"
            ),
            None
        );
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn an_https_registry_may_not_redirect_its_token_realm_to_cleartext() {
        assert!(realm_is_acceptable(
            "https://auth.example.test/token",
            "https"
        ));
        assert!(
            !realm_is_acceptable("http://auth.example.test/token", "https"),
            "an https registry must not talk varve into posting Basic over http"
        );
        // The test double and air-gapped mirrors are reached over http.
        assert!(realm_is_acceptable("http://127.0.0.1:5000/token", "http"));
        assert!(realm_is_acceptable("https://127.0.0.1:5000/token", "http"));
        assert!(!realm_is_acceptable("ftp://x/token", "http"));
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_token_response_is_read_from_either_spelling() {
        assert_eq!(
            token_from_body(r#"{"token":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(
            token_from_body(r#"{"access_token":"xyz"}"#).as_deref(),
            Some("xyz"),
            "the OAuth2 spelling several registries answer with"
        );
        assert_eq!(token_from_body(r#"{"token":""}"#), None);
        assert_eq!(token_from_body(r#"{"nope":1}"#), None);
        assert_eq!(token_from_body("not json"), None);
    }

    // ─────────────── clause 2: credentials without exec ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn base64_round_trips_and_decodes_a_docker_auth_field() {
        for input in [
            "".as_bytes(),
            b"a",
            b"ab",
            b"abc",
            b"user:pass",
            b"\x00\xff\xfe\x01",
        ] {
            assert_eq!(
                base64_decode(&base64_encode(input)).as_deref(),
                Some(input),
                "round trip"
            );
        }
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(
            decode_basic_auth("dXNlcjpwYXNz"),
            Some(("user".to_string(), "pass".to_string()))
        );
        // Padding-free and newline-wrapped configs still decode.
        assert_eq!(
            decode_basic_auth("dXNlcjpwYXNz\n"),
            Some(("user".to_string(), "pass".to_string()))
        );
        // A password may contain colons; only the first splits.
        assert_eq!(
            decode_basic_auth(&base64_encode(b"user:a:b")),
            Some(("user".to_string(), "a:b".to_string()))
        );
        assert_eq!(base64_decode("not base64!"), None);
        assert_eq!(decode_basic_auth(&base64_encode(b"nocolon")), None);
        assert_eq!(decode_basic_auth(&base64_encode(b":onlypass")), None);
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_docker_config_auths_entry_becomes_a_credential() {
        let config = serde_json::json!({
            "auths": {
                "ghcr.io": { "auth": base64_encode(format!("alice:{SECRET}").as_bytes()) }
            }
        });
        match credential_from_docker_config(&config, "ghcr.io", "/cfg") {
            CredentialLookup::Found(c) => {
                assert_eq!(c.username, "alice");
                assert_eq!(c.password, SECRET);
                assert_eq!(c.origin, "/cfg");
            }
            other => panic!("expected a credential, got {other:?}"),
        }

        // Keys are written with a scheme and a path in the wild.
        let config = serde_json::json!({
            "auths": { "https://index.docker.io/v1/": { "auth": base64_encode(b"bob:pw") } }
        });
        assert!(matches!(
            credential_from_docker_config(&config, "registry-1.docker.io", "/cfg"),
            CredentialLookup::Found(_)
        ));

        // Plaintext username/password entries (podman writes these).
        let config = serde_json::json!({
            "auths": { "reg.test": { "username": "carol", "password": SECRET } }
        });
        match credential_from_docker_config(&config, "reg.test", "/cfg") {
            CredentialLookup::Found(c) => assert_eq!(c.username, "carol"),
            other => panic!("expected a credential, got {other:?}"),
        }

        // A different registry's entry is not this registry's credential.
        assert_eq!(
            credential_from_docker_config(&config, "other.test", "/cfg"),
            CredentialLookup::Absent
        );
        // An unreadable auth blob is malformed, not silently absent.
        let config = serde_json::json!({ "auths": { "reg.test": { "auth": "%%%" } } });
        assert!(matches!(
            credential_from_docker_config(&config, "reg.test", "/cfg"),
            CredentialLookup::Malformed { .. }
        ));
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_credential_helper_is_named_and_never_run() {
        let config = serde_json::json!({ "credsStore": "osxkeychain" });
        assert_eq!(
            credential_from_docker_config(&config, "ghcr.io", "~/.docker/config.json"),
            CredentialLookup::HelperOnly {
                helper: "osxkeychain".to_string(),
                origin: "~/.docker/config.json".to_string()
            },
            "a credsStore-only config must be reported, not executed"
        );
        let config = serde_json::json!({ "credHelpers": { "ghcr.io": "ghcr-login" } });
        assert_eq!(
            credential_from_docker_config(&config, "ghcr.io", "/cfg"),
            CredentialLookup::HelperOnly {
                helper: "ghcr-login".to_string(),
                origin: "/cfg".to_string()
            }
        );
        // A helper for ANOTHER registry says nothing about this one.
        let config = serde_json::json!({ "credHelpers": { "other.test": "h" } });
        assert_eq!(
            credential_from_docker_config(&config, "ghcr.io", "/cfg"),
            CredentialLookup::Absent
        );
        // A real credential beats the store setting sitting next to it.
        let config = serde_json::json!({
            "credsStore": "osxkeychain",
            "auths": { "ghcr.io": { "auth": base64_encode(b"alice:pw") } }
        });
        assert!(matches!(
            credential_from_docker_config(&config, "ghcr.io", "/cfg"),
            CredentialLookup::Found(_)
        ));
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn the_environment_variable_is_a_username_colon_password_pair() {
        match credential_from_env_value(&format!("alice:{SECRET}")) {
            CredentialLookup::Found(c) => {
                assert_eq!(c.username, "alice");
                assert_eq!(c.password, SECRET);
                assert_eq!(c.origin, "$VARVE_REGISTRY_AUTH");
            }
            other => panic!("expected a credential, got {other:?}"),
        }
        // `$(aws ecr get-login-password)` brings a newline along.
        match credential_from_env_value("AWS:token-value\n") {
            CredentialLookup::Found(c) => assert_eq!(c.password, "token-value"),
            other => panic!("expected a credential, got {other:?}"),
        }
        assert_eq!(credential_from_env_value(""), CredentialLookup::Absent);
        assert!(matches!(
            credential_from_env_value("no-colon-here"),
            CredentialLookup::Malformed { .. }
        ));
        assert!(matches!(
            credential_from_env_value(":only-password"),
            CredentialLookup::Malformed { .. }
        ));
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn precedence_prefers_a_real_credential_and_otherwise_keeps_the_explanation() {
        let found = CredentialLookup::Found(Credential {
            username: "a".into(),
            password: "b".into(),
            origin: "second".into(),
        });
        let helper = CredentialLookup::HelperOnly {
            helper: "h".into(),
            origin: "first".into(),
        };
        // A helper-only earlier source must not shadow a usable later one.
        assert_eq!(
            first_usable(vec![helper.clone(), found.clone()]),
            found,
            "a usable credential wins wherever it is found"
        );
        // Two usable ones: the earlier source wins.
        let first_found = CredentialLookup::Found(Credential {
            username: "z".into(),
            password: "b".into(),
            origin: "first".into(),
        });
        assert_eq!(
            first_usable(vec![first_found.clone(), found.clone()]),
            first_found
        );
        // Nothing usable: the first source that had something to say.
        assert_eq!(
            first_usable(vec![CredentialLookup::Absent, helper.clone()]),
            helper
        );
        assert_eq!(first_usable(vec![]), CredentialLookup::Absent);
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn config_files_are_read_in_order_and_a_broken_one_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let broken = tmp.path().join("broken.json");
        std::fs::write(&broken, "{ not json").unwrap();
        let good = tmp.path().join("good.json");
        std::fs::write(
            &good,
            serde_json::to_vec(&serde_json::json!({
                "auths": { "reg.test": { "auth": base64_encode(format!("dave:{SECRET}").as_bytes()) } }
            }))
            .unwrap(),
        )
        .unwrap();
        let missing = tmp.path().join("absent.json");

        let lookups = lookups_from_paths(&[missing, broken, good], "reg.test");
        assert_eq!(
            lookups.len(),
            1,
            "a missing and an unparseable config contribute nothing, they do not fail the pull"
        );
        match first_usable(lookups) {
            CredentialLookup::Found(c) => assert_eq!(c.username, "dave"),
            other => panic!("expected the good config's credential, got {other:?}"),
        }
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_credential_never_reaches_a_debug_line_or_an_error_message() {
        let credential = Credential {
            username: "alice".into(),
            password: SECRET.into(),
            origin: "/home/u/.docker/config.json".into(),
        };
        let debug = format!("{credential:?}");
        assert!(
            !debug.contains(SECRET),
            "Debug leaked the password: {debug}"
        );
        assert!(
            !debug.contains("alice"),
            "Debug leaked the username: {debug}"
        );
        assert!(debug.contains("/home/u/.docker/config.json"), "{debug}");

        let lookup = CredentialLookup::Found(credential.clone());
        let debug = format!("{lookup:?}");
        assert!(!debug.contains(SECRET), "{debug}");

        let advice = credential_advice(&lookup, "ghcr.io", "org/repo");
        assert!(!advice.contains(SECRET), "advice leaked the password");
        assert!(
            advice.contains("/home/u/.docker/config.json"),
            "the advice must name where the rejected credential came from: {advice}"
        );

        // The Basic header is the one place the secret legitimately appears —
        // and it is built, never printed.
        assert_eq!(
            credential.basic_header(),
            format!(
                "Basic {}",
                base64_encode(format!("alice:{SECRET}").as_bytes())
            )
        );

        // A source Debug-printed whole must not carry it either — not the
        // configured credential, and not the bearer token the realm issued,
        // which is short-lived but is still a credential.
        let source = RegistrySource::parse("oci://ghcr.io/org/repo")
            .unwrap()
            .with_credential("alice", SECRET);
        *source.token.borrow_mut() = Some("issued-bearer-token".to_string());
        let debug = format!("{source:?}");
        assert!(
            !debug.contains("issued-bearer-token"),
            "RegistrySource Debug leaked the bearer token: {debug}"
        );
        assert!(
            debug.contains("ghcr.io"),
            "the reference is not a secret and must stay legible: {debug}"
        );
        assert!(
            !debug.contains(SECRET),
            "RegistrySource Debug leaked the password: {debug}"
        );
    }

    // ─────────────── clause 5: say which kind of nothing ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_refusal_distinguishes_no_credential_from_a_rejected_one() {
        let rejected = credential_advice(
            &CredentialLookup::Found(Credential {
                username: "alice".into(),
                password: SECRET.into(),
                origin: "$VARVE_REGISTRY_AUTH".into(),
            }),
            "ghcr.io",
            "org/repo",
        );
        assert!(
            rejected.contains("rejected it"),
            "a rejected credential must be named as rejected: {rejected}"
        );
        assert!(!rejected.contains("offered no credential"), "{rejected}");

        for lookup in [
            CredentialLookup::Absent,
            CredentialLookup::Malformed {
                origin: "$VARVE_REGISTRY_AUTH".into(),
            },
            CredentialLookup::HelperOnly {
                helper: "osxkeychain".into(),
                origin: "~/.docker/config.json".into(),
            },
        ] {
            let advice = credential_advice(&lookup, "ghcr.io", "org/repo");
            assert!(
                advice.contains("offered no credential"),
                "{lookup:?} must be reported as having offered nothing: {advice}"
            );
            assert!(
                advice.contains(CREDENTIAL_ENV),
                "every no-credential message must name the fix: {advice}"
            );
        }

        // The helper case must say WHY varve did not run the helper, and name
        // the alternative — otherwise the user reads it as a varve bug.
        let advice = credential_advice(
            &CredentialLookup::HelperOnly {
                helper: "osxkeychain".into(),
                origin: "~/.docker/config.json".into(),
            },
            "ghcr.io",
            "org/repo",
        );
        assert!(advice.contains("osxkeychain"), "{advice}");
        assert!(
            advice.contains("does not execute credential helpers"),
            "{advice}"
        );
        assert!(advice.contains("REQ-SHADOW-001"), "{advice}");
    }

    // ─────────────── clause 3: pagination ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_link_header_names_the_next_page_and_only_within_the_origin() {
        let current = "https://reg.test/v2/org/repo/tags/list?n=100";
        assert_eq!(
            parse_link_next(
                r#"</v2/org/repo/tags/list?n=100&last=2026.08.9>; rel="next""#,
                current
            )
            .as_deref(),
            Some("https://reg.test/v2/org/repo/tags/list?n=100&last=2026.08.9")
        );
        // Unquoted rel, extra params, and a multi-link header.
        assert_eq!(
            parse_link_next(
                r#"</v2/a?x=1>; rel=prev, </v2/b?x=2>; type="text"; rel="next""#,
                current
            )
            .as_deref(),
            Some("https://reg.test/v2/b?x=2")
        );
        // An absolute same-origin link is fine.
        assert_eq!(
            parse_link_next(r#"<https://reg.test/v2/next>; rel="next""#, current).as_deref(),
            Some("https://reg.test/v2/next")
        );
        // A cross-origin next would hand the bearer token to another host.
        assert_eq!(
            parse_link_next(r#"<https://evil.test/v2/next>; rel="next""#, current),
            None,
            "a rel=next pointing off-origin must not be followed"
        );
        // No next link, and a rel that is not next.
        assert_eq!(parse_link_next(r#"</v2/a>; rel="prev""#, current), None);
        assert_eq!(parse_link_next("", current), None);
        // rel="prev next" is a next link.
        assert!(parse_link_next(r#"</v2/a>; rel="prev next""#, current).is_some());
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn a_tags_page_is_parsed_and_a_broken_one_is_not_an_empty_repository() {
        assert_eq!(
            tags_from_page(br#"{"name":"r","tags":["a","b"]}"#).unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        // `tags: null` is spec-legal for an empty page.
        assert_eq!(
            tags_from_page(br#"{"name":"r","tags":null}"#).unwrap(),
            Vec::<String>::new()
        );
        // Garbage is a transport failure. Returning an empty list here would
        // read downstream as "this repository has no such layer".
        assert!(tags_from_page(b"<html>502</html>").is_err());
    }

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn the_first_tags_page_asks_the_registry_to_paginate() {
        let url = tags_first_page_url("https://reg.test/v2/org/repo");
        assert_eq!(
            url,
            format!("https://reg.test/v2/org/repo/tags/list?n={TAGS_PAGE_SIZE}")
        );
        assert!(
            url.contains("?n="),
            "without ?n= a registry may answer one implementation-defined page and \
             the client never learns there was more: {url}"
        );
        // The page bound is what stops a registry that never says 'no more'.
        // Its effect is proven end-to-end by the registry_double test
        // `an_endless_tag_list_stops_with_an_error_rather_than_looping_or_truncating`.
        assert_eq!(MAX_TAG_PAGES, 64);
    }

    // ─────────────── clause 4: both manifest media types ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn the_manifest_accept_header_offers_the_docker_type_as_well_as_the_oci_one() {
        assert!(
            MANIFEST_ACCEPT.contains("application/vnd.oci.image.manifest.v1+json"),
            "{MANIFEST_ACCEPT}"
        );
        assert!(
            MANIFEST_ACCEPT.contains("application/vnd.docker.distribution.manifest.v2+json"),
            "a registry serving only the Docker type is unreachable without this: \
             {MANIFEST_ACCEPT}"
        );
    }

    // ─────────────── clause 6: no Authorization across a redirect ───────────────

    // rivet: verifies REQ-REGISTRY-002
    #[test]
    fn the_agent_never_carries_authorization_across_a_redirect() {
        let config = agent_config();
        assert_eq!(
            config.redirect_auth_headers(),
            ureq::config::RedirectAuthHeaders::Never,
            "blob fetches redirect to CDNs; the credential must not go with them"
        );
        assert!(
            !config.http_status_as_error(),
            "a 401 must arrive as a response so its WWW-Authenticate challenge can be read"
        );
    }

    #[test]
    fn percent_encoding_escapes_what_a_scope_contains() {
        assert_eq!(
            percent_encode("repository:org/repo:pull"),
            "repository%3Aorg%2Frepo%3Apull"
        );
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode("a b"), "a%20b");
    }
}
