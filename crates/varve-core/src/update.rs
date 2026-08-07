//! Self-update (REQ-UPDATE-001) — updating the updater, without a flag day.
//!
//! The chain: the RUNNING varve verifies the candidate release against the
//! pinned trust root before anything is replaced — old-verifies-new, the
//! same shape as a TUF root rotation. Explicit invocation only: varve makes
//! no network request the user did not command (no phone-home), and any
//! verification failure refuses rather than warns. The one unavoidable TOFU
//! moment is the very first install, established out-of-band (cosign +
//! build provenance); every update after that rides this chain.

use crate::install::VerifyError;
use crate::selfverify::{SelfVerifyError, verify_release_file};

/// What an update check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub current: String,
    pub latest: String,
    pub archive_name: String,
    pub archive_url: String,
    pub envelope_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("release API error: {0}")]
    Api(String),
    #[error("release {tag} carries no asset for platform {platform}")]
    NoAsset { tag: String, platform: String },
    #[error(
        "release {tag} carries no varve-native signed sums (SHA256SUMS.txt.dsse.json) — cannot \
         self-update without it; verify and install manually (cosign) or wait for a signed release"
    )]
    NoEnvelope { tag: String },
    #[error(transparent)]
    Verify(#[from] SelfVerifyError),
    #[error(transparent)]
    Signature(#[from] VerifyError),
    #[error("downloaded archive does not contain a 'varve' binary")]
    NoBinaryInArchive,
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Strictly-parsed x.y.z (a leading `v` is tolerated).
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, patch))
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(c), Some(cur)) => c > cur,
        // Unparseable versions never count as newer — fail closed.
        _ => false,
    }
}

/// Ask the release API for the latest tag and locate this platform's assets.
/// `api_latest_url` is the GitHub "latest release" endpoint (or a mirror /
/// test double — the URL changes availability, never acceptance).
pub fn check_latest(
    api_latest_url: &str,
    current_version: &str,
    platform: &str,
) -> Result<Option<UpdatePlan>, UpdateError> {
    let agent = ureq::Agent::new_with_defaults();
    let body = agent
        .get(api_latest_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "varve-self-update")
        .call()
        .map_err(|e| UpdateError::Api(e.to_string()))?
        .body_mut()
        .read_to_string()
        .map_err(|e| UpdateError::Api(e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| UpdateError::Api(e.to_string()))?;
    let tag = json["tag_name"]
        .as_str()
        .ok_or_else(|| UpdateError::Api("latest release has no tag_name".into()))?
        .to_string();
    if !is_newer(&tag, current_version) {
        return Ok(None);
    }
    let assets = json["assets"].as_array().cloned().unwrap_or_default();
    let find = |name: &str| -> Option<String> {
        assets
            .iter()
            .find(|a| a["name"].as_str() == Some(name))
            .and_then(|a| a["browser_download_url"].as_str())
            .map(str::to_string)
    };
    let archive_name = format!("varve-{tag}-{platform}.tar.gz");
    let archive_url = find(&archive_name).ok_or_else(|| UpdateError::NoAsset {
        tag: tag.clone(),
        platform: platform.to_string(),
    })?;
    let envelope_url = find("SHA256SUMS.txt.dsse.json")
        .ok_or_else(|| UpdateError::NoEnvelope { tag: tag.clone() })?;
    Ok(Some(UpdatePlan {
        current: current_version.to_string(),
        latest: tag,
        archive_name,
        archive_url,
        envelope_url,
    }))
}

/// Extract one file from a gzipped tarball.
pub fn extract_tool_from_targz(bytes: &[u8], tool: &str) -> Result<Vec<u8>, UpdateError> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    for entry in archive.entries().map_err(|e| UpdateError::Io {
        path: "<archive>".into(),
        source: e,
    })? {
        let mut entry = entry.map_err(|e| UpdateError::Io {
            path: "<archive>".into(),
            source: e,
        })?;
        let is_match = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n == tool))
            .unwrap_or(false);
        if is_match {
            let mut out = Vec::new();
            use std::io::Read;
            entry.read_to_end(&mut out).map_err(|e| UpdateError::Io {
                path: tool.into(),
                source: e,
            })?;
            return Ok(out);
        }
    }
    Err(UpdateError::NoBinaryInArchive)
}

/// Execute an update plan: download, VERIFY with the running binary's trust
/// root, extract, and atomically install at `dest`. Returns the verified
/// archive digest.
pub fn perform(
    plan: &UpdatePlan,
    root_public_key: &[u8],
    dest: &std::path::Path,
) -> Result<String, UpdateError> {
    let agent = ureq::Agent::new_with_defaults();
    let fetch = |url: &str| -> Result<Vec<u8>, UpdateError> {
        agent
            .get(url)
            .header("User-Agent", "varve-self-update")
            .call()
            .map_err(|e| UpdateError::Api(e.to_string()))?
            .body_mut()
            .with_config()
            .limit(8 * 1024 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| UpdateError::Api(e.to_string()))
    };
    let envelope = fetch(&plan.envelope_url)?;
    let archive = fetch(&plan.archive_url)?;

    // The trust decision: the running varve verifies its successor.
    let digest = verify_release_file(&plan.archive_name, &archive, &envelope, root_public_key)?;

    let binary = extract_tool_from_targz(&archive, "varve")?;
    let io = |path: &std::path::Path, source: std::io::Error| UpdateError::Io {
        path: path.display().to_string(),
        source,
    };
    // Atomic on the same filesystem: write beside dest, then rename over it.
    let tmp = dest.with_extension("varve-update-tmp");
    std::fs::write(&tmp, &binary).map_err(|e| io(&tmp, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| io(&tmp, e))?;
    }
    std::fs::rename(&tmp, dest).map_err(|e| io(dest, e))?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-UPDATE-001
    #[test]
    fn version_comparison_is_strict_and_fails_closed() {
        assert!(is_newer("v0.8.0", "0.7.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("v0.7.0", "0.7.0"));
        assert!(!is_newer("0.6.9", "0.7.0"));
        // Unparseable never counts as newer.
        assert!(!is_newer("nightly", "0.7.0"));
        assert!(!is_newer("v0.8", "0.7.0"));
        assert!(!is_newer("0.8.0.1", "0.7.0"));
    }

    // rivet: verifies REQ-UPDATE-001
    #[test]
    fn the_binary_is_extracted_from_a_release_shaped_tarball() {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in [("README.md", b"docs".as_slice()), ("varve", b"the-binary")] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes).unwrap();
        }
        let targz = builder.into_inner().unwrap().finish().unwrap();
        assert_eq!(
            extract_tool_from_targz(&targz, "varve").unwrap(),
            b"the-binary"
        );
        let no_binary = {
            let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            let mut h = tar::Header::new_gnu();
            h.set_size(4);
            h.set_cksum();
            b.append_data(&mut h, "other", b"data".as_slice()).unwrap();
            b.into_inner().unwrap().finish().unwrap()
        };
        assert!(matches!(
            extract_tool_from_targz(&no_binary, "varve").unwrap_err(),
            UpdateError::NoBinaryInArchive
        ));
    }
}
