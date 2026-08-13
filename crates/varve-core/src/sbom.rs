//! SBOM emission from the signed layer manifest (REQ-SBOM-001).
//!
//! Most SBOMs are *scanned*: a tool walks a filesystem or a lockfile and
//! reports what it believes it found. varve's is a **transcription of signed
//! data** — every component, version and hash in the output is copied from the
//! DSSE-signed layer manifest that the trust root anchored. Nothing is
//! discovered, so nothing can be missed or invented: the SBOM is exactly as
//! trustworthy as the layer, and `varve verify` already decides that.
//!
//! This is what a CRA Article 13(5) "due diligence when integrating components
//! sourced from third parties" answer looks like mechanically, and what lets a
//! manufacturer say which components are in a shipped product inside the 24
//! hours Article 14 allows from 2026-09-11.
//!
//! Output is deterministic — stable ordering, no timestamps of its own, a
//! serial number derived from the layer digest — so re-emitting the same layer
//! byte-identically is the expected result, and a diff means the layer changed.

use crate::manifest::LayerManifest;

/// Which document format to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    /// CycloneDX 1.6 JSON.
    CycloneDx,
}

impl std::str::FromStr for SbomFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cyclonedx" | "cdx" => Ok(SbomFormat::CycloneDx),
            other => Err(format!(
                "unknown SBOM format '{other}' (supported: cyclonedx)"
            )),
        }
    }
}

/// One component as the signed manifest describes it.
fn component(entry: &crate::manifest::ManifestEntry) -> Option<serde_json::Value> {
    let name = entry.annotations.get("eu.pulseengine.tool")?;
    let version = entry
        .annotations
        .get("eu.pulseengine.tool.version")
        .cloned()
        .unwrap_or_default();
    let hex = entry
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&entry.digest);
    // A payload kind maps to a CycloneDX component type. An unknown kind is
    // not guessed here — `kind()` already refuses it before we are called.
    let ctype = match entry.kind().ok()? {
        crate::kind::PayloadKind::Tool => "application",
        crate::kind::PayloadKind::Crate
        | crate::kind::PayloadKind::Wit
        | crate::kind::PayloadKind::Sdk
        | crate::kind::PayloadKind::ZephyrModule => "library",
        crate::kind::PayloadKind::WasmComponent => "library",
    };
    let mut c = serde_json::json!({
        "type": ctype,
        "name": name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": hex}],
        // The digest IS the identity here: bom-ref stays stable across emissions.
        "bom-ref": entry.digest,
    });
    // A layer carries one entry per tool PER PLATFORM, each a distinct binary
    // with a distinct digest. They are genuinely different components, so they
    // are all listed — but without the platform they read as duplicates.
    if let Some(platform) = entry.annotations.get("eu.pulseengine.platform") {
        c["properties"] = serde_json::json!([
            {"name": "eu.pulseengine.platform", "value": platform}
        ]);
    }
    // Upstream provenance, where the depositor recorded it — the external
    // reference an assessor follows back to the source of record.
    if let Some(repo) = entry.annotations.get("eu.pulseengine.source.repo") {
        let mut refs = vec![serde_json::json!({"type": "vcs", "url": repo})];
        if let Some(asset) = entry.annotations.get("eu.pulseengine.source.asset") {
            refs.push(serde_json::json!({"type": "distribution", "url": asset}));
        }
        c["externalReferences"] = serde_json::Value::Array(refs);
    }
    Some(c)
}

/// Emit an SBOM for a verified layer manifest. Deterministic: same manifest in,
/// byte-identical document out.
pub fn emit(manifest: &LayerManifest, manifest_digest: &str, format: SbomFormat) -> String {
    let SbomFormat::CycloneDx = format;
    let mut components: Vec<serde_json::Value> =
        manifest.entries.iter().filter_map(component).collect();
    // Stable order by bom-ref (the digest), so the document is diffable.
    components.sort_by(|a, b| a["bom-ref"].as_str().cmp(&b["bom-ref"].as_str()));
    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        // Derived from the layer, never random: re-emission is byte-identical.
        "serialNumber": format!("urn:uuid:{}", uuid_from_digest(manifest_digest)),
        "metadata": {
            // The layer's own issued-at, not "now" — the document describes a
            // released artifact, not the moment someone asked about it.
            "timestamp": manifest.issued_at,
            "component": {
                "type": "firmware",
                "name": format!("varve-layer-{}", manifest.layer),
                "version": manifest.layer.to_string(),
                "bom-ref": manifest_digest,
            },
            "properties": [
                {"name": "eu.pulseengine.varve.channel", "value": manifest.channel},
                {"name": "eu.pulseengine.varve.counter", "value": manifest.counter.to_string()},
                {"name": "eu.pulseengine.varve.manifest-digest", "value": manifest_digest},
            ],
        },
        "components": components,
    });
    serde_json::to_string_pretty(&doc).expect("sbom serialises")
}

/// A stable RFC-4122-shaped identifier derived from the manifest digest, so the
/// serial number is a function of the layer rather than of the clock.
fn uuid_from_digest(digest: &str) -> String {
    let hex: String = digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(32)
        .collect();
    let h = format!("{hex:0<32}");
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> (LayerManifest, String) {
        let bytes = crate::manifest::fixtures::manifest_with_tools(
            "2026.08.0",
            "qualified",
            7,
            "2026-08-01T00:00:00Z",
            &[("synth", "sha256:aaaa"), ("rivet", "sha256:bbbb")],
        );
        let m = LayerManifest::parse(&bytes).unwrap();
        (m, "sha256:1234567890abcdef".to_string())
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn every_component_is_transcribed_from_the_signed_manifest() {
        let (m, digest) = manifest();
        let doc: serde_json::Value =
            serde_json::from_str(&emit(&m, &digest, SbomFormat::CycloneDx)).unwrap();
        let comps = doc["components"].as_array().unwrap();
        assert_eq!(
            comps.len(),
            m.entries.len(),
            "the SBOM must describe exactly the signed entries — no more, no fewer"
        );
        // Every hash in the document appears in the signed manifest.
        for c in comps {
            let hex = c["hashes"][0]["content"].as_str().unwrap();
            assert!(
                m.entries
                    .iter()
                    .any(|e| e.digest.strip_prefix("sha256:") == Some(hex)),
                "component hash {hex} is not in the signed manifest"
            );
        }
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.6");
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn per_platform_entries_are_distinguishable_not_duplicates() {
        // A layer holds one entry per tool per platform — distinct binaries
        // with distinct digests. Listing them without the platform makes a
        // real SBOM look like it repeats itself.
        let bytes = crate::manifest::fixtures::manifest_with_platform_tools(
            "2026.08.0",
            "qualified",
            1,
            "2026-08-01T00:00:00Z",
            &[
                ("kilnd", "sha256:aaaa", Some("x86_64-unknown-linux-gnu")),
                ("kilnd", "sha256:bbbb", Some("aarch64-apple-darwin")),
            ],
        );
        let m = LayerManifest::parse(&bytes).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&emit(&m, "sha256:dd", SbomFormat::CycloneDx)).unwrap();
        let comps = doc["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
        let platforms: Vec<&str> = comps
            .iter()
            .map(|c| c["properties"][0]["value"].as_str().unwrap())
            .collect();
        assert!(platforms.contains(&"x86_64-unknown-linux-gnu"));
        assert!(platforms.contains(&"aarch64-apple-darwin"));
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn emission_is_deterministic() {
        let (m, digest) = manifest();
        let a = emit(&m, &digest, SbomFormat::CycloneDx);
        let b = emit(&m, &digest, SbomFormat::CycloneDx);
        assert_eq!(a, b, "the same layer must emit a byte-identical document");
        // …and it carries the layer's own issued-at, not the wall clock.
        let doc: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(doc["metadata"]["timestamp"], "2026-08-01T00:00:00Z");
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn the_document_binds_itself_to_the_layer_it_describes() {
        let (m, digest) = manifest();
        let doc: serde_json::Value =
            serde_json::from_str(&emit(&m, &digest, SbomFormat::CycloneDx)).unwrap();
        // An SBOM that does not say which signed artifact it describes cannot
        // be checked against one.
        assert_eq!(doc["metadata"]["component"]["bom-ref"], digest);
        let props = doc["metadata"]["properties"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "eu.pulseengine.varve.manifest-digest"
                    && p["value"] == digest.as_str()),
            "the manifest digest must be recorded in the document"
        );
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "eu.pulseengine.varve.counter" && p["value"] == "7"),
            "the anti-rollback counter belongs in the document"
        );
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn an_unknown_format_is_refused_not_guessed() {
        assert!("cyclonedx".parse::<SbomFormat>().is_ok());
        assert!("spdx".parse::<SbomFormat>().is_err());
        assert!("".parse::<SbomFormat>().is_err());
    }
}
