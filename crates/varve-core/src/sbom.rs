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

/// One component, as the signed manifest describes it.
///
/// INFALLIBLE by design. An earlier version returned `Option` and was
/// `filter_map`'d, so an entry lacking a tool annotation — which foreign-platform
/// entries legitimately do — or carrying a payload kind this build does not
/// recognise disappeared from the document with no error. For a document whose
/// entire claim is that it cannot miss a component, silent omission is the one
/// failure mode that must be impossible. Whatever is unknown is LABELLED, never
/// dropped: the digest is always present, and it alone identifies the artifact.
fn component(entry: &crate::manifest::ManifestEntry) -> serde_json::Value {
    let hex = entry
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&entry.digest);
    let mut props: Vec<serde_json::Value> = Vec::new();

    // A layer holds one entry per tool PER PLATFORM, each a distinct binary
    // with a distinct digest. Without the platform they read as duplicates.
    if let Some(platform) = entry.annotations.get("eu.pulseengine.platform") {
        props.push(serde_json::json!({"name": "eu.pulseengine.platform", "value": platform}));
    }

    // An unrecognised payload kind is recorded verbatim and the component is
    // still emitted. `kind()` is NOT enforced on the install path (see
    // kind.rs), so a layer deposited by a newer varve can reach us here.
    let ctype = match entry.kind() {
        Ok(crate::kind::PayloadKind::Tool) => "application",
        // A composed layer is not a library — it is another BOM. Recorded as a
        // platform component with a nested-BOM reference, so a consumer follows
        // it rather than mistaking it for a shipped artifact.
        Ok(crate::kind::PayloadKind::Layer) => "platform",
        Ok(_) => "library",
        Err(_) => {
            if let Some(raw) = entry.annotations.get(crate::kind::ANN_KIND) {
                props.push(serde_json::json!({
                    "name": "eu.pulseengine.varve.kind.unrecognised",
                    "value": raw
                }));
            }
            "library"
        }
    };

    // A name is required by CycloneDX. Where the manifest names the artifact we
    // transcribe it; where it does not (a foreign-platform entry), the digest
    // is the only honest identifier, and we say so rather than inventing one.
    let name = match entry.annotations.get("eu.pulseengine.tool") {
        Some(n) => n.clone(),
        None => {
            props.push(serde_json::json!({
                "name": "eu.pulseengine.varve.unnamed",
                "value": "the signed manifest names no tool for this entry; identified by digest"
            }));
            format!("sha256-{}", &hex[..hex.len().min(16)])
        }
    };
    let version = entry
        .annotations
        .get("eu.pulseengine.tool.version")
        .cloned()
        .unwrap_or_default();

    let mut c = serde_json::json!({
        "type": ctype,
        "name": name,
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": hex}],
        // The digest IS the identity here: bom-ref stays stable across emissions.
        "bom-ref": entry.digest,
    });

    // A package URL is what lets a consumer match a component against a CVE
    // feed — the whole point of holding an SBOM when a report is due. Derived
    // only from signed annotations, and omitted when they do not support it.
    if let (Some(repo), false) = (
        entry.annotations.get("eu.pulseengine.source.repo"),
        version.is_empty(),
    ) && let Some((owner, name)) = repo.split_once('/')
    {
        c["purl"] = serde_json::json!(format!("pkg:github/{owner}/{name}@{version}"));
    }

    // Clause 1: the supplier is the upstream organisation the signed repo
    // annotation names. Without one there is no supplier to name, and
    // inventing one would be the scan-shaped guess this document exists to
    // avoid.
    if let Some((owner, _)) = entry
        .annotations
        .get("eu.pulseengine.source.repo")
        .and_then(|r| r.split_once('/'))
    {
        c["supplier"] = serde_json::json!({
            "name": owner,
            "url": [format!("https://github.com/{owner}")]
        });
    }

    // A composed layer points at its own document rather than restating it.
    if entry.kind() == Ok(crate::kind::PayloadKind::Layer) {
        c["externalReferences"] = serde_json::json!([{
            "type": "bom",
            "url": format!("urn:varve:layer:{}", entry.digest)
        }]);
        return c;
    }
    // Upstream provenance, where the depositor recorded it. The repo annotation
    // is a bare `owner/name` slug, so it is expanded into something an assessor
    // can actually follow; the asset name is left relative to that release.
    if let Some(repo) = entry.annotations.get("eu.pulseengine.source.repo") {
        let mut refs = vec![serde_json::json!({
            "type": "vcs",
            "url": format!("https://github.com/{repo}")
        })];
        if let (Some(asset), Some(release)) = (
            entry.annotations.get("eu.pulseengine.source.asset"),
            entry.annotations.get("eu.pulseengine.source.release"),
        ) {
            refs.push(serde_json::json!({
                "type": "distribution",
                "url": format!("https://github.com/{repo}/releases/download/{release}/{asset}")
            }));
        }
        // Clause 4: upstream's own SBOM, pinned by the digest the deposit saw.
        if let (Some(sbom), Some(release), Some(sha)) = (
            entry.annotations.get(crate::ingest::ANN_SBOM),
            entry.annotations.get("eu.pulseengine.source.release"),
            entry.annotations.get(crate::ingest::ANN_SBOM_SHA256),
        ) {
            refs.push(serde_json::json!({
                "type": "bom",
                "url": format!("https://github.com/{repo}/releases/download/{release}/{sbom}"),
                "hashes": [{"alg": "SHA-256", "content": sha}]
            }));
        }
        c["externalReferences"] = serde_json::Value::Array(refs);
    }
    // Clauses 5 and 6: upstream's DECLARED license, said to be declared; and
    // where none was recorded, a statement that none was — absence must not
    // read as "unlicensed".
    match entry.annotations.get(crate::ingest::ANN_LICENSE) {
        Some(expr) => {
            c["licenses"] =
                serde_json::json!([{"expression": expr, "acknowledgement": "declared"}]);
        }
        None => props.push(serde_json::json!({
            "name": "eu.pulseengine.varve.license",
            "value": "not recorded: this layer was deposited before varve recorded upstream licenses, \
                      or upstream declares none GitHub can identify"
        })),
    }
    if !props.is_empty() {
        c["properties"] = serde_json::Value::Array(props);
    }
    c
}

/// Emit an SBOM for a verified layer manifest. Deterministic: same manifest in,
/// byte-identical document out.
/// `author` names the realm whose root signed the layer (REQ-SBOMFIELDS-001
/// clause 2) — the caller knows it from the pin; the manifest does not say.
pub fn emit(
    manifest: &LayerManifest,
    manifest_digest: &str,
    format: SbomFormat,
    author: &str,
) -> String {
    let SbomFormat::CycloneDx = format;
    let mut components: Vec<serde_json::Value> = manifest.entries.iter().map(component).collect();
    // Stable order by bom-ref (the digest), so the document is diffable.
    components.sort_by(|a, b| a["bom-ref"].as_str().cmp(&b["bom-ref"].as_str()));
    let refs: Vec<serde_json::Value> = components.iter().map(|c| c["bom-ref"].clone()).collect();
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
            "authors": [{"name": format!("varve realm {author} (whose root signed this layer)")}],
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
        // Clause 3. The layer's own contents are COMPLETE — every component
        // is a signed entry, and none can be missing. What each component was
        // built from is not recorded anywhere varve can see, so it is stated
        // as unknown: a component absent from `dependencies` means unknown in
        // CycloneDX, but a reader skimming for empty lists should not have to
        // know that.
        "dependencies": [{"ref": manifest_digest, "dependsOn": refs}],
        "compositions": [
            {"aggregate": "complete", "dependencies": [manifest_digest]},
            {"aggregate": "unknown", "dependencies": refs},
        ],
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
    let mut h: Vec<u8> = format!("{hex:0<32}").into_bytes();
    // RFC 9562 UUIDv8 is the custom/deterministic version, so set the version
    // nibble to 8 and the variant to 10x. Without this the serial parses as
    // "version 11", which no RFC defines — CycloneDX's own schema text asks for
    // an RFC 4122 conformant serialNumber even though its pattern only checks
    // shape. Still a pure function of the digest: two nibbles are forced.
    h[12] = b'8';
    h[16] = b'a';
    let h = String::from_utf8(h).expect("hex digits stay ascii");
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
            serde_json::from_str(&emit(&m, &digest, SbomFormat::CycloneDx, "pulseengine")).unwrap();
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
            serde_json::from_str(&emit(&m, "sha256:dd", SbomFormat::CycloneDx, "pulseengine"))
                .unwrap();
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
    fn no_signed_entry_is_ever_dropped_from_the_document() {
        // THE invariant this feature sells: "a scanner can miss a component;
        // a transcription cannot." Clean-room review refuted an earlier version
        // that returned Option and filter_map'd — three signed entries emitted
        // one component, silently, exit 0. Entries can legitimately lack a tool
        // annotation (foreign-platform entries install without one) or carry a
        // payload kind this build does not know (a newer depositor). Neither
        // may vanish: an SBOM that omits a component is worse than none.
        let bytes = br#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {
    "eu.pulseengine.varve.layer": "2026.08.0",
    "eu.pulseengine.varve.channel": "qualified",
    "eu.pulseengine.varve.counter": "1",
    "org.opencontainers.image.created": "2026-08-01T00:00:00Z"
  },
  "manifests": [
    { "digest": "sha256:aaaa", "annotations": { "eu.pulseengine.tool": "synth", "eu.pulseengine.tool.version": "1.0.0" } },
    { "digest": "sha256:bbbb", "annotations": { "eu.pulseengine.tool": "future", "eu.pulseengine.varve.kind": "quantum-blob" } },
    { "digest": "sha256:cccc", "annotations": { "eu.pulseengine.platform": "riscv64-unknown-none" } }
  ]
}"#;
        let m = LayerManifest::parse(bytes).unwrap();
        assert_eq!(m.entries.len(), 3, "fixture sanity");
        let doc: serde_json::Value =
            serde_json::from_str(&emit(&m, "sha256:dd", SbomFormat::CycloneDx, "pulseengine"))
                .unwrap();
        let comps = doc["components"].as_array().unwrap();
        assert_eq!(
            comps.len(),
            3,
            "every signed entry must appear; got {comps:#?}"
        );
        // Every signed digest is present as a bom-ref.
        for e in &m.entries {
            assert!(
                comps.iter().any(|c| c["bom-ref"] == e.digest.as_str()),
                "signed entry {} is missing from the document",
                e.digest
            );
        }
    }

    // rivet: verifies REQ-SBOM-001
    #[test]
    fn emission_is_deterministic() {
        let (m, digest) = manifest();
        let a = emit(&m, &digest, SbomFormat::CycloneDx, "pulseengine");
        let b = emit(&m, &digest, SbomFormat::CycloneDx, "pulseengine");
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
            serde_json::from_str(&emit(&m, &digest, SbomFormat::CycloneDx, "pulseengine")).unwrap();
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

    /// A layer like the ones on the registry today: two tools from one
    /// upstream, one recorded with the new license and upstream-SBOM
    /// annotations, one deposited before they existed.
    const FIELDS: &[u8] = br#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {
    "eu.pulseengine.varve.layer": "2026.10.0",
    "eu.pulseengine.varve.channel": "rolling",
    "eu.pulseengine.varve.counter": "0",
    "org.opencontainers.image.created": "2026-10-01T00:00:00Z"
  },
  "manifests": [
    { "digest": "sha256:aaaa", "annotations": {
        "eu.pulseengine.tool": "kilnd", "eu.pulseengine.tool.version": "0.5.0",
        "eu.pulseengine.source.repo": "pulseengine/kiln",
        "eu.pulseengine.source.release": "v0.5.0",
        "eu.pulseengine.source.asset": "kiln-v0.5.0-x86_64-unknown-linux-gnu.tar.gz",
        "eu.pulseengine.source.license": "Apache-2.0 OR MIT",
        "eu.pulseengine.source.sbom": "kiln-0.5.0.cdx.json",
        "eu.pulseengine.source.sbom.sha256": "5555555555555555555555555555555555555555555555555555555555555555" } },
    { "digest": "sha256:bbbb", "annotations": {
        "eu.pulseengine.tool": "rivet", "eu.pulseengine.tool.version": "0.40.0",
        "eu.pulseengine.source.repo": "pulseengine/rivet",
        "eu.pulseengine.source.release": "v0.40.0" } },
    { "digest": "sha256:cccc", "annotations": { "eu.pulseengine.platform": "riscv64-unknown-none" } }
  ]
}"#;

    fn fields_doc() -> serde_json::Value {
        let m = LayerManifest::parse(FIELDS).unwrap();
        serde_json::from_str(&emit(&m, "sha256:dd", SbomFormat::CycloneDx, "pulseengine")).unwrap()
    }

    fn comp<'a>(doc: &'a serde_json::Value, digest: &str) -> &'a serde_json::Value {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["bom-ref"] == digest)
            .unwrap()
    }

    /// Clause 1: the supplier is the upstream organisation the signed repo
    /// annotation names. No repo, no supplier — never an invented one.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn each_component_names_the_upstream_that_supplied_it() {
        let doc = fields_doc();
        assert_eq!(
            comp(&doc, "sha256:aaaa")["supplier"],
            serde_json::json!({"name": "pulseengine", "url": ["https://github.com/pulseengine"]})
        );
        assert!(comp(&doc, "sha256:cccc").get("supplier").is_none());
    }

    /// Clause 2: the author is the realm whose root signed the layer.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn the_document_names_the_realm_that_signed_it_as_author() {
        let doc = fields_doc();
        let authors = doc["metadata"]["authors"].as_array().unwrap();
        assert_eq!(authors.len(), 1);
        assert!(
            authors[0]["name"].as_str().unwrap().contains("pulseengine"),
            "{authors:?}"
        );
    }

    /// Clause 3: the layer depends on every component, and nothing says a
    /// component has NO dependencies — that is stated as unknown.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn the_layer_depends_on_every_component_and_their_own_are_unknown() {
        let doc = fields_doc();
        assert_eq!(
            doc["dependencies"],
            serde_json::json!([{
                "ref": "sha256:dd",
                "dependsOn": ["sha256:aaaa", "sha256:bbbb", "sha256:cccc"]
            }])
        );
        assert_eq!(
            doc["compositions"],
            serde_json::json!([
                {"aggregate": "complete", "dependencies": ["sha256:dd"]},
                {"aggregate": "unknown", "dependencies": ["sha256:aaaa", "sha256:bbbb", "sha256:cccc"]}
            ])
        );
    }

    /// Clause 5: the license is upstream's DECLARED statement, said so.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_recorded_license_is_emitted_as_declared() {
        let doc = fields_doc();
        assert_eq!(
            comp(&doc, "sha256:aaaa")["licenses"],
            serde_json::json!([{"expression": "Apache-2.0 OR MIT", "acknowledgement": "declared"}])
        );
    }

    /// Clause 6: a layer deposited before licenses were recorded says so,
    /// rather than leaving a gap a reader takes for "no license".
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn an_unrecorded_license_is_said_to_be_unrecorded() {
        let doc = fields_doc();
        let c = comp(&doc, "sha256:bbbb");
        assert!(c.get("licenses").is_none());
        let props = c["properties"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "eu.pulseengine.varve.license"
                    && p["value"].as_str().unwrap().contains("not recorded")),
            "{props:?}"
        );
    }

    /// Clause 4: upstream's own SBOM is referenced, pinned by the digest the
    /// deposit saw.
    // rivet: verifies REQ-SBOMFIELDS-001
    #[test]
    fn a_recorded_upstream_sbom_is_referenced_with_its_digest() {
        let doc = fields_doc();
        let refs = comp(&doc, "sha256:aaaa")["externalReferences"]
            .as_array()
            .unwrap();
        assert!(
            refs.contains(&serde_json::json!({
                "type": "bom",
                "url": "https://github.com/pulseengine/kiln/releases/download/v0.5.0/kiln-0.5.0.cdx.json",
                "hashes": [{"alg": "SHA-256", "content": "5555555555555555555555555555555555555555555555555555555555555555"}]
            })),
            "{refs:?}"
        );
        assert!(
            !comp(&doc, "sha256:bbbb")["externalReferences"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["type"] == "bom")
        );
    }

    /// The serial number is a function of the layer digest, RFC 9562 v8
    /// shaped: version nibble 8, variant 10x. Pinned by value, not only by
    /// re-emission being stable, so a constant serial cannot pass.
    // rivet: verifies REQ-SBOM-001
    #[test]
    fn the_serial_number_is_derived_from_the_digest() {
        let digest = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert_eq!(
            uuid_from_digest(&digest),
            "01234567-89ab-8def-a123-456789abcdef"
        );
        assert_ne!(
            uuid_from_digest(&digest),
            uuid_from_digest(&format!("sha256:{}", "f".repeat(64)))
        );
    }
}
