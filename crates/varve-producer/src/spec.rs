//! Emitting the deposit spec (REQ-PRODUCER-002).
//!
//! The assembler's output is a TOML document that `varve deposit` reads. The
//! shell built it with `cat >> spec <<TOMLEOF` and a hand-written escaper,
//! which is two failure modes in one: a value containing a quote or a
//! backslash corrupts the document, and a document that fails to parse is only
//! discovered after every asset has been downloaded and verified — at the last
//! step before signing.
//!
//! Here the spec is a typed structure serialised by the `toml` crate, so
//! escaping is not our problem, and every test round-trips through
//! [`varve_core::parse_deposit_spec`] — the REAL parser `varve deposit` uses.
//! A test against a re-implementation of that parser would prove nothing; this
//! is the same reasoning that moved the assembler's system gate onto the
//! production script.

use serde::Serialize;

/// One payload's upstream provenance, including which mechanism vouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceOut {
    pub repo: String,
    pub release: String,
    pub asset: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// ABSENT when there is no signer, never `""`.
    ///
    /// An empty string here would be a signed claim that somebody vouched and
    /// declined to say who — and `varve deposit` refuses a signer on an
    /// `unverified` payload for exactly that reason.
    #[serde(rename = "proof-signer", skip_serializing_if = "Option::is_none")]
    pub proof_signer: Option<String>,
    #[serde(rename = "proof-asserts", skip_serializing_if = "Option::is_none")]
    pub proof_asserts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolOut {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub source: SourceOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncludeOut {
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecOut {
    pub layer: String,
    pub channel: String,
    pub counter: u64,
    #[serde(rename = "tool", skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolOut>,
    #[serde(rename = "include", skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<IncludeOut>,
}

impl SpecOut {
    pub fn new(layer: &str, channel: &str, counter: u64) -> Self {
        SpecOut {
            layer: layer.to_string(),
            channel: channel.to_string(),
            counter,
            tools: Vec::new(),
            includes: Vec::new(),
        }
    }

    /// Serialise, and REFUSE to hand back a document the real parser rejects.
    ///
    /// The check is here rather than at the call site because the expensive,
    /// irreversible work — download, verify, deposit, sign — happens after
    /// this point. A spec that cannot parse must fail now, not at the step
    /// where the signing key is already in memory.
    pub fn render(&self) -> anyhow::Result<String> {
        let text = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("cannot serialise the deposit spec: {e}"))?;
        varve_core::parse_deposit_spec(&text).map_err(|e| {
            anyhow::anyhow!(
                "the assembler produced a deposit spec that `varve deposit` \
                 cannot read: {e}\n--- spec ---\n{text}"
            )
        })?;
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SourceOut {
        SourceOut {
            repo: "pulseengine/rivet".into(),
            release: "v0.34.0".into(),
            asset: "rivet-v0.34.0-aarch64-apple-darwin.tar.gz".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            proof: Some("cosign-sums".into()),
            proof_signer: Some("https://github.com/pulseengine/rivet/".into()),
            proof_asserts: Some("SHA256SUMS.txt signed by an identity under …".into()),
        }
    }

    fn tool() -> ToolOut {
        ToolOut {
            name: "rivet".into(),
            version: "0.34.0".into(),
            platform: Some("aarch64-apple-darwin".into()),
            path: "tools/rivet-aarch64-apple-darwin".into(),
            kind: None,
            source: src(),
        }
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_rendered_spec_is_accepted_by_the_real_parser() {
        let mut spec = SpecOut::new("2026.08.4", "rolling", 5);
        spec.tools.push(tool());
        let text = spec.render().expect("renders and parses");
        let parsed = varve_core::parse_deposit_spec(&text).expect("parses");
        assert_eq!(parsed.layer, "2026.08.4");
        assert_eq!(parsed.channel, "rolling");
        assert_eq!(parsed.counter, 5);
        assert_eq!(parsed.tools.len(), 1);
        let t = &parsed.tools[0];
        assert_eq!(t.name, "rivet");
        assert_eq!(t.platform.as_deref(), Some("aarch64-apple-darwin"));
        let s = t.source.as_ref().expect("source survives the round trip");
        assert_eq!(s.repo, "pulseengine/rivet");
        assert_eq!(
            s.proof_signer.as_deref(),
            Some("https://github.com/pulseengine/rivet/")
        );
    }

    /// The shell escaped TOML by hand. A reason containing a quote, a
    /// backslash or a newline is exactly what an operator writes, and it must
    /// not be able to corrupt the document — or worse, close the string and
    /// have the remainder read as TOML.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_operator_reason_full_of_metacharacters_survives_intact() {
        let nasty = "upstream said \"Q3\"; path C:\\tmp\\x, newline ->\n<- and a ] bracket";
        let mut spec = SpecOut::new("2026.08.4", "rolling", 5);
        let mut t = tool();
        t.source.proof = Some("unverified".into());
        t.source.proof_signer = None;
        t.source.proof_asserts = Some(nasty.to_string());
        spec.tools.push(t);
        let text = spec.render().expect("renders and parses");
        let parsed = varve_core::parse_deposit_spec(&text).expect("parses");
        let s = parsed.tools[0].source.as_ref().unwrap();
        assert_eq!(s.proof_asserts.as_deref(), Some(nasty));
    }

    /// `proof-signer = ""` would be a signed claim that somebody vouched and
    /// declined to say who. It must be ABSENT, not empty.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_unverified_payload_omits_the_signer_rather_than_emitting_an_empty_one() {
        let mut spec = SpecOut::new("2026.08.4", "rolling", 5);
        let mut t = tool();
        t.source.proof = Some("unverified".into());
        t.source.proof_signer = None;
        t.source.proof_asserts = Some("nothing vouched; reason: fork tracked in #77".into());
        spec.tools.push(t);
        let text = spec.render().expect("renders");
        assert!(!text.contains("proof-signer"), "{text}");
        let parsed = varve_core::parse_deposit_spec(&text).unwrap();
        assert!(
            parsed.tools[0]
                .source
                .as_ref()
                .unwrap()
                .proof_signer
                .is_none()
        );
    }

    /// A platform-independent payload must omit `platform`, not emit `""` —
    /// an empty triple is not a claim varve can act on.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_portable_payload_omits_the_platform() {
        let mut spec = SpecOut::new("2026.08.4", "rolling", 5);
        let mut t = tool();
        t.platform = None;
        t.kind = Some("vsix".into());
        spec.tools.push(t);
        let text = spec.render().expect("renders");
        assert!(!text.contains("platform"), "{text}");
        let parsed = varve_core::parse_deposit_spec(&text).unwrap();
        assert!(parsed.tools[0].platform.is_none());
        assert_eq!(parsed.tools[0].kind.as_deref(), Some("vsix"));
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn composed_layers_round_trip_as_includes() {
        let mut spec = SpecOut::new("2026.08.4", "rolling", 5);
        spec.tools.push(tool());
        spec.includes.push(IncludeOut {
            digest: "sha256:abc".into(),
            realm: Some("bytecodealliance".into()),
            layer: Some("1.257.1".into()),
        });
        let text = spec.render().expect("renders");
        let parsed = varve_core::parse_deposit_spec(&text).unwrap();
        assert_eq!(parsed.includes.len(), 1);
        assert_eq!(
            parsed.includes[0].realm.as_deref(),
            Some("bytecodealliance")
        );
    }

    /// A spec with no payloads at all still has to be a document the parser
    /// accepts, so the failure surfaces as varve's own refusal rather than as
    /// a TOML error the operator has to decode.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_empty_spec_still_parses_so_varve_can_refuse_it_on_its_own_terms() {
        let text = SpecOut::new("2026.08.4", "rolling", 5)
            .render()
            .expect("renders");
        let parsed = varve_core::parse_deposit_spec(&text).unwrap();
        assert!(parsed.tools.is_empty());
    }
}
