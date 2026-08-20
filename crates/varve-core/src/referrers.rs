//! What signed work an OCI image layout already carries (REQ-NODESTROY-001).
//!
//! A layout is append-only by convention and rewritable by construction:
//! `deposit` writes the whole thing, `index.json` included, so a second
//! `--out` at the same directory dropped the baseline line-status, the signed
//! line-index and every attestation attached since — and reported success in
//! a message byte-identical to a clean run. Three docs topics warned about it;
//! zero lines of code guarded it, and an own-realm operator hit it by
//! accident. For a realm declaring `signed-index = true` the blast radius is
//! total: every consumer install afterwards fails closed.
//!
//! This module is the inventory the guard refuses on. It answers one question
//! — *what would be destroyed?* — and it answers it by NAME, because a refusal
//! that does not say what it found leaves the operator guessing which artifact
//! they nearly lost.
//!
//! ## Unknown referrers count
//!
//! Every index entry carrying an `artifactType` other than the deposit's own
//! signature entry is a referrer, whether or not this version of varve knows
//! what it is. A guard enumerating only the three referrer kinds that exist
//! today would silently stop protecting the fourth one added tomorrow — the
//! same shape of silent loss the guard exists to prevent.

use std::path::Path;

/// The signed work a layout already carries, as an inventory to name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarriedWork {
    /// Lines named by attached line-status documents.
    pub line_status: Vec<String>,
    /// Lines named by attached line-index documents.
    pub line_index: Vec<String>,
    /// Attestation statements travelling with the layer.
    pub attestations: usize,
    /// The attested bytes travelling beside those statements.
    pub attestation_blobs: usize,
    /// Referrer artifact types this version of varve does not recognise.
    pub other: Vec<String>,
    /// `index.json` is there and could not be read — so what the layout
    /// carries could not be ESTABLISHED. Reporting "carries nothing" here
    /// would be an absence nobody checked.
    pub unreadable: Option<String>,
}

impl CarriedWork {
    /// Would overwriting this layout destroy anything?
    pub fn is_empty(&self) -> bool {
        self.line_status.is_empty()
            && self.line_index.is_empty()
            && self.attestations == 0
            && self.attestation_blobs == 0
            && self.other.is_empty()
            && self.unreadable.is_none()
    }

    /// The inventory, in prose, for the refusal message.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for line in &self.line_status {
            parts.push(format!("a baseline line-status for {line}"));
        }
        for line in &self.line_index {
            parts.push(format!("a signed line-index for {line}"));
        }
        if self.attestations > 0 {
            parts.push(format!(
                "{} carried attestation{}",
                self.attestations,
                plural(self.attestations)
            ));
        } else if self.attestation_blobs > 0 {
            parts.push(format!(
                "{} attestation blob{}",
                self.attestation_blobs,
                plural(self.attestation_blobs)
            ));
        }
        for kind in &self.other {
            parts.push(format!("a referrer of type '{kind}'"));
        }
        if let Some(reason) = &self.unreadable {
            parts.push(format!(
                "an index.json this varve cannot read ({reason}), so what it carries could not \
                 be established"
            ));
        }
        if parts.is_empty() {
            return "nothing".to_string();
        }
        parts.join(", ")
    }

    /// The re-attach sequence for exactly what was found, so the operator
    /// recovers from the MESSAGE rather than from the docs. The docs already
    /// said it three times over and it still happened.
    pub fn recovery(&self, dest: &str) -> String {
        let mut lines: Vec<String> = Vec::new();
        for _ in &self.line_status {
            lines.push(
                "  varve sign-status --file <status.json> --key <KEYFILE> --out <status.dsse>"
                    .to_string(),
            );
            lines.push(format!(
                "  varve attach-status --layout {dest} --status <status.dsse>"
            ));
        }
        for _ in &self.line_index {
            lines.push(
                "  varve sign-index --file <index.json> --key <KEYFILE> --out <index.dsse>"
                    .to_string(),
            );
            lines.push(format!(
                "  varve attach-index --layout {dest} --index <index.dsse>"
            ));
        }
        if self.attestations > 0 || self.attestation_blobs > 0 {
            lines.push(format!(
                "  varve sign-attestation --kind <kind> --file <evidence> --key <KEYFILE> \
                 --out <statement> --attach-to {dest}   (once per attestation; the layer must \
                 be installed first)"
            ));
        }
        if lines.is_empty() {
            return String::new();
        }
        format!("{}\n", lines.join("\n"))
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// A write refused because it would have destroyed signed work
/// (REQ-NODESTROY-001 clauses 1, 3 and 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WouldDestroy {
    pub dest: String,
    pub found: String,
    pub recover: String,
}

impl std::fmt::Display for WouldDestroy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let WouldDestroy {
            dest,
            found,
            recover,
        } = self;
        write!(
            f,
            "refusing to write a layout into {dest}: it already carries signed work this would \
             destroy — {found}. Writing a layout rewrites index.json wholesale, so every \
             referrer above would be dropped and nothing would say so; for a realm declaring \
             `signed-index = true` every consumer install afterwards fails closed. Nothing has \
             been written — {dest} is byte-identical to what it was. Write into a FRESH \
             directory, or write there and re-attach:\n{recover}\
             Re-run with --force to overwrite the layout and drop them deliberately."
        )
    }
}

impl std::error::Error for WouldDestroy {}

/// The single question every layout writer asks before it touches anything.
///
/// Clause 4 — "the same guard shall apply to any other command that writes a
/// layout in place" — is met structurally rather than by repetition: this is
/// called from `archive::write_oci_layout`, which is the ONLY code in varve
/// that writes a layout. A command that starts writing layouts tomorrow
/// inherits the guard by construction, and cannot forget it.
pub fn guard(dest: &Path, force: bool) -> Result<(), WouldDestroy> {
    if force {
        return Ok(());
    }
    let carried = scan(dest);
    if carried.is_empty() {
        return Ok(());
    }
    let dest = dest.display().to_string();
    Err(WouldDestroy {
        found: carried.describe(),
        recover: carried.recovery(&dest),
        dest,
    })
}

/// Take stock of a layout without touching it.
///
/// An absent `index.json` is an empty layout — the ordinary case of depositing
/// into a fresh directory, and not an error. An index.json that is present and
/// unreadable is recorded as such, never as "carries nothing": the guard must
/// not report an absence it never established.
pub fn scan(layout: &Path) -> CarriedWork {
    let index_path = layout.join("index.json");
    let bytes = match std::fs::read(&index_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CarriedWork::default(),
        Err(source) => {
            return CarriedWork {
                unreadable: Some(source.to_string()),
                ..CarriedWork::default()
            };
        }
    };
    let index: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(index) => index,
        Err(e) => {
            return CarriedWork {
                unreadable: Some(e.to_string()),
                ..CarriedWork::default()
            };
        }
    };
    let Some(entries) = index["manifests"].as_array() else {
        // A layout with an index.json that has no manifests array is not one
        // varve wrote. It holds no referrer we can name, and it is not the
        // append-only artifact this guard protects.
        return CarriedWork::default();
    };

    let mut work = CarriedWork::default();
    for entry in entries {
        // No artifactType: the layer manifest entry deposit writes itself.
        let Some(kind) = entry["artifactType"].as_str() else {
            continue;
        };
        match kind {
            // The deposit's own signature blob travels INSIDE the layout, not
            // beside it. Overwriting it is what a re-deposit is for.
            crate::archive::SIGNATURE_ARTIFACT_TYPE => {}
            crate::linestatus::LINE_STATUS_ARTIFACT_TYPE => work.line_status.push(
                entry["annotations"][crate::linestatus::ANN_LINE]
                    .as_str()
                    .unwrap_or("an unnamed line")
                    .to_string(),
            ),
            crate::lineindex::LINE_INDEX_ARTIFACT_TYPE => work.line_index.push(
                entry["annotations"][crate::lineindex::ANN_INDEX_LINE]
                    .as_str()
                    .unwrap_or("an unnamed line")
                    .to_string(),
            ),
            crate::attestcarry::STATEMENT_ARTIFACT_TYPE => work.attestations += 1,
            crate::attestcarry::ATTESTATION_ARTIFACT_TYPE => work.attestation_blobs += 1,
            // See the module note: a referrer kind varve does not recognise is
            // still somebody's signed work.
            other => {
                if !work.other.iter().any(|k| k == other) {
                    work.other.push(other.to_string());
                }
            }
        }
    }
    work
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_with(entries: serde_json::Value) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("index.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 2,
                "manifests": entries,
            }))
            .unwrap(),
        )
        .unwrap();
        tmp
    }

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn a_freshly_deposited_layout_carries_nothing_to_destroy() {
        // The guard must not turn "deposit into a directory you already used
        // for a clean deposit" into an error — only signed work ATTACHED
        // afterwards is what may not be dropped. A guard that fires on the
        // layout deposit writes itself would make re-running CI impossible and
        // get switched off.
        let tmp = layout_with(serde_json::json!([
            { "mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:aa" },
            {
                "mediaType": "application/json",
                "artifactType": crate::archive::SIGNATURE_ARTIFACT_TYPE,
                "digest": "sha256:bb",
            },
        ]));
        let work = scan(tmp.path());
        assert!(work.is_empty(), "{work:?}");
        assert_eq!(work.describe(), "nothing");
        assert_eq!(work.recovery("/out"), "");
    }

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn an_absent_layout_carries_nothing_and_an_unreadable_one_is_not_silently_empty() {
        // The two failures must not look alike. A fresh directory is the
        // ordinary case; an index.json present and unreadable is an absence
        // NOBODY ESTABLISHED, and answering "carries nothing" there is exactly
        // the silent drop this guard exists to prevent.
        let empty = tempfile::tempdir().unwrap();
        assert!(scan(empty.path()).is_empty());

        let broken = tempfile::tempdir().unwrap();
        std::fs::write(broken.path().join("index.json"), b"{not json").unwrap();
        let work = scan(broken.path());
        assert!(
            !work.is_empty(),
            "an unreadable index must not read back as 'carries nothing'"
        );
        assert!(work.describe().contains("could not be established"));
    }

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn every_referrer_kind_is_named_including_one_varve_does_not_know() {
        // Naming is the whole job: "refused" without the inventory leaves the
        // operator guessing. And the unknown-type arm is what keeps the guard
        // protecting a referrer kind added after this code was written —
        // enumerating only today's three would silently stop guarding the
        // fourth.
        let tmp = layout_with(serde_json::json!([
            {
                "artifactType": crate::linestatus::LINE_STATUS_ARTIFACT_TYPE,
                "digest": "sha256:aa",
                "annotations": { crate::linestatus::ANN_LINE: "2026.08" },
            },
            {
                "artifactType": crate::lineindex::LINE_INDEX_ARTIFACT_TYPE,
                "digest": "sha256:bb",
                "annotations": { crate::lineindex::ANN_INDEX_LINE: "2026.08" },
            },
            {
                "artifactType": crate::attestcarry::STATEMENT_ARTIFACT_TYPE,
                "digest": "sha256:cc",
            },
            {
                "artifactType": crate::attestcarry::ATTESTATION_ARTIFACT_TYPE,
                "digest": "sha256:dd",
            },
            { "artifactType": "application/vnd.someone.invented.this.v1", "digest": "sha256:ee" },
        ]));
        let work = scan(tmp.path());
        assert_eq!(work.line_status, vec!["2026.08".to_string()]);
        assert_eq!(work.line_index, vec!["2026.08".to_string()]);
        assert_eq!(work.attestations, 1);
        assert_eq!(work.attestation_blobs, 1);
        assert_eq!(
            work.other,
            vec!["application/vnd.someone.invented.this.v1".to_string()]
        );
        assert!(!work.is_empty());

        let described = work.describe();
        for expected in [
            "a baseline line-status for 2026.08",
            "a signed line-index for 2026.08",
            "1 carried attestation",
            "application/vnd.someone.invented.this.v1",
        ] {
            assert!(described.contains(expected), "{described}");
        }

        // The recovery sequence covers exactly what was found, naming the
        // destination so it can be pasted.
        let recovery = work.recovery("/tmp/layout");
        for expected in [
            "varve sign-status --file",
            "varve attach-status --layout /tmp/layout",
            "varve sign-index --file",
            "varve attach-index --layout /tmp/layout",
            "--attach-to /tmp/layout",
        ] {
            assert!(recovery.contains(expected), "{recovery}");
        }
    }

    // rivet: verifies REQ-NODESTROY-001
    #[test]
    fn an_attestation_that_lost_its_statement_still_counts_as_work() {
        // Half an attestation is still somebody's evidence, and a guard that
        // counted only statements would let a re-deposit drop the bytes of one
        // whose statement had already gone missing — losing the last copy.
        let tmp = layout_with(serde_json::json!([
            {
                "artifactType": crate::attestcarry::ATTESTATION_ARTIFACT_TYPE,
                "digest": "sha256:dd",
            },
        ]));
        let work = scan(tmp.path());
        assert!(!work.is_empty());
        assert!(work.describe().contains("1 attestation blob"), "{work:?}");
        assert!(work.recovery("/out").contains("sign-attestation"));
    }
}
