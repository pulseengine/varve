//! Comparing two layers' payload sets (REQ-LAYERDIFF-001, DD-032).
//!
//! This lives in the LIBRARY, not in the CLI, for the reason `varve-serve`
//! states about its own move: the mutation gate's kill criteria are
//! `--workspace --lib`, so no mutant in a binary crate's module can ever be
//! killed. The finding this module computes — a payload that stopped being
//! vouched for — is what a CI gate refuses a toolchain bump on, and logic a
//! gate keys on does not belong somewhere the gate structurally cannot reach.
//!
//! `varve diff` renders what this returns; it decides nothing itself.

/// One payload of a layer, as its SIGNED manifest describes it.
///
/// The fields a comparison is entitled to look at, and no others — a row's
/// presentation (does it dispatch, is it on disk, what does its docs
/// annotation say) belongs to whatever is rendering, not to what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRow {
    pub name: String,
    pub version: Option<String>,
    pub kind: String,
    pub platform: String,
    pub target: Option<String>,
    pub digest: String,
    pub ingest_proof: String,
    /// The identity credited with vouching, where one is recorded.
    ///
    /// Compared, because `cosign-sums` signed by a DIFFERENT identity is the
    /// same proof mechanism making a different claim, and that is precisely
    /// the substitution a consumer pins a realm to notice.
    pub proof_signer: Option<String>,
    pub realm: String,
}

/// What makes two payloads the same payload across layers.
///
/// Version is deliberately NOT part of the identity — a version bump is the
/// change this command exists to report, and folding it into the key would
/// turn every bump into an unrelated add plus an unrelated remove.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub realm: String,
    pub kind: String,
    pub name: String,
    pub platform: String,
    pub target: Option<String>,
}

pub fn key_of(r: &PayloadRow) -> Key {
    Key {
        realm: r.realm.clone(),
        kind: r.kind.clone(),
        name: r.name.clone(),
        platform: r.platform.clone(),
        target: r.target.clone(),
    }
}

/// What a payload's recorded proof says about whether anything vouched for it.
///
/// Deliberately NOT a rank. `IngestProof::is_verified` documents why:
/// `cosign-sums` and `build-provenance` are both accepted proofs carrying
/// different claims, and varve does not collapse that distinction for the
/// consumer. So this classifies only into the states a FINDING can rest on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vouch {
    /// Something vouched for these bytes.
    Verified,
    /// Explicitly nothing did, with a recorded operator reason.
    Unverified,
    /// The layer predates REQ-INGEST-001. Absence of a claim is not a claim.
    Unrecorded,
    /// A proof mechanism this varve does not know. Not guessed about.
    Unknown,
}

pub fn vouch(label: &str) -> Vouch {
    use crate::IngestProof as P;
    match label {
        l if l == P::CosignSums.as_str()
            || l == P::BuildProvenance.as_str()
            || l == P::UpstreamSums.as_str() =>
        {
            Vouch::Verified
        }
        l if l == P::Unverified.as_str() => Vouch::Unverified,
        "unrecorded" => Vouch::Unrecorded,
        _ => Vouch::Unknown,
    }
}

/// Which attributes of one payload moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub key: Key,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub from_digest: String,
    pub to_digest: String,
    pub from_proof: String,
    pub to_proof: String,
    pub from_signer: Option<String>,
    pub to_signer: Option<String>,
}

impl Changed {
    pub fn version_moved(&self) -> bool {
        self.from_version != self.to_version
    }
    pub fn proof_moved(&self) -> bool {
        self.from_proof != self.to_proof
    }
    pub fn signer_moved(&self) -> bool {
        self.from_signer != self.to_signer
    }
}

/// Something an operator must not have to find by reading rows.
///
/// Clause 5: the ingestion proof travels into the diff, and a payload that
/// stopped being vouched for is a more consequential change than any version
/// bump in the same table. It is reported separately so a renderer cannot
/// bury it, and so a CI gate has something to key on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Was vouched for; is now explicitly vouched for by nothing.
    LostProofOfOrigin { key: Key, from: String },
    /// Was vouched for; the newer layer records no proof at all.
    StoppedRecordingProof { key: Key, from: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delta {
    pub added: Vec<PayloadRow>,
    pub removed: Vec<PayloadRow>,
    pub changed: Vec<Changed>,
    pub findings: Vec<Finding>,
}

impl Delta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Compare two layers' payload sets.
///
/// Keyed order throughout, so two runs — and two machines — agree, which is
/// what lets a CI gate compare this output against a previous one.
pub fn delta(from: &[PayloadRow], to: &[PayloadRow]) -> Delta {
    use std::collections::BTreeMap;
    let index = |rows: &[PayloadRow]| -> BTreeMap<Key, PayloadRow> {
        rows.iter().map(|r| (key_of(r), r.clone())).collect()
    };
    let (a, b) = (index(from), index(to));
    let mut d = Delta::default();

    for (k, to_row) in &b {
        let Some(from_row) = a.get(k) else {
            d.added.push(to_row.clone());
            continue;
        };
        if from_row.version != to_row.version
            || from_row.digest != to_row.digest
            || from_row.ingest_proof != to_row.ingest_proof
            || from_row.proof_signer != to_row.proof_signer
        {
            d.changed.push(Changed {
                key: k.clone(),
                from_version: from_row.version.clone(),
                to_version: to_row.version.clone(),
                from_digest: from_row.digest.clone(),
                to_digest: to_row.digest.clone(),
                from_proof: from_row.ingest_proof.clone(),
                to_proof: to_row.ingest_proof.clone(),
                from_signer: from_row.proof_signer.clone(),
                to_signer: to_row.proof_signer.clone(),
            });
        }
        // A finding rests only on the distinction varve-core sanctions:
        // something vouched for these bytes, and now nothing does. Moving
        // between two accepted proofs is a change and never a finding, and an
        // unknown mechanism is not judged in either direction.
        if vouch(&from_row.ingest_proof) == Vouch::Verified {
            let f = match vouch(&to_row.ingest_proof) {
                Vouch::Unverified => Some(Finding::LostProofOfOrigin {
                    key: k.clone(),
                    from: from_row.ingest_proof.clone(),
                }),
                Vouch::Unrecorded => Some(Finding::StoppedRecordingProof {
                    key: k.clone(),
                    from: from_row.ingest_proof.clone(),
                }),
                Vouch::Verified | Vouch::Unknown => None,
            };
            d.findings.extend(f);
        }
    }
    for (k, from_row) in &a {
        if !b.contains_key(k) {
            d.removed.push(from_row.clone());
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, version: &str, proof: &str) -> PayloadRow {
        PayloadRow {
            name: name.to_string(),
            version: Some(version.to_string()),
            kind: "tool".to_string(),
            platform: "x86_64-unknown-linux-gnu".to_string(),
            target: None,
            digest: format!("sha256:{name}-{version}"),
            ingest_proof: proof.to_string(),
            proof_signer: Some("pulseengine/rivet".to_string()),
            realm: "pulseengine".to_string(),
        }
    }

    fn on(mut r: PayloadRow, platform: &str) -> PayloadRow {
        r.platform = platform.to_string();
        r
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_only_in_the_newer_layer_is_added() {
        let d = delta(
            &[row("rivet", "0.39.0", "cosign-sums")],
            &[
                row("rivet", "0.39.0", "cosign-sums"),
                row("wac", "0.11.0", "unverified"),
            ],
        );
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "wac");
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_only_in_the_older_layer_is_removed() {
        let d = delta(
            &[
                row("rivet", "0.39.0", "cosign-sums"),
                row("kilnd", "0.5.0", "cosign-sums"),
            ],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].name, "kilnd");
        assert!(d.added.is_empty());
    }

    /// The whole reason version is not part of `Key`.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_version_bump_is_one_changed_row_not_an_add_and_a_remove() {
        let d = delta(
            &[row("synth", "0.74.0", "cosign-sums")],
            &[row("synth", "0.75.0", "cosign-sums")],
        );
        assert!(
            d.added.is_empty() && d.removed.is_empty(),
            "a version bump was reported as an unrelated add and remove: {d:?}"
        );
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].version_moved());
        assert_eq!(d.changed[0].from_version.as_deref(), Some("0.74.0"));
        assert_eq!(d.changed[0].to_version.as_deref(), Some("0.75.0"));
    }

    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn an_unchanged_payload_appears_nowhere() {
        let d = delta(
            &[row("rivet", "0.39.0", "cosign-sums")],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert!(d.is_empty(), "an identical layer produced a delta: {d:?}");
        assert!(d.findings.is_empty());
    }

    /// Clause 5. This is the headline a bump can carry.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_payload_that_lost_its_proof_of_origin_is_a_finding() {
        let d = delta(
            &[row("wac", "0.11.0", "cosign-sums")],
            &[row("wac", "0.12.0", "unverified")],
        );
        assert_eq!(
            d.findings.len(),
            1,
            "losing a proof of origin was not reported as a finding: {d:?}"
        );
        match &d.findings[0] {
            Finding::LostProofOfOrigin { key, from } => {
                assert_eq!(key.name, "wac");
                assert_eq!(from, "cosign-sums");
            }
            other => panic!("wrong finding: {other:?}"),
        }
    }

    /// Negative control on the rule varve-core documents: `cosign-sums` and
    /// `build-provenance` are both accepted proofs and varve does not rank
    /// them. Reporting a finding here would be inventing a judgement.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_move_between_two_accepted_proofs_is_a_change_but_never_a_finding() {
        let d = delta(
            &[row("rivet", "0.39.0", "build-provenance")],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].proof_moved());
        assert!(
            d.findings.is_empty(),
            "varve ranked two accepted proofs against each other: {d:?}"
        );
    }

    /// Absence of a claim is not a claim — so gaining one is not a loss.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn unrecorded_becoming_unverified_is_not_a_loss() {
        let d = delta(
            &[row("wkg", "0.4.0", "unrecorded")],
            &[row("wkg", "0.4.0", "unverified")],
        );
        assert!(
            d.findings.is_empty(),
            "a layer that predates the requirement was treated as having lost something: {d:?}"
        );
    }

    /// …but a layer that HAD a proof and now records none has lost one.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_recorded_proof_becoming_unrecorded_is_a_finding() {
        let d = delta(
            &[row("wkg", "0.4.0", "cosign-sums")],
            &[row("wkg", "0.4.0", "unrecorded")],
        );
        assert!(matches!(
            d.findings.as_slice(),
            [Finding::StoppedRecordingProof { .. }]
        ));
    }

    /// One tool on two platforms is two payloads: bumping one must not read
    /// as bumping the tool.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn the_same_tool_on_two_platforms_is_two_payloads() {
        let linux = row("synth", "0.74.0", "cosign-sums");
        let mac = on(
            row("synth", "0.74.0", "cosign-sums"),
            "aarch64-apple-darwin",
        );
        let linux_new = row("synth", "0.75.0", "cosign-sums");
        let d = delta(&[linux, mac.clone()], &[linux_new, mac]);
        assert_eq!(d.changed.len(), 1, "both platforms moved: {d:?}");
        assert_eq!(
            d.changed[0].key.platform, "x86_64-unknown-linux-gnu",
            "the wrong platform was reported as the one that moved"
        );
    }

    /// An unknown proof mechanism is not guessed about in either direction.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn an_unknown_proof_mechanism_produces_no_finding() {
        let d = delta(
            &[row("wac", "0.11.0", "notarised-by-something-new")],
            &[row("wac", "0.11.0", "unverified")],
        );
        assert!(
            d.findings.is_empty(),
            "varve judged a proof mechanism it does not know: {d:?}"
        );
    }

    /// The same proof mechanism under a different identity is a change.
    ///
    /// Deliberately NOT a finding: whether "cosign-sums, but signed by
    /// someone else" should refuse a bump is a policy question for the
    /// consumer, and `--json` carries both identities so a gate can decide.
    /// varve reports the move and does not judge it.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_change_of_vouching_identity_is_reported() {
        let mut moved = row("rivet", "0.39.0", "cosign-sums");
        moved.proof_signer = Some("someone-else/rivet".to_string());
        let d = delta(&[row("rivet", "0.39.0", "cosign-sums")], &[moved]);
        assert_eq!(
            d.changed.len(),
            1,
            "the vouching identity changed and nothing reported it: {d:?}"
        );
        assert!(d.changed[0].signer_moved());
        assert!(!d.changed[0].version_moved() && !d.changed[0].proof_moved());
        assert!(d.findings.is_empty(), "varve judged a signer change: {d:?}");
    }

    /// Every label, pinned individually.
    ///
    /// The mutation gate reached this file the moment it moved into the lib
    /// and reported `replace || with && in vouch` as a survivor: the tests
    /// exercised `vouch` only through `delta`, which never distinguished the
    /// three accepted proofs from each other.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn every_proof_label_classifies_on_its_own() {
        for l in ["cosign-sums", "build-provenance", "upstream-sums"] {
            assert_eq!(vouch(l), Vouch::Verified, "{l} must count as vouched for");
        }
        assert_eq!(vouch("unverified"), Vouch::Unverified);
        assert_eq!(vouch("unrecorded"), Vouch::Unrecorded);
        assert_eq!(vouch("notarised-by-something-new"), Vouch::Unknown);
        assert_eq!(vouch(""), Vouch::Unknown);
    }

    /// Bytes replaced under an unchanged version — the case a version
    /// comparison cannot see, and the one a consumer most needs told.
    ///
    /// Also a fixture defect the gate caught: `row()` derives the digest FROM
    /// the version, so every earlier test moved both at once and no test could
    /// tell which of them `delta` was actually keying on.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_digest_that_moved_under_an_unchanged_version_is_a_change() {
        let mut repointed = row("rivet", "0.39.0", "cosign-sums");
        repointed.digest = "sha256:different-bytes-same-version".to_string();
        let d = delta(&[row("rivet", "0.39.0", "cosign-sums")], &[repointed]);
        assert_eq!(
            d.changed.len(),
            1,
            "the bytes changed under the same version and nothing reported it: {d:?}"
        );
        assert!(!d.changed[0].version_moved());
    }

    /// A version that moved with the digest held fixed. Together with the
    /// test above this pins each operand of the change condition on its own.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_version_that_moved_under_an_unchanged_digest_is_a_change() {
        let mut relabelled = row("rivet", "0.40.0", "cosign-sums");
        relabelled.digest = row("rivet", "0.39.0", "cosign-sums").digest;
        let d = delta(&[row("rivet", "0.39.0", "cosign-sums")], &[relabelled]);
        assert_eq!(d.changed.len(), 1);
        assert!(d.changed[0].version_moved());
    }

    /// An unchanged payload moves nothing — the false half of each predicate.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn nothing_moved_means_every_predicate_is_false() {
        let d = delta(
            &[row("rivet", "0.39.0", "cosign-sums")],
            &[row("rivet", "0.39.0", "cosign-sums")],
        );
        assert!(d.changed.is_empty());
        let same = Changed {
            key: key_of(&row("rivet", "0.39.0", "cosign-sums")),
            from_version: Some("0.39.0".into()),
            to_version: Some("0.39.0".into()),
            from_digest: "sha256:a".into(),
            to_digest: "sha256:a".into(),
            from_proof: "cosign-sums".into(),
            to_proof: "cosign-sums".into(),
            from_signer: Some("pulseengine/rivet".into()),
            to_signer: Some("pulseengine/rivet".into()),
        };
        assert!(!same.version_moved());
        assert!(!same.proof_moved());
        assert!(!same.signer_moved());
    }

    /// `is_empty` is three conditions, and each has to be able to say no.
    // rivet: verifies REQ-LAYERDIFF-001
    #[test]
    fn a_delta_with_anything_in_it_is_not_empty() {
        let base = row("rivet", "0.39.0", "cosign-sums");
        let added = delta(&[], std::slice::from_ref(&base));
        assert!(!added.is_empty(), "an added payload read as no change");
        let removed = delta(std::slice::from_ref(&base), &[]);
        assert!(!removed.is_empty(), "a removed payload read as no change");
        let changed = delta(
            std::slice::from_ref(&base),
            &[row("rivet", "0.40.0", "cosign-sums")],
        );
        assert!(!changed.is_empty(), "a changed payload read as no change");
        let same = std::slice::from_ref(&base);
        assert!(delta(same, same).is_empty());
    }
}
