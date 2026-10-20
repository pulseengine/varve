//! Preparing the NEXT line-status document from advisory findings, and
//! deciding whether a registry needs republishing (REQ-ADVISORYWATCH-001
//! clause 3, REQ-POSTDEPOSIT-001).
//!
//! Two pure decisions live here, both deliberately network-free:
//!
//!   * [`next_document`] — given the line's CURRENT signed status and a batch
//!     of advisory findings the watcher collected, decide what the next
//!     document should say. It never signs and never publishes; the PR body
//!     merging signs and publishes is a human decision this module only
//!     prepares.
//!   * [`reconcile`] — given the layer repository's committed status (source
//!     of truth) and what the registry currently serves, decide whether the
//!     publish-on-merge job has anything to do, and refuse to guess when two
//!     documents disagree at the same counter.

use varve_core::{KnownProblem, LayerId, Line, LineStatus};

/// One advisory and the layers of THIS line it affects, as the watcher found
/// it — not yet a [`KnownProblem`], because an alias match may fold it into
/// one that already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposed {
    pub id: String,
    pub aliases: Vec<String>,
    pub title: String,
    pub severity: String,
    pub affected: Vec<String>,
    pub workaround: Option<String>,
}

/// Why a proposed finding could not become a draft.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// Mirrors why `varve sign-status` refuses an `affected` id that is not a
    /// layer of the line (varve#61): an id outside the shape `<line>.<n>`
    /// signs cleanly and then fires for nobody.
    #[error(
        "finding '{finding}' names '{id}' as affected, which is not a layer of line {line}: {reason}"
    )]
    NotALayerOfLine {
        finding: String,
        id: String,
        line: String,
        reason: String,
    },
    /// Severity is load-bearing for `varve status` output; a typo must not
    /// silently become some default severity.
    #[error(
        "finding '{finding}' has severity '{got}', which is not one of critical/high/medium/low"
    )]
    BadSeverity { finding: String, got: String },
}

const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Normalise and validate one finding's severity (clause 7): lowercase, and
/// one of the four recognised levels — anything else is an error, never a
/// silent default.
fn normalised_severity(finding: &str, severity: &str) -> Result<String, DraftError> {
    let lower = severity.to_ascii_lowercase();
    if SEVERITIES.contains(&lower.as_str()) {
        Ok(lower)
    } else {
        Err(DraftError::BadSeverity {
            finding: finding.to_string(),
            got: severity.to_string(),
        })
    }
}

/// Check one `affected` id is a well-formed layer of `line` (clause 6),
/// mirroring `LineStatus::check_layer_refs`'s own shape-and-membership check.
fn check_affected(finding: &str, id: &str, line: &Line) -> Result<(), DraftError> {
    match id.parse::<LayerId>() {
        Ok(layer) if layer.line() == line => Ok(()),
        Ok(layer) => Err(DraftError::NotALayerOfLine {
            finding: finding.to_string(),
            id: id.to_string(),
            line: line.to_string(),
            reason: format!("it belongs to line {}", layer.line()),
        }),
        Err(e) => Err(DraftError::NotALayerOfLine {
            finding: finding.to_string(),
            id: id.to_string(),
            line: line.to_string(),
            reason: e.to_string(),
        }),
    }
}

/// Sort layer ids by LAYER NUMBER, not lexicographically — `2026.10.9` must
/// come before `2026.10.10`, which a plain string sort gets backwards. The
/// same `sort_by_key(|id| id.parse::<LayerId>().ok())` pattern
/// `LineIndex::newer_than` already uses, reused rather than a second
/// layer-ordering helper: `LayerId`'s derived `Ord` already compares its
/// `patch` field numerically (`u16`), which is the whole fix.
fn sort_layers(ids: &mut [String]) {
    ids.sort_by_key(|id| id.parse::<LayerId>().ok());
}

/// Union `new_ids` into `existing`, sorted and de-duplicated. Returns whether
/// anything was actually added — the caller uses this to decide whether the
/// document changed at all (clause 4).
fn merge_affected(existing: &mut Vec<String>, new_ids: &[String]) -> bool {
    let mut changed = false;
    for id in new_ids {
        if !existing.iter().any(|e| e == id) {
            existing.push(id.clone());
            changed = true;
        }
    }
    sort_layers(existing);
    changed
}

/// Decide what the NEXT line-status document should say, given the line's
/// current signed document and a batch of advisory findings.
///
/// Returns `Ok(None)` when nothing would change — the idempotence clause 4
/// guarantees running the watcher twice on the same findings never proposes a
/// second document.
pub fn next_document(
    current: &LineStatus,
    findings: &[Proposed],
    issued_at: &str,
) -> Result<Option<LineStatus>, DraftError> {
    let line: Line = current
        .line
        .parse()
        .map_err(|e: varve_core::LayerIdError| DraftError::NotALayerOfLine {
            finding: String::new(),
            id: current.line.clone(),
            line: current.line.clone(),
            reason: e.to_string(),
        })?;

    // Validate everything up front — clauses 6 and 7 are refusals, not
    // defaults, and must not depend on whether a finding ends up merging into
    // an existing entry or becoming a new one.
    for finding in findings {
        normalised_severity(&finding.id, &finding.severity)?;
        for id in &finding.affected {
            check_affected(&finding.id, id, &line)?;
        }
    }

    let mut problems: Vec<KnownProblem> = current.known_problems.clone();
    let mut changed = false;

    for finding in findings {
        let existing_index = problems
            .iter()
            .position(|kp| kp.id == finding.id || finding.aliases.iter().any(|a| a == &kp.id));
        match existing_index {
            Some(idx) => {
                // Same problem (clause 1): only `affected` may grow. The
                // operator may have hand-edited title/workaround, which must
                // survive untouched.
                if merge_affected(&mut problems[idx].affected, &finding.affected) {
                    changed = true;
                }
            }
            None => {
                // A genuinely new finding (clause 2).
                let severity = normalised_severity(&finding.id, &finding.severity)?;
                let mut affected = finding.affected.clone();
                sort_layers(&mut affected);
                affected.dedup();
                problems.push(KnownProblem {
                    id: finding.id.clone(),
                    title: finding.title.clone(),
                    severity,
                    affected,
                    workaround: finding.workaround.clone(),
                    detection: None,
                    mitigation: None,
                });
                changed = true;
            }
        }
    }

    if !changed {
        return Ok(None);
    }

    Ok(Some(LineStatus {
        line: current.line.clone(),
        counter: current.counter + 1,
        issued_at: issued_at.to_string(),
        support_until: current.support_until.clone(),
        min_counter: current.min_counter,
        yanked: current.yanked.clone(),
        known_problems: problems,
    }))
}

/// What the publish-on-merge job should do, deciding from the layer
/// repository's committed status (source of truth) and what the registry
/// currently serves (REQ-POSTDEPOSIT-001 clauses 1-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconcile {
    /// The registry has nothing, or something stale — (re-)publish.
    Publish,
    /// The registry already serves exactly what the repository commits.
    UpToDate,
    /// The registry's counter is ahead of the repository's — someone
    /// published out of band. Never roll it back.
    RegistryAhead {
        repo_counter: u64,
        registry_counter: u64,
    },
    /// Same counter, different content: two documents claim one counter.
    /// Never overwrite; a person decides.
    Diverged { counter: u64 },
}

/// Decide what the publish-on-merge job should do.
///
/// Content is compared structurally (parsed `LineStatus` equality), not by
/// bytes or whitespace — a re-serialisation that changed nothing must not
/// read as a divergence.
pub fn reconcile(repo: &LineStatus, registry: Option<&LineStatus>) -> Reconcile {
    let Some(registry) = registry else {
        // The document was lost or never published — re-create it.
        return Reconcile::Publish;
    };
    if registry.counter < repo.counter {
        return Reconcile::Publish;
    }
    if registry.counter > repo.counter {
        return Reconcile::RegistryAhead {
            repo_counter: repo.counter,
            registry_counter: registry.counter,
        };
    }
    if registry == repo {
        Reconcile::UpToDate
    } else {
        Reconcile::Diverged {
            counter: repo.counter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use varve_core::generate_root_keypair;

    /// `sort_layers` orders by layer NUMBER, not lexicographically — given
    /// out of order on purpose (`.10` first) so a no-op in place of the
    /// sort would leave them unsorted, unlike `merge_affected`'s own
    /// tests, whose starting lists already happen to land in the right
    /// order by coincidence.
    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn sort_layers_orders_by_layer_number_not_lexicographically() {
        let mut ids = vec![
            "2026.10.10".to_string(),
            "2026.10.2".to_string(),
            "2026.10.9".to_string(),
        ];
        sort_layers(&mut ids);
        assert_eq!(
            ids,
            vec![
                "2026.10.2".to_string(),
                "2026.10.9".to_string(),
                "2026.10.10".to_string(),
            ]
        );
    }

    /// Line "2026.09", with one existing known problem whose range is
    /// collapsed to its two endpoints — this is test data, not a literal
    /// enumeration of every layer in between.
    fn baseline() -> LineStatus {
        LineStatus {
            line: "2026.09".into(),
            counter: 5,
            issued_at: "2026-10-14T00:00:00Z".into(),
            support_until: Some("2027-04-14".into()),
            min_counter: Some(3),
            yanked: BTreeMap::new(),
            known_problems: vec![KnownProblem {
                id: "GHSA-xfxf-qxr3-435x".into(),
                title: "ordeal gate skips disabled suites silently".into(),
                severity: "high".into(),
                affected: vec!["2026.09.2".into(), "2026.09.17".into()],
                workaround: Some("pin ordeal to 0.4.3 or run suites explicitly".into()),
                detection: None,
                mitigation: None,
            }],
        }
    }

    fn rustsec_finding() -> Proposed {
        Proposed {
            id: "RUSTSEC-2026-0346".into(),
            aliases: vec!["GHSA-c8m5-c952-6cm4".into()],
            title: "rustls: internal buffer overread in TLS 1.3 handling".into(),
            severity: "HIGH".into(),
            affected: vec!["2026.09.2".into(), "2026.09.20".into()],
            workaround: Some("upgrade to rustls 0.23.46".into()),
        }
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn a_new_finding_becomes_a_new_known_problem_after_the_existing_ones() {
        let current = baseline();
        let next = next_document(&current, &[rustsec_finding()], "2026-10-15T00:00:00Z")
            .unwrap()
            .expect("a new finding is a change");

        assert_eq!(next.line, "2026.09");
        assert_eq!(next.counter, 6);
        assert_eq!(next.issued_at, "2026-10-15T00:00:00Z");
        assert_eq!(next.known_problems.len(), 2);
        // Existing entry untouched and still first.
        assert_eq!(next.known_problems[0], current.known_problems[0]);
        let added = &next.known_problems[1];
        assert_eq!(added.id, "RUSTSEC-2026-0346");
        assert_eq!(added.severity, "high");
        assert_eq!(added.affected, vec!["2026.09.2", "2026.09.20"]);
        assert_eq!(
            added.workaround,
            Some("upgrade to rustls 0.23.46".to_string())
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn every_existing_field_not_mentioned_is_preserved_exactly() {
        let current = baseline();
        let next = next_document(&current, &[rustsec_finding()], "2026-10-15T00:00:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(next.support_until, current.support_until);
        assert_eq!(next.min_counter, current.min_counter);
        assert_eq!(next.yanked, current.yanked);
        assert_eq!(next.known_problems[0], current.known_problems[0]);
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_alias_match_merges_into_the_existing_entry_instead_of_a_second_one() {
        let current = baseline();
        // Same advisory under a different name; its alias names the existing
        // problem's id directly. Affects a layer the existing entry does not
        // yet list.
        let finding = Proposed {
            id: "CVE-2026-55512".into(),
            aliases: vec!["GHSA-xfxf-qxr3-435x".into()],
            title: "unrelated title text that must not overwrite anything".into(),
            severity: "critical".into(),
            affected: vec!["2026.09.18".into()],
            workaround: None,
        };
        let next = next_document(&current, &[finding], "2026-10-15T00:00:00Z")
            .unwrap()
            .expect("the merge is a change: affected grew");

        assert_eq!(
            next.known_problems.len(),
            1,
            "an alias match is the SAME problem, never a second entry"
        );
        let merged = &next.known_problems[0];
        assert_eq!(merged.id, "GHSA-xfxf-qxr3-435x");
        assert_eq!(
            merged.affected,
            vec!["2026.09.2", "2026.09.17", "2026.09.18"],
            "affected gains the new layer, sorted by layer NUMBER, de-duplicated"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_operator_edited_title_and_workaround_survive_a_merge() {
        let mut current = baseline();
        current.known_problems[0].title = "operator-rewritten title, keep this exact text".into();
        current.known_problems[0].workaround = Some("operator's own workaround text".into());

        let finding = Proposed {
            id: "GHSA-xfxf-qxr3-435x".into(),
            aliases: vec![],
            title: "scanner's own title, must NOT win".into(),
            severity: "medium".into(),
            affected: vec!["2026.09.19".into()],
            workaround: Some("scanner's own workaround, must NOT win".into()),
        };
        let next = next_document(&current, &[finding], "2026-10-15T00:00:00Z")
            .unwrap()
            .unwrap();

        let kp = &next.known_problems[0];
        assert_eq!(kp.title, "operator-rewritten title, keep this exact text");
        assert_eq!(
            kp.workaround,
            Some("operator's own workaround text".to_string())
        );
        // Severity, similarly, is never overwritten by a merge.
        assert_eq!(kp.severity, "high");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn rerunning_on_its_own_output_with_the_same_findings_proposes_nothing() {
        let current = baseline();
        let findings = [rustsec_finding()];
        let next = next_document(&current, &findings, "2026-10-15T00:00:00Z")
            .unwrap()
            .unwrap();

        let again = next_document(&next, &findings, "2026-10-16T00:00:00Z").unwrap();
        assert_eq!(
            again, None,
            "idempotence: the same findings against their own prior output change nothing"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn nothing_changing_returns_none_not_a_same_shaped_document() {
        let current = baseline();
        // A finding that is already fully covered: same id, no new affected.
        let finding = Proposed {
            id: "GHSA-xfxf-qxr3-435x".into(),
            aliases: vec![],
            title: "irrelevant".into(),
            severity: "high".into(),
            affected: vec!["2026.09.2".into()],
            workaround: None,
        };
        assert_eq!(
            next_document(&current, &[finding], "2026-10-15T00:00:00Z").unwrap(),
            None
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_affected_id_outside_the_line_is_a_typed_error_not_a_panic() {
        let current = baseline();
        let finding = Proposed {
            id: "GHSA-other".into(),
            aliases: vec![],
            title: "wrong line".into(),
            severity: "low".into(),
            affected: vec!["2026.10.1".into()],
            workaround: None,
        };
        let err = next_document(&current, &[finding], "2026-10-15T00:00:00Z").unwrap_err();
        assert!(
            matches!(err, DraftError::NotALayerOfLine { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_affected_id_that_is_not_a_layer_id_at_all_is_a_typed_error() {
        let current = baseline();
        let finding = Proposed {
            id: "GHSA-malformed".into(),
            aliases: vec![],
            title: "not a layer id".into(),
            severity: "low".into(),
            affected: vec!["not-a-layer".into()],
            workaround: None,
        };
        let err = next_document(&current, &[finding], "2026-10-15T00:00:00Z").unwrap_err();
        assert!(
            matches!(err, DraftError::NotALayerOfLine { .. }),
            "got: {err}"
        );
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn severity_is_normalised_to_lowercase() {
        let current = baseline();
        let next = next_document(&current, &[rustsec_finding()], "2026-10-15T00:00:00Z")
            .unwrap()
            .unwrap();
        assert_eq!(next.known_problems[1].severity, "high");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn an_unrecognised_severity_is_an_error_not_a_default() {
        let current = baseline();
        let finding = Proposed {
            id: "GHSA-sev".into(),
            aliases: vec![],
            title: "bad severity".into(),
            severity: "catastrophic".into(),
            affected: vec!["2026.09.3".into()],
            workaround: None,
        };
        let err = next_document(&current, &[finding], "2026-10-15T00:00:00Z").unwrap_err();
        assert!(matches!(err, DraftError::BadSeverity { .. }), "got: {err}");
    }

    // rivet: verifies REQ-ADVISORYWATCH-001
    #[test]
    fn the_prepared_document_signs_and_verifies_as_a_real_line_status() {
        let current = baseline();
        let next = next_document(&current, &[rustsec_finding()], "2026-10-15T00:00:00Z")
            .unwrap()
            .unwrap();

        let (sk, pk) = generate_root_keypair();
        let envelope = next.sign(&sk, "varve-root-1").unwrap();
        let parsed = LineStatus::verify_and_parse(envelope.as_bytes(), &pk).unwrap();
        assert_eq!(parsed, next);
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_missing_registry_document_is_published() {
        let repo = baseline();
        assert_eq!(reconcile(&repo, None), Reconcile::Publish);
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_registry_behind_the_repo_counter_is_published() {
        let repo = baseline();
        let mut registry = repo.clone();
        registry.counter = repo.counter - 1;
        assert_eq!(reconcile(&repo, Some(&registry)), Reconcile::Publish);
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn equal_counter_and_equal_content_is_up_to_date() {
        let repo = baseline();
        let registry = repo.clone();
        assert_eq!(reconcile(&repo, Some(&registry)), Reconcile::UpToDate);
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn up_to_date_survives_a_mere_reserialisation_not_just_identical_bytes() {
        let repo = baseline();
        // Parse a round trip through JSON to prove the comparison is
        // structural, not byte-for-byte.
        let bytes = serde_json::to_vec(&repo).unwrap();
        let registry: LineStatus = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reconcile(&repo, Some(&registry)), Reconcile::UpToDate);
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn equal_counter_different_content_is_diverged_never_overwritten() {
        let repo = baseline();
        let mut registry = repo.clone();
        registry.support_until = Some("2099-01-01".into());
        assert_eq!(
            reconcile(&repo, Some(&registry)),
            Reconcile::Diverged {
                counter: repo.counter
            }
        );
    }

    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_registry_ahead_of_the_repo_is_never_rolled_back() {
        let repo = baseline();
        let mut registry = repo.clone();
        registry.counter = repo.counter + 1;
        assert_eq!(
            reconcile(&repo, Some(&registry)),
            Reconcile::RegistryAhead {
                repo_counter: repo.counter,
                registry_counter: registry.counter
            }
        );
    }
}
