//! The signed line index (REQ-INDEXAUTH-001) — which layers a line HAS.
//!
//! varve signs each layer manifest and each realm, but the LISTING of a line's
//! layers has been the registry's raw `/tags/list`: unauthenticated. A
//! compromised or merely stale index host can HIDE a layer and every artifact
//! it does serve still verifies, so nothing detects it. Hiding also breaks
//! digest-pinned resolution, because a `LayerRef::Digest` is resolved by
//! enumerating tags and checking each candidate's payload digest.
//!
//! This is the Uptane insight applied to varve: rollback protection has to
//! survive a compromised Director/registry, not merely a tampered artifact.
//! Guix gets the equivalent property by authenticating its index git-history
//! through signed commits.
//!
//! The document is deliberately the same shape as `linestatus`: a DSSE
//! envelope under its own payload type, a monotonic per-line counter, and the
//! same refusal on a counter regression. Two signed documents about the same
//! line that disagree on how they are handled would be a bug generator.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::install::VerifyError;
use crate::layer::Line;
use crate::verify::{dsse_sign_typed, dsse_verify_typed};

/// The authenticated payload type — a signed something-else (a layer manifest,
/// a line-status) cannot be replayed as an index.
pub const LINE_INDEX_PAYLOAD_TYPE: &str = "application/vnd.pulseengine.varve.line-index.v1+json";

/// The artifact type under which an index travels as an OCI referrer.
pub const LINE_INDEX_ARTIFACT_TYPE: &str = LINE_INDEX_PAYLOAD_TYPE;

/// One layer the realm asserts exists on this line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexedLayer {
    /// The layer id, e.g. "2026.08.2".
    pub layer: String,
    /// The digest of that layer's signed PAYLOAD — the same identity a pin's
    /// `digest` names, so an index entry and a pin can be compared directly.
    pub digest: String,
    /// The channel the layer was published on.
    pub channel: String,
    /// That layer's manifest counter. The anti-rollback high-water mark is
    /// keyed on a COUNTER, not a layer id, so the index must carry the counter
    /// or clause 4 cannot feed the mechanism it exists to protect. (An earlier
    /// draft returned the greatest layer id here, which type-checked and was
    /// useless.)
    pub counter: u64,
}

/// What the realm says a line contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineIndex {
    /// The release line, e.g. "2026.08".
    pub line: String,
    /// Monotonic per-line document counter — a stale index must not silently
    /// replace a newer one, exactly as for line-status.
    pub counter: u64,
    /// RFC 3339 issue time of this document.
    #[serde(rename = "issued-at")]
    pub issued_at: String,
    /// Every layer of this line, in publication order.
    pub layers: Vec<IndexedLayer>,
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("line-index payload is not valid: {0}")]
    Payload(String),
    #[error(
        "refusing stale line-index for {line}: presented counter {presented}, cached {cached} — \
         a withdrawn or superseded index cannot be replayed over a newer one"
    )]
    Stale {
        line: String,
        presented: u64,
        cached: u64,
    },
    #[error(
        "the realm's signed index for {line} names layer {layer} ({digest}), which this source \
         does not serve. A source that hides a layer is either compromised or stale; every \
         layer it DOES serve still verifies, which is exactly why this check exists. Use a \
         different source, or obtain a newer signed index."
    )]
    Omitted {
        line: String,
        layer: String,
        digest: String,
    },
    #[error(
        "realm '{realm}' declares that it publishes a signed line index, but none was found for \
         {line}. Either the source is not serving it, or the realm's declaration is wrong — \
         varve will not fall back to an unauthenticated listing for a realm that promised one."
    )]
    Missing { realm: String, line: String },
    #[error("line-index document is for line {document}, not {expected}")]
    WrongLine { document: String, expected: String },
}

impl LineIndex {
    /// Verify an envelope against the realm's trust root and parse it.
    pub fn verify_and_parse(envelope: &[u8], root_public_key: &[u8]) -> Result<Self, IndexError> {
        let payload = dsse_verify_typed(envelope, LINE_INDEX_PAYLOAD_TYPE, root_public_key)?;
        serde_json::from_slice(&payload).map_err(|e| IndexError::Payload(e.to_string()))
    }

    /// Sign an index (the producing side — CI, beside deposit).
    pub fn sign(&self, secret_key: &[u8], key_id: &str) -> Result<String, IndexError> {
        let payload = serde_json::to_vec_pretty(self).expect("index serializes");
        Ok(dsse_sign_typed(
            &payload,
            LINE_INDEX_PAYLOAD_TYPE,
            secret_key,
            key_id,
        )?)
    }

    /// The line this document is about.
    pub fn line(&self) -> Result<Line, IndexError> {
        self.line
            .parse()
            .map_err(|e: crate::layer::LayerIdError| IndexError::Payload(e.to_string()))
    }

    /// Clause 3: every layer the index names must be present in what the
    /// source actually offers. `served` is the set of layer ids the source
    /// enumerated. Returns the FIRST omission, named — not a boolean, because
    /// an error a user cannot act on is not a check.
    pub fn refuse_omission(&self, served: &[String]) -> Result<(), IndexError> {
        for entry in &self.layers {
            if !served.iter().any(|s| s == &entry.layer) {
                return Err(IndexError::Omitted {
                    line: self.line.clone(),
                    layer: entry.layer.clone(),
                    digest: entry.digest.clone(),
                });
            }
        }
        Ok(())
    }

    /// Clause 4: the high-water mark this index justifies, independent of what
    /// the source chose to serve. A registry that hides the newest layer must
    /// not thereby lower the bar a later install has to clear, which is the
    /// whole point of authenticating the listing.
    ///
    /// The greatest counter the realm asserts for this line. `None` for an
    /// empty index, which asserts nothing and must not be mistaken for a mark
    /// of zero.
    pub fn high_water(&self) -> Option<u64> {
        self.layers.iter().map(|e| e.counter).max()
    }

    /// Clause 2: refuse a presented index older than one already held.
    /// Equality is allowed — a CI re-run must stay idempotent, the same rule
    /// `attach_envelope_to_layout` follows for line-status.
    pub fn refuse_regression(&self, cached: Option<&LineIndex>) -> Result<(), IndexError> {
        if let Some(prev) = cached
            && prev.line == self.line
            && self.counter < prev.counter
        {
            return Err(IndexError::Stale {
                line: self.line.clone(),
                presented: self.counter,
                cached: prev.counter,
            });
        }
        Ok(())
    }

    /// The index as a lookup from layer id to its signed payload digest.
    pub fn by_layer(&self) -> BTreeMap<&str, &str> {
        self.layers
            .iter()
            .map(|e| (e.layer.as_str(), e.digest.as_str()))
            .collect()
    }
}

/// What a consumer knows about a realm's index obligation.
#[derive(Debug, Clone, Copy)]
pub struct IndexPolicy<'a> {
    /// The realm's name, for error messages.
    pub realm: &'a str,
    /// The realm's trust root — the index verifies against this and nothing
    /// else. The SOURCE is the party being constrained, so it is never asked
    /// whether the index is good.
    pub root_public_key: &'a [u8],
    /// The realm declared `signed-index = true` (clause 5).
    pub required: bool,
}

/// Run the whole index check for one line, returning the verified index when
/// there is one. Separate from `install` so each clause is exercised directly:
/// integration tests cannot kill mutants under `--workspace --lib`, and this
/// is trust-critical code.
///
/// `envelope` is what the source offered (None = it offered nothing);
/// `served` is what the source is willing to serve (None = it cannot
/// enumerate); `cached` is the index already held, if any.
pub fn check(
    line: &str,
    envelope: Option<&[u8]>,
    served: Option<&[String]>,
    cached: Option<&LineIndex>,
    policy: &IndexPolicy<'_>,
) -> Result<Option<LineIndex>, IndexError> {
    let Some(bytes) = envelope else {
        // Clause 5: absence is an error only where the realm promised one.
        if policy.required {
            return Err(IndexError::Missing {
                realm: policy.realm.to_string(),
                line: line.to_string(),
            });
        }
        return Ok(None);
    };

    let index = LineIndex::verify_and_parse(bytes, policy.root_public_key)?;
    // The document must be about the line we asked about. Without this, a
    // valid index for a QUIET line would satisfy the check for a busy one
    // while naming none of its layers — omission detection that always passes.
    if index.line != line {
        return Err(IndexError::WrongLine {
            document: index.line.clone(),
            expected: line.to_string(),
        });
    }
    index.refuse_regression(cached)?;
    if let Some(served) = served {
        index.refuse_omission(served)?;
    }
    Ok(Some(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::generate_root_keypair;

    fn index(counter: u64, layers: &[(&str, &str)]) -> LineIndex {
        // Layer counters ascend with the layer id, as a real line's do.
        LineIndex {
            line: "2026.08".into(),
            counter,
            issued_at: "2026-08-18T00:00:00Z".into(),
            layers: layers
                .iter()
                .enumerate()
                .map(|(i, (l, d))| IndexedLayer {
                    layer: (*l).into(),
                    digest: (*d).into(),
                    channel: "qualified".into(),
                    counter: (i as u64) + 1,
                })
                .collect(),
        }
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn an_index_verifies_only_against_the_realm_that_signed_it() {
        let (sk, pk) = generate_root_keypair();
        let (_other_sk, other_pk) = generate_root_keypair();
        let doc = index(1, &[("2026.08.0", "sha256:aa"), ("2026.08.1", "sha256:bb")]);
        let envelope = doc.sign(&sk, "root-1").unwrap();

        assert_eq!(
            LineIndex::verify_and_parse(envelope.as_bytes(), &pk).unwrap(),
            doc
        );
        // Another realm's root must not accept it — an index is an assertion
        // BY a realm, so it carries that realm's authority and no other's.
        assert!(LineIndex::verify_and_parse(envelope.as_bytes(), &other_pk).is_err());
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_signed_line_status_cannot_be_replayed_as_an_index() {
        // The payload type is the whole defence against cross-document replay.
        // Both documents are signed by the SAME root and both are about a
        // line, so without a distinct type a status could stand in for an
        // index and assert that a line contains nothing.
        let (sk, pk) = generate_root_keypair();
        let status = crate::linestatus::LineStatus {
            line: "2026.08".into(),
            counter: 9,
            issued_at: "2026-08-18T00:00:00Z".into(),
            support_until: None,
            yanked: Default::default(),
            known_problems: Vec::new(),
        };
        let envelope = status.sign(&sk, "root-1").unwrap();
        // Assert the TYPE rejected it, not the schema. Mutating the payload
        // type constant to line-status's left an `is_err()` version of this
        // test GREEN, because the two structs have divergent
        // deny_unknown_fields shapes and serde refused it anyway — the test
        // proved schema divergence while claiming to prove the type check. If
        // the schemas ever converged, replay would open and nothing would
        // notice.
        match LineIndex::verify_and_parse(envelope.as_bytes(), &pk) {
            Err(IndexError::Verify(_)) => {}
            Err(IndexError::Payload(p)) => panic!(
                "rejected by the SCHEMA ({p}), not by the payload type — the type is the \
                 defence against cross-document replay and must be what fails"
            ),
            Ok(_) => panic!("a line-status must not verify as a line-index"),
            Err(other) => panic!("expected a payload-type rejection, got {other}"),
        }

        // The converse, so the defence is shown to be symmetric: an index
        // must not be accepted as a status either.
        let idx = index(1, &[("2026.08.0", "sha256:aa")]);
        let idx_env = idx.sign(&sk, "root-1").unwrap();
        assert!(
            crate::linestatus::LineStatus::verify_and_parse(idx_env.as_bytes(), &pk).is_err(),
            "a line-index must not verify as a line-status"
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_source_that_hides_a_layer_the_index_names_is_refused() {
        // THE attack this requirement exists for. The registry serves a valid,
        // correctly-signed 2026.08.0 and simply omits 2026.08.1 — a freshness
        // attack in which every byte the consumer receives verifies.
        let doc = index(1, &[("2026.08.0", "sha256:aa"), ("2026.08.1", "sha256:bb")]);
        let err = doc
            .refuse_omission(&["2026.08.0".to_string()])
            .expect_err("hiding a layer must be refused");
        match &err {
            IndexError::Omitted { layer, digest, .. } => {
                assert_eq!(layer, "2026.08.1");
                assert_eq!(digest, "sha256:bb", "name the digest, so it can be sought");
            }
            other => panic!("expected Omitted, got {other}"),
        }
        // The message must be actionable, not merely correct.
        let msg = err.to_string();
        assert!(msg.contains("2026.08.1"), "names the hidden layer: {msg}");
        assert!(
            msg.contains("still verifies"),
            "says WHY per-artifact verification did not catch this: {msg}"
        );

        // A source serving everything the index names is accepted, and extra
        // layers are not an error: an index is a floor, not a whitelist, so a
        // consumer holding an older index still works against a newer source.
        assert!(
            doc.refuse_omission(&[
                "2026.08.0".to_string(),
                "2026.08.1".to_string(),
                "2026.08.2".to_string(),
            ])
            .is_ok()
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn the_high_water_mark_comes_from_the_index_not_from_what_was_served() {
        // Clause 4, and the Uptane property: a registry hiding the newest
        // layer must not lower the bar a later install has to clear.
        let doc = index(
            1,
            &[
                ("2026.08.0", "sha256:aa"),
                ("2026.08.2", "sha256:cc"),
                ("2026.08.1", "sha256:bb"),
            ],
        );
        // The mark is a COUNTER — the units HighWaterMarks actually stores.
        // An earlier draft returned the greatest LayerId here: it type-checked
        // and could not feed the mechanism clause 4 exists to protect.
        assert_eq!(
            doc.high_water(),
            Some(3),
            "the greatest counter the REALM asserts, regardless of the order \
             entries appear in the document or of what any source served"
        );
        // An empty index asserts nothing and must not be read as a mark of 0,
        // which would be a mark that every layer clears.
        assert_eq!(index(1, &[]).high_water(), None);
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_stale_index_cannot_replace_a_newer_one() {
        let newer = index(7, &[("2026.08.1", "sha256:bb")]);
        let older = index(3, &[("2026.08.0", "sha256:aa")]);

        let err = older
            .refuse_regression(Some(&newer))
            .expect_err("a lower counter must be refused");
        assert!(matches!(
            err,
            IndexError::Stale {
                presented: 3,
                cached: 7,
                ..
            }
        ));
        let msg = err.to_string();
        assert!(msg.contains('3') && msg.contains('7'), "names both: {msg}");

        // Equal is not a regression — CI re-runs must stay idempotent, the
        // same rule line-status follows.
        assert!(newer.refuse_regression(Some(&newer)).is_ok());
        // Newer over older is the ordinary case.
        assert!(newer.refuse_regression(Some(&older)).is_ok());
        // Nothing cached yet is not a regression either.
        assert!(older.refuse_regression(None).is_ok());
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn an_index_for_another_line_is_not_silently_accepted() {
        let doc = index(1, &[("2026.08.0", "sha256:aa")]);
        let other = LineIndex {
            line: "2026.09".into(),
            ..index(1, &[("2026.09.0", "sha256:zz")])
        };
        // A different line is not a regression — the counters are per line, so
        // comparing them would refuse a legitimate document.
        assert!(doc.refuse_regression(Some(&other)).is_ok());
        assert_eq!(doc.line().unwrap().to_string(), "2026.08");
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_realm_that_promised_an_index_does_not_fall_back_to_an_unsigned_listing() {
        // Clause 5, both directions. If absence were tolerated for a
        // declaring realm, an attacker would disable the entire check by
        // deleting one file — the check would be advisory, not a control.
        let (_sk, pk) = generate_root_keypair();
        let declaring = IndexPolicy {
            realm: "acme",
            root_public_key: &pk,
            required: true,
        };
        let silent = IndexPolicy {
            required: false,
            ..declaring
        };

        let err = check("2026.08", None, None, None, &declaring)
            .expect_err("a declaring realm must not accept a missing index");
        assert!(matches!(err, IndexError::Missing { .. }));
        let msg = err.to_string();
        assert!(msg.contains("acme"), "names the realm: {msg}");
        assert!(
            msg.contains("will not fall back"),
            "says what it refused to do, not merely that something is absent: {msg}"
        );

        // A realm that never promised one keeps working — the default must not
        // break every realm in existence.
        assert!(
            check("2026.08", None, None, None, &silent)
                .unwrap()
                .is_none()
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn an_index_for_a_different_line_cannot_satisfy_this_line() {
        // Without this, a valid index for a QUIET line satisfies the check for
        // a busy one while naming none of its layers — omission detection that
        // structurally always passes, which is worse than no check because it
        // reports success.
        let (sk, pk) = generate_root_keypair();
        let policy = IndexPolicy {
            realm: "acme",
            root_public_key: &pk,
            required: true,
        };
        let quiet = LineIndex {
            line: "2026.01".into(),
            ..index(1, &[])
        };
        let envelope = quiet.sign(&sk, "k").unwrap();
        let err = check(
            "2026.08",
            Some(envelope.as_bytes()),
            Some(&["2026.08.0".to_string()]),
            None,
            &policy,
        )
        .expect_err("an index for another line must not satisfy this one");
        assert!(matches!(
            err,
            IndexError::WrongLine { ref document, ref expected }
                if document == "2026.01" && expected == "2026.08"
        ));
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn a_source_that_cannot_enumerate_is_not_treated_as_hiding_everything() {
        // `None` (cannot enumerate — an offline archive directory) must be
        // distinct from `Some(vec![])` (enumerates, has nothing). Collapsing
        // them would make every air-gapped install fail with a false
        // accusation of tampering, which is how a security control gets turned
        // off in the field.
        let (sk, pk) = generate_root_keypair();
        let policy = IndexPolicy {
            realm: "acme",
            root_public_key: &pk,
            required: true,
        };
        let doc = index(1, &[("2026.08.0", "sha256:aa")]);
        let envelope = doc.sign(&sk, "k").unwrap();

        let ok = check("2026.08", Some(envelope.as_bytes()), None, None, &policy)
            .expect("a source that cannot enumerate is not evidence of hiding");
        assert_eq!(ok.unwrap().counter, 1);

        // …but one that CAN enumerate and serves nothing is hiding everything.
        assert!(matches!(
            check(
                "2026.08",
                Some(envelope.as_bytes()),
                Some(&[]),
                None,
                &policy
            ),
            Err(IndexError::Omitted { .. })
        ));
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn check_refuses_a_stale_index_not_only_refuse_regression_does() {
        // `a_stale_index_cannot_replace_a_newer_one` calls refuse_regression
        // DIRECTLY, so deleting the call from `check` — the function install
        // actually goes through — left the suite green. That is the exact
        // shape four consecutive reviews have found: evidence that exercises a
        // different function than the clause runs through. This one goes
        // through `check`.
        let (sk, pk) = generate_root_keypair();
        let policy = IndexPolicy {
            realm: "acme",
            root_public_key: &pk,
            required: true,
        };
        let cached = index(7, &[("2026.08.1", "sha256:bb")]);
        let stale = index(3, &[("2026.08.0", "sha256:aa")]);
        let envelope = stale.sign(&sk, "k").unwrap();

        let err = check(
            "2026.08",
            Some(envelope.as_bytes()),
            None,
            Some(&cached),
            &policy,
        )
        .expect_err("a replayed older index must be refused by the path install uses");
        assert!(matches!(
            err,
            IndexError::Stale {
                presented: 3,
                cached: 7,
                ..
            }
        ));

        // The newer one is accepted through the same path.
        let fresher = index(8, &[("2026.08.1", "sha256:bb")]);
        let ok = fresher.sign(&sk, "k").unwrap();
        assert_eq!(
            check("2026.08", Some(ok.as_bytes()), None, Some(&cached), &policy)
                .unwrap()
                .unwrap()
                .counter,
            8
        );
    }

    // rivet: verifies REQ-INDEXAUTH-001
    #[test]
    fn the_source_never_gets_to_vouch_for_its_own_index() {
        // The source is the party this document exists to constrain, so an
        // index it signs with its own key must be worthless.
        let (_realm_sk, realm_pk) = generate_root_keypair();
        let (impostor_sk, _impostor_pk) = generate_root_keypair();
        let policy = IndexPolicy {
            realm: "acme",
            root_public_key: &realm_pk,
            required: true,
        };
        let forged = index(99, &[("2026.08.0", "sha256:aa")])
            .sign(&impostor_sk, "not-the-realm")
            .unwrap();
        assert!(matches!(
            check("2026.08", Some(forged.as_bytes()), None, None, &policy),
            Err(IndexError::Verify(_))
        ));
    }
}
