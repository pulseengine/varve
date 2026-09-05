//! A realm served from more than one place (REQ-MIRROR-001).
//!
//! Today a realm names exactly one registry. If it is unreachable — an outage,
//! a partition, an org-level package change, a blocked region — no consumer can
//! install or update, and a fresh one cannot bootstrap at all.
//!
//! ## Why mirroring is safe here, and why that is the point
//!
//! In most package managers a mirror is a trust decision: you are choosing
//! another party to believe. Here it is not. A layer is accepted because its
//! manifest verifies against the realm's trust root and its payload digests
//! match — the registry is transport, not authority, and `source.rs` says so
//! in its first paragraph: *"A source can obtain bytes. It has no voice in
//! whether those bytes are accepted."*
//!
//! So a tampered mirror fails the DSSE check and a truncated one fails the
//! digest check, exactly as the primary would. A second source widens
//! availability and not the trust surface, which is precisely why it is worth
//! having.
//!
//! ## The clause that matters
//!
//! Falling through on failure is the whole feature, and it is also the way to
//! ruin it. If "the bytes did not verify" were a reason to try the next
//! source, then a mirror serving bad bytes would be silently skipped — and the
//! single most interesting event this design can surface, an attacker or a
//! corruption at one source, would become invisible. The system would look
//! healthier the more it was attacked.
//!
//! That is structural here rather than a rule to remember: verification runs
//! ABOVE this type, in the install pipeline, on whatever a source returns.
//! This type only sees `SourceError`, which cannot express "did not verify" —
//! there is deliberately no such variant. A future refactor that tried to make
//! one would have to change `source.rs`'s contract to do it.

use crate::source::{LayerRef, LayerSource, SourceError};
use std::cell::RefCell;

/// One named place a realm's layers can be obtained from.
pub struct Mirror {
    /// How the source is named to an operator — a registry URL, a path.
    pub label: String,
    pub source: Box<dyn LayerSource>,
}

/// An ordered list of sources for one realm.
///
/// Order is the realm's stated preference, not a race: a deterministic order
/// means an operator can predict which source served them, and a run that
/// picked a different mirror each time would make an incident unreproducible.
pub struct Mirrors {
    mirrors: Vec<Mirror>,
    /// The label of the source that last answered, for reporting.
    served_by: RefCell<Option<String>>,
    /// Why each earlier source did not answer, for the error if none does.
    attempts: RefCell<Vec<(String, String)>>,
}

impl Mirrors {
    pub fn new(mirrors: Vec<Mirror>) -> Self {
        Mirrors {
            mirrors,
            served_by: RefCell::new(None),
            attempts: RefCell::new(Vec::new()),
        }
    }

    /// Which source last answered (REQ-MIRROR-001 clause 4).
    ///
    /// Reportable *before* an incident, not only during one: an operator who
    /// cannot tell that they have been on a mirror for a month cannot tell
    /// that the primary has been down for a month.
    pub fn served_by(&self) -> Option<String> {
        self.served_by.borrow().clone()
    }

    /// What was tried, and what each said.
    pub fn attempts(&self) -> Vec<(String, String)> {
        self.attempts.borrow().clone()
    }

    pub fn labels(&self) -> Vec<&str> {
        self.mirrors.iter().map(|m| m.label.as_str()).collect()
    }

    /// Try each source in order.
    ///
    /// `NotFound` and `Transport` both continue: a mirror that has not synced
    /// this layer yet is as unhelpful as one that is unreachable, and neither
    /// says anything about the bytes. Nothing else can arrive here —
    /// `SourceError` has no variant meaning "did not verify", by design.
    fn try_each<T>(
        &self,
        what: &str,
        mut f: impl FnMut(&dyn LayerSource) -> Result<T, SourceError>,
    ) -> Result<T, SourceError> {
        self.attempts.borrow_mut().clear();
        if self.mirrors.is_empty() {
            return Err(SourceError::Transport(
                "this realm declares no sources at all".into(),
            ));
        }
        for m in &self.mirrors {
            match f(m.source.as_ref()) {
                Ok(v) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    return Ok(v);
                }
                Err(e) => {
                    self.attempts
                        .borrow_mut()
                        .push((m.label.clone(), e.to_string()));
                }
            }
        }
        let tried = self
            .attempts
            .borrow()
            .iter()
            .map(|(l, e)| format!("\n  {l}: {e}"))
            .collect::<String>();
        Err(SourceError::Transport(format!(
            "no source could supply {what}. Tried {} source(s):{tried}",
            self.mirrors.len()
        )))
    }
}

impl LayerSource for Mirrors {
    fn fetch_manifest(&self, layer: &LayerRef) -> Result<Vec<u8>, SourceError> {
        self.try_each("the layer manifest", |s| s.fetch_manifest(layer))
    }

    fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>, SourceError> {
        self.try_each(&format!("blob {digest}"), |s| s.fetch_blob(digest))
    }

    fn fetch_line_status(&self, layer: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
        // `Ok(None)` is "this source carries none", which is not an error and
        // not a reason to keep looking on THIS method — but a mirror that has
        // the status when the primary does not is worth reaching, so an
        // explicit None continues while an error also continues.
        self.try_each_optional("the line-status document", |s| s.fetch_line_status(layer))
    }

    fn fetch_line_index(&self, line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        self.try_each_optional("the line index", |s| s.fetch_line_index(line))
    }

    fn fetch_attestations(
        &self,
        layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        self.try_each("the attestations", |s| s.fetch_attestations(layer))
    }
}

impl Mirrors {
    /// For the `Option`-returning fetches: a source that returns `None` has
    /// answered honestly, but another source may still carry the document, so
    /// keep looking and report `None` only when nobody has it.
    fn try_each_optional(
        &self,
        what: &str,
        mut f: impl FnMut(&dyn LayerSource) -> Result<Option<Vec<u8>>, SourceError>,
    ) -> Result<Option<Vec<u8>>, SourceError> {
        self.attempts.borrow_mut().clear();
        let mut any_answered = false;
        for m in &self.mirrors {
            match f(m.source.as_ref()) {
                Ok(Some(v)) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    return Ok(Some(v));
                }
                Ok(None) => {
                    any_answered = true;
                    self.attempts
                        .borrow_mut()
                        .push((m.label.clone(), "carries none".into()));
                }
                Err(e) => {
                    self.attempts
                        .borrow_mut()
                        .push((m.label.clone(), e.to_string()));
                }
            }
        }
        if any_answered {
            // At least one source answered "I do not carry this", which is a
            // legitimate absence rather than a failure to reach anyone.
            return Ok(None);
        }
        let tried = self
            .attempts
            .borrow()
            .iter()
            .map(|(l, e)| format!("\n  {l}: {e}"))
            .collect::<String>();
        Err(SourceError::Transport(format!(
            "no source could be reached for {what}:{tried}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct Fake {
        manifest: Option<Vec<u8>>,
        err: Option<SourceError>,
        status: Option<Option<Vec<u8>>>,
        calls: Rc<Cell<usize>>,
    }

    fn ok(bytes: &[u8]) -> Box<Fake> {
        Box::new(Fake {
            manifest: Some(bytes.to_vec()),
            err: None,
            status: Some(Some(bytes.to_vec())),
            calls: Rc::new(Cell::new(0)),
        })
    }
    fn down(msg: &str) -> Box<Fake> {
        Box::new(Fake {
            manifest: None,
            err: Some(SourceError::Transport(msg.into())),
            status: None,
            calls: Rc::new(Cell::new(0)),
        })
    }
    fn empty() -> Box<Fake> {
        Box::new(Fake {
            manifest: None,
            err: Some(SourceError::NotFound("layer".into())),
            status: Some(None),
            calls: Rc::new(Cell::new(0)),
        })
    }

    impl LayerSource for Fake {
        fn fetch_manifest(&self, _l: &LayerRef) -> Result<Vec<u8>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            match (&self.manifest, &self.err) {
                (Some(m), _) => Ok(m.clone()),
                (None, Some(e)) => Err(clone_err(e)),
                _ => Err(SourceError::NotFound("x".into())),
            }
        }
        fn fetch_blob(&self, _d: &str) -> Result<Vec<u8>, SourceError> {
            self.fetch_manifest(&LayerRef::Digest("x".into()))
        }
        fn fetch_line_status(&self, _l: &LayerRef) -> Result<Option<Vec<u8>>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            match (&self.status, &self.err) {
                (Some(s), _) => Ok(s.clone()),
                (None, Some(e)) => Err(clone_err(e)),
                _ => Ok(None),
            }
        }
        fn fetch_line_index(&self, _line: &str) -> Result<Option<Vec<u8>>, SourceError> {
            self.fetch_line_status(&LayerRef::Digest("x".into()))
        }
        fn fetch_attestations(
            &self,
            _l: &LayerRef,
        ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            match (&self.manifest, &self.err) {
                (Some(_), _) => Ok(Vec::new()),
                (None, Some(e)) => Err(clone_err(e)),
                _ => Ok(Vec::new()),
            }
        }
    }

    fn clone_err(e: &SourceError) -> SourceError {
        match e {
            SourceError::NotFound(s) => SourceError::NotFound(s.clone()),
            SourceError::Transport(s) => SourceError::Transport(s.clone()),
            other => SourceError::Transport(other.to_string()),
        }
    }

    fn mirrors(v: Vec<(&str, Box<Fake>)>) -> Mirrors {
        Mirrors::new(
            v.into_iter()
                .map(|(l, s)| Mirror {
                    label: l.into(),
                    source: s as Box<dyn LayerSource>,
                })
                .collect(),
        )
    }

    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn the_first_source_that_answers_serves_the_layer() {
        let m = mirrors(vec![("primary", ok(b"manifest")), ("mirror", ok(b"other"))]);
        assert_eq!(
            m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap(),
            b"manifest".to_vec()
        );
        assert_eq!(m.served_by().as_deref(), Some("primary"));
    }

    /// The whole point: an unreachable primary must not stop an install.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn an_unreachable_source_falls_through_to_the_next() {
        let m = mirrors(vec![
            ("primary", down("dial tcp: no such host")),
            ("mirror", ok(b"manifest")),
        ]);
        assert_eq!(
            m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap(),
            b"manifest".to_vec()
        );
        assert_eq!(m.served_by().as_deref(), Some("mirror"));
    }

    /// A mirror that has not synced this layer is as unhelpful as one that is
    /// down, and neither says anything about the bytes.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_source_that_lacks_the_layer_falls_through_too() {
        let m = mirrors(vec![("primary", empty()), ("mirror", ok(b"manifest"))]);
        assert!(m.fetch_manifest(&LayerRef::Digest("d".into())).is_ok());
        assert_eq!(m.served_by().as_deref(), Some("mirror"));
    }

    /// Clause 4. An operator who cannot tell they have been on a mirror for a
    /// month cannot tell the primary has been down for a month.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn which_source_served_the_layer_is_reportable() {
        let m = mirrors(vec![
            ("oci://primary", down("503")),
            ("oci://backup", ok(b"m")),
        ]);
        m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap();
        assert_eq!(m.served_by().as_deref(), Some("oci://backup"));
        let attempts = m.attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].0, "oci://primary");
        assert!(attempts[0].1.contains("503"), "{attempts:?}");
    }

    /// When nothing answers, the error names every source and what each said —
    /// "the registry is down" is not actionable when there were three.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn when_no_source_answers_the_error_names_all_of_them() {
        let m = mirrors(vec![
            ("oci://a", down("no such host")),
            ("oci://b", down("503 Service Unavailable")),
        ]);
        let e = m
            .fetch_manifest(&LayerRef::Digest("d".into()))
            .expect_err("must fail");
        let msg = e.to_string();
        assert!(
            msg.contains("oci://a") && msg.contains("no such host"),
            "{msg}"
        );
        assert!(msg.contains("oci://b") && msg.contains("503"), "{msg}");
        assert!(msg.contains("2 source(s)"), "{msg}");
        assert!(m.served_by().is_none());
    }

    /// A realm with no sources is a configuration error, not an empty loop
    /// that silently reports "not found".
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_realm_with_no_sources_says_so() {
        let m = Mirrors::new(Vec::new());
        let e = m
            .fetch_manifest(&LayerRef::Digest("d".into()))
            .expect_err("must fail");
        assert!(e.to_string().contains("no sources at all"), "{e}");
    }

    /// A later source is not consulted once an earlier one answers — order is
    /// a stated preference, and an operator must be able to predict it.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_source_after_the_one_that_answered_is_not_consulted() {
        let second = ok(b"second");
        let counter = Rc::clone(&second.calls);
        let m = mirrors(vec![("primary", ok(b"first")), ("mirror", second)]);
        m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap();
        assert_eq!(counter.get(), 0, "the later source was consulted anyway");
    }

    /// Every fetch must fall through, not just the manifest. Each is a
    /// separate delegation, and a copy-paste slip in one of them would fail
    /// over on the manifest and then stall on the blob — an install that gets
    /// halfway and dies is worse than one that never starts.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn every_kind_of_fetch_falls_through_not_only_the_manifest() {
        let m = mirrors(vec![("primary", down("503")), ("mirror", ok(b"bytes"))]);
        assert_eq!(m.fetch_blob("sha256:x").unwrap(), b"bytes".to_vec());
        assert_eq!(m.served_by().as_deref(), Some("mirror"));

        let m = mirrors(vec![("primary", down("503")), ("mirror", ok(b"index"))]);
        assert_eq!(
            m.fetch_line_index("2026.09").unwrap(),
            Some(b"index".to_vec())
        );
        assert_eq!(m.served_by().as_deref(), Some("mirror"));

        let m = mirrors(vec![("primary", down("503")), ("mirror", ok(b"att"))]);
        assert!(m.fetch_attestations(&LayerRef::Digest("d".into())).is_ok());
        assert_eq!(m.served_by().as_deref(), Some("mirror"));
    }

    /// ...and every kind must REFUSE when nobody answers, rather than
    /// returning an empty result that reads as "there is none".
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn every_kind_of_fetch_refuses_when_no_source_answers() {
        let m = mirrors(vec![("a", down("no such host")), ("b", down("503"))]);
        assert!(m.fetch_manifest(&LayerRef::Digest("d".into())).is_err());
        assert!(m.fetch_blob("sha256:x").is_err());
        assert!(m.fetch_line_index("2026.09").is_err());
        assert!(m.fetch_attestations(&LayerRef::Digest("d".into())).is_err());
        assert!(
            m.served_by().is_none(),
            "nothing served, yet a source is named"
        );
    }

    /// The labels are what an operator is shown; an empty list would make
    /// every mirror diagnostic say nothing.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn the_configured_sources_are_reportable_in_order() {
        let m = mirrors(vec![("oci://a", ok(b"x")), ("oci://b", ok(b"y"))]);
        assert_eq!(m.labels(), vec!["oci://a", "oci://b"]);
        assert_eq!(Mirrors::new(Vec::new()).labels(), Vec::<&str>::new());
    }

    /// `Ok(None)` from every source is a legitimate absence — line-status is
    /// updatable evidence and some layers have none. That must not be reported
    /// as "no source could be reached".
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_document_no_source_carries_is_absent_not_unreachable() {
        let m = mirrors(vec![("a", empty()), ("b", empty())]);
        assert_eq!(
            m.fetch_line_status(&LayerRef::Digest("d".into())).unwrap(),
            None
        );
    }

    /// ...but if nobody could be REACHED, that is not absence.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_document_nobody_could_be_asked_about_is_not_reported_as_absent() {
        let m = mirrors(vec![("a", down("no such host")), ("b", down("503"))]);
        let e = m
            .fetch_line_status(&LayerRef::Digest("d".into()))
            .expect_err("must not report absence");
        assert!(e.to_string().contains("could be reached"), "{e}");
    }

    /// A source that carries the status is preferred over one that does not,
    /// even when the one that does not comes first.
    // rivet: verifies REQ-MIRROR-001
    #[test]
    fn a_source_carrying_the_document_is_reached_past_one_that_does_not() {
        let m = mirrors(vec![("a", empty()), ("b", ok(b"status"))]);
        assert_eq!(
            m.fetch_line_status(&LayerRef::Digest("d".into())).unwrap(),
            Some(b"status".to_vec())
        );
        assert_eq!(m.served_by().as_deref(), Some("b"));
    }
}
