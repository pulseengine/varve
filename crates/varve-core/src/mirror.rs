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

#[cfg(test)]
use crate::source::LayerRef;
use crate::source::{LayerSource, SourceError};
use std::cell::RefCell;
use std::collections::BTreeSet;

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
    /// The realm to name when telling the user a mirror answered. `None` for
    /// a source set that is not a realm's (an explicit `--from`).
    announce_for: Option<String>,
    /// Mirrors already announced, so one install says it once, not once per
    /// blob.
    announced: RefCell<BTreeSet<String>>,
    notices: RefCell<Vec<String>>,
}

/// Whether `spec` starts like a URL (`scheme://`).
fn url_scheme(spec: &str) -> Option<&str> {
    let (scheme, _) = spec.split_once("://")?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    (first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+.-".contains(c)))
    .then_some(scheme)
}

/// Turn one source string into a source. An `oci://` / `oci+http://`
/// reference is a registry; a path is an OCI image layout (the `varve
/// archive` / `deposit` output) or a plain `manifests/` + `blobs/` directory.
/// Any OTHER URL scheme is refused: it would otherwise be read as a relative
/// directory literally named `https:`, and fail later as "no layer found"
/// instead of saying what is wrong. The shape changes availability, never
/// acceptance.
pub fn source_from_spec(spec: &str, platform: &str) -> Result<Box<dyn LayerSource>, SourceError> {
    build_source(spec, platform, Role::Primary)
}

fn build_source(
    spec: &str,
    platform: &str,
    role: Role<'_>,
) -> Result<Box<dyn LayerSource>, SourceError> {
    if spec.starts_with("oci://") || spec.starts_with("oci+http://") {
        let mut registry = crate::RegistrySource::parse(spec)?;
        if let Role::Mirror { primary_origin } = role {
            registry = registry.as_mirror_of(primary_origin);
        }
        return Ok(Box::new(registry));
    }
    if let Some(scheme) = url_scheme(spec) {
        return Err(SourceError::Transport(format!(
            "'{spec}' uses the '{scheme}://' scheme, which varve cannot read: a source is an \
             oci:// or oci+http:// registry, or a local directory"
        )));
    }
    let path = std::path::Path::new(spec);
    if path.join("oci-layout").is_file() {
        // Tell the layout which platform we want, so a payload it does not
        // carry is reported as the single-platform archive it is rather than
        // as a bare missing digest (varve#80).
        Ok(Box::new(
            crate::OciLayoutSource::at(path).for_platform(platform),
        ))
    } else {
        Ok(Box::new(crate::DirSource::at(path)))
    }
}

/// What a source is in its realm: the primary, or a mirror (with the
/// primary's origin when the primary is a registry).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Role<'a> {
    Primary,
    Mirror { primary_origin: Option<&'a str> },
}

/// The role of the source at position `index`. EVERY source after the first
/// is a mirror, whether or not the primary is a registry: a mirror is
/// credential-restricted unless it is provably the primary's origin
/// (`RegistrySource::as_mirror_of`), so a directory primary fails closed.
fn role(index: usize, primary_origin: Option<&str>) -> Role<'_> {
    if index > 0 {
        Role::Mirror { primary_origin }
    } else {
        Role::Primary
    }
}

/// The origin (`scheme://host[:port]`) of an `oci://` / `oci+http://` source,
/// if it is one.
fn registry_origin(spec: &str) -> Option<String> {
    crate::RegistrySource::parse(spec)
        .ok()
        .map(|source| source.origin())
}

/// A reason in one short line, for a notice.
fn short_reason(e: &dyn std::fmt::Display) -> String {
    let text = e.to_string();
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() > 140 {
        let cut: String = line.chars().take(140).collect();
        format!("{cut}...")
    } else {
        line.to_string()
    }
}

impl Mirrors {
    pub fn new(mirrors: Vec<Mirror>) -> Self {
        Mirrors {
            mirrors,
            served_by: RefCell::new(None),
            attempts: RefCell::new(Vec::new()),
            announce_for: None,
            announced: RefCell::new(BTreeSet::new()),
            notices: RefCell::new(Vec::new()),
        }
    }

    /// The sources a realm declares, primary first and then its mirrors in the
    /// order written (REQ-MIRROR-002 clause 1). `realm.sources` is the one
    /// list; nothing else may decide where a realm's bytes come from.
    ///
    /// Tells the user on stderr, naming `realm_name`, whenever a source other
    /// than the primary answers (clause 3).
    pub fn for_realm(
        realm_name: &str,
        sources: &[String],
        platform: &str,
    ) -> Result<Self, SourceError> {
        let primary_origin = sources.first().and_then(|p| registry_origin(p));
        let mut mirrors = Vec::with_capacity(sources.len());
        for (i, spec) in sources.iter().enumerate() {
            let refuse = |why: String| {
                SourceError::Transport(format!("realm '{realm_name}': source '{spec}': {why}"))
            };
            // A relative path would resolve against whatever directory varve
            // happens to run in, so the same realms file would mean different
            // sources from different places. Refused rather than guessed.
            if url_scheme(spec).is_none()
                && !spec.starts_with("oci://")
                && !spec.starts_with("oci+http://")
                && !std::path::Path::new(spec).is_absolute()
            {
                return Err(refuse(
                    "a relative path is ambiguous (it would depend on the working directory); \
                     write an absolute path or an oci:// registry"
                        .to_string(),
                ));
            }
            let source = build_source(spec, platform, role(i, primary_origin.as_deref()))
                .map_err(|e| refuse(e.to_string()))?;
            mirrors.push(Mirror {
                label: spec.clone(),
                source,
            });
        }
        let mut m = Mirrors::new(mirrors);
        m.announce_for = Some(realm_name.to_string());
        Ok(m)
    }

    /// One source, no realm: an explicit `--from`. Nothing to fail over to and
    /// nothing to announce.
    pub fn single(spec: &str, platform: &str) -> Result<Self, SourceError> {
        Ok(Mirrors::new(vec![Mirror {
            label: spec.to_string(),
            source: source_from_spec(spec, platform)?,
        }]))
    }

    /// Run a WHOLE operation (fetch AND verify) against each source in turn
    /// until one succeeds. The per-fetch failover of `LayerSource for Mirrors`
    /// cannot do this: it only sees transport errors, so bytes that fail the
    /// realm's trust root would end the install instead of moving on
    /// (REQ-MIRROR-002 clause 2). Here the closure verifies, so "did not
    /// verify" is a reason to try the next source, and every source's bytes
    /// are judged by the same root because the closure is the same.
    ///
    /// Returns the value, or every source's failure in order.
    ///
    /// `fails_over` says whether an error is about THIS source's bytes
    /// (unavailable, unauthentic, substituted) and so a reason to ask the next.
    /// An error it rejects is a verified verdict or a local failure and is
    /// TERMINAL: it is returned at once, as the last entry, and no later
    /// source is asked. Otherwise a stale mirror would get a second chance
    /// against a lower bar than the primary's genuine, refused layer, and
    /// failover itself would be the rollback attack.
    pub fn attempt<T, E: std::fmt::Display>(
        &self,
        mut f: impl FnMut(&dyn LayerSource, bool) -> Result<T, E>,
        fails_over: impl Fn(&E) -> bool,
    ) -> Result<T, Vec<(String, E)>> {
        let mut failures: Vec<(String, E)> = Vec::new();
        for (i, m) in self.mirrors.iter().enumerate() {
            match f(m.source.as_ref(), i == 0) {
                Ok(v) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    if i > 0 {
                        self.announce(&m.label, &Self::reasons(&failures, false));
                    }
                    return Ok(v);
                }
                Err(e) => {
                    let terminal = !fails_over(&e);
                    failures.push((m.label.clone(), e));
                    if terminal {
                        break;
                    }
                }
            }
        }
        Err(failures)
    }

    /// Each skipped source and why, in one short line apiece. A forged answer
    /// and an outage must read differently, or an operator cannot tell an
    /// attack from a bad afternoon. `absent`: an earlier source ANSWERED that
    /// it carries none, which is not a failure and is said as such.
    fn reasons<E: std::fmt::Display>(failures: &[(String, E)], absent: bool) -> String {
        let mut parts: Vec<String> = failures
            .iter()
            .map(|(l, e)| format!("{l}: {}", short_reason(e)))
            .collect();
        if absent {
            parts.push("an earlier source answered that it carries none".to_string());
        }
        parts.join("; ")
    }

    /// [`attempt`](Self::attempt) for an answer that can legitimately be
    /// ABSENT: `Ok(None)` from one source is not the end of the search while
    /// another may carry it. The first `Some` wins. A `None` is AUTHORITATIVE
    /// only if no source failed to answer BEFORE it: an unreachable primary
    /// might hold the document, and a mirror's silence cannot stand for it, so
    /// absence is then UNKNOWN and that is an error. Once a source has
    /// answered none authoritatively, a LATER source's failure does not undo
    /// it. A terminal error stops the search at once.
    pub fn attempt_some<T, E: std::fmt::Display>(
        &self,
        mut f: impl FnMut(&dyn LayerSource, bool) -> Result<Option<T>, E>,
        fails_over: impl Fn(&E) -> bool,
    ) -> Result<Option<T>, Vec<(String, E)>> {
        let mut failures: Vec<(String, E)> = Vec::new();
        let mut absent = false;
        // A failure before the first answered-none makes absence unknown.
        let mut failed_before_none = false;
        for (i, m) in self.mirrors.iter().enumerate() {
            match f(m.source.as_ref(), i == 0) {
                Ok(Some(v)) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    if i > 0 {
                        self.announce(&m.label, &Self::reasons(&failures, absent));
                    }
                    return Ok(Some(v));
                }
                Ok(None) => absent = true,
                Err(e) => {
                    let terminal = !fails_over(&e);
                    failed_before_none |= !absent;
                    failures.push((m.label.clone(), e));
                    if terminal {
                        return Err(failures);
                    }
                }
            }
        }
        if failed_before_none {
            Err(failures)
        } else {
            Ok(None)
        }
    }

    /// The realm's PRIMARY source (the first), for the one thing only it may
    /// answer: a published correction.
    pub fn primary(&self) -> Option<&dyn LayerSource> {
        self.mirrors.first().map(|m| m.source.as_ref())
    }

    /// One source by its label, to ask it directly (a diagnosis about the
    /// source whose bytes produced a verdict). Never announces.
    pub fn source_for_label(&self, label: &str) -> Option<&dyn LayerSource> {
        self.mirrors
            .iter()
            .find(|m| m.label == label)
            .map(|m| m.source.as_ref())
    }

    /// Say, once per source, that a mirror and not the primary answered.
    fn announce(&self, label: &str, why: &str) {
        let Some(realm) = &self.announce_for else {
            return;
        };
        if !self.announced.borrow_mut().insert(label.to_string()) {
            return;
        }
        let primary = self.mirrors.first().map_or("", |m| m.label.as_str());
        let notice = format!(
            "note: realm '{realm}': answered by mirror {label}, not the primary {primary} \
             ({why}). A mirror is transport only: its bytes are accepted only if they verify \
             against the realm's trust root."
        );
        eprintln!("{notice}");
        self.notices.borrow_mut().push(notice);
    }

    /// What the user was told about sources, in order. Kept so the wording and
    /// the once-per-source rule are testable without capturing stderr.
    pub fn notices(&self) -> Vec<String> {
        self.notices.borrow().clone()
    }

    #[cfg(test)]
    fn note_served(&self, index: usize) {
        if index > 0 {
            let why = self
                .attempts
                .borrow()
                .iter()
                .map(|(l, e)| format!("{l}: {e}"))
                .collect::<Vec<_>>()
                .join("; ");
            self.announce(&self.mirrors[index].label, &why);
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
    #[cfg(test)]
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
        for (i, m) in self.mirrors.iter().enumerate() {
            match f(m.source.as_ref()) {
                Ok(v) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    self.note_served(i);
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

// Per-fetch failover is TEST-ONLY. It combines answers across sources (a
// manifest from one, a blob from another, an absence from a third), which is
// exactly what a verified realm fetch must not do; production reads go through
// `attempt` / `attempt_some`, where ONE source serves a coherent, fully
// verified set. Keeping this out of release builds means a new fetch site
// cannot adopt cross-source combination by passing `&Mirrors` as a source.
#[cfg(test)]
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

    fn fetch_published_line_status(&self, line: &str) -> Result<Option<Vec<u8>>, SourceError> {
        // A mirror that carries a correction the primary is missing is worth
        // reaching — that asymmetry is the reason a yank can be suppressed by
        // one registry and still arrive, so an explicit None keeps looking.
        self.try_each_optional("the published line-status document", |s| {
            s.fetch_published_line_status(line)
        })
    }

    fn fetch_attestations(
        &self,
        layer: &LayerRef,
    ) -> Result<Vec<crate::attestcarry::CarriedAttestation>, SourceError> {
        self.try_each("the attestations", |s| s.fetch_attestations(layer))
    }

    fn served_layers(&self, line: &str) -> Result<Option<Vec<String>>, SourceError> {
        // Left at the trait default this would say `Ok(None)` ("cannot
        // enumerate") for a realm whose primary CAN, silently switching off
        // the omission check. Delegated like every other fetch.
        self.try_each_optional("the served layers", |s| s.served_layers(line))
    }
}

#[cfg(test)]
impl Mirrors {
    /// For the `Option`-returning fetches: a source that returns `None` has
    /// answered honestly, but another source may still carry the document, so
    /// keep looking and report `None` only when nobody has it.
    fn try_each_optional<T>(
        &self,
        what: &str,
        mut f: impl FnMut(&dyn LayerSource) -> Result<Option<T>, SourceError>,
    ) -> Result<Option<T>, SourceError> {
        self.attempts.borrow_mut().clear();
        let mut any_answered = false;
        for (i, m) in self.mirrors.iter().enumerate() {
            match f(m.source.as_ref()) {
                Ok(Some(v)) => {
                    *self.served_by.borrow_mut() = Some(m.label.clone());
                    self.note_served(i);
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
        let unreachable = self
            .attempts
            .borrow()
            .iter()
            .any(|(_, e)| e != "carries none");
        if any_answered && !unreachable {
            // Every source answered "I do not carry this", which is a
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
        /// The document published under the line's OWN tag, separately from
        /// the baseline carried beside a layer (REQ-POSTDEPOSIT-001). Fake did
        /// not model this at all, so every source fell through to the trait
        /// default `Ok(None)` and four mutants on the Mirrors delegation were
        /// indistinguishable from the real thing.
        published: Option<Option<Vec<u8>>>,
        calls: Rc<Cell<usize>>,
    }

    fn ok(bytes: &[u8]) -> Box<Fake> {
        Box::new(Fake {
            manifest: Some(bytes.to_vec()),
            err: None,
            status: Some(Some(bytes.to_vec())),
            published: Some(Some(bytes.to_vec())),
            calls: Rc::new(Cell::new(0)),
        })
    }
    fn down(msg: &str) -> Box<Fake> {
        Box::new(Fake {
            manifest: None,
            err: Some(SourceError::Transport(msg.into())),
            status: None,
            published: None,
            calls: Rc::new(Cell::new(0)),
        })
    }
    fn empty() -> Box<Fake> {
        Box::new(Fake {
            manifest: None,
            err: Some(SourceError::NotFound("layer".into())),
            status: Some(None),
            published: Some(None),
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
        fn fetch_published_line_status(&self, _l: &str) -> Result<Option<Vec<u8>>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            match (&self.published, &self.err) {
                (Some(s), _) => Ok(s.clone()),
                (None, Some(e)) => Err(clone_err(e)),
                (None, None) => Ok(None),
            }
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

    /// A mirror carrying a CORRECTION the primary is missing must be reached.
    /// That asymmetry is the reason a yank can be suppressed by one registry
    /// and still arrive, so an explicit None has to keep looking rather than
    /// end the search.
    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_mirror_carrying_a_correction_is_reached_past_one_that_has_none() {
        let m = mirrors(vec![("a", empty()), ("b", ok(b"correction"))]);
        assert_eq!(
            m.fetch_published_line_status("2026.09").unwrap(),
            Some(b"correction".to_vec())
        );
        assert_eq!(m.served_by().as_deref(), Some("b"));
    }

    /// Nobody reachable is not "there is no correction". Reporting absence
    /// here would let a network fault look exactly like a line with nothing
    /// to say — and a suppressed yank is the difference.
    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_correction_nobody_could_be_asked_about_is_not_reported_as_absent() {
        let m = mirrors(vec![("a", down("no such host")), ("b", down("503"))]);
        let e = m
            .fetch_published_line_status("2026.09")
            .expect_err("must not report absence");
        assert!(e.to_string().contains("could be reached"), "{e}");
    }

    /// A line with genuinely nothing published is `Ok(None)` — distinct from
    /// both of the above.
    // rivet: verifies REQ-POSTDEPOSIT-001
    #[test]
    fn a_line_with_no_correction_published_is_absent_not_an_error() {
        let m = mirrors(vec![("a", empty()), ("b", empty())]);
        assert_eq!(m.fetch_published_line_status("2026.09").unwrap(), None);
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

    // ---- REQ-MIRROR-002 ----

    /// A source that can only enumerate, for the `served_layers` delegation.
    struct Serves(Option<Vec<String>>);
    impl LayerSource for Serves {
        fn fetch_manifest(&self, _l: &LayerRef) -> Result<Vec<u8>, SourceError> {
            Err(SourceError::NotFound("x".into()))
        }
        fn fetch_blob(&self, _d: &str) -> Result<Vec<u8>, SourceError> {
            Err(SourceError::NotFound("x".into()))
        }
        fn served_layers(&self, _line: &str) -> Result<Option<Vec<String>>, SourceError> {
            Ok(self.0.clone())
        }
    }

    fn realm_mirrors(v: Vec<(&str, Box<Fake>)>) -> Mirrors {
        let mut m = mirrors(v);
        m.announce_for = Some("acme".into());
        m
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn served_layers_is_delegated_not_left_at_the_cannot_enumerate_default() {
        let m = Mirrors::new(vec![Mirror {
            label: "primary".into(),
            source: Box::new(Serves(Some(vec!["2026.10.0".into()]))),
        }]);
        assert_eq!(
            m.served_layers("2026.10").unwrap(),
            Some(vec!["2026.10.0".to_string()])
        );
        let none = Mirrors::new(vec![Mirror {
            label: "primary".into(),
            source: Box::new(Serves(None)),
        }]);
        assert_eq!(none.served_layers("2026.10").unwrap(), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn served_layers_reaches_a_mirror_that_can_enumerate_past_one_that_cannot() {
        let m = Mirrors::new(vec![
            Mirror {
                label: "a".into(),
                source: Box::new(Serves(None)),
            },
            Mirror {
                label: "b".into(),
                source: Box::new(Serves(Some(vec!["l".into()]))),
            },
        ]);
        assert_eq!(m.served_layers("x").unwrap(), Some(vec!["l".to_string()]));
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_returns_the_first_success_and_asks_no_further() {
        let m = realm_mirrors(vec![("primary", ok(b"p")), ("mirror", ok(b"m"))]);
        let mut asked = 0;
        let v: Result<u32, Vec<(String, String)>> = m.attempt(
            |_s, _| {
                asked += 1;
                Ok(7)
            },
            |_| true,
        );
        assert_eq!(v.unwrap(), 7);
        assert_eq!(asked, 1);
        assert_eq!(m.served_by().as_deref(), Some("primary"));
        assert!(m.notices().is_empty(), "the primary answered");
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_moves_on_when_a_source_fails_verification_and_names_the_mirror() {
        let m = realm_mirrors(vec![("primary", ok(b"p")), ("mirror", ok(b"m"))]);
        let mut n = 0;
        let v: Result<&str, Vec<(String, String)>> = m.attempt(
            |_s, _| {
                n += 1;
                if n == 1 {
                    Err("signature does not verify".to_string())
                } else {
                    Ok("fine")
                }
            },
            |_| true,
        );
        assert_eq!(v.unwrap(), "fine");
        assert_eq!(m.served_by().as_deref(), Some("mirror"));
        let notices = m.notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        for needle in ["acme", "primary", "mirror", "trust root"] {
            assert!(notices[0].contains(needle), "{needle}: {}", notices[0]);
        }
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_reports_every_source_failure_in_order_when_none_succeeds() {
        let m = realm_mirrors(vec![("a", ok(b"p")), ("b", ok(b"m")), ("c", ok(b"c"))]);
        let r: Result<(), Vec<(String, String)>> =
            m.attempt(|_s, _| Err("no".to_string()), |_| true);
        let failures = r.unwrap_err();
        let labels: Vec<_> = failures.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, ["a", "b", "c"]);
        assert!(m.notices().is_empty(), "nobody answered");
        assert_eq!(m.served_by(), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_mirror_answering_a_fetch_is_announced_once_not_per_fetch() {
        let m = realm_mirrors(vec![
            ("primary", down("connection refused")),
            ("mirror", ok(b"m")),
        ]);
        m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap();
        m.fetch_blob("sha256:x").unwrap();
        m.fetch_line_status(&LayerRef::Digest("d".into())).unwrap();
        let notices = m.notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("connection refused"), "{}", notices[0]);
        assert!(notices[0].contains("mirror"));
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn the_primary_answering_is_never_announced() {
        let m = realm_mirrors(vec![("primary", ok(b"p")), ("mirror", ok(b"m"))]);
        m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap();
        m.fetch_line_status(&LayerRef::Digest("d".into())).unwrap();
        assert!(m.notices().is_empty());
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_source_set_that_is_not_a_realm_announces_nothing() {
        let m = mirrors(vec![("primary", down("x")), ("mirror", ok(b"m"))]);
        m.fetch_manifest(&LayerRef::Digest("d".into())).unwrap();
        assert!(m.notices().is_empty());
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn for_realm_orders_sources_primary_first_then_mirrors_as_written() {
        let m = Mirrors::for_realm(
            "acme",
            &[
                "oci://primary.example/r".to_string(),
                "oci+http://127.0.0.1:1/r".to_string(),
                "/nonexistent/dir".to_string(),
            ],
            "linux-x86_64",
        )
        .unwrap();
        assert_eq!(
            m.labels(),
            [
                "oci://primary.example/r",
                "oci+http://127.0.0.1:1/r",
                "/nonexistent/dir"
            ]
        );
        assert_eq!(m.announce_for.as_deref(), Some("acme"));
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn for_realm_refuses_a_malformed_source_instead_of_dropping_it() {
        assert!(Mirrors::for_realm("acme", &["oci://".to_string()], "p").is_err());
        assert!(Mirrors::for_realm("acme", &["oci+http://nohost".to_string()], "p").is_err());
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn single_is_one_source_with_nobody_to_announce_to() {
        let m = Mirrors::single("oci://r.example/x", "p").unwrap();
        assert_eq!(m.labels(), ["oci://r.example/x"]);
        assert_eq!(m.announce_for, None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn source_from_spec_tells_a_registry_a_layout_and_a_plain_directory_apart() {
        // A plain directory is a DirSource: it serves what `put` wrote.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("plain");
        crate::DirSource::at(&dir)
            .put(b"manifest-bytes", &[])
            .unwrap();
        let src = source_from_spec(dir.to_str().unwrap(), "p").unwrap();
        let digest = crate::store::manifest_digest(b"manifest-bytes");
        assert_eq!(
            src.fetch_manifest(&LayerRef::Digest(digest)).unwrap(),
            b"manifest-bytes".to_vec()
        );
        // A directory with an `oci-layout` marker is read as a layout, so it
        // does NOT serve a DirSource's files.
        let layout = tmp.path().join("layout");
        std::fs::create_dir_all(&layout).unwrap();
        std::fs::write(
            layout.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        crate::DirSource::at(&layout)
            .put(b"manifest-bytes", &[])
            .unwrap();
        let src = source_from_spec(layout.to_str().unwrap(), "p").unwrap();
        let digest = crate::store::manifest_digest(b"manifest-bytes");
        assert!(src.fetch_manifest(&LayerRef::Digest(digest)).is_err());
        // Both registry schemes are registries (and a bad one is an error,
        // not a directory named "oci://...").
        assert!(source_from_spec("oci://r.example/x", "p").is_ok());
        assert!(source_from_spec("oci+http://127.0.0.1:1/x", "p").is_ok());
        assert!(source_from_spec("oci://", "p").is_err());
        assert!(source_from_spec("oci+http://", "p").is_err());
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_terminal_error_stops_failover_and_no_later_source_is_asked() {
        let m = realm_mirrors(vec![
            ("primary", ok(b"p")),
            ("mirror", ok(b"m")),
            ("third", ok(b"t")),
        ]);
        let mut asked = 0;
        let r: Result<(), Vec<(String, String)>> = m.attempt(
            |_s, _| {
                asked += 1;
                Err("rollback refused".to_string())
            },
            |e| e != "rollback refused",
        );
        let failures = r.unwrap_err();
        assert_eq!(asked, 1, "a verified verdict must not be retried elsewhere");
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0],
            ("primary".to_string(), "rollback refused".to_string())
        );
        assert!(m.notices().is_empty(), "no mirror answered, none announced");
        assert_eq!(m.served_by(), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_terminal_error_after_a_failover_error_is_the_last_entry() {
        let m = realm_mirrors(vec![
            ("primary", ok(b"p")),
            ("mirror", ok(b"m")),
            ("third", ok(b"t")),
        ]);
        let mut n = 0;
        let r: Result<(), Vec<(String, String)>> = m.attempt(
            |_s, _| {
                n += 1;
                Err(if n == 1 { "down" } else { "verdict" }.to_string())
            },
            |e| e == "down",
        );
        let failures = r.unwrap_err();
        assert_eq!(n, 2, "the third source must not be asked");
        let labels: Vec<_> = failures.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, ["primary", "mirror"]);
        assert_eq!(failures[1].1, "verdict");
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn the_notice_gives_each_skipped_sources_reason_so_forgery_is_not_an_outage() {
        let m = realm_mirrors(vec![("primary", ok(b"p")), ("mirror", ok(b"m"))]);
        let mut n = 0;
        let _: Result<(), Vec<(String, String)>> = m.attempt(
            |_s, _| {
                n += 1;
                if n == 1 {
                    Err("signature does not verify against the trust root".to_string())
                } else {
                    Ok(())
                }
            },
            |_| true,
        );
        let notices = m.notices();
        assert!(
            notices[0].contains("signature does not verify"),
            "the reason must be stated: {}",
            notices[0]
        );
        assert!(
            !notices[0].contains("did not supply a layer that verified"),
            "that wording blamed forgery for an outage too: {}",
            notices[0]
        );
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn an_unreachable_source_then_a_none_is_not_reported_as_nothing_published() {
        // The fail-open: with the primary unreachable, a mirror that simply
        // carries no correction would make "could not ask" read as "there is
        // none", and a signer would sign a longer horizon than the correction
        // the primary holds permits.
        let m = mirrors(vec![
            ("primary", down("connection refused")),
            ("mirror", empty()),
        ]);
        let r = m.fetch_published_line_status("2026.09");
        assert!(r.is_err(), "unknown must not become absent: {r:?}");
        let r = m.fetch_line_status(&LayerRef::Digest("d".into()));
        assert!(r.is_err(), "{r:?}");
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_source_spec_with_an_unknown_url_scheme_is_refused_not_read_as_a_path() {
        for spec in [
            "https://mirror.example/x",
            "ftp://m/x",
            "s3://bucket/k",
            "file:///tmp/x",
        ] {
            let e = source_from_spec(spec, "p").err().expect(spec).to_string();
            assert!(e.contains(spec), "{e}");
        }
        let e = Mirrors::for_realm(
            "acme",
            &["oci://p.example/x".into(), "https://m/x".into()],
            "p",
        )
        .err()
        .expect("refused")
        .to_string();
        assert!(e.contains("acme") && e.contains("https://m/x"), "{e}");
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_relative_path_in_a_realm_is_refused_rather_than_resolved_against_the_cwd() {
        let e = Mirrors::for_realm(
            "acme",
            &["oci://p.example/x".into(), "mirror-dir".into()],
            "p",
        )
        .err()
        .expect("refused")
        .to_string();
        assert!(e.contains("acme") && e.contains("mirror-dir"), "{e}");
        // An absolute path is fine, and an explicit --from keeps its meaning.
        assert!(Mirrors::for_realm("acme", &["/abs/dir".into()], "p").is_ok());
        assert!(Mirrors::single("rel/dir", "p").is_ok());
    }

    // ---- attempt_some: absent is not the end of the search ----

    type SomeResult = Result<Option<u32>, Vec<(String, String)>>;

    fn some_then(
        answers: Vec<Result<Option<u32>, &'static str>>,
        fails_over: impl Fn(&String) -> bool,
    ) -> (SomeResult, usize, Mirrors) {
        let n = answers.len();
        let m = realm_mirrors(
            (0..n)
                .map(|i| (["a", "b", "c"][i], ok(b"x")))
                .collect::<Vec<_>>(),
        );
        let mut i = 0;
        let r = m.attempt_some(
            |_s, _| {
                let a = answers[i];
                i += 1;
                a.map_err(str::to_string)
            },
            fails_over,
        );
        (r, i, m)
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_keeps_asking_past_a_source_that_carries_none() {
        let (r, asked, m) = some_then(vec![Ok(None), Ok(Some(7))], |_| true);
        assert_eq!(r.unwrap(), Some(7));
        assert_eq!(asked, 2);
        assert_eq!(m.served_by().as_deref(), Some("b"));
        assert_eq!(m.notices().len(), 1, "the mirror answered, so it is said");
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_stops_at_the_first_some_and_does_not_announce_the_primary() {
        let (r, asked, m) = some_then(vec![Ok(Some(1)), Ok(Some(2))], |_| true);
        assert_eq!(r.unwrap(), Some(1));
        assert_eq!(asked, 1);
        assert!(m.notices().is_empty());
        assert_eq!(m.served_by().as_deref(), Some("a"));
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_reports_none_only_when_every_source_answered_none() {
        let (r, asked, m) = some_then(vec![Ok(None), Ok(None)], |_| true);
        assert_eq!(r.unwrap(), None);
        assert_eq!(asked, 2);
        assert_eq!(m.served_by(), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_treats_a_none_after_a_failed_source_as_unknown_not_absent() {
        // Absence on a mirror cannot prove absence after the primary failed to
        // answer: an unreachable source might hold the document.
        let (r, asked, _) = some_then(vec![Err("down"), Ok(None)], |_| true);
        let failures = r.expect_err("unknown, not none");
        assert_eq!(asked, 2);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "a");
        // The other order: the first source ANSWERED none authoritatively, and a
        // LATER one failed. Only failures BEFORE the first none make absence
        // unknown, so this is none.
        let (r, _, _) = some_then(vec![Ok(None), Err("down")], |_| true);
        assert_eq!(r.unwrap(), None);
        // A Some after a failure still wins.
        let (r, _, _) = some_then(vec![Err("down"), Ok(Some(3))], |_| true);
        assert_eq!(r.unwrap(), Some(3));
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn only_the_first_source_is_told_it_is_the_primary() {
        let m = realm_mirrors(vec![("a", ok(b"x")), ("b", ok(b"x")), ("c", ok(b"x"))]);
        let mut seen = Vec::new();
        let _: Result<(), Vec<(String, String)>> = m.attempt(
            |_s, primary| {
                seen.push(primary);
                Err("no".to_string())
            },
            |_| true,
        );
        assert_eq!(seen, [true, false, false]);
        let m = realm_mirrors(vec![("a", ok(b"x")), ("b", ok(b"x"))]);
        let mut seen = Vec::new();
        let _: Result<Option<()>, Vec<(String, String)>> = m.attempt_some(
            |_s, primary| {
                seen.push(primary);
                Ok(None)
            },
            |_| true,
        );
        assert_eq!(seen, [true, false]);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_mirror_answering_after_a_none_says_so_without_an_empty_reason() {
        let (_, _, m) = some_then(vec![Ok(None), Ok(Some(1))], |_| true);
        let notice = m.notices().remove(0);
        assert!(
            !notice.contains("()"),
            "an empty reason was printed: {notice}"
        );
        assert!(notice.contains("carries none"), "{notice}");
        assert!(notice.contains("answered by mirror b"), "{notice}");
        // With a failure AND an absence, both are said.
        let (_, _, m) = some_then(vec![Err("503"), Ok(None), Ok(Some(1))], |_| true);
        let notice = m.notices().remove(0);
        assert!(
            notice.contains("a: 503") && notice.contains("carries none"),
            "{notice}"
        );
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_errors_only_when_no_source_answered_at_all() {
        let (r, asked, _) = some_then(vec![Err("down"), Err("503")], |_| true);
        let failures = r.unwrap_err();
        assert_eq!(asked, 2);
        let labels: Vec<_> = failures.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels, ["a", "b"]);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn attempt_some_stops_at_a_terminal_error() {
        let (r, asked, m) = some_then(vec![Err("verdict"), Ok(Some(9)), Ok(Some(9))], |e| {
            e != "verdict"
        });
        let failures = r.unwrap_err();
        assert_eq!(asked, 1, "a verdict is never second-guessed by a mirror");
        assert_eq!(failures.len(), 1);
        assert!(m.notices().is_empty());
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_source_is_found_by_its_label_and_an_unknown_label_is_none() {
        let m = mirrors(vec![("primary", ok(b"p")), ("mirror", ok(b"m"))]);
        let got = m
            .source_for_label("mirror")
            .expect("labelled")
            .fetch_manifest(&LayerRef::Digest("d".into()))
            .unwrap();
        assert_eq!(got, b"m".to_vec());
        let got = m
            .source_for_label("primary")
            .unwrap()
            .fetch_manifest(&LayerRef::Digest("d".into()))
            .unwrap();
        assert_eq!(got, b"p".to_vec());
        assert!(m.source_for_label("nobody").is_none());
        assert!(
            m.notices().is_empty(),
            "asking a source directly announces nothing"
        );
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_registry_origin_is_scheme_host_and_port_and_a_path_has_none() {
        assert_eq!(
            registry_origin("oci://ghcr.io/a/b").as_deref(),
            Some("https://ghcr.io")
        );
        assert_eq!(
            registry_origin("oci+http://127.0.0.1:5000/a").as_deref(),
            Some("http://127.0.0.1:5000")
        );
        assert_eq!(registry_origin("/some/dir"), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn only_a_lowercase_scheme_before_colon_slash_slash_is_a_url_scheme() {
        assert_eq!(url_scheme("https://x"), Some("https"));
        assert_eq!(url_scheme("a+b.c-d://x"), Some("a+b.c-d"));
        assert_eq!(url_scheme("s3://bucket"), Some("s3"));
        assert_eq!(url_scheme("Https://x"), None, "uppercase first letter");
        assert_eq!(url_scheme("1ab://x"), None, "digit first");
        assert_eq!(url_scheme("/abs://x"), None, "a path that contains ://");
        assert_eq!(
            url_scheme("a_b://x"),
            None,
            "underscore is not scheme syntax"
        );
        assert_eq!(url_scheme("aB://x"), None, "uppercase later");
        assert_eq!(url_scheme("://x"), None);
        assert_eq!(url_scheme("/plain/dir"), None);
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_refused_source_names_the_realm_and_the_source_whatever_went_wrong() {
        for spec in ["oci://", "ftp://m/x", "mirror-dir"] {
            let e = Mirrors::for_realm("acme", &["oci://p.example/x".into(), spec.into()], "p")
                .err()
                .expect(spec)
                .to_string();
            assert!(
                e.contains("realm 'acme': source '") && e.contains(spec),
                "{e}"
            );
        }
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn every_source_after_the_first_is_a_mirror_even_when_the_primary_is_not_a_registry() {
        assert_eq!(role(0, Some("https://ghcr.io")), Role::Primary);
        assert_eq!(role(0, None), Role::Primary);
        assert_eq!(
            role(1, Some("https://ghcr.io")),
            Role::Mirror {
                primary_origin: Some("https://ghcr.io")
            }
        );
        assert_eq!(
            role(2, None),
            Role::Mirror {
                primary_origin: None
            },
            "a directory primary must not unlock mirrors: fail closed"
        );
    }

    // rivet: verifies REQ-MIRROR-002
    #[test]
    fn a_reason_is_one_short_line() {
        assert_eq!(short_reason(&"first\nsecond"), "first");
        let long = "x".repeat(400);
        let r = short_reason(&long);
        assert!(r.ends_with("...") && r.chars().count() == 143, "{r}");
        assert_eq!(short_reason(&"  padded  "), "padded");
        let exact = "y".repeat(140);
        assert_eq!(short_reason(&exact), exact);
    }
}
