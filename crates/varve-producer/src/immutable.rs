//! A layer id names one set of bytes, forever (REQ-IMMUTABLE-001).
//!
//! ## Why this lives here and not in `varve`
//!
//! `varve deposit` signs a layer and writes an OCI layout. It does not publish:
//! *"varve runs no server and pushes nothing, by design"*. That is not an
//! accident of implementation — `varve docs air-gap` and the threat model both
//! rest on varve contacting no network, and a registry lookup added to
//! `deposit` would spend that claim to fix a publisher's bug.
//!
//! So the publisher asks the question, and the publisher is this program.
//!
//! ## What went wrong, and what did not
//!
//! Measured against varve 0.31.0: the same deposit spec, deposited twice with
//! `issued-at` one second apart, yields two different manifest digests; with
//! the same `issued-at` it reproduces the digest exactly. The deposit is
//! already deterministic **given its inputs**. Nothing constrained a layer id
//! from being *published* twice.
//!
//! `rolling` republished `2026.08.4` overnight and every name-only pin on it
//! stopped resolving — gale's shimmed tools failed with *"layer 2026.08.4 is
//! installed more than once under different digests"*. varve's consumer side
//! behaved correctly, and is why it was caught. But once two digests exist
//! under one name, no amount of consumer-side care repairs it: the name has
//! stopped identifying anything.

use std::fmt;

/// What the destination already holds for a layer id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// The destination does not carry this id.
    Absent,
    /// The destination carries this id at this manifest digest.
    At(String),
}

/// What the publisher should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing there yet — publish.
    Publish,
    /// Already published, byte for byte. A re-run, not a republish.
    AlreadyPublished,
    /// Already published as something ELSE. Refuse.
    WouldReplace { existing: String, incoming: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub layer: String,
    pub existing: String,
    pub incoming: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "layer {} is already published under a different manifest digest.\n\
             \n  already published: {}\n  about to publish:  {}\n\n\
             Refusing. A layer id names one set of bytes: publishing a second \
             set under this name does not replace the first for anyone who \
             already resolved it, and it breaks every pin that names the layer \
             without a digest — `varve which` then reports the layer is \
             installed more than once and cannot say which is meant.\n\n\
             If the published layer is wrong and NOBODY has consumed it, \
             re-publish deliberately with --replace-published, which says what \
             it destroys. If anyone may have consumed it, publish a NEW layer \
             id instead: the counter exists so that a correction is a new \
             layer, not a rewritten one.",
            self.layer, self.existing, self.incoming
        )
    }
}

impl std::error::Error for Refusal {}

/// Reject a digest that is not one.
///
/// `--digest ""` used to sail straight through to `verdict: publish` — an
/// unset shell variable in a workflow would have published without the check
/// ever comparing anything. A digest is 64 hex characters, optionally prefixed
/// `sha256:`; anything else is a caller bug and is refused rather than
/// compared.
pub fn parse_digest(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(
            "no digest given (an unset variable reaches here as an empty \
                    string, and an empty digest must never be compared)"
                .into(),
        );
    }
    let hex = match t.split_once(':') {
        Some(("sha256", h)) => h,
        Some((alg, _)) => {
            return Err(format!(
                "digest algorithm `{alg}` is not supported; a layer manifest \
                 digest is sha256"
            ));
        }
        None => t,
    };
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "`{t}` is not a sha256 digest: expected 64 hex characters, \
             optionally prefixed `sha256:`"
        ));
    }
    Ok(t.to_string())
}

/// The whole decision, as a pure function over two descriptors.
///
/// Deliberately not a method on anything that can reach a network: what the
/// registry says is an input, so this is decided by tests rather than by a
/// registry being reachable.
pub fn decide(existing: &Existing, incoming: &str) -> Verdict {
    match existing {
        Existing::Absent => Verdict::Publish,
        Existing::At(d) if digests_equal(d, incoming) => Verdict::AlreadyPublished,
        Existing::At(d) => Verdict::WouldReplace {
            existing: d.clone(),
            incoming: incoming.to_string(),
        },
    }
}

/// Compare two manifest digests.
///
/// Case-insensitive on the hex, and tolerant of one side carrying the
/// `sha256:` prefix and the other not — registries and tools disagree about
/// that, and a spurious difference here would report a republish that is not
/// happening, which trains an operator to pass `--replace-published`.
fn digests_equal(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        s.trim()
            .strip_prefix("sha256:")
            .unwrap_or(s.trim())
            .to_ascii_lowercase()
    }
    let (a, b) = (norm(a), norm(b));
    // An empty digest is not equal to anything, including another empty one:
    // "we could not read a digest" must never come out as "they match".
    !a.is_empty() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:088db18c45da66ae7b8570f5736fc71e777df2c4a48ab2263242bb6eb0e4655b";
    const D2: &str = "sha256:9d2a30f2f2283f8590f6822a1a5a0dcb2020a6a53422f863c709293e7f9e4078";

    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn an_unpublished_layer_is_published() {
        assert_eq!(decide(&Existing::Absent, D1), Verdict::Publish);
    }

    /// Clause 2. A re-run of the same workflow must be safe, not merely lucky.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn republishing_the_identical_layer_is_a_no_op_not_a_failure() {
        assert_eq!(
            decide(&Existing::At(D1.into()), D1),
            Verdict::AlreadyPublished
        );
    }

    /// Clause 1 — the whole point. This is the 2026.08.4 incident.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn publishing_different_bytes_under_a_published_id_is_refused() {
        let v = decide(&Existing::At(D1.into()), D2);
        assert_eq!(
            v,
            Verdict::WouldReplace {
                existing: D1.into(),
                incoming: D2.into()
            }
        );
    }

    /// Registries and tools disagree about the `sha256:` prefix. A spurious
    /// difference would report a republish that is not happening, and train an
    /// operator to reach for --replace-published as a matter of routine.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn the_same_digest_spelled_differently_is_still_the_same_digest() {
        let bare = D1.trim_start_matches("sha256:");
        assert_eq!(
            decide(&Existing::At(bare.into()), D1),
            Verdict::AlreadyPublished
        );
        assert_eq!(
            decide(&Existing::At(D1.into()), &bare.to_ascii_uppercase()),
            Verdict::AlreadyPublished
        );
        assert_eq!(
            decide(&Existing::At(format!(" {D1} ")), D1),
            Verdict::AlreadyPublished
        );
    }

    /// "We could not read a digest" must never come out as "they match" — that
    /// would turn an unreadable registry answer into permission to overwrite.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn an_empty_digest_never_compares_equal_to_anything() {
        assert!(matches!(
            decide(&Existing::At(String::new()), D1),
            Verdict::WouldReplace { .. }
        ));
        assert!(matches!(
            decide(&Existing::At(String::new()), ""),
            Verdict::WouldReplace { .. }
        ));
        assert!(matches!(
            decide(&Existing::At(D1.into()), ""),
            Verdict::WouldReplace { .. }
        ));
    }

    /// An unset shell variable arrives as an empty string. It used to reach
    /// `verdict: publish` untouched.
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn a_digest_that_is_not_a_digest_is_refused_before_anything_is_compared() {
        for bad in [
            "",
            "   ",
            "sha256:",
            "not-a-digest",
            "sha256:088db18c",
            "sha512:088db18c45da66ae7b8570f5736fc71e777df2c4a48ab2263242bb6eb0e4655b",
            "088db18c45da66ae7b8570f5736fc71e777df2c4a48ab2263242bb6eb0e4655bZZ",
        ] {
            assert!(parse_digest(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(parse_digest(D1).is_ok());
        assert!(parse_digest(D1.trim_start_matches("sha256:")).is_ok());
        assert!(parse_digest(&format!("  {D1}  ")).is_ok());
    }

    /// Clause 3: an operator's next question is always "which one is live".
    // rivet: verifies REQ-IMMUTABLE-001
    #[test]
    fn the_refusal_names_the_layer_and_both_digests_and_the_way_out() {
        let msg = Refusal {
            layer: "2026.08.4".into(),
            existing: D1.into(),
            incoming: D2.into(),
        }
        .to_string();
        assert!(msg.contains("2026.08.4"), "{msg}");
        assert!(msg.contains(D1) && msg.contains(D2), "{msg}");
        // And it says what to do instead, both ways round.
        assert!(msg.contains("--replace-published"), "{msg}");
        assert!(msg.contains("publish a NEW layer id"), "{msg}");
    }
}
