//! Write a scan's proposal into the manifest, in place (REQ-PREPARED-001).
//!
//! `scan` only ever REPORTS — it is pure, and stays that way. This module is
//! the one piece of `scan --apply` that is allowed an opinion about the
//! manifest's TEXT, and even here the opinion is narrow: locate the exact
//! bytes a `Moved` licenses touching, and touch nothing else.
//!
//! `layer.toml` is mostly comments — the realm's own reasoning for every pin
//! it carries — so re-serialising it through `toml`/serde (which keeps only
//! the data, never the prose around it) would sign a layer that silently
//! erased the record. `toml_edit` edits the parse tree in place instead:
//! every comment, blank line and bit of whitespace that this function does
//! not specifically change survives byte-for-byte.
//!
//! Kept PURE on purpose, like `scan` itself: no file I/O here, so the rules
//! below are testable against fixtures rather than only exercised against a
//! real `layer.toml`. The caller (`main.rs`) does the reading, the atomic
//! write, and nothing else.

use std::collections::BTreeMap;

use crate::scan::{Moved, Remeasured};

/// Why `apply` refused to write a proposal.
///
/// Every variant here is a case where writing SOMETHING would be a guess, or
/// where varve's own validator would refuse the result — and a refusal must
/// never reach the caller as a half-written file. `main.rs` only writes to
/// disk on `Ok`; on `Err` the manifest is exactly what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The text handed in did not parse as TOML at all.
    ParseFailed(String),
    /// A `Moved` entry's name matches no `[[tool]]`, or more than one.
    ///
    /// "Never guess" (clause 2): a scanner that picked the first match, or
    /// bumped every match, would be choosing on the operator's behalf which
    /// entry a report about one payload actually describes.
    ToolNotFound {
        name: String,
    },
    ToolAmbiguous {
        name: String,
        count: usize,
    },
    /// The entry carries the OLD, unsplit `unverified-reason = "..."` and the
    /// re-measurement needs `[tool.unverified].measured` to land in.
    ///
    /// Editing free prose by heuristic (replace up to the first full stop) is
    /// exactly the failure mode `[tool.unverified]` exists to retire — it
    /// mangles an unusually punctuated reason and then SIGNS the result. A
    /// person migrates the entry first.
    LegacyOptInNeedsMigration {
        name: String,
    },
    /// Two auto-bumpable tools share a release (same `repo`, same `latest`)
    /// and their re-measurements disagree — which `remeasured` being computed
    /// ONCE per release should already prevent (REQ-PREPARED-001 clause 2).
    /// Caught here anyway, because an assumption enforced only upstream is an
    /// assumption a future caller can violate without this module noticing.
    InconsistentRemeasurement {
        repo: String,
        release: String,
        first: String,
        second: String,
    },
    /// The rewritten text does not parse under `varve_core`'s own validator.
    ///
    /// Never returned alongside the new text — a proposal varve itself would
    /// refuse to deposit must not be the thing this function hands back as
    /// success.
    ResultRefused(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::ParseFailed(e) => write!(f, "manifest does not parse as TOML: {e}"),
            ApplyError::ToolNotFound { name } => write!(
                f,
                "no [[tool]] entry named {name:?} — refusing to guess which entry a \
                 scan report about {name:?} describes"
            ),
            ApplyError::ToolAmbiguous { name, count } => write!(
                f,
                "{count} [[tool]] entries are named {name:?} — refusing to guess \
                 which one a scan report about {name:?} describes"
            ),
            ApplyError::LegacyOptInNeedsMigration { name } => write!(
                f,
                "{name:?} carries the old `unverified-reason = \"...\"` form and its \
                 opt-in must be re-measured. Migrate it to `[tool.unverified]` first — \
                 editing the free-prose reason by heuristic is the failure mode the \
                 split form exists to retire."
            ),
            ApplyError::InconsistentRemeasurement {
                repo,
                release,
                first,
                second,
            } => write!(
                f,
                "{repo} {release} was re-measured twice with different results, which \
                 must not happen for one release:\n  {first:?}\n  {second:?}"
            ),
            ApplyError::ResultRefused(e) => write!(
                f,
                "the rewritten manifest would not parse, so nothing was written:\n{e}"
            ),
        }
    }
}

impl std::error::Error for ApplyError {}

/// Rewrite `text` in light of what `scan` found, returning the new text and a
/// human-readable list of what changed.
///
/// Only entries whose [`Moved::auto_bumpable`] is true are touched; every
/// other byte of `text` is untouched. On any error, the returned `Result` is
/// `Err` and no text is returned at all — the caller must not write a partial
/// result.
pub fn apply(text: &str, moved: &[Moved]) -> Result<(String, Vec<String>), ApplyError> {
    let bumpable: Vec<&Moved> = moved.iter().filter(|m| m.auto_bumpable()).collect();
    if bumpable.is_empty() {
        // CLAUSE 7. Not even a re-serialisation: identical input, identical
        // output, so a caller comparing bytes (or mtimes, or a VCS diff) sees
        // nothing happened.
        return Ok((text.to_string(), Vec::new()));
    }

    // CLAUSE 5, asserted rather than assumed. `remeasured` is computed once
    // per release by the caller, so two auto-bumpable tools sharing one
    // SHOULD already agree — but an assumption enforced only upstream is one
    // a future caller can break without this module noticing.
    let mut measured_by_release: BTreeMap<(String, String), String> = BTreeMap::new();
    for m in &bumpable {
        if let Some(Remeasured::StillUnproven { measured }) = &m.remeasured {
            let key = (m.repo.clone(), m.latest.clone());
            match measured_by_release.get(&key) {
                Some(prev) if prev != measured => {
                    return Err(ApplyError::InconsistentRemeasurement {
                        repo: key.0,
                        release: key.1,
                        first: prev.clone(),
                        second: measured.clone(),
                    });
                }
                Some(_) => {}
                None => {
                    measured_by_release.insert(key, measured.clone());
                }
            }
        }
    }

    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| ApplyError::ParseFailed(e.to_string()))?;

    let mut changes = Vec::new();

    for m in &bumpable {
        apply_one(&mut doc, m, &mut changes)?;
    }

    let new_text = doc.to_string();

    // CLAUSE 6. Validate with varve's OWN parser before handing back
    // anything — never the second opinion this module could form on its own.
    varve_core::layerspec::parse_layer_manifest(&new_text)
        .map_err(|e| ApplyError::ResultRefused(e.to_string()))?;

    Ok((new_text, changes))
}

/// Apply one `Moved` entry's proposal to the one `[[tool]]` table it names.
fn apply_one(
    doc: &mut toml_edit::DocumentMut,
    m: &Moved,
    changes: &mut Vec<String>,
) -> Result<(), ApplyError> {
    // CLAUSE 2. Locate the ONE matching entry, or refuse. Counted on an
    // immutable view first, because a mutable borrow of the array can only be
    // taken once the index is known.
    let matches = doc
        .get("tool")
        .and_then(toml_edit::Item::as_array_of_tables)
        .map(|arr| {
            arr.iter()
                .enumerate()
                .filter(|(_, t)| {
                    t.get("name").and_then(toml_edit::Item::as_str) == Some(m.name.as_str())
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let idx = match matches.len() {
        0 => {
            return Err(ApplyError::ToolNotFound {
                name: m.name.clone(),
            });
        }
        1 => matches[0],
        n => {
            return Err(ApplyError::ToolAmbiguous {
                name: m.name.clone(),
                count: n,
            });
        }
    };

    let table = doc
        .get_mut("tool")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
        .and_then(|arr| arr.get_mut(idx))
        .expect("the index was just found in this same array");

    // CLAUSE 3. `version` always, since only an auto-bumpable entry (which
    // requires `derived_version.is_some()`) ever reaches here.
    //
    // BUT WHICH VALUE depends on whether the entry has a `release` key. With
    // one, `version` is the payload's own number and `release` is the tag, so
    // `version` takes the bare derived number. WITHOUT one, `version` is BOTH
    // the payload's number and the tag the deposit asks the forge for — so it
    // must keep the tag's own spelling, `v1.262.0`, not the bare `1.262.0`.
    // Writing the bare form handed the next deposit a tag that does not exist,
    // and `plan` accepted it because `plan` never fetches.
    let derived = m
        .derived_version
        .as_deref()
        .expect("auto_bumpable() requires derived_version to be Some");
    let new_version: &str = if table.contains_key("release") {
        derived
    } else {
        &m.latest
    };
    let old_version = table
        .get("version")
        .and_then(toml_edit::Item::as_str)
        .map(str::to_string);
    set_string(table, "version", new_version);
    changes.push(format!(
        "{}: version {} -> {}",
        m.name,
        old_version.as_deref().unwrap_or("?"),
        new_version
    ));

    if table.contains_key("release") {
        let old_release = table
            .get("release")
            .and_then(toml_edit::Item::as_str)
            .map(str::to_string);
        set_string(table, "release", &m.latest);
        changes.push(format!(
            "{}: release {} -> {}",
            m.name,
            old_release.as_deref().unwrap_or("?"),
            m.latest
        ));
    }

    // Opt-in handling (clause 4), only for an entry that carries one AND was
    // re-measured — `remeasured` is `None` for a payload with no opt-in at
    // all, and for one a probe could not reach, and neither case licenses
    // touching anything here.
    if let Some(remeasured) = &m.remeasured {
        let has_legacy = table.contains_key("unverified-reason");
        let has_split = table
            .get("unverified")
            .map(|i| i.is_table())
            .unwrap_or(false);

        match remeasured {
            Remeasured::StillUnproven { measured } => {
                if has_legacy {
                    // Never attempted: editing free prose by heuristic is
                    // exactly what the split form exists to retire.
                    return Err(ApplyError::LegacyOptInNeedsMigration {
                        name: m.name.clone(),
                    });
                }
                if has_split {
                    let sub = table
                        .get_mut("unverified")
                        .and_then(toml_edit::Item::as_table_mut)
                        .expect("has_split just confirmed this is a table");
                    set_string(sub, "measured", measured);
                    changes.push(format!("{}: unverified.measured re-measured", m.name));
                }
                // No opt-in at all: nothing to do, and `remeasured` should
                // not have been set for this entry — but silently doing
                // nothing is the safe response to a caller's bookkeeping bug,
                // not a reason to invent a write.
            }
            Remeasured::ProofNowExists { mechanism } => {
                if has_legacy {
                    table.remove("unverified-reason");
                    changes.push(format!(
                        "{}: unverified-reason removed ({mechanism} now published)",
                        m.name
                    ));
                } else if has_split {
                    table.remove("unverified");
                    changes.push(format!(
                        "{}: [tool.unverified] removed ({mechanism} now published)",
                        m.name
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Set a string value, preserving the existing key's decor (leading comments,
/// inline trailing comments, surrounding whitespace) exactly.
///
/// Replacing the whole `Item` with a freshly constructed one would also
/// replace its decor with toml_edit's defaults — which is how a bump would
/// silently eat a trailing `# why` comment on the same line. Mutating the
/// existing `Value` in place keeps everything but the string itself.
fn set_string(table: &mut toml_edit::Table, key: &str, new_value: &str) {
    if let Some(val) = table.get_mut(key).and_then(toml_edit::Item::as_value_mut) {
        let decor = val.decor().clone();
        let mut replacement = toml_edit::Value::from(new_value);
        *replacement.decor_mut() = decor;
        *val = replacement;
        return;
    }
    // No existing value to preserve decor from — write a plain one. `apply`
    // never reaches this for `version` (an entry without one cannot have
    // been `auto_bumpable`'s `derived_version` compared against anything),
    // but `release`/`measured` are each guarded by a `contains_key` check
    // before this is called, so this arm is unreachable in practice and only
    // here so the function is total.
    table.insert(key, toml_edit::value(new_value));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moved_ordinary(name: &str, repo: &str, pinned: &str, latest: &str, derived: &str) -> Moved {
        Moved {
            name: name.to_string(),
            repo: repo.to_string(),
            pinned: pinned.to_string(),
            latest: latest.to_string(),
            payload_version: None,
            derived_version: Some(derived.to_string()),
            unverified_reason: None,
            remeasured: None,
        }
    }

    /// An entry WITHOUT a `release` key keeps the tag's own spelling.
    ///
    /// For such an entry `version` is not just the payload's number — it is
    /// the RELEASE TAG the deposit will ask the forge for. `derived_version` is
    /// the bare number (`1.262.0`), and writing that gave the next deposit a
    /// tag that does not exist (`1.262.0`, not `v1.262.0`). `plan` accepted
    /// the result because it never fetches; only the deposit would have
    /// found out — after the PR was merged.
    ///
    /// Found end to end against the real wasm-layers manifest. The realms'
    /// Python scanner had this right: it wrote the new tag verbatim.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn a_version_that_is_also_the_tag_keeps_the_tags_spelling() {
        let text = "[[tool]]\nname = \"wasm-tools\"\nrepo = \"bytecodealliance/wasm-tools\"\nversion = \"v1.260.0\"\n";
        let m = moved_ordinary(
            "wasm-tools",
            "bytecodealliance/wasm-tools",
            "v1.260.0",
            "v1.262.0",
            "1.262.0",
        );
        let full = format!(
            "[varve]\nversion = \"v0.41.0\"\n\n[realm]\nname = \"r\"\nchannel = \"rolling\"\nregistry = \"oci://x/y\"\n\n{text}"
        );
        let (out, _) = apply(&full, &[m]).expect("applies");
        assert!(
            out.contains("version = \"v1.262.0\""),
            "the tag is v1.262.0, and for this entry version IS the tag:\n{out}"
        );
        assert!(!out.contains("version = \"1.262.0\""), "{out}");
    }

    const BASIC: &str = r#"# What the realm carries.
#
# Comments everywhere, because the real file is mostly comments.

[varve]
version = "v0.33.0"

[realm]
name = "pulseengine"
channel = "rolling"
registry = "oci://ghcr.io/pulseengine/layers"

# meld moves here from time to time.
[[tool]]
name = "meld"
version = "v0.53.0"

# loom never moves in this fixture.
[[tool]]
name = "loom"
repo = "pulseengine/loom"
version = "v1.4.1"
"#;

    /// Comments and blank lines are not data `apply` is allowed an opinion
    /// about. The real `layer.toml` is mostly comments — the realm's own
    /// reasoning for every pin — so losing them while "just bumping a
    /// version" would silently erase the record.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn comments_and_blank_lines_survive() {
        let moved = vec![moved_ordinary(
            "meld",
            "pulseengine/meld",
            "v0.53.0",
            "v0.55.1",
            "v0.55.1",
        )];
        let (new_text, changes) = apply(BASIC, &moved).expect("a clean bump");
        assert_eq!(changes.len(), 1, "{changes:?}");

        let before: Vec<&str> = BASIC.lines().collect();
        let after: Vec<&str> = new_text.lines().collect();
        assert_eq!(before.len(), after.len(), "no line was added or removed");
        for (b, a) in before.iter().zip(after.iter()) {
            if *b == "version = \"v0.53.0\"" {
                assert_eq!(*a, "version = \"v0.55.1\"", "the targeted line changed");
            } else {
                assert_eq!(a, b, "an untouched line must survive verbatim");
            }
        }
    }

    /// An entry `apply` has no licence to touch — here, a hub payload whose
    /// version is not derivable — is left byte-for-byte as it was, even while
    /// a sibling entry in the same file IS bumped.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn a_non_auto_bumpable_entry_is_untouched() {
        let hub_section = "\n# with-device cannot be auto-bumped: the version is not derivable.\n\
             [[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.1\"\nrelease = \"v0.7.1\"\n\
             asset = \"with-device-%V-%T.tar.gz\"\n";
        let text = format!("{BASIC}{hub_section}");

        let bumpable = moved_ordinary("meld", "pulseengine/meld", "v0.53.0", "v0.55.1", "v0.55.1");
        let not_bumpable = Moved {
            name: "with-device".to_string(),
            repo: "pulseengine/jess".to_string(),
            pinned: "v0.7.1".to_string(),
            latest: "v0.7.2".to_string(),
            payload_version: Some("0.2.1".to_string()),
            derived_version: None,
            unverified_reason: None,
            remeasured: None,
        };
        assert!(!not_bumpable.auto_bumpable());

        let (new_text, _) =
            apply(&text, &[bumpable, not_bumpable]).expect("the bumpable half applies");
        assert!(
            new_text.contains(hub_section.trim_start_matches('\n')),
            "the non-auto-bumpable section must survive byte-for-byte:\n{new_text}"
        );
    }

    /// A hub payload's `release` field moves alongside `version`, because the
    /// two mean different things and both must stay current (REQ-PAYLOADID-001).
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn release_bumps_alongside_version_when_present() {
        let text = format!(
            "{BASIC}\n[[tool]]\nname = \"with-device\"\nrepo = \"pulseengine/jess\"\n\
             version = \"0.2.1\"\nrelease = \"v0.7.1\"\n\
             asset = \"with-device-%V-%T.tar.gz\"\n"
        );
        let moved = Moved {
            name: "with-device".to_string(),
            repo: "pulseengine/jess".to_string(),
            pinned: "v0.7.1".to_string(),
            latest: "v0.7.2".to_string(),
            payload_version: Some("0.2.1".to_string()),
            derived_version: Some("0.3.0".to_string()),
            unverified_reason: None,
            remeasured: None,
        };
        assert!(moved.auto_bumpable());
        let (new_text, changes) = apply(&text, &[moved]).expect("a hub bump with derivation");
        assert!(new_text.contains("version = \"0.3.0\""), "{new_text}");
        assert!(new_text.contains("release = \"v0.7.2\""), "{new_text}");
        assert_eq!(changes.len(), 2, "{changes:?}");
    }

    const SPLIT_OPTIN: &str = "\n[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
         version = \"v0.12.0\"\n\
         [tool.unverified]\n\
         measured = \"bytecodealliance/wac v0.12.0 publishes no sums and no provenance (measured 2026-10-02).\"\n\
         accepted = \"Accepted for the rolling channel only: the toolchain is unusable without wac.\"\n\
         exit = \"Removed by upstream adding attest-build-provenance.\"\n";

    /// `StillUnproven` rewrites `measured` ALONE. `accepted` and `exit` are
    /// the operator's own judgement, never a scanner's to touch.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn still_unproven_replaces_only_measured() {
        let text = format!("{BASIC}{SPLIT_OPTIN}");
        let moved = Moved {
            name: "wac".to_string(),
            repo: "bytecodealliance/wac".to_string(),
            pinned: "v0.12.0".to_string(),
            latest: "v0.13.0".to_string(),
            payload_version: None,
            derived_version: Some("v0.13.0".to_string()),
            unverified_reason: Some("old reason".to_string()),
            remeasured: Some(Remeasured::StillUnproven {
                measured: "bytecodealliance/wac v0.13.0 publishes no sums and no provenance \
                           (measured 2026-10-10)."
                    .to_string(),
            }),
        };
        let (new_text, changes) =
            apply(&text, &[moved]).expect("a re-measured still-unproven bump");
        assert!(
            new_text.contains(
                "measured = \"bytecodealliance/wac v0.13.0 publishes no sums and no provenance \
                 (measured 2026-10-10).\""
            ),
            "{new_text}"
        );
        assert!(
            new_text.contains(
                "accepted = \"Accepted for the rolling channel only: the toolchain is unusable without wac.\""
            ),
            "accepted must be byte-identical: {new_text}"
        );
        assert!(
            new_text.contains("exit = \"Removed by upstream adding attest-build-provenance.\""),
            "exit must be byte-identical: {new_text}"
        );
        assert!(changes.iter().any(|c| c.contains("measured")));
    }

    /// `ProofNowExists` REMOVES the opt-in — the upstream now vouches for
    /// itself, and the good news must not be swallowed by a renewed excuse.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn proof_now_exists_removes_the_opt_in() {
        let text = format!("{BASIC}{SPLIT_OPTIN}");
        let moved = Moved {
            name: "wac".to_string(),
            repo: "bytecodealliance/wac".to_string(),
            pinned: "v0.12.0".to_string(),
            latest: "v0.13.0".to_string(),
            payload_version: None,
            derived_version: Some("v0.13.0".to_string()),
            unverified_reason: Some("old reason".to_string()),
            remeasured: Some(Remeasured::ProofNowExists {
                mechanism: "a cosign-signed SHA256SUMS.txt",
            }),
        };
        let (new_text, _) = apply(&text, &[moved]).expect("removing a now-proven opt-in");
        assert!(!new_text.contains("unverified"), "{new_text}");
        assert!(!new_text.contains("accepted ="), "{new_text}");
        assert!(new_text.contains("version = \"v0.13.0\""));
    }

    /// The legacy `unverified-reason = "..."` string must never be edited by
    /// heuristic. A migration is required first, and the manifest text is
    /// unchanged by the refusal.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn legacy_opt_in_with_still_unproven_is_refused() {
        let text = format!(
            "{BASIC}\n[[tool]]\nname = \"wac\"\nrepo = \"bytecodealliance/wac\"\n\
             version = \"v0.12.0\"\n\
             unverified-reason = \"bytecodealliance/wac v0.12.0 publishes no sums and no \
             provenance (measured 2026-10-02).\"\n"
        );
        let moved = Moved {
            name: "wac".to_string(),
            repo: "bytecodealliance/wac".to_string(),
            pinned: "v0.12.0".to_string(),
            latest: "v0.13.0".to_string(),
            payload_version: None,
            derived_version: Some("v0.13.0".to_string()),
            unverified_reason: Some("bytecodealliance/wac v0.12.0 ...".to_string()),
            remeasured: Some(Remeasured::StillUnproven {
                measured: "bytecodealliance/wac v0.13.0 publishes no sums and no provenance \
                           (measured 2026-10-10)."
                    .to_string(),
            }),
        };
        let err = apply(&text, &[moved]).expect_err("the legacy form must not be auto-edited");
        assert!(matches!(err, ApplyError::LegacyOptInNeedsMigration { ref name } if name == "wac"));
    }

    /// Two tools sharing one release must agree about the re-measurement.
    /// `remeasured` is computed once per release by the caller, so this is a
    /// belt-and-suspenders assertion — but it must fire if that ever breaks.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn two_tools_sharing_a_release_with_different_measurements_is_refused() {
        let text = format!(
            "{BASIC}\n\
             [[tool]]\nname = \"wit-bindgen-wrpc\"\nrepo = \"bytecodealliance/wrpc\"\n\
             version = \"v0.17.0\"\n\
             [tool.unverified]\n\
             measured = \"old measurement A\"\naccepted = \"a\"\nexit = \"a\"\n\
             [[tool]]\nname = \"wrpc-wasmtime\"\nrepo = \"bytecodealliance/wrpc\"\n\
             version = \"v0.17.0\"\n\
             [tool.unverified]\n\
             measured = \"old measurement B\"\naccepted = \"b\"\nexit = \"b\"\n"
        );
        let base = Moved {
            name: String::new(),
            repo: "bytecodealliance/wrpc".to_string(),
            pinned: "v0.17.0".to_string(),
            latest: "v0.18.0".to_string(),
            payload_version: None,
            derived_version: Some("v0.18.0".to_string()),
            unverified_reason: Some("x".to_string()),
            remeasured: None,
        };
        let first = Moved {
            name: "wit-bindgen-wrpc".to_string(),
            remeasured: Some(Remeasured::StillUnproven {
                measured: "measurement ONE".to_string(),
            }),
            ..base.clone()
        };
        let second = Moved {
            name: "wrpc-wasmtime".to_string(),
            remeasured: Some(Remeasured::StillUnproven {
                measured: "measurement TWO".to_string(),
            }),
            ..base
        };
        let err = apply(&text, &[first, second]).expect_err("the two measurements disagree");
        assert!(
            matches!(err, ApplyError::InconsistentRemeasurement { .. }),
            "{err:?}"
        );
    }

    /// If the rewritten manifest would not parse, `apply` returns an error
    /// and nothing is handed back to write — never a half-right result.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn a_result_the_validator_refuses_is_an_error() {
        let text = format!("{BASIC}{SPLIT_OPTIN}");
        let moved = Moved {
            name: "wac".to_string(),
            repo: "bytecodealliance/wac".to_string(),
            pinned: "v0.12.0".to_string(),
            latest: "v0.13.0".to_string(),
            payload_version: None,
            derived_version: Some("v0.13.0".to_string()),
            unverified_reason: Some("old reason".to_string()),
            remeasured: Some(Remeasured::StillUnproven {
                // Deliberately does not name v0.13.0 (nor v0.12.0), so the
                // release-naming rule in `parse_layer_manifest` refuses it.
                measured: "bytecodealliance/wac publishes no sums and no provenance.".to_string(),
            }),
        };
        let err = apply(&text, &[moved]).expect_err("a measurement naming no release is refused");
        assert!(matches!(err, ApplyError::ResultRefused(_)), "{err:?}");
    }

    /// Nothing auto-bumpable means `--apply` must not even re-serialise the
    /// file: the output is the exact input, not an equivalent rendering of it.
    // rivet: verifies REQ-PREPARED-001
    #[test]
    fn nothing_auto_bumpable_leaves_the_text_identical() {
        let not_bumpable = Moved {
            name: "with-device".to_string(),
            repo: "pulseengine/jess".to_string(),
            pinned: "v0.7.1".to_string(),
            latest: "v0.7.2".to_string(),
            payload_version: Some("0.2.1".to_string()),
            derived_version: None,
            unverified_reason: None,
            remeasured: None,
        };
        let (new_text, changes) = apply(BASIC, &[not_bumpable]).expect("nothing to apply");
        assert_eq!(new_text, BASIC);
        assert!(changes.is_empty());
    }
}
