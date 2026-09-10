//! Which files the trust-critical mutation gate covers (REQ-MUTATE-003).
//!
//! The gate's file list lives in `.github/workflows/ci.yml` and was maintained
//! by hand. Nothing checked it for completeness, so coverage drifted silently
//! as files gained trust decisions: `linestatus.rs` gained the two-document
//! preference in v0.33.0, nobody noticed it was outside the gate, and a mutant
//! that permitted YANK SUPPRESSION survived until someone chose to run the tool
//! on an ungated file. Choosing to look is not a control.
//!
//! So the split is declared in `mutation-scope.toml` and asserted here. A file
//! that is neither gated nor declared fails the check — which means a NEW file
//! cannot land ungated without someone writing down why.
//!
//! This module holds no runtime logic. It exists so the assertion runs with
//! `cargo test` everywhere, rather than only inside the workflow it describes.
//!
//! It is nonetheless IN the gate, and `cargo mutants` finds zero mutants here —
//! a const and some tests are nothing to mutate. That is deliberate rather than
//! an oversight: gating it now means logic added here later is covered without
//! anyone remembering to add it, which is the failure mode this whole module
//! exists to prevent. Zero survivors out of zero mutants proves nothing today,
//! and the honest way to record that is here rather than in a number.

/// The three legitimate reasons a source file is outside the gate.
///
/// `not-yet` is deliberately one of them, and deliberately counted. Honest
/// debt that a check reports every run is a different thing from debt nobody
/// can see — the second is what this requirement exists to end.
pub const REASONS: [&str; 3] = ["bin-target", "re-export", "not-yet"];

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/varve-core is two levels below the repo root")
            .to_path_buf()
    }

    /// Every `-f <path>` in the gate's shard matrix.
    ///
    /// Read out of the workflow TEXT rather than a YAML parser: the file list
    /// is a folded scalar of shell flags, so the flags are what matter and a
    /// structural parse would only add a dependency to reach the same string.
    fn gated(root: &Path) -> BTreeSet<String> {
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml"))
            .expect("the workflow that defines the gate must be readable");
        let mut out = BTreeSet::new();
        for (i, _) in ci.match_indices("-f ") {
            let rest = &ci[i + 3..];
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let path = rest[..end].trim();
            if path.ends_with(".rs") {
                out.insert(path.to_string());
            }
        }
        assert!(
            !out.is_empty(),
            "no `-f <file>.rs` found in ci.yml — the gate cannot be empty, and a \
             check that reads an empty list would pass by finding nothing"
        );
        out
    }

    /// Every `.rs` file under `crates/*/src`, recursively.
    fn sources(root: &Path) -> BTreeSet<String> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, root, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let rel = p.strip_prefix(root).expect("under the repo root");
                    out.insert(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let mut out = BTreeSet::new();
        for crate_dir in std::fs::read_dir(root.join("crates"))
            .expect("crates/ exists")
            .flatten()
        {
            walk(&crate_dir.path().join("src"), root, &mut out);
        }
        assert!(out.len() > 10, "suspiciously few sources: {}", out.len());
        out
    }

    /// The declared exclusions, flattened to path -> (reason, note).
    fn declared(root: &Path) -> BTreeMap<String, (String, String)> {
        let text = std::fs::read_to_string(root.join("mutation-scope.toml"))
            .expect("mutation-scope.toml must exist — it IS the declaration");
        let doc: toml::Value = toml::from_str(&text).expect("mutation-scope.toml must parse");
        let mut out = BTreeMap::new();
        for reason in super::REASONS {
            let Some(table) = doc.get(reason).and_then(|v| v.as_table()) else {
                continue;
            };
            for (path, note) in table {
                let note = note.as_str().unwrap_or("").trim().to_string();
                assert!(
                    !note.is_empty(),
                    "{path} is excluded as `{reason}` with no reason written down — \
                     an empty reason is an omission wearing a decision's clothes"
                );
                if let Some((prev, _)) = out.insert(path.clone(), (reason.to_string(), note)) {
                    panic!("{path} is declared twice, as `{prev}` and as `{reason}`");
                }
            }
        }
        out
    }

    /// THE CHECK. Every source file is gated, or declared with a reason.
    ///
    /// A new file that is neither fails here — which is the whole point. The
    /// previous arrangement could not fail at all: the list was hand-kept, and
    /// a file that gained a trust decision simply did not appear in it.
    // rivet: verifies REQ-MUTATE-003
    #[test]
    fn mutation_scope_is_decided_not_drifted() {
        let root = repo_root();
        let gated = gated(&root);
        let sources = sources(&root);
        let declared = declared(&root);

        let undecided: Vec<_> = sources
            .iter()
            .filter(|f| !gated.contains(*f) && !declared.contains_key(*f))
            .collect();
        assert!(
            undecided.is_empty(),
            "these source files are neither in the mutation gate nor declared in \
             mutation-scope.toml:\n  {}\n\nAdd them to the gate's shard matrix in \
             ci.yml, or declare them with a reason. A file that is silently \
             ungated is how a mutant permitting yank suppression survived \
             v0.33.0.",
            undecided
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    /// A file cannot be both gated and excused. The contradiction is silent
    /// otherwise: the gate would test it while the declaration claimed it was
    /// out of scope, and a later reader would believe whichever they found.
    // rivet: verifies REQ-MUTATE-003
    #[test]
    fn nothing_is_both_gated_and_excused() {
        let root = repo_root();
        let gated = gated(&root);
        let declared = declared(&root);
        let both: Vec<_> = declared.keys().filter(|f| gated.contains(*f)).collect();
        assert!(
            both.is_empty(),
            "declared as excluded AND named in the gate: {both:?} — remove it from \
             one, since the two say opposite things about the same file"
        );
    }

    /// The declaration may not name a file that does not exist. A stale entry
    /// silently excuses nothing while looking like it excuses something, and it
    /// is exactly what a rename leaves behind.
    // rivet: verifies REQ-MUTATE-003
    #[test]
    fn the_declaration_names_only_files_that_exist() {
        let root = repo_root();
        let sources = sources(&root);
        let stale: Vec<_> = declared(&root)
            .into_keys()
            .filter(|f| !sources.contains(f))
            .collect();
        assert!(
            stale.is_empty(),
            "mutation-scope.toml names files that do not exist: {stale:?} — a stale \
             exclusion is what a rename leaves behind, and it excuses nothing while \
             appearing to"
        );
    }

    /// The gate may not name a file that does not exist either — a rename there
    /// removes a file from the gate WITHOUT removing the line that claims it is
    /// covered, which is the failure that reads as coverage.
    // rivet: verifies REQ-MUTATE-003
    #[test]
    fn the_gate_names_only_files_that_exist() {
        let root = repo_root();
        let sources = sources(&root);
        let missing: Vec<_> = gated(&root)
            .into_iter()
            .filter(|f| !sources.contains(f))
            .collect();
        assert!(
            missing.is_empty(),
            "ci.yml's mutation shards name files that do not exist: {missing:?} — \
             cargo-mutants would test nothing for them while the list still reads \
             as coverage"
        );
    }

    /// Report the debt every run, so `not-yet` cannot become permanent by being
    /// quiet. This asserts a CEILING, not zero: the number is allowed to be
    /// large and is not allowed to grow unnoticed.
    // rivet: verifies REQ-MUTATE-003
    #[test]
    fn the_ungated_trust_relevant_backlog_is_counted_and_capped() {
        let declared = declared(&repo_root());
        let not_yet: Vec<_> = declared
            .iter()
            .filter(|(_, (reason, _))| reason == "not-yet")
            .map(|(f, _)| f.as_str())
            .collect();
        eprintln!(
            "mutation gate: {} file(s) trust-relevant and not yet gated:\n  {}",
            not_yet.len(),
            not_yet.join("\n  ")
        );
        const CAP: usize = 22;
        assert!(
            not_yet.len() <= CAP,
            "{} files are declared `not-yet`, above the cap of {CAP}. The cap only \
             ratchets DOWN: raising it is how a backlog becomes a permanent \
             exemption, so gate a file instead.",
            not_yet.len()
        );
    }
}
