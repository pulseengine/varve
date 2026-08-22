//! Lockfile agreement (REQ-LOCKPIN-001).
//!
//! varve pins what it DISPATCHES. But a code-generating dependency reaches the
//! artifact as a Cargo dependency compiled INTO it — `wit-bindgen-rt` is baked
//! into every component one consumer publishes, and supplies `cabi_realloc`,
//! the symbol whose absence shipped a raw core module downstream (varve#52).
//! There is no binary to shim, so `varve which` has nothing to point at, and
//! that consumer reported running three versions of one generator at once with
//! nothing recording which produced a given artifact.
//!
//! varve already carries the `crate` payload kind, so it can DISTRIBUTE such a
//! dependency. What was missing is AGREEMENT: this module compares a project's
//! resolved lockfile against the layer's `crate` entries and reports every
//! disagreement.
//!
//! THE BOUNDARY, chosen rather than overlooked: varve cannot intercept a Cargo
//! build and cannot guarantee the compiler used the bytes it pins. Provenance
//! for a compiled-in dependency is by ASSERTED AGREEMENT — the lockfile and the
//! layer must say the same thing, mechanically, or CI goes red — not by
//! dispatch. Packages the layer does not pin are ignored: the layer does not
//! claim to cover every dependency, and pretending otherwise would make this
//! check noise instead of signal.

/// One package as the lockfile resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    /// Registry checksum, when the lockfile records one (path and git
    /// dependencies have none).
    pub checksum: Option<String>,
}

/// How a pinned crate and the lockfile disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disagreement {
    /// Same name, different version — the drift that goes unnoticed.
    Version {
        name: String,
        pinned: String,
        locked: String,
    },
    /// Same name and version, different bytes. Rarer and more serious: two
    /// different artifacts are claiming one identity.
    Checksum {
        name: String,
        version: String,
        pinned: String,
        locked: String,
    },
}

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version {
                name,
                pinned,
                locked,
            } => write!(
                f,
                "{name}: the layer pins {pinned}, the lockfile resolves {locked}"
            ),
            Self::Checksum {
                name,
                version,
                pinned,
                locked,
            } => write!(
                f,
                "{name} {version}: same version, DIFFERENT bytes — layer {pinned}, lockfile {locked}"
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("cannot parse {path} as a Cargo lockfile: {reason}")]
    Parse { path: String, reason: String },
}

/// Parse the `[[package]]` entries of a Cargo lockfile. Deliberately minimal:
/// only name, version and checksum are read, because only those are compared.
pub fn parse_lockfile(text: &str, path: &str) -> Result<Vec<LockedPackage>, LockError> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| LockError::Parse {
        path: path.to_string(),
        reason: e.to_string(),
    })?;
    let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
        // A lockfile with no packages is unusual but not malformed.
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for p in packages {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(|v| v.as_str()),
            p.get("version").and_then(|v| v.as_str()),
        ) else {
            return Err(LockError::Parse {
                path: path.to_string(),
                reason: "a [[package]] entry lacks name or version".into(),
            });
        };
        out.push(LockedPackage {
            name: name.to_string(),
            version: version.to_string(),
            checksum: p
                .get("checksum")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }
    Ok(out)
}

/// Compare the layer's pinned crates against the lockfile. Returns every
/// disagreement, in a stable order. A pinned crate absent from the lockfile is
/// NOT a disagreement — the project simply does not depend on it.
pub fn disagreements(
    pinned: &[crate::crateexport::CrateEntry],
    locked: &[LockedPackage],
) -> Vec<Disagreement> {
    let mut out = Vec::new();
    for p in pinned {
        for l in locked.iter().filter(|l| l.name == p.name) {
            if l.version != p.version {
                // A layer may pin SEVERAL versions of one crate (REQ-STORE-002):
                // varve's own lockfile has 14 such names. The locked version
                // agreeing with a DIFFERENT pinned entry of the same name is
                // agreement, not drift — reporting it would make this gate go
                // red on every real dependency graph.
                if pinned
                    .iter()
                    .any(|q| q.name == l.name && q.version == l.version)
                {
                    continue;
                }
                out.push(Disagreement::Version {
                    name: p.name.clone(),
                    pinned: p.version.clone(),
                    locked: l.version.clone(),
                });
            } else if let Some(lc) = &l.checksum
                && !lc.is_empty()
                && lc != &p.cksum
            {
                out.push(Disagreement::Checksum {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    pinned: p.cksum.clone(),
                    locked: lc.clone(),
                });
            }
        }
    }
    out.sort_by_key(|d| match d {
        Disagreement::Version { name, .. } | Disagreement::Checksum { name, .. } => name.clone(),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crateexport::CrateEntry;

    fn pinned(name: &str, version: &str, cksum: &str) -> CrateEntry {
        CrateEntry {
            name: name.into(),
            version: version.into(),
            cksum: cksum.into(),
            bytes: vec![],
        }
    }

    const LOCK: &str = r#"
version = 4

[[package]]
name = "wit-bindgen-rt"
version = "0.41.0"
checksum = "aaaa"

[[package]]
name = "serde"
version = "1.0.229"
checksum = "bbbb"

[[package]]
name = "my-local-crate"
version = "0.1.0"
"#;

    // rivet: verifies REQ-LOCKPIN-001
    #[test]
    fn a_lockfile_parses_to_name_version_and_checksum() {
        let pkgs = parse_lockfile(LOCK, "Cargo.lock").unwrap();
        assert_eq!(pkgs.len(), 3);
        let wb = pkgs.iter().find(|p| p.name == "wit-bindgen-rt").unwrap();
        assert_eq!(wb.version, "0.41.0");
        assert_eq!(wb.checksum.as_deref(), Some("aaaa"));
        // A path dependency has no checksum, and that is not an error.
        let local = pkgs.iter().find(|p| p.name == "my-local-crate").unwrap();
        assert_eq!(local.checksum, None);
    }

    // rivet: verifies REQ-LOCKPIN-001
    #[test]
    fn the_reported_drift_is_caught() {
        // The consumer's actual case: the layer pins 0.58.0, the project's
        // components resolve 0.41.0, and nothing said so.
        let d = disagreements(
            &[pinned("wit-bindgen-rt", "0.58.0", "zzzz")],
            &parse_lockfile(LOCK, "l").unwrap(),
        );
        assert_eq!(d.len(), 1);
        match &d[0] {
            Disagreement::Version {
                name,
                pinned,
                locked,
            } => {
                assert_eq!(name, "wit-bindgen-rt");
                assert_eq!(pinned, "0.58.0");
                assert_eq!(locked, "0.41.0");
            }
            other => panic!("expected a version disagreement, got {other:?}"),
        }
    }

    // rivet: verifies REQ-LOCKPIN-001
    #[test]
    fn same_version_different_bytes_is_the_more_serious_case() {
        let d = disagreements(
            &[pinned("serde", "1.0.229", "DIFFERENT")],
            &parse_lockfile(LOCK, "l").unwrap(),
        );
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0], Disagreement::Checksum { .. }), "{:?}", d[0]);
    }

    // rivet: verifies REQ-LOCKPIN-001
    #[test]
    fn agreement_is_silent_and_unpinned_packages_are_not_our_business() {
        let locked = parse_lockfile(LOCK, "l").unwrap();
        // Exact agreement: nothing to report.
        assert!(disagreements(&[pinned("serde", "1.0.229", "bbbb")], &locked).is_empty());
        // The layer pins something the project does not use: not a finding.
        assert!(disagreements(&[pinned("not-used-here", "9.9.9", "cccc")], &locked).is_empty());
        // The project uses something the layer does not pin: also not a
        // finding — the layer never claimed to cover every dependency.
        assert!(disagreements(&[], &locked).is_empty());
    }

    // rivet: verifies REQ-STORE-002, REQ-LOCKPIN-001
    #[test]
    fn a_layer_pinning_two_versions_of_one_crate_agrees_with_a_lockfile_holding_both() {
        // REQ-STORE-002 lets a layer hold several versions of one name — the
        // ordinary shape of a dependency graph, 14 such names in varve's own
        // lockfile. This gate compared every pinned entry against every locked
        // package OF THE SAME NAME, so the moment such a layer existed it
        // reported 1.0.200-vs-1.0.210 as drift and went red on a lockfile it
        // agrees with completely.
        let lock = "version = 4\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nchecksum = \"aa\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nchecksum = \"bb\"\n";
        let locked = parse_lockfile(lock, "Cargo.lock").unwrap();
        let both = [
            pinned("serde", "1.0.200", "aa"),
            pinned("serde", "1.0.210", "bb"),
        ];
        assert!(
            disagreements(&both, &locked).is_empty(),
            "both versions are pinned AND locked — that is agreement: {:?}",
            disagreements(&both, &locked)
        );

        // The gate still bites: a version the layer does not pin at all is
        // still drift, and same-version-different-bytes is still caught.
        let other = parse_lockfile(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.5\"\n",
            "Cargo.lock",
        )
        .unwrap();
        assert!(!disagreements(&both, &other).is_empty());
        let wrong_bytes = [
            pinned("serde", "1.0.200", "aa"),
            pinned("serde", "1.0.210", "NOPE"),
        ];
        assert!(matches!(
            disagreements(&wrong_bytes, &locked).as_slice(),
            [Disagreement::Checksum { version, .. }] if version == "1.0.210"
        ));
    }

    // rivet: verifies REQ-LOCKPIN-001
    #[test]
    fn a_malformed_lockfile_is_an_error_not_a_silent_pass() {
        // Failing open here would report "agreement" for a file we could not
        // read — the worst possible answer for a gate.
        assert!(parse_lockfile("this is not toml {{{", "Cargo.lock").is_err());
        assert!(parse_lockfile("[[package]]\nversion = \"1.0\"\n", "Cargo.lock").is_err());
    }
}
