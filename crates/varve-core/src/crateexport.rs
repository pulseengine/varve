//! Cargo local-registry export (REQ-CRATE-001).
//!
//! A `crate`-kind entry carries a `.crate` tarball. `export-cargo` materialises
//! a Cargo LOCAL REGISTRY from the verified store — the `.crate` files plus a
//! registry index — and emits a `.cargo/config.toml` source-replacement, so a
//! consumer builds fully offline against crates whose bytes varve signed.
//!
//! The trust chain needs nothing new: a `.crate` is signed like any blob (its
//! digest is in the DSSE-signed layer manifest), and that digest IS the sha256
//! Cargo records as the index `cksum`. Cargo re-checks the `.crate` against the
//! cksum, so the consumer verifies a second time on its own terms.

use std::path::Path;

/// One crate to place in the registry: its identity, the Cargo cksum (bare
/// sha256 hex of the `.crate`), and the tarball bytes.
#[derive(Debug, Clone)]
pub struct CrateEntry {
    pub name: String,
    pub version: String,
    /// Bare sha256 hex (no `sha256:` prefix) of the `.crate` tarball.
    pub cksum: String,
    pub bytes: Vec<u8>,
}

/// The registry-index sub-path for a crate name, per Cargo's layout: 1/2/3
/// char names get special prefixes, 4+ use first-two/next-two. Lowercased.
pub fn index_path(name: &str) -> String {
    let n = name.to_lowercase();
    // Slice by CHARACTER, not byte: matching on `chars().count()` and then
    // indexing bytes panicked mid-codepoint on any non-ASCII name. Export
    // paths refuse such names outright (`validate_crate_name`); this stays
    // total anyway so a layout helper can never crash a client.
    let take =
        |from: usize, to: usize| -> String { n.chars().skip(from).take(to - from).collect() };
    match n.chars().count() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", take(0, 1)),
        _ => format!("{}/{}/{n}", take(0, 2), take(2, 4)),
    }
}

/// Refuse a crate name Cargo's registry index cannot express, or that would
/// corrupt the index line's JSON. Cargo's rule: ASCII alphanumeric, `-`, `_`,
/// non-empty. Failing closed here keeps `index_path`/`index_line` honest — the
/// alternative is a panic or a silently malformed registry (REQ-CRATENAME-001).
pub fn validate_crate_name(name: &str) -> Result<(), CrateExportError> {
    if name.is_empty() {
        return Err(CrateExportError::UnrepresentableName {
            name: name.to_string(),
            why: "empty".into(),
        });
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
    {
        return Err(CrateExportError::UnrepresentableName {
            name: name.to_string(),
            why: format!("contains {bad:?}; Cargo names are ASCII alphanumeric, '-' or '_'"),
        });
    }
    Ok(())
}

/// Refuse a version string that would corrupt the index line's JSON. Semver's
/// own alphabet (alphanumerics, `.`, `-`, `+`) admits no quote or backslash.
pub fn validate_crate_version(version: &str) -> Result<(), CrateExportError> {
    if version.is_empty() {
        return Err(CrateExportError::UnrepresentableVersion {
            version: version.to_string(),
            why: "empty".into(),
        });
    }
    if let Some(bad) = version
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
    {
        return Err(CrateExportError::UnrepresentableVersion {
            version: version.to_string(),
            why: format!("contains {bad:?}; semver is ASCII alphanumeric, '.', '-' or '+'"),
        });
    }
    Ok(())
}

/// Gate every export adapter: no entry leaves the store unless its name and
/// version are representable. One place, so the adapters cannot drift apart.
fn validate_entries(crates: &[CrateEntry]) -> Result<(), CrateExportError> {
    for e in crates {
        validate_crate_name(&e.name)?;
        validate_crate_version(&e.version)?;
        // The cksum is the THIRD string interpolated into the index JSON with
        // no escaping. The CLI can only produce a real digest here (it re-hashes
        // the bytes against the signed digest first), but this is a public
        // library API and a caller could hand us anything.
        if e.cksum.len() != 64 || !e.cksum.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CrateExportError::UnrepresentableCksum {
                name: e.name.clone(),
                cksum: e.cksum.clone(),
            });
        }
    }
    Ok(())
}

/// One index line for a crate version. `deps` empty is correct for a leaf
/// crate; Cargo cross-checks the line against the `.crate`'s own Cargo.toml,
/// so a crate with dependencies needs those listed (a follow-up parses them).
pub fn index_line(entry: &CrateEntry) -> String {
    // Compact JSON, one line, stable key order — Cargo parses per line.
    format!(
        r#"{{"name":"{}","vers":"{}","deps":[],"cksum":"{}","features":{{}},"yanked":false}}"#,
        entry.name, entry.version, entry.cksum
    )
}

/// The `.cargo/config.toml` that redirects crates.io to the local registry,
/// so an unmodified `Cargo.toml` resolves against varve's verified bytes.
pub fn cargo_config_toml(registry_dir: &Path) -> String {
    format!(
        "# Generated by `varve export-cargo` (REQ-CRATE-001).\n\
         # Redirects crates.io to a varve-verified local registry; build --offline.\n\
         [source.crates-io]\n\
         replace-with = \"varve\"\n\n\
         [source.varve]\n\
         local-registry = \"{}\"\n",
        registry_dir.display()
    )
}

#[derive(Debug, thiserror::Error)]
pub enum CrateExportError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("crate name {name:?} cannot be exported: {why}")]
    UnrepresentableName { name: String, why: String },
    #[error("crate version {version:?} cannot be exported: {why}")]
    UnrepresentableVersion { version: String, why: String },
    #[error("crate {name:?} has a cksum that is not a bare sha256 hex digest: {cksum:?}")]
    UnrepresentableCksum { name: String, cksum: String },
}

/// The `.cargo-checksum.json` for a vendored crate. `package` is the sha256 of
/// the `.crate` tarball — the SAME digest varve signs, so the upstream
/// integrity anchor is preserved into the vendored tree, not discarded
/// (REQ-BRIDGE-001). `files` empty is valid for a registry-sourced crate
/// (matches real `cargo vendor` output for registry crates).
pub fn cargo_checksum_json(cksum: &str) -> String {
    format!(r#"{{"files":{{}},"package":"{cksum}"}}"#)
}

/// The consumer config pairing with a vendored directory: redirects crates.io
/// to the on-disk unpacked trees. Consumed natively by bare Cargo and by
/// Corrosion (both proven offline). rules_rust needs generated BUILD files on
/// top of this tree — its `crate.from_cargo` splice wants a registry index and
/// rejects a bare directory source (v0.16.0 spike); see REQ-VENDOR-002.
pub fn vendored_config_toml(vendor_dir: &Path) -> String {
    format!(
        "# Generated by `varve export-crates-vendor` (REQ-VENDOR-001).\n\
         [source.crates-io]\n\
         replace-with = \"vendored-sources\"\n\n\
         [source.vendored-sources]\n\
         directory = \"{}\"\n",
        vendor_dir.display()
    )
}

/// Materialise a `cargo vendor`-shaped directory from verified crate entries:
/// each `.crate` UNPACKED into `<vendor>/<name>-<version>/` with its
/// `.cargo-checksum.json`. Proven offline-consumable by bare Cargo and
/// Corrosion. (rules_rust needs BUILD files over this tree — REQ-VENDOR-002.)
/// Returns the crate count.
pub fn export_vendor_dir(
    crates: &[CrateEntry],
    vendor_dir: &Path,
) -> Result<usize, CrateExportError> {
    // Fail closed before writing anything: an unrepresentable name would
    // panic the index layout or corrupt the index JSON (REQ-CRATENAME-001).
    validate_entries(crates)?;
    let io = |path: &Path, source: std::io::Error| CrateExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(vendor_dir).map_err(|e| io(vendor_dir, e))?;
    for entry in crates {
        // A `.crate` is a gzip tar whose top-level dir is `<name>-<version>/`.
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(entry.bytes.as_slice()));
        archive.unpack(vendor_dir).map_err(|e| io(vendor_dir, e))?;
        let crate_dir = vendor_dir.join(format!("{}-{}", entry.name, entry.version));
        let checksum = crate_dir.join(".cargo-checksum.json");
        std::fs::write(&checksum, cargo_checksum_json(&entry.cksum))
            .map_err(|e| io(&checksum, e))?;
    }
    Ok(crates.len())
}

/// Materialise a Cargo local registry at `registry_dir`: write each `.crate`
/// file and its index entry. Returns the number of crates written.
pub fn export_local_registry(
    crates: &[CrateEntry],
    registry_dir: &Path,
) -> Result<usize, CrateExportError> {
    // Fail closed before writing anything: an unrepresentable name would
    // panic the index layout or corrupt the index JSON (REQ-CRATENAME-001).
    validate_entries(crates)?;
    let io = |path: &Path, source: std::io::Error| CrateExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(registry_dir).map_err(|e| io(registry_dir, e))?;
    for entry in crates {
        // The .crate tarball at <registry>/<name>-<version>.crate.
        let crate_file = registry_dir.join(format!("{}-{}.crate", entry.name, entry.version));
        std::fs::write(&crate_file, &entry.bytes).map_err(|e| io(&crate_file, e))?;

        // The index entry, appended (multiple versions share one file).
        let idx = registry_dir.join("index").join(index_path(&entry.name));
        if let Some(parent) = idx.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        let mut line = index_line(entry);
        line.push('\n');
        // De-dup by (name, vers): rewrite the file with this version present.
        let existing = std::fs::read_to_string(&idx).unwrap_or_default();
        let prefix = format!(r#"{{"name":"{}","vers":"{}""#, entry.name, entry.version);
        let mut kept: Vec<String> = existing
            .lines()
            .filter(|l| !l.starts_with(&prefix))
            .map(str::to_string)
            .collect();
        kept.push(line.trim_end().to_string());
        std::fs::write(&idx, kept.join("\n") + "\n").map_err(|e| io(&idx, e))?;
    }
    Ok(crates.len())
}

/// Materialise a Bazel **distdir** of the verified `.crate` tarballs
/// (REQ-VENDOR-002, air-gap rules_rust). Bazel's `--distdir` resolves an
/// `http_archive` from a local file whose sha256 matches — with NO network and
/// NO URL rewrite. Because varve's signed `.crate` digest IS the `crate_universe`
/// pin (== the crates.io checksum), a consumer that pre-generates its
/// `crate_universe` output once and then builds with
/// `bazel build --distdir=<this dir>` (network off) resolves every crate from
/// varve's verified bytes. varve emits the bytes; the consumer commits the
/// generated `crate_universe` output (so no repin/index lookup at build time).
/// Returns the number of tarballs written.
pub fn export_distdir(crates: &[CrateEntry], distdir: &Path) -> Result<usize, CrateExportError> {
    // Fail closed before writing anything: an unrepresentable name would
    // panic the index layout or corrupt the index JSON (REQ-CRATENAME-001).
    validate_entries(crates)?;
    let io = |path: &Path, source: std::io::Error| CrateExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(distdir).map_err(|e| io(distdir, e))?;
    for entry in crates {
        // Bazel matches distdir files by content sha256; the name is for
        // humans. `<name>-<version>.crate` mirrors the crates.io asset name.
        let file = distdir.join(format!("{}-{}.crate", entry.name, entry.version));
        std::fs::write(&file, &entry.bytes).map_err(|e| io(&file, e))?;
    }
    Ok(crates.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-CRATE-001
    #[test]
    fn index_paths_follow_cargos_layout() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("serde"), "se/rd/serde");
        assert_eq!(index_path("Varve-SDK"), "va/rv/varve-sdk"); // lowercased
    }

    // rivet: verifies REQ-CRATENAME-001
    #[test]
    fn a_non_ascii_crate_name_is_an_error_not_a_panic() {
        // `chars().count()` + BYTE slicing used to panic mid-codepoint here.
        // A name Cargo's index layout cannot express must fail closed.
        for bad in ["日本語", "ααα", "café-utils"] {
            assert!(
                validate_crate_name(bad).is_err(),
                "{bad} must be refused, not sliced"
            );
            // And the layout function itself must never panic, whatever it gets.
            let _ = index_path(bad);
        }
    }

    // rivet: verifies REQ-CRATENAME-001
    #[test]
    fn a_name_or_version_that_would_corrupt_the_index_json_is_refused() {
        // index_line interpolates into JSON; a quote/backslash would break the
        // line Cargo parses. Refuse at the gate rather than emit corrupt JSON.
        assert!(validate_crate_name("evil\"name").is_err());
        assert!(validate_crate_name("back\\slash").is_err());
        assert!(validate_crate_name("").is_err());
        assert!(validate_crate_version("1.0.0\"").is_err());
        assert!(validate_crate_name("serde_json").is_ok());
        assert!(validate_crate_name("varve-core").is_ok());
        assert!(validate_crate_version("0.1.0-alpha.1+build.2").is_ok());
    }

    // rivet: verifies REQ-CRATENAME-001
    #[test]
    fn export_refuses_an_unrepresentable_crate_name() {
        let dir = tempfile::tempdir().unwrap();
        let bad = [CrateEntry {
            name: "café-utils".into(),
            version: "0.1.0".into(),
            cksum: "a".repeat(64),
            bytes: vec![],
        }];
        // Every export adapter fails closed on the same input.
        assert!(export_local_registry(&bad, dir.path()).is_err());
        assert!(export_vendor_dir(&bad, dir.path()).is_err());
        assert!(export_distdir(&bad, dir.path()).is_err());
    }

    // rivet: verifies REQ-CRATE-001
    #[test]
    fn an_index_line_carries_the_cksum_cargo_will_verify() {
        let e = CrateEntry {
            name: "demo".into(),
            version: "0.1.0".into(),
            cksum: "b".repeat(64),
            bytes: vec![],
        };
        let line = index_line(&e);
        assert!(line.contains(r#""name":"demo""#));
        assert!(line.contains(r#""vers":"0.1.0""#));
        assert!(line.contains(&format!(r#""cksum":"{}""#, "b".repeat(64))));
        assert!(line.contains(r#""yanked":false"#));
    }

    // rivet: verifies REQ-CRATENAME-001
    #[test]
    fn vendoring_never_writes_outside_the_vendor_directory() {
        // `export_vendor_dir` untars depositor-supplied bytes. The tar crate
        // refuses both escapes today; this pins that guarantee so a dependency
        // bump or a switch to manual entry handling cannot silently lose it
        // (the Cargo CVE-2026-5223 bug class: symlink out, then write through).
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("OUTSIDE");
        std::fs::create_dir_all(&outside).unwrap();
        let vendor = dir.path().join("vendor");

        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            // 1. a symlink escaping the destination …
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            b.append_link(&mut link, "escape-0.1.0/link", &outside)
                .unwrap();
            // 2. … then a write THROUGH it.
            let payload = b"PWNED";
            let mut f = tar::Header::new_gnu();
            f.set_size(payload.len() as u64);
            f.set_mode(0o644);
            b.append_data(&mut f, "escape-0.1.0/link/pwned.txt", &payload[..])
                .unwrap();
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let evil = gz.finish().unwrap();

        let entries = [CrateEntry {
            name: "escape".into(),
            version: "0.1.0".into(),
            cksum: "c".repeat(64),
            bytes: evil,
        }];
        // Whether it errors or skips the entry, the invariant is the same:
        // nothing may be written outside the vendor directory.
        let _ = export_vendor_dir(&entries, &vendor);
        assert!(
            !outside.join("pwned.txt").exists(),
            "a crate tarball escaped the vendor directory"
        );
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing may be written outside the vendor directory"
        );
    }

    // rivet: verifies REQ-VENDOR-001, REQ-BRIDGE-001
    #[test]
    fn vendoring_unpacks_the_crate_and_preserves_the_upstream_hash() {
        // A `.crate`-shaped gzip tar with the top-level <name>-<version>/ dir.
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, body) in [
            ("demo-0.1.0/Cargo.toml", "[package]\nname=\"demo\"\n"),
            ("demo-0.1.0/src/lib.rs", "pub fn f() {}\n"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
        let targz = builder.into_inner().unwrap().finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join("vendor");
        let e = CrateEntry {
            name: "demo".into(),
            version: "0.1.0".into(),
            cksum: "d".repeat(64),
            bytes: targz,
        };
        assert_eq!(
            export_vendor_dir(std::slice::from_ref(&e), &vendor).unwrap(),
            1
        );
        // The crate is UNPACKED (a directory source, not a tarball).
        assert!(vendor.join("demo-0.1.0/Cargo.toml").is_file());
        assert!(vendor.join("demo-0.1.0/src/lib.rs").is_file());
        // The upstream integrity anchor (the .crate sha256) is preserved.
        let checksum =
            std::fs::read_to_string(vendor.join("demo-0.1.0/.cargo-checksum.json")).unwrap();
        assert_eq!(
            checksum,
            format!(r#"{{"files":{{}},"package":"{}"}}"#, "d".repeat(64))
        );
    }

    // rivet: verifies REQ-VENDOR-002
    #[test]
    fn a_distdir_holds_the_verified_crate_bytes_keyed_for_bazel() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = tmp.path().join("distdir");
        let bytes = b"the-verified-crate-tarball-bytes".to_vec();
        // varve's cksum IS the sha256 of these bytes == the crate_universe pin.
        let cksum = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        let e = CrateEntry {
            name: "cfg-if".into(),
            version: "1.0.0".into(),
            cksum: cksum.clone(),
            bytes: bytes.clone(),
        };
        assert_eq!(export_distdir(std::slice::from_ref(&e), &dd).unwrap(), 1);
        let file = dd.join("cfg-if-1.0.0.crate");
        // The exact verified bytes are present...
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        // ...and their sha256 is the join key Bazel's --distdir matches on.
        let on_disk = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(std::fs::read(&file).unwrap()))
        };
        assert_eq!(
            on_disk, cksum,
            "distdir file sha256 must equal the crate_universe pin"
        );
    }

    // rivet: verifies REQ-VENDOR-001
    #[test]
    fn the_vendored_config_replaces_with_a_directory_source() {
        let cfg = vendored_config_toml(Path::new("/v/dir"));
        assert!(cfg.contains(r#"replace-with = "vendored-sources""#));
        assert!(cfg.contains(r#"directory = "/v/dir""#));
    }

    // rivet: verifies REQ-CRATE-001
    #[test]
    fn config_redirects_crates_io_to_the_local_registry() {
        let cfg = cargo_config_toml(Path::new("/verified/reg"));
        assert!(cfg.contains(r#"replace-with = "varve""#));
        assert!(cfg.contains(r#"local-registry = "/verified/reg""#));
    }

    // rivet: verifies REQ-CRATE-001
    #[test]
    fn materialising_writes_the_crate_and_a_matching_index_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("registry");
        let e = CrateEntry {
            name: "demo".into(),
            version: "0.1.0".into(),
            cksum: "e".repeat(64),
            bytes: b"crate-tarball-bytes".to_vec(),
        };
        assert_eq!(
            export_local_registry(std::slice::from_ref(&e), &reg).unwrap(),
            1
        );
        // The .crate file is the verified bytes.
        assert_eq!(
            std::fs::read(reg.join("demo-0.1.0.crate")).unwrap(),
            b"crate-tarball-bytes"
        );
        // The index entry is at Cargo's path and carries the cksum.
        let idx = std::fs::read_to_string(reg.join("index/de/mo/demo")).unwrap();
        assert!(idx.contains(&format!(r#""cksum":"{}""#, "e".repeat(64))));

        // Re-exporting the same version does not duplicate the index line.
        export_local_registry(std::slice::from_ref(&e), &reg).unwrap();
        let idx2 = std::fs::read_to_string(reg.join("index/de/mo/demo")).unwrap();
        assert_eq!(idx2.lines().count(), 1, "one line per (name, version)");
    }
}
