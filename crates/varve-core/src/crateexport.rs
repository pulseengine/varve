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

/// One dependency exactly as a Cargo registry index expresses it
/// (REQ-CRATEIDX-001 clause 1). Field names and order mirror crates.io's index
/// so a line varve writes and a line crates.io writes are the same shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IndexDep {
    /// The name the dependant refers to it by — the RENAMED name if renamed;
    /// `package` then carries the real crate name.
    pub name: String,
    /// The SemVer requirement.
    pub req: String,
    pub features: Vec<String>,
    pub optional: bool,
    pub default_features: bool,
    /// `None` for an unconditional dependency, else the `cfg(...)`/triple key.
    pub target: Option<String>,
    /// `normal`, `dev` or `build`.
    pub kind: String,
    /// Index URL of another registry, or `None` for this one.
    pub registry: Option<String>,
    /// The real crate name when `name` is a rename, else `None`.
    pub package: Option<String>,
}

/// Everything an index line needs beyond identity and cksum, read from the
/// `Cargo.toml` inside the signed `.crate` (REQ-CRATEIDX-001 clause 1).
///
/// `features2` exists because Cargo splits namespaced (`dep:foo`) and weak
/// (`foo?/bar`) feature values into a second map guarded by `"v":2`, exactly as
/// crates.io does; a modern Cargo merges the two on load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrateMeta {
    pub deps: Vec<IndexDep>,
    pub features: std::collections::BTreeMap<String, Vec<String>>,
    pub features2: std::collections::BTreeMap<String, Vec<String>>,
    pub links: Option<String>,
    pub rust_version: Option<String>,
}

/// The serialised shape of one index line. A derived `Serialize` fixes the key
/// order at the declaration order regardless of the map backing serde_json
/// happens to be compiled with — so the bytes are a function of the crate, not
/// of feature unification (REQ-REPRO-001 clause 1).
#[derive(serde::Serialize)]
struct IndexEntry {
    name: String,
    vers: String,
    deps: Vec<IndexDep>,
    cksum: String,
    features: std::collections::BTreeMap<String, Vec<String>>,
    yanked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<u32>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    features2: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rust_version: Option<String>,
}

/// The dependency sections of a Cargo manifest, and the index `kind` each maps
/// to. One list, so the plain and `[target.…]` walks cannot drift apart.
const DEP_SECTIONS: [(&str, &str); 3] = [
    ("dependencies", "normal"),
    ("dev-dependencies", "dev"),
    ("build-dependencies", "build"),
];

/// Dependency keys varve knows how to transcribe. Anything else is refused by
/// name rather than ignored — an ignored key is a changed meaning, and clause 2
/// exists because a silently dropped entry is the failure mode that exits 0.
const KNOWN_DEP_KEYS: [&str; 9] = [
    "version",
    "features",
    "optional",
    "default-features",
    "default_features",
    "package",
    "registry-index",
    "path",
    "public",
];

/// Read the `deps` and `features` of a crate from the `Cargo.toml` inside its
/// signed `.crate` tarball (REQ-CRATEIDX-001 clause 1).
///
/// The transcription is faithful or it refuses (clause 2): a dependency or a
/// feature this cannot express is an error naming the crate, never an omission.
/// Cargo resolves the graph FROM the index, so an index that under-reports is
/// not a smaller truth — it is a build that can compile a crate with no
/// features at all and exit 0.
pub fn read_crate_meta(
    name: &str,
    version: &str,
    tarball: &[u8],
) -> Result<CrateMeta, CrateExportError> {
    let text = manifest_text(name, version, tarball)?;
    parse_crate_meta(name, version, &text)
}

/// Pull `<name>-<version>/Cargo.toml` out of a `.crate` gzip tar. The exact
/// path is preferred; any single-directory `Cargo.toml` is accepted as a
/// fallback, because the tarball's top directory is the producer's to name.
fn manifest_text(name: &str, version: &str, tarball: &[u8]) -> Result<String, CrateExportError> {
    use std::io::Read;
    let unreadable = |why: String| CrateExportError::UnreadableManifest {
        name: name.to_string(),
        version: version.to_string(),
        why,
    };
    let wanted = format!("{name}-{version}/Cargo.toml");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    let entries = archive
        .entries()
        .map_err(|e| unreadable(format!("the .crate tarball could not be opened: {e}")))?;
    let mut fallback: Option<String> = None;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| unreadable(format!("the .crate tarball is truncated: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| unreadable(format!("a tarball entry has an unusable path: {e}")))?
            .to_string_lossy()
            .into_owned();
        let components: Vec<&str> = path.split('/').collect();
        if components.len() != 2 || components[1] != "Cargo.toml" {
            continue;
        }
        let mut text = String::new();
        entry
            .read_to_string(&mut text)
            .map_err(|e| unreadable(format!("{path} could not be read: {e}")))?;
        if path == wanted {
            return Ok(text);
        }
        fallback.get_or_insert(text);
    }
    fallback.ok_or(CrateExportError::MissingManifest {
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// Transcribe a `Cargo.toml` into index metadata, refusing anything the index
/// cannot express.
fn parse_crate_meta(
    name: &str,
    version: &str,
    manifest: &str,
) -> Result<CrateMeta, CrateExportError> {
    let doc: toml::Value =
        toml::from_str(manifest).map_err(|e| CrateExportError::UnreadableManifest {
            name: name.to_string(),
            version: version.to_string(),
            why: format!("its Cargo.toml is not valid TOML: {e}"),
        })?;
    let mut meta = CrateMeta::default();
    if let Some(pkg) = doc.get("package").and_then(toml::Value::as_table) {
        meta.links = pkg
            .get("links")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        meta.rust_version = pkg
            .get("rust-version")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
    }
    for (section, kind) in DEP_SECTIONS {
        if let Some(table) = doc.get(section).and_then(toml::Value::as_table) {
            collect_deps(name, version, table, kind, None, &mut meta.deps)?;
        }
    }
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for (cfg, per_target) in targets {
            let Some(per_target) = per_target.as_table() else {
                return Err(CrateExportError::UnreadableManifest {
                    name: name.to_string(),
                    version: version.to_string(),
                    why: format!("[target.{cfg}] is not a table"),
                });
            };
            for (section, kind) in DEP_SECTIONS {
                if let Some(table) = per_target.get(section).and_then(toml::Value::as_table) {
                    collect_deps(name, version, table, kind, Some(cfg), &mut meta.deps)?;
                }
            }
        }
    }
    if let Some(features) = doc.get("features").and_then(toml::Value::as_table) {
        for (feature, values) in features {
            let bad = |why: &str| CrateExportError::UnrepresentableFeature {
                name: name.to_string(),
                version: version.to_string(),
                feature: feature.clone(),
                why: why.to_string(),
            };
            let values = values.as_array().ok_or_else(|| bad("is not an array"))?;
            let mut list = Vec::with_capacity(values.len());
            for v in values {
                list.push(
                    v.as_str()
                        .ok_or_else(|| bad("holds a value that is not a string"))?
                        .to_string(),
                );
            }
            // Namespaced (`dep:`) and weak (`?/`) values live in `features2`
            // behind `"v":2`, exactly as crates.io splits them.
            if list
                .iter()
                .any(|s| s.starts_with("dep:") || s.contains("?/"))
            {
                meta.features2.insert(feature.clone(), list);
            } else {
                meta.features.insert(feature.clone(), list);
            }
        }
    }
    Ok(meta)
}

/// Transcribe one dependency table (`[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`, plain or under `[target.<cfg>]`) into index deps.
fn collect_deps(
    crate_name: &str,
    crate_version: &str,
    table: &toml::Table,
    kind: &str,
    target: Option<&str>,
    out: &mut Vec<IndexDep>,
) -> Result<(), CrateExportError> {
    for (key, value) in table {
        let refuse = |why: String| CrateExportError::UnrepresentableDep {
            name: crate_name.to_string(),
            version: crate_version.to_string(),
            dep: key.clone(),
            kind: kind.to_string(),
            why,
        };
        let mut dep = IndexDep {
            name: key.clone(),
            req: String::new(),
            features: Vec::new(),
            optional: false,
            default_features: true,
            target: target.map(str::to_string),
            kind: kind.to_string(),
            registry: None,
            package: None,
        };
        match value {
            toml::Value::String(req) => dep.req = req.clone(),
            toml::Value::Table(spec) => {
                // Refuse what the index has no field for, BEFORE transcribing
                // the rest — a half-transcribed dependency is the silent one.
                if spec.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                    return Err(refuse(
                        "`workspace = true` is unresolved workspace inheritance; a packaged \
                         .crate should carry the resolved requirement"
                            .into(),
                    ));
                }
                if spec.contains_key("git") {
                    return Err(refuse(
                        "a git dependency has no representation in a Cargo registry index, and \
                         no local registry can satisfy it"
                            .into(),
                    ));
                }
                if let Some(alias) = spec.get("registry").and_then(toml::Value::as_str) {
                    return Err(refuse(format!(
                        "`registry = {alias:?}` is a local registry ALIAS; the index field is a \
                         URL, and the alias means nothing to a consumer of this export"
                    )));
                }
                if let Some(unknown) = spec.keys().find(|k| !KNOWN_DEP_KEYS.contains(&k.as_str())) {
                    return Err(refuse(format!(
                        "key `{unknown}` is one varve does not know how to transcribe into a \
                         registry index entry; refusing rather than dropping it"
                    )));
                }
                match spec.get("version") {
                    Some(toml::Value::String(req)) => dep.req = req.clone(),
                    Some(other) => {
                        return Err(refuse(format!("`version` is {other}, not a string")));
                    }
                    None if spec.contains_key("path") => {
                        return Err(refuse(
                            "a path dependency with no `version` cannot be resolved from a \
                             registry"
                                .into(),
                        ));
                    }
                    // No requirement at all means "any version", which the
                    // index spells `*` — Cargo's own normalisation.
                    None => dep.req = "*".into(),
                }
                if let Some(v) = spec.get("optional") {
                    dep.optional = v
                        .as_bool()
                        .ok_or_else(|| refuse(format!("`optional` is {v}, not a boolean")))?;
                }
                for key in ["default-features", "default_features"] {
                    if let Some(v) = spec.get(key) {
                        dep.default_features = v
                            .as_bool()
                            .ok_or_else(|| refuse(format!("`{key}` is {v}, not a boolean")))?;
                    }
                }
                if let Some(v) = spec.get("features") {
                    let list = v
                        .as_array()
                        .ok_or_else(|| refuse(format!("`features` is {v}, not an array")))?;
                    for f in list {
                        dep.features.push(
                            f.as_str()
                                .ok_or_else(|| refuse(format!("feature {f} is not a string")))?
                                .to_string(),
                        );
                    }
                }
                if let Some(v) = spec.get("package") {
                    dep.package = Some(
                        v.as_str()
                            .ok_or_else(|| refuse(format!("`package` is {v}, not a string")))?
                            .to_string(),
                    );
                }
                if let Some(v) = spec.get("registry-index") {
                    dep.registry = Some(
                        v.as_str()
                            .ok_or_else(|| {
                                refuse(format!("`registry-index` is {v}, not a string"))
                            })?
                            .to_string(),
                    );
                }
            }
            other => {
                return Err(refuse(format!(
                    "is {other}, neither a version string nor a table"
                )));
            }
        }
        out.push(dep);
    }
    Ok(())
}

/// One index line for a crate version, carrying the crate's REAL `deps` and
/// `features` read from the `Cargo.toml` inside its signed `.crate`
/// (REQ-CRATEIDX-001). Cargo resolves the dependency graph from this line, so
/// an empty `deps`/`features` is not a conservative default — it is a lie that
/// resolves, builds, and exits 0 with the crate compiled featureless.
pub fn index_line(entry: &CrateEntry) -> Result<String, CrateExportError> {
    let meta = read_crate_meta(&entry.name, &entry.version, &entry.bytes)?;
    index_line_from_meta(entry, &meta)
}

/// The line for an entry whose metadata is already in hand. Split out so the
/// transcription can be unit-tested without a tarball, and so both halves are
/// exercised by the same serialisation.
pub fn index_line_from_meta(
    entry: &CrateEntry,
    meta: &CrateMeta,
) -> Result<String, CrateExportError> {
    let line = IndexEntry {
        name: entry.name.clone(),
        vers: entry.version.clone(),
        deps: meta.deps.clone(),
        cksum: entry.cksum.clone(),
        features: meta.features.clone(),
        yanked: false,
        links: meta.links.clone(),
        // `"v":2` is what tells Cargo this entry may use `features2`; without
        // it a namespaced feature would be read as a literal feature name.
        v: (!meta.features2.is_empty()).then_some(2),
        features2: meta.features2.clone(),
        rust_version: meta.rust_version.clone(),
    };
    // serde_json escapes; nothing here is interpolated into JSON by hand.
    serde_json::to_string(&line).map_err(|e| CrateExportError::UnreadableManifest {
        name: entry.name.clone(),
        version: entry.version.clone(),
        why: format!("its index entry could not be serialised: {e}"),
    })
}

/// The subdirectory `export-cargo` puts the local registry in, relative to the
/// export root. A constant, not a caller's path, so the generated config is a
/// function of the layer alone (REQ-REPRO-001 clause 1).
pub const REGISTRY_SUBDIR: &str = "registry";

/// The subdirectory `export-crates-vendor` puts the vendored trees in.
pub const VENDOR_SUBDIR: &str = "vendor";

/// The `.cargo/config.toml` that redirects crates.io to the local registry,
/// so an unmodified `Cargo.toml` resolves against varve's verified bytes.
///
/// `registry_subdir` is RELATIVE to the directory that holds `.cargo/`, which
/// is where Cargo resolves such a path from — settled empirically against a
/// real Cargo, not assumed: with the config at `<root>/.cargo/config.toml` and
/// the registry at `<root>/registry`, a build run from `<root>/sub` resolves it
/// and a registry placed at either `<root>/sub/registry` or
/// `<root>/.cargo/registry` does not (REQ-REPRO-001 clause 1, and the
/// `cargo_offline` oracle pins it).
///
/// This is the correction to REQ-PRODUCE-002's absolute path. The bug that fix
/// reacted to was a relative `--out` embedded VERBATIM, so the string depended
/// on the invoking cwd; a subdirectory constant depends on nothing, keeps the
/// export copyable, and makes two exports of one layer byte-identical.
pub fn cargo_config_toml(registry_subdir: &str) -> String {
    format!(
        "# Generated by `varve export-cargo` (REQ-CRATE-001).\n\
         # Redirects crates.io to a varve-verified local registry; build --offline.\n\
         # The path is relative to the directory holding this `.cargo/` — keep the\n\
         # two together and the export can be copied, committed and relocated.\n\
         [source.crates-io]\n\
         replace-with = \"varve\"\n\n\
         [source.varve]\n\
         local-registry = \"{registry_subdir}\"\n",
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
    #[error(
        "crate {name:?} version {version:?}: no Cargo.toml inside the signed .crate tarball — \
         a registry index entry cannot be written without it, and an entry with empty deps \
         would resolve and then build the crate wrong"
    )]
    MissingManifest { name: String, version: String },
    #[error("crate {name:?} version {version:?}: {why}")]
    UnreadableManifest {
        name: String,
        version: String,
        why: String,
    },
    #[error(
        "crate {name:?} version {version:?}: its {kind} dependency {dep:?} cannot be expressed \
         in a Cargo registry index — {why}. Refusing to write an index entry that omits it \
         (REQ-CRATEIDX-001 clause 2): a dropped dependency is the failure that exits 0."
    )]
    UnrepresentableDep {
        name: String,
        version: String,
        dep: String,
        kind: String,
        why: String,
    },
    #[error(
        "crate {name:?} version {version:?}: its feature {feature:?} cannot be expressed in a \
         Cargo registry index — it {why}. Refusing to write an index entry that omits it \
         (REQ-CRATEIDX-001 clause 2)."
    )]
    UnrepresentableFeature {
        name: String,
        version: String,
        feature: String,
        why: String,
    },
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
///
/// `vendor_subdir` is relative to the directory holding `.cargo/`, for the same
/// empirically-settled reason as `cargo_config_toml` (REQ-REPRO-001 clause 1).
pub fn vendored_config_toml(vendor_subdir: &str) -> String {
    format!(
        "# Generated by `varve export-crates-vendor` (REQ-VENDOR-001).\n\
         # The path is relative to the directory holding this `.cargo/` — keep the\n\
         # two together and the export can be copied, committed and relocated.\n\
         [source.crates-io]\n\
         replace-with = \"vendored-sources\"\n\n\
         [source.vendored-sources]\n\
         directory = \"{vendor_subdir}\"\n",
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
    // panic the index layout or corrupt the index JSON (REQ-CRATENAME-001),
    // and an unrepresentable dependency must not leave a half-written registry
    // whose index under-reports the graph (REQ-CRATEIDX-001 clause 2).
    validate_entries(crates)?;
    let mut lines: Vec<String> = Vec::with_capacity(crates.len());
    for entry in crates {
        lines.push(index_line(entry)?);
    }
    let io = |path: &Path, source: std::io::Error| CrateExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(registry_dir).map_err(|e| io(registry_dir, e))?;
    for (entry, line) in crates.iter().zip(&lines) {
        // The .crate tarball at <registry>/<name>-<version>.crate.
        let crate_file = registry_dir.join(format!("{}-{}.crate", entry.name, entry.version));
        std::fs::write(&crate_file, &entry.bytes).map_err(|e| io(&crate_file, e))?;

        // The index entry, appended (multiple versions share one file).
        let idx = registry_dir.join("index").join(index_path(&entry.name));
        if let Some(parent) = idx.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        // De-dup by (name, vers): rewrite the file with this version present.
        let existing = std::fs::read_to_string(&idx).unwrap_or_default();
        let prefix = format!(r#"{{"name":"{}","vers":"{}""#, entry.name, entry.version);
        let mut kept: Vec<String> = existing
            .lines()
            .filter(|l| !l.starts_with(&prefix))
            .map(str::to_string)
            .collect();
        kept.push(line.clone());
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

    /// A `.crate`-shaped gzip tar: `<name>-<version>/Cargo.toml` plus a source
    /// file. Every registry test now uses one, because the index entry is READ
    /// from the tarball — a fixture of opaque bytes could not tell the truth
    /// about deps and features and so could not have caught varve#73.
    fn crate_tarball(name: &str, version: &str, cargo_toml: &str) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, body) in [
            (
                format!("{name}-{version}/Cargo.toml"),
                cargo_toml.to_string(),
            ),
            (
                format!("{name}-{version}/src/lib.rs"),
                "pub fn f() {}\n".to_string(),
            ),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, &path, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    /// The manifest of a dependency-free, feature-free crate.
    fn plain_manifest(name: &str, version: &str) -> String {
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n")
    }

    /// A `CrateEntry` whose bytes are a real `.crate` carrying `cargo_toml`.
    fn entry_with(name: &str, version: &str, cargo_toml: &str) -> CrateEntry {
        use sha2::{Digest, Sha256};
        let bytes = crate_tarball(name, version, cargo_toml);
        CrateEntry {
            name: name.into(),
            version: version.into(),
            cksum: hex::encode(Sha256::digest(&bytes)),
            bytes,
        }
    }

    /// The parsed index line for a manifest — the thing Cargo actually reads.
    fn line_json(entry: &CrateEntry) -> serde_json::Value {
        serde_json::from_str(&index_line(entry).unwrap()).expect("Cargo parses one JSON per line")
    }

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
        let mut e = entry_with("demo", "0.1.0", &plain_manifest("demo", "0.1.0"));
        e.cksum = "b".repeat(64);
        let line = index_line(&e).unwrap();
        assert!(line.contains(r#""name":"demo""#));
        assert!(line.contains(r#""vers":"0.1.0""#));
        assert!(line.contains(&format!(r#""cksum":"{}""#, "b".repeat(64))));
        assert!(line.contains(r#""yanked":false"#));
    }

    // rivet: verifies REQ-CRATEIDX-001
    #[test]
    fn an_index_entry_carries_the_crates_real_deps_and_features() {
        // varve#73: `deps:[]` and `features:{}` for EVERY crate, while Cargo
        // resolves the graph FROM the index. Measured on varve's own lockfile,
        // 226 of 250 crates declare a dependency or a feature — so the stub was
        // wrong for 90% of a real layer, and its worst outcome was not a
        // failure but a build that exits 0 with a crate compiled featureless.
        let e = entry_with(
            "demo",
            "0.1.0",
            r#"
[package]
name = "demo"
version = "0.1.0"
links = "demolib"
rust-version = "1.70"

[dependencies]
serde = { version = "1.0", features = ["derive"], default-features = false }
cfg-if = "1"
rand = { version = "0.8", optional = true }
renamed = { version = "2", package = "real-crate" }

[dev-dependencies]
tempfile = "3"

[build-dependencies]
cc = "1"

[target."cfg(unix)".dependencies]
libc = "0.2"

[features]
default = ["std"]
std = ["serde/std"]
"#,
        );
        let line = line_json(&e);
        let deps = line["deps"].as_array().unwrap();
        let find = |n: &str| {
            deps.iter()
                .find(|d| d["name"] == n)
                .unwrap_or_else(|| panic!("dependency {n} missing from the index entry"))
        };

        // The plain requirement, and the defaults Cargo assumes.
        assert_eq!(find("cfg-if")["req"], "1");
        assert_eq!(find("cfg-if")["kind"], "normal");
        assert_eq!(find("cfg-if")["optional"], false);
        assert_eq!(find("cfg-if")["default_features"], true);
        assert_eq!(find("cfg-if")["target"], serde_json::Value::Null);

        // Features requested OF a dependency, and default-features turned off:
        // the pair whose loss compiles a crate with the wrong code in it.
        assert_eq!(find("serde")["features"], serde_json::json!(["derive"]));
        assert_eq!(find("serde")["default_features"], false);

        assert_eq!(find("rand")["optional"], true);
        // A rename: the index `name` is the RENAME, `package` the real crate.
        assert_eq!(find("renamed")["package"], "real-crate");
        assert_eq!(find("tempfile")["kind"], "dev");
        assert_eq!(find("cc")["kind"], "build");
        assert_eq!(find("libc")["target"], "cfg(unix)");
        assert_eq!(find("libc")["kind"], "normal");

        // The crate's OWN features — `default` included, the one whose absence
        // exits 0 with nothing enabled (aho-corasick, in the measured run).
        assert_eq!(line["features"]["default"], serde_json::json!(["std"]));
        assert_eq!(line["features"]["std"], serde_json::json!(["serde/std"]));
        // …and the fields Cargo resolves with beyond the graph.
        assert_eq!(line["links"], "demolib");
        assert_eq!(line["rust_version"], "1.70");
    }

    // rivet: verifies REQ-CRATEIDX-001
    #[test]
    fn namespaced_and_weak_features_go_to_features2_behind_v2() {
        // Cargo reads `dep:`/`?/` feature values only from `features2`, and
        // only when `"v":2` says the entry may carry them. Putting them in
        // plain `features` would have Cargo read `dep:serde` as the literal
        // name of a feature that does not exist.
        let e = entry_with(
            "demo",
            "0.1.0",
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = { version = "1", optional = true }
rayon = { version = "1", optional = true }

[features]
plain = []
ns = ["dep:serde"]
weak = ["rayon?/std"]
"#,
        );
        let line = line_json(&e);
        assert_eq!(line["v"], 2, "the entry must declare index version 2");
        assert_eq!(line["features"]["plain"], serde_json::json!([]));
        assert!(
            line["features"].get("ns").is_none(),
            "a namespaced feature must not sit in plain `features`"
        );
        assert_eq!(line["features2"]["ns"], serde_json::json!(["dep:serde"]));
        assert_eq!(line["features2"]["weak"], serde_json::json!(["rayon?/std"]));

        // …and a crate with no such feature carries neither field, exactly as
        // an old-style crates.io entry does.
        let plain = entry_with("demo", "0.1.0", &plain_manifest("demo", "0.1.0"));
        let plain = line_json(&plain);
        assert!(plain.get("v").is_none());
        assert!(plain.get("features2").is_none());
        assert!(plain.get("links").is_none());
        assert!(plain.get("rust_version").is_none());
    }

    // rivet: verifies REQ-CRATEIDX-001
    #[test]
    fn a_dependency_the_index_cannot_express_is_an_error_naming_the_crate() {
        // Clause 2. The alternative — dropping it — is precisely the failure
        // mode that exits 0, so each of these must be loud and must name the
        // crate AND the dependency, or the reader cannot act on it.
        // Each case names the CONSTRUCT in its message, not merely "something
        // is wrong": three of these would also be caught by the unknown-key
        // check, so without pinning the wording those branches could be
        // deleted and the suite would stay green while the reader lost the
        // one sentence that says what to do.
        let cases = [
            (
                "git",
                r#"gitdep = { git = "https://example.invalid/x" }"#,
                "git dependency",
            ),
            (
                "workspace",
                r#"wsdep = { workspace = true }"#,
                "workspace inheritance",
            ),
            (
                "registry alias",
                r#"aliased = { version = "1", registry = "internal" }"#,
                "ALIAS",
            ),
            (
                "bare path",
                r#"local = { path = "../local" }"#,
                "path dependency",
            ),
            (
                "unknown key",
                r#"weird = { version = "1", artifact = "bin" }"#,
                "artifact",
            ),
            (
                "non-string version",
                r#"odd = { version = 1 }"#,
                "not a string",
            ),
            (
                "non-boolean optional",
                r#"odd = { version = "1", optional = "yes" }"#,
                "not a boolean",
            ),
            (
                "array-valued dep",
                r#"odd = ["1.0"]"#,
                "neither a version string nor a table",
            ),
        ];
        for (what, dep, says) in cases {
            let e = entry_with(
                "demo",
                "0.1.0",
                &format!(
                    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\n{dep}\n"
                ),
            );
            let err = index_line(&e).expect_err("{what} must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains("demo") && msg.contains("0.1.0"),
                "{what}: the error must name the crate: {msg}"
            );
            assert!(
                msg.contains(says),
                "{what}: the error must say what it could not express ({says:?}): {msg}"
            );
            // …and the whole export refuses, rather than writing a registry
            // whose index quietly under-reports the graph.
            let dir = tempfile::tempdir().unwrap();
            assert!(
                export_local_registry(std::slice::from_ref(&e), dir.path()).is_err(),
                "{what}: the export must fail closed"
            );
            assert!(
                !dir.path().join("demo-0.1.0.crate").exists(),
                "{what}: nothing may be written before the refusal"
            );
        }
    }

    // rivet: verifies REQ-CRATEIDX-001
    #[test]
    fn a_feature_the_index_cannot_express_is_an_error_naming_the_crate() {
        for feature in [r#"bad = "notanarray""#, r#"bad = [1, 2]"#] {
            let e = entry_with(
                "demo",
                "0.1.0",
                &format!(
                    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[features]\n{feature}\n"
                ),
            );
            let err = index_line(&e).expect_err("an unrepresentable feature must be refused");
            assert!(
                err.to_string().contains("bad") && err.to_string().contains("demo"),
                "{err}"
            );
        }
    }

    // rivet: verifies REQ-CRATEIDX-001
    #[test]
    fn a_crate_tarball_without_a_cargo_toml_is_refused_not_stubbed() {
        // The stub's home: bytes we cannot read used to become `deps:[]`. Now
        // an unreadable crate is an error, because "no dependencies" and "we
        // did not look" must not produce the same index line.
        let opaque = CrateEntry {
            name: "demo".into(),
            version: "0.1.0".into(),
            cksum: "a".repeat(64),
            bytes: b"not a gzip tarball at all".to_vec(),
        };
        assert!(index_line(&opaque).is_err());

        let mut empty_tar = CrateEntry {
            name: "demo".into(),
            version: "0.1.0".into(),
            cksum: "a".repeat(64),
            bytes: Vec::new(),
        };
        empty_tar.bytes = {
            let b = tar::Builder::new(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            ));
            b.into_inner().unwrap().finish().unwrap()
        };
        let err = index_line(&empty_tar).unwrap_err();
        assert!(
            matches!(err, CrateExportError::MissingManifest { .. }),
            "{err}"
        );
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
        let cfg = vendored_config_toml(VENDOR_SUBDIR);
        assert!(cfg.contains(r#"replace-with = "vendored-sources""#));
        assert!(cfg.contains(r#"directory = "vendor""#));
    }

    // rivet: verifies REQ-CRATE-001, REQ-REPRO-001
    #[test]
    fn config_redirects_crates_io_to_the_local_registry() {
        let cfg = cargo_config_toml(REGISTRY_SUBDIR);
        assert!(cfg.contains(r#"replace-with = "varve""#));
        assert!(cfg.contains(r#"local-registry = "registry""#));
        // REQ-REPRO-001 clause 1: nothing machine-specific may reach the file.
        // Cargo resolves this against the directory holding `.cargo/` (proven
        // in the `cargo_offline` oracle), so a relative subdirectory is both
        // correct and identical between two exports of the same layer.
        for cfg in [
            cargo_config_toml(REGISTRY_SUBDIR),
            vendored_config_toml(VENDOR_SUBDIR),
        ] {
            for line in cfg
                .lines()
                .filter(|l| l.starts_with("local-registry") || l.starts_with("directory"))
            {
                let path = line.split('"').nth(1).expect("a quoted path");
                assert!(
                    !std::path::Path::new(path).is_absolute() && !path.contains('/'),
                    "a generated config must carry a bare relative subdirectory, \
                     not a machine-specific path: {line}"
                );
            }
        }
    }

    // rivet: verifies REQ-CRATE-001
    #[test]
    fn materialising_writes_the_crate_and_a_matching_index_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("registry");
        let mut e = entry_with("demo", "0.1.0", &plain_manifest("demo", "0.1.0"));
        e.cksum = "e".repeat(64);
        let bytes = e.bytes.clone();
        assert_eq!(
            export_local_registry(std::slice::from_ref(&e), &reg).unwrap(),
            1
        );
        // The .crate file is the verified bytes.
        assert_eq!(std::fs::read(reg.join("demo-0.1.0.crate")).unwrap(), bytes);
        // The index entry is at Cargo's path and carries the cksum.
        let idx = std::fs::read_to_string(reg.join("index/de/mo/demo")).unwrap();
        assert!(idx.contains(&format!(r#""cksum":"{}""#, "e".repeat(64))));

        // Re-exporting the same version does not duplicate the index line.
        export_local_registry(std::slice::from_ref(&e), &reg).unwrap();
        let idx2 = std::fs::read_to_string(reg.join("index/de/mo/demo")).unwrap();
        assert_eq!(idx2.lines().count(), 1, "one line per (name, version)");
    }

    // rivet: verifies REQ-STORE-002
    #[test]
    fn a_registry_exported_from_a_layer_offers_every_version_it_pins() {
        // Clause 5. A lockfile that names two majors of one crate needs BOTH
        // present to build offline — varve's own lockfile has 14 such names —
        // so the exported registry must OFFER both, with an index entry per
        // version carrying that version's own cksum. Checked by reading the
        // index Cargo reads, not by counting what we handed in.
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("registry");
        let entry = |v: &str| entry_with("serde", v, &plain_manifest("serde", v));
        let crates = [entry("1.0.200"), entry("1.0.210")];
        let bytes = |v: &str| {
            crates
                .iter()
                .find(|c| c.version == v)
                .unwrap()
                .bytes
                .clone()
        };
        export_local_registry(&crates, &reg).unwrap();

        // Both tarballs are on disk, each holding its OWN bytes.
        for v in ["1.0.200", "1.0.210"] {
            assert_eq!(
                std::fs::read(reg.join(format!("serde-{v}.crate"))).unwrap(),
                bytes(v),
                "version {v} must export its own bytes"
            );
        }

        // And the index — one JSON line per version, at Cargo's path, each
        // with the cksum Cargo will check the corresponding tarball against.
        let idx = std::fs::read_to_string(reg.join("index/se/rd/serde")).unwrap();
        let lines: Vec<serde_json::Value> = idx
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each index line is JSON Cargo can parse"))
            .collect();
        let mut offered: Vec<(String, String)> = lines
            .iter()
            .map(|l| {
                (
                    l["vers"].as_str().unwrap().to_string(),
                    l["cksum"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        offered.sort();
        assert_eq!(
            offered,
            vec![
                (
                    "1.0.200".to_string(),
                    hex::encode(Sha256::digest(bytes("1.0.200")))
                ),
                (
                    "1.0.210".to_string(),
                    hex::encode(Sha256::digest(bytes("1.0.210")))
                ),
            ],
            "the index must offer BOTH versions, each bound to its own bytes"
        );
        assert!(lines.iter().all(|l| l["name"] == "serde"));

        // A distdir and a vendor tree hold both versions too — the same layer
        // must be exportable to every adapter without one version vanishing.
        let dd = tmp.path().join("distdir");
        export_distdir(&crates, &dd).unwrap();
        assert_eq!(
            std::fs::read(dd.join("serde-1.0.200.crate")).unwrap(),
            bytes("1.0.200")
        );
        assert_eq!(
            std::fs::read(dd.join("serde-1.0.210.crate")).unwrap(),
            bytes("1.0.210")
        );
    }
}
