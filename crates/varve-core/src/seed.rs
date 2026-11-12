//! Seeding another store from this one (REQ-SEED-001).
//!
//! A container's store (a Docker volume) is a separate store from its host's,
//! and a pin change there refetched a composed layer and wanted the registry
//! credential — although the host store already held every byte. `varve seed
//! <DIR>` writes the installed layers into a directory a realm's `mirrors`
//! entry accepts, so the other store installs from it with no network and no
//! credential.
//!
//! ## What a seed is
//!
//! A directory holding one directory-shaped OCI image layout per layer, plus a
//! marker file that says the directory is a seed. It is one layout PER LAYER
//! because a layout's referrers (the baseline status, the carried attestations)
//! are not keyed by layer: two layers in one layout would hand each install the
//! other's evidence. Each subdirectory is exactly what `varve archive` writes,
//! plus the realm's signed line index, which `archive` does not carry — so each
//! one is a `mirrors` entry on its own, read by the same `OciLayoutSource`.
//!
//! ## A mirror is transport, not authority
//!
//! Nothing here signs, re-encodes or vouches for anything. The signed manifest
//! envelope, the status envelope, the index envelope and every payload are the
//! bytes the store already holds (which are the bytes it verified on the way
//! in). The store that reads the seed verifies all of them against ITS realm's
//! trust root exactly as it would from the registry (REQ-MIRROR-002), so a seed
//! that was altered in transit is refused, not trusted.
//!
//! ## What is not copied
//!
//! Shims, the `env` script and anything else that holds the source store's
//! absolute path live outside a layer's directory and are never read here. The
//! target store lays down its own (clause 3).

use std::path::{Path, PathBuf};

use crate::archive::{ArchiveError, ArchiveOptions};
use crate::lineindex::{IndexCache, IndexError};
use crate::realm::{Realm, RealmError};
use crate::store::{InstalledLayer, Store};

/// The file that says a directory is a seed. A directory without it, that is
/// not empty, is somebody else's and is never written into.
pub const MARKER_FILE: &str = "varve-seed.json";

/// What the marker file holds. Written, and required to match when read back:
/// a file that merely shares the name is not a claim on the directory.
const MARKER_BODY: &str = "{\"varve-seed\":1}\n";

#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    #[error(
        "the seed directory {dest} is not an absolute path. A realm's `mirrors` entry has to be \
         absolute (a relative one would resolve against whatever directory varve happens to run \
         in), so a seed written to a relative path could not be used as one. Pass an absolute \
         path."
    )]
    RelativeDestination { dest: String },
    #[error(
        "{dest} is not empty and is not a varve seed (it has no {MARKER_FILE}), so nothing was \
         written: mixing a seed into somebody else's files would leave a directory that is \
         neither. Seed into an empty or new directory, or into one a previous `varve seed` wrote."
    )]
    ForeignDestination { dest: String },
    #[error(
        "{dest} is a symbolic link, so nothing was written: a seed directory that redirects \
         somewhere else would put the seed (and replace files) wherever the link points. Name \
         the real directory."
    )]
    SymlinkDestination { dest: String },
    #[error(
        "layer {layer} cannot be seeded: realm '{realm}' declares `signed-index = true`, and this \
         store holds no signed line index for line {line}. A seed without it could not satisfy \
         that realm, and varve will not make one up — install the layer from a source that \
         carries the index (the realm's registry), then seed again."
    )]
    MissingIndex {
        layer: String,
        line: String,
        realm: String,
    },
    #[error("io error at {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot tell whether a composed layer's realm requires a signed index: {0}")]
    Realm(#[source] RealmError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    Index(#[from] IndexError),
}

/// What one layer's seed carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedOutcome {
    /// The layout directory — the value to put in a realm's `mirrors`.
    pub layout: PathBuf,
    /// Payload blobs written.
    pub payloads: usize,
    /// Entries left out because they name another platform.
    pub omitted: usize,
    /// True when the store cached no baseline line-status for the line, so the
    /// seed carries none.
    pub baseline_missing: bool,
    /// Whether the realm's signed line index went into the seed.
    pub index_carried: bool,
}

/// Check `dest` may receive a seed, writing nothing.
///
/// Absolute, because a realm's `mirrors` entry must be (`mirror.rs` refuses a
/// relative one rather than resolving it against the working directory).
/// Absent, empty, or already marked as a seed: anything else is somebody
/// else's directory and is refused before a byte is written.
pub fn check_destination(dest: &Path) -> Result<(), SeedError> {
    let shown = dest.display().to_string();
    if !dest.is_absolute() {
        return Err(SeedError::RelativeDestination { dest: shown });
    }
    if std::fs::symlink_metadata(dest).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(SeedError::SymlinkDestination { dest: shown });
    }
    match std::fs::read_dir(dest) {
        Ok(mut entries) => {
            let empty = entries.next().is_none();
            let ours = std::fs::read_to_string(dest.join(MARKER_FILE))
                .is_ok_and(|body| body == MARKER_BODY);
            if empty || ours {
                Ok(())
            } else {
                Err(SeedError::ForeignDestination { dest: shown })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // Not a directory (a file, say): it is not ours to replace.
        Err(_) => Err(SeedError::ForeignDestination { dest: shown }),
    }
}

/// `check_destination`, then create the directory and mark it as a seed.
pub fn claim_destination(dest: &Path) -> Result<(), SeedError> {
    check_destination(dest)?;
    std::fs::create_dir_all(dest).map_err(|source| SeedError::Io {
        path: dest.display().to_string(),
        source,
    })?;
    let marker = dest.join(MARKER_FILE);
    std::fs::write(&marker, MARKER_BODY).map_err(|source| SeedError::Io {
        path: marker.display().to_string(),
        source,
    })
}

/// Where one layer's layout goes inside a seed: `<layer>-<12 hex of digest>`.
/// The layer id alone is not unique — two realms may each have a `2026.08.0` —
/// so the digest keeps two different layers from landing in one layout.
pub fn layout_dir(dest: &Path, layer: &InstalledLayer) -> PathBuf {
    let hex = layer
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&layer.digest);
    let short: String = hex.chars().take(12).collect();
    dest.join(format!("{}-{short}", layer.layer))
}

/// What a composed layer's realm obliges, from resolving it.
///
/// A realm that is not defined anywhere visible (no realms file, or none
/// naming it) states no obligation, so `None`. A realms file that exists but
/// cannot be read, parsed or used is NOT "unknown": treating it so would skip
/// a `signed-index = true` the file may well declare, so it is a refusal.
pub fn realm_obligation(
    resolved: Result<Realm, RealmError>,
) -> Result<Option<(String, bool)>, SeedError> {
    match resolved {
        Ok(realm) => Ok(Some((realm.name.clone(), realm.signed_index))),
        Err(RealmError::NoRealmsFile { .. } | RealmError::Undefined { .. }) => Ok(None),
        Err(e) => Err(SeedError::Realm(e)),
    }
}

/// The signed line index this store holds for the layer's line, as the bytes it
/// accepted. `realm` is `Some((name, signed_index))` when the layer's realm is
/// known: a realm requiring an index and a store lacking one is a refusal, not
/// a seed that fails on the far side.
pub fn read_index(
    store: &Store,
    layer: &InstalledLayer,
    realm: Option<(&str, bool)>,
) -> Result<Option<Vec<u8>>, SeedError> {
    let line = layer.layer.line().to_string();
    let held = IndexCache::at_root(store.root()).envelope_bytes(&line)?;
    match (&held, realm) {
        (None, Some((name, true))) => Err(SeedError::MissingIndex {
            layer: layer.layer.to_string(),
            line,
            realm: name.to_string(),
        }),
        _ => Ok(held),
    }
}

/// What a staging directory inside a seed is called. It never survives a run.
const STAGING_PREFIX: &str = ".varve-seed-staging-";

/// One layer to put in a seed: where it is installed, and the signed line index
/// `read_index` returned for it.
pub struct SeedItem<'a> {
    pub store: &'a Store,
    pub layer: &'a InstalledLayer,
    pub index: Option<&'a [u8]>,
}

/// Write every layer into the seed at `dest`, or none of them.
///
/// Each layer is exported into a fresh staging directory inside `dest` (made
/// with `create_dir`, so it cannot be a directory or a link somebody else
/// left). Only when EVERY layer succeeded is each one moved into place: an
/// existing `<layer>-<hex>` entry is removed first, WITHOUT following it if it
/// is a symlink, and the marker is written last. Any error removes the staging
/// directory (and `dest` if this run created it) and leaves what `dest` held
/// before untouched — a refusal in the second layer does not leave the first.
/// Nothing is ever written into an existing layer directory, so nothing a
/// previous seed's directory now links to is followed.
pub fn write_seed(
    items: &[SeedItem<'_>],
    dest: &Path,
    platform: &str,
) -> Result<Vec<SeedOutcome>, SeedError> {
    check_destination(dest)?;
    let io = |path: &Path| {
        let path = path.display().to_string();
        move |source| SeedError::Io { path, source }
    };
    let created = !dest.exists();
    std::fs::create_dir_all(dest).map_err(io(dest))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let staging = dest.join(format!("{STAGING_PREFIX}{}-{nanos}", std::process::id()));
    let result = std::fs::create_dir(&staging)
        .map_err(io(&staging))
        .and_then(|()| stage_and_commit(items, dest, &staging, platform));
    if staging.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    if result.is_err() && created {
        // Only if empty: never remove something this run did not make.
        let _ = std::fs::remove_dir(dest);
    }
    result
}

fn stage_and_commit(
    items: &[SeedItem<'_>],
    dest: &Path,
    staging: &Path,
    platform: &str,
) -> Result<Vec<SeedOutcome>, SeedError> {
    let mut outcomes = Vec::new();
    for item in items {
        outcomes.push(seed_layer(
            item.store, item.layer, dest, staging, platform, item.index,
        )?);
    }
    for item in items {
        let staged = layout_dir(staging, item.layer);
        let target = layout_dir(dest, item.layer);
        remove_entry(&target)?;
        std::fs::rename(&staged, &target).map_err(|source| SeedError::Io {
            path: target.display().to_string(),
            source,
        })?;
    }
    let marker = dest.join(MARKER_FILE);
    remove_entry(&marker)?;
    std::fs::write(&marker, MARKER_BODY).map_err(|source| SeedError::Io {
        path: marker.display().to_string(),
        source,
    })?;
    Ok(outcomes)
}

/// Remove whatever is at `path`, a symlink itself and never what it points at.
fn remove_entry(path: &Path) -> Result<(), SeedError> {
    let io = |source| SeedError::Io {
        path: path.display().to_string(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path).map_err(io),
        Ok(_) => std::fs::remove_file(path).map_err(io),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(e)),
    }
}

/// Export one installed layer into `staging`; its final place is
/// `layout_dir(dest, layer)`. `index` is what `read_index` returned.
///
/// The layout itself is `archive`'s, written by the same code: the retained
/// signature envelope verbatim, each payload re-hashed against the digest the
/// manifest signs, the baseline status and the carried attestations. The one
/// addition is the line index, attached verbatim.
fn seed_layer(
    store: &Store,
    layer: &InstalledLayer,
    dest: &Path,
    staging: &Path,
    platform: &str,
    index: Option<&[u8]>,
) -> Result<SeedOutcome, SeedError> {
    let staged = layout_dir(staging, layer);
    let summary = crate::archive::export_with_options(
        store,
        layer,
        &staged,
        platform,
        &ArchiveOptions {
            // The staging directory is new; nothing is replaced.
            force: false,
            allow_no_status: false,
        },
    )?;
    if let Some(envelope) = index {
        crate::lineindex::attach_to_layout(&staged, &layer.layer.line().to_string(), envelope)?;
    }
    Ok(SeedOutcome {
        layout: layout_dir(dest, layer),
        payloads: summary.archived,
        omitted: summary.omitted.values().sum(),
        baseline_missing: summary.baseline_missing,
        index_carried: index.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::OciLayoutSource;
    use crate::install::{InstallPolicy, install};
    use crate::pin::Pin;
    use crate::rollback::HighWaterMarks;
    use crate::source::{LayerRef, LayerSource, MemorySource};
    use crate::store::manifest_digest;
    use crate::verify::{PinnedKeyVerifier, generate_root_keypair, sign_layer_manifest};

    const PLATFORM: &str = "test-platform";

    fn pin(layer: &str) -> Pin {
        Pin::parse(
            &format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
            ),
            "varve.toml",
        )
        .unwrap()
    }

    fn policy() -> InstallPolicy<'static> {
        InstallPolicy {
            index: None,
            now: "2026-08-07T00:00:00Z",
            staleness_threshold_days: 90,
            platform: PLATFORM,
        }
    }

    struct Near {
        tmp: tempfile::TempDir,
        store: Store,
        layer: InstalledLayer,
        pk: Vec<u8>,
        sk: Vec<u8>,
        envelope: String,
        tool: Vec<u8>,
    }

    /// A signed layer installed into a fresh "host" store.
    fn near() -> Near {
        near_with(&[("synth", b"synth-bytes", None)])
    }

    /// The same, for tools given as (name, bytes, platform). Only the entries
    /// for `PLATFORM` (or none) are installed, as a real install does.
    fn near_with(tools: &[(&str, &[u8], Option<&str>)]) -> Near {
        use crate::manifest::fixtures::manifest_with_platform_tools;
        let (sk, pk) = generate_root_keypair();
        let digests: Vec<String> = tools.iter().map(|(_, b, _)| manifest_digest(b)).collect();
        let entries: Vec<(&str, &str, Option<&str>)> = tools
            .iter()
            .zip(&digests)
            .map(|((name, _, platform), d)| (*name, d.as_str(), *platform))
            .collect();
        let payload = manifest_with_platform_tools(
            "2026.07.0",
            "qualified",
            1,
            "2026-07-31T09:14:00Z",
            &entries,
        );
        let envelope = sign_layer_manifest(&payload, &sk, "varve-root-1").unwrap();
        let mut source = MemorySource::new().with_manifest(envelope.as_bytes());
        for ((_, bytes, _), digest) in tools.iter().zip(&digests) {
            source = source.with_blob(digest, bytes);
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("host");
        let store = Store::at(&root);
        let mut marks = HighWaterMarks::load(&root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
        let outcome = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &store,
            &mut marks,
            &policy(),
        )
        .unwrap();
        let layer = store.get(&outcome.digest).unwrap().unwrap();
        Near {
            tmp,
            store,
            layer,
            pk,
            sk,
            envelope,
            tool: tools[0].1.to_vec(),
        }
    }

    /// One layer through `write_seed`, the way the command seeds it.
    fn seed_layer(
        store: &Store,
        layer: &InstalledLayer,
        dest: &Path,
        platform: &str,
        index: Option<&[u8]>,
    ) -> Result<SeedOutcome, SeedError> {
        let item = SeedItem {
            store,
            layer,
            index,
        };
        Ok(write_seed(&[item], dest, platform)?.remove(0))
    }

    fn seed_dir(n: &Near) -> PathBuf {
        n.tmp.path().join("seed")
    }

    fn files_under(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap()) {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_relative_destination_is_refused_and_names_why() {
        let err = claim_destination(Path::new("relative/seed")).unwrap_err();
        assert!(matches!(err, SeedError::RelativeDestination { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("relative/seed") && msg.contains("absolute"),
            "{msg}"
        );
        assert!(
            !Path::new("relative/seed").exists(),
            "a refusal must not create the directory"
        );
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_new_or_empty_destination_is_claimed_with_the_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("a/b/new");
        claim_destination(&fresh).unwrap();
        assert_eq!(
            std::fs::read_to_string(fresh.join(MARKER_FILE)).unwrap(),
            MARKER_BODY
        );
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        claim_destination(&empty).unwrap();
        assert!(empty.join(MARKER_FILE).is_file());
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_seed_a_previous_run_wrote_is_accepted_again_and_its_contents_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("seed");
        claim_destination(&dest).unwrap();
        std::fs::create_dir(dest.join("kept-1.2.3")).unwrap();
        claim_destination(&dest).unwrap();
        assert!(dest.join("kept-1.2.3").is_dir());
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_non_empty_directory_that_is_not_a_seed_is_refused_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let foreign = tmp.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("notes.txt"), "mine").unwrap();
        let err = claim_destination(&foreign).unwrap_err();
        assert!(matches!(err, SeedError::ForeignDestination { .. }), "{err}");
        assert!(err.to_string().contains(&foreign.display().to_string()));
        assert!(
            !foreign.join(MARKER_FILE).exists(),
            "nothing may be written"
        );
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);

        // A file that only SHARES the marker's name is not a claim.
        let impostor = tmp.path().join("impostor");
        std::fs::create_dir(&impostor).unwrap();
        std::fs::write(impostor.join(MARKER_FILE), "not ours").unwrap();
        let err = claim_destination(&impostor).unwrap_err();
        assert!(matches!(err, SeedError::ForeignDestination { .. }), "{err}");
        assert_eq!(
            std::fs::read_to_string(impostor.join(MARKER_FILE)).unwrap(),
            "not ours"
        );

        // A plain file where the directory should be is refused too.
        let file = tmp.path().join("afile");
        std::fs::write(&file, "x").unwrap();
        assert!(claim_destination(&file).is_err());
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn checking_a_destination_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("new");
        check_destination(&fresh).unwrap();
        assert!(!fresh.exists(), "check must not create the directory");
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        check_destination(&empty).unwrap();
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        assert!(matches!(
            check_destination(Path::new("rel")),
            Err(SeedError::RelativeDestination { .. })
        ));
        std::fs::write(empty.join("x"), "x").unwrap();
        assert!(matches!(
            check_destination(&empty),
            Err(SeedError::ForeignDestination { .. })
        ));
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_layout_is_named_by_layer_and_the_start_of_its_digest() {
        let n = near();
        let hex = n.layer.digest.strip_prefix("sha256:").unwrap();
        assert_eq!(
            layout_dir(Path::new("/s"), &n.layer),
            Path::new("/s").join(format!("2026.07.0-{}", &hex[..12]))
        );
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_missing_index_is_refused_only_where_the_realm_requires_one() {
        let n = near();
        // Required and absent: refuse, naming the layer, line and realm.
        let err = read_index(&n.store, &n.layer, Some(("acme", true))).unwrap_err();
        assert!(matches!(err, SeedError::MissingIndex { .. }), "{err}");
        let msg = err.to_string();
        for needle in ["2026.07.0", "2026.07", "acme", "signed-index"] {
            assert!(msg.contains(needle), "{needle} missing from: {msg}");
        }
        // Not required, or realm unknown: nothing to carry, nothing refused.
        assert_eq!(
            read_index(&n.store, &n.layer, Some(("acme", false))).unwrap(),
            None
        );
        assert_eq!(read_index(&n.store, &n.layer, None).unwrap(), None);
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_cached_index_is_read_back_byte_for_byte() {
        let n = near();
        let dir = n.store.root().join("state").join("line-index");
        std::fs::create_dir_all(&dir).unwrap();
        // Bytes that are NOT valid JSON: a seed copies, it never re-encodes.
        let odd = b"  {\"signed\" :  \"as-fetched\"}\r\n".to_vec();
        std::fs::write(dir.join("2026.07.dsse.json"), &odd).unwrap();
        for realm in [None, Some(("acme", false)), Some(("acme", true))] {
            assert_eq!(
                read_index(&n.store, &n.layer, realm).unwrap(),
                Some(odd.clone())
            );
        }
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_seeded_layer_installs_into_a_fresh_store_from_the_directory_alone() {
        let n = near();
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let outcome = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        assert_eq!(outcome.layout, layout_dir(&dest, &n.layer));
        assert_eq!(outcome.payloads, 1);
        assert_eq!(outcome.omitted, 0);
        assert!(
            outcome.baseline_missing,
            "this store cached no baseline, and the outcome must say so"
        );
        assert!(!outcome.index_carried);

        // The far side: a fresh store, the pinned root, and ONLY the seed.
        let far_root = n.tmp.path().join("container");
        let far = Store::at(&far_root);
        let mut marks = HighWaterMarks::load(&far_root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&n.pk).unwrap();
        let source = OciLayoutSource::at(&outcome.layout).for_platform(PLATFORM);
        let installed = install(
            &pin("2026.07.0"),
            &source,
            &verifier,
            &far,
            &mut marks,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            installed.digest, n.layer.digest,
            "the same layer, by digest"
        );
        let got = far.get(&installed.digest).unwrap().unwrap();
        assert_eq!(
            std::fs::read(far.tool_path(&got, "synth").unwrap()).unwrap(),
            n.tool
        );
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn the_signed_documents_are_the_stores_own_bytes_and_the_index_rides_along() {
        let n = near();
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let index = b"{\"payload\":\"opaque\",\"as\":\"fetched\"}".to_vec();
        let outcome = seed_layer(&n.store, &n.layer, &dest, PLATFORM, Some(&index)).unwrap();
        assert!(outcome.index_carried);
        let source = OciLayoutSource::at(&outcome.layout);
        // The manifest comes back as the exact envelope that was signed.
        let fetched = source
            .fetch_manifest(&LayerRef::Name("2026.07.0".parse().unwrap()))
            .unwrap();
        assert_eq!(fetched, n.envelope.as_bytes());
        // The index comes back as the bytes handed over.
        assert_eq!(source.fetch_line_index("2026.07").unwrap(), Some(index));
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_seed_holds_no_path_of_the_store_it_came_from() {
        let n = near();
        // Where a shim and the env script would be: next to the layers, in the
        // store, holding the store's absolute path.
        std::fs::create_dir_all(n.store.root().join("shims")).unwrap();
        std::fs::write(
            n.store.root().join("env"),
            format!("PATH={}/shims:$PATH\n", n.store.root().display()),
        )
        .unwrap();
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        let root = n.store.root().display().to_string();
        let canonical = std::fs::canonicalize(n.store.root())
            .unwrap()
            .display()
            .to_string();
        let files = files_under(&dest);
        assert!(files.len() >= 4, "the scan has to have something to scan");
        for f in files {
            let bytes = std::fs::read(&f).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(&root) && !text.contains(&canonical),
                "{} holds the source store's path",
                f.display()
            );
            assert_ne!(f.file_name().unwrap(), "env");
        }
        assert!(!dest.join("shims").exists());
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_seed_is_not_authority_a_flipped_byte_is_refused_by_the_far_side() {
        let n = near();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&n.pk).unwrap();
        let try_install = |layout: &Path, name: &str| {
            let root = n.tmp.path().join(name);
            let far = Store::at(&root);
            let mut marks = HighWaterMarks::load(&root).unwrap();
            install(
                &pin("2026.07.0"),
                &OciLayoutSource::at(layout).for_platform(PLATFORM),
                &verifier,
                &far,
                &mut marks,
                &policy(),
            )
        };
        let flip = |path: &Path, at: usize| {
            let mut bytes = std::fs::read(path).unwrap();
            bytes[at] ^= 0x01;
            std::fs::write(path, bytes).unwrap();
        };
        let blob_of = |layout: &Path, bytes: &[u8]| {
            let hex = manifest_digest(bytes);
            layout
                .join("blobs/sha256")
                .join(hex.strip_prefix("sha256:").unwrap())
        };

        // Control: the untouched seed installs.
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let out = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        try_install(&out.layout, "control").expect("the untampered seed installs");

        // A payload byte: the digest the manifest signs no longer matches.
        let payload_blob = blob_of(&out.layout, &n.tool);
        flip(&payload_blob, 0);
        let err = try_install(&out.layout, "bad-payload").unwrap_err();
        assert!(
            matches!(err, crate::install::InstallError::BlobDigestMismatch { .. }),
            "{err}"
        );
        flip(&payload_blob, 0);

        // A byte inside the signature of the manifest envelope.
        let env_blob = blob_of(&out.layout, n.envelope.as_bytes());
        let text = String::from_utf8(std::fs::read(&env_blob).unwrap()).unwrap();
        // The signature VALUE (after the `sig` key's colon and opening quote),
        // so the envelope stays well-formed JSON and only the proof is wrong.
        let key_at = text.find("\"sig\"").expect("the envelope has a `sig` key");
        let colon = key_at + text[key_at..].find(':').unwrap();
        let sig_at = colon + text[colon..].find('"').unwrap() + 1 + 4;
        flip(&env_blob, sig_at);
        let err = try_install(&out.layout, "bad-envelope").unwrap_err();
        assert!(
            matches!(err, crate::install::InstallError::Verify(_)),
            "{err}"
        );
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn seeding_the_same_layer_twice_is_idempotent_and_keeps_other_layers() {
        let n = near();
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let first = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        let before: Vec<_> = files_under(&dest)
            .into_iter()
            .map(|f| (f.clone(), std::fs::read(&f).unwrap()))
            .collect();
        // Another layer's layout, as a previous run would have left it.
        let other = dest.join("other-1.0.0-aaaaaaaaaaaa");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("index.json"), "{}").unwrap();
        claim_destination(&dest).unwrap();
        let again = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        assert_eq!(first, again);
        let mut after: Vec<_> = files_under(&dest)
            .into_iter()
            .filter(|f| !f.starts_with(&other))
            .map(|f| (f.clone(), std::fs::read(&f).unwrap()))
            .collect();
        let mut before = before;
        before.sort();
        after.sort();
        assert_eq!(before, after);
        assert!(other.join("index.json").is_file());
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn payloads_written_and_entries_left_out_are_both_counted() {
        let n = near_with(&[
            ("a", b"aaa", Some(PLATFORM)),
            ("b", b"bbb", Some(PLATFORM)),
            ("c", b"ccc", Some("other-platform")),
            ("d", b"ddd", Some("other-platform")),
        ]);
        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let out = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        assert_eq!(out.payloads, 2, "the two payloads this store installed");
        assert_eq!(out.omitted, 2, "the two entries for another platform");
        // Only what was installed is in the seed: blobs = 2 payloads + the
        // manifest + its envelope.
        let blobs = std::fs::read_dir(out.layout.join("blobs/sha256"))
            .unwrap()
            .count();
        assert_eq!(blobs, 4);
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_cached_baseline_travels_and_seeding_over_it_again_is_not_refused() {
        use crate::linestatus::LineStatus;
        let n = near();
        let line: crate::layer::Line = "2026.07".parse().unwrap();
        let status = LineStatus {
            min_counter: None,
            line: "2026.07".into(),
            counter: 3,
            issued_at: "2026-08-07T00:00:00Z".into(),
            support_until: Some("2028-07-31".into()),
            yanked: std::collections::BTreeMap::new(),
            known_problems: Vec::new(),
        };
        let status_envelope = status.sign(&n.sk, "varve-root-1").unwrap().into_bytes();
        let carrier = MemorySource::new().with_line_status(&status_envelope);
        crate::linestatus::cache_baseline_from_source(
            &carrier,
            &LayerRef::Name("2026.07.0".parse().unwrap()),
            &line,
            &crate::keyroles::test_support::rt(&n.pk),
            n.store.root(),
        )
        .unwrap()
        .expect("the store cached the baseline");

        let dest = seed_dir(&n);
        claim_destination(&dest).unwrap();
        let out = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        assert!(!out.baseline_missing);
        let source = OciLayoutSource::at(&out.layout);
        let carried = source
            .fetch_line_status(&LayerRef::Name("2026.07.0".parse().unwrap()))
            .unwrap();
        assert_eq!(
            carried,
            Some(status_envelope),
            "verbatim, the store's bytes"
        );

        // The layout now carries a referrer. It is OUR layout (the marker says
        // so), so seeding again replaces it rather than tripping the guard that
        // protects somebody else's signed work.
        let again = seed_layer(&n.store, &n.layer, &dest, PLATFORM, None).unwrap();
        assert_eq!(again, out);
    }

    // rivet: verifies REQ-SEED-001
    #[test]
    fn a_realm_nobody_defines_states_no_obligation_but_a_broken_file_is_a_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pk) = generate_root_keypair();
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();

        // No realms file at all, and a file that does not name the realm.
        assert_eq!(
            realm_obligation(crate::realm::resolve_realm(tmp.path(), "acme")).unwrap(),
            None
        );
        std::fs::write(
            tmp.path().join("varve-realms.toml"),
            format!("[realm.other]\nregistry = \"r\"\ntrust-root = \"{hex}\"\n"),
        )
        .unwrap();
        assert_eq!(
            realm_obligation(crate::realm::resolve_realm(tmp.path(), "acme")).unwrap(),
            None
        );

        // Defined: the obligation is the realm's, either way round.
        for required in [false, true] {
            std::fs::write(
                tmp.path().join("varve-realms.toml"),
                format!(
                    "[realm.acme]\nregistry = \"r\"\ntrust-root = \"{hex}\"\n\
                     signed-index = {required}\n"
                ),
            )
            .unwrap();
            assert_eq!(
                realm_obligation(crate::realm::resolve_realm(tmp.path(), "acme")).unwrap(),
                Some(("acme".to_string(), required))
            );
        }

        // Broken: parse error and a bad definition are refusals naming the file.
        for body in ["[realm.acme\nnot toml", "[realm.acme]\nregistry = \"r\"\n"] {
            std::fs::write(tmp.path().join("varve-realms.toml"), body).unwrap();
            let err =
                realm_obligation(crate::realm::resolve_realm(tmp.path(), "acme")).unwrap_err();
            assert!(matches!(err, SeedError::Realm(_)), "{err}");
            let full = format!("{err} / {:?}", std::error::Error::source(&err));
            assert!(full.contains("varve-realms.toml"), "{full}");
        }
    }
}
