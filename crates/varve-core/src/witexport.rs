//! Laying a WIT package and its dependencies out where a tool will find them
//! (REQ-WIT-001 clause 3, DD-036).
//!
//! A layer carries WIT packages FLAT, one per `namespace:name@version`
//! (`witclosure`). A consumer does not want them flat — they want one package
//! treated as top level with everything it needs beside it. This composes
//! that, from packages already in the verified store, with no network.
//!
//! THE LAYOUT IS `wkg`'s, and that is the whole reason to prefer it. Its local
//! backend reads `<root>/<namespace>/<name>/<version>.wasm`, which is exactly
//! what `PackageIdent::binary_path` returns — so this export is a copy, not a
//! conversion, and the bytes a consumer builds against are byte-identical to
//! the bytes varve verified. A re-encode here would mean the digest in the
//! layer and the digest on disk were different numbers for "the same" package,
//! which is the ambiguity the flat-storage rule exists to remove.
//!
//! WHAT THIS IS NOT. It is not the `link` of DD-035/DD-036. A link points a
//! resolver INTO the store and copies nothing; this writes a tree the consumer
//! owns, can commit, and can hand to an assessor six months later. The layouts
//! are the same, which is deliberate: when the link lands it points at the
//! store using this same shape, and nothing a consumer wrote has to change.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::witclosure::{PackageIdent, WitClosureError};

#[derive(Debug, thiserror::Error)]
pub enum WitExportError {
    #[error(transparent)]
    Closure(#[from] WitClosureError),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The closure named a package the caller did not supply bytes for.
    ///
    /// Distinct from `Closure(MissingPackage)`: that one means the LAYER does
    /// not carry it. This means the layer carries it and the bytes did not
    /// reach here, which is a wiring mistake and not a manifest one.
    #[error(
        "the closure names {ident}, and the layer carries it, but no bytes were supplied for it \
         — the caller built an index the export could not read back"
    )]
    BytesMissing { ident: String },
}

/// What an export wrote, so a caller can report it rather than guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitExportReport {
    /// The package asked for, first in intent and last in the closure order.
    pub root: String,
    /// Every package written, in the closure's deterministic order.
    pub written: Vec<String>,
    /// Where `wkg`'s `local` backend should point to read this.
    pub wkg_root: PathBuf,
}

/// Write `root` and its transitive dependencies into `out`, in the layout
/// `wkg`'s local backend reads.
///
/// `bytes_of` supplies each package's stored bytes. It is a closure rather
/// than a directory so this works against a store, an archive or a test
/// fixture without knowing which — the same reason `witclosure` takes an
/// index rather than a path.
///
/// Byte-for-byte: what is written is what was verified. This function does
/// not decode, re-encode, canonicalise or reformat anything.
pub fn export(
    closure: &[PackageIdent],
    root: &PackageIdent,
    out: &Path,
    bytes_of: &dyn Fn(&PackageIdent) -> Option<Vec<u8>>,
) -> Result<WitExportReport, WitExportError> {
    let io = |path: &Path, source: std::io::Error| WitExportError::Io {
        path: path.display().to_string(),
        source,
    };

    // Resolve every package's bytes BEFORE writing any of them. A partial
    // tree is worse than no tree: it type-checks far enough to produce a
    // confusing error inside another tool, which is the same reason
    // `witclosure` refuses rather than truncating (clause 4).
    let mut resolved: BTreeMap<&PackageIdent, Vec<u8>> = BTreeMap::new();
    for ident in closure {
        let Some(bytes) = bytes_of(ident) else {
            return Err(WitExportError::BytesMissing {
                ident: ident.as_str().to_string(),
            });
        };
        resolved.insert(ident, bytes);
    }

    std::fs::create_dir_all(out).map_err(|e| io(out, e))?;
    let mut written = Vec::with_capacity(closure.len());
    for ident in closure {
        let rel = ident.binary_path();
        let dest = out.join(&rel);
        let parent = dest.parent().expect("binary_path always has a directory");
        std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        let bytes = resolved
            .get(ident)
            .expect("every closure member was resolved above");
        std::fs::write(&dest, bytes).map_err(|e| io(&dest, e))?;
        written.push(ident.as_str().to_string());
    }

    Ok(WitExportReport {
        root: root.as_str().to_string(),
        written,
        wkg_root: out.to_path_buf(),
    })
}

/// The `wkg` config stanza that makes the exported tree resolvable.
///
/// Emitted as text for the operator to place, NOT written into their config:
/// varve does not edit a consumer's tool configuration. The registry name is
/// the caller's, because it is what their `wkg.toml` or build rule already
/// refers to, and inventing one here would produce a stanza that resolves
/// nothing.
pub fn wkg_stanza(registry: &str, root: &Path) -> String {
    format!(
        "[registry.\"{registry}\".local]\nroot = \"{}\"\n",
        root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(s: &str) -> PackageIdent {
        s.parse().expect("fixture ident must parse")
    }

    /// The layout is wkg's, and the bytes are untouched.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn each_package_lands_where_wkg_reads_it_with_the_bytes_it_was_given() {
        let tmp = tempfile::tempdir().unwrap();
        let base = ident("acme:base@2.0.0");
        let app = ident("acme:app@0.3.0");
        let closure = vec![base.clone(), app.clone()];
        let bytes_of = |i: &PackageIdent| Some(format!("bytes-of-{}", i.as_str()).into_bytes());

        let report = export(&closure, &app, tmp.path(), &bytes_of).unwrap();

        let base_path = tmp.path().join("acme/base/2.0.0.wasm");
        let app_path = tmp.path().join("acme/app/0.3.0.wasm");
        assert!(base_path.is_file(), "wkg reads <ns>/<name>/<version>.wasm");
        assert!(app_path.is_file());
        assert_eq!(
            std::fs::read(&app_path).unwrap(),
            b"bytes-of-acme:app@0.3.0".to_vec(),
            "the export re-encoded a package instead of copying it"
        );
        assert_eq!(report.written.len(), 2);
        assert_eq!(report.root, "acme:app@0.3.0");
    }

    /// A dependency whose bytes are missing writes NOTHING.
    ///
    /// The ordering matters and is the reason bytes are resolved up front: a
    /// half-written tree parses far enough to fail inside wit-bindgen with a
    /// message about an interface, and the operator then debugs their WIT
    /// instead of their layer.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn a_package_with_no_bytes_leaves_no_partial_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let base = ident("acme:base@2.0.0");
        let app = ident("acme:app@0.3.0");
        // `base` sorts first and would be written first.
        let closure = vec![base.clone(), app.clone()];
        let bytes_of =
            |i: &PackageIdent| (i.as_str() != "acme:app@0.3.0").then(|| b"some-bytes".to_vec());

        let err = export(&closure, &app, tmp.path(), &bytes_of).unwrap_err();
        assert!(
            matches!(&err, WitExportError::BytesMissing { ident } if ident == "acme:app@0.3.0"),
            "{err:?}"
        );
        assert!(
            !tmp.path().join("acme/base/2.0.0.wasm").exists(),
            "the dependency was written before the failure — a partial tree"
        );
    }

    /// The stanza names the caller's registry and the directory just written.
    // rivet: verifies REQ-WIT-001
    #[test]
    fn the_wkg_stanza_points_at_what_was_exported() {
        let s = wkg_stanza("acme.registry.example", Path::new("/w/wit"));
        assert!(
            s.contains("[registry.\"acme.registry.example\".local]"),
            "{s}"
        );
        assert!(s.contains("root = \"/w/wit\""), "{s}");
    }
}
