//! Reading and exporting the documentation a layer carries (REQ-LAYERDOCS-001).
//!
//! The payload is the archive exactly as its producer published it — never
//! unpacked into the store. That is not a preference about tidiness: the
//! stored bytes have to stay identical to what the signature covers, or
//! `varve verify` cannot re-derive the digest. An unpacked store would trade
//! re-verification for disk, which is the wrong way round for a tool whose
//! whole claim is that it can still prove what it holds.
//!
//! So there are two ways to get at a document, and they answer different
//! questions:
//!
//! - [`read_one`] pulls ONE file out of the archive in place. Nothing is
//!   written and nothing is duplicated; this is what the viewer uses, and it
//!   is the reason the viewer does not need an export first.
//! - [`export`] materialises a copy on disk, for handing to someone or
//!   publishing as a CI artifact. It costs space only when asked for.
//!
//! **The known cost, stated rather than discovered.** A `.tar.gz` is
//! sequential: [`read_one`] decompresses the whole archive to reach one
//! member. That is free for the 1.2 MB traceability bundle and wrong for a
//! few-hundred-megabyte rustdoc. The fix is a random-access container (zip's
//! central directory lets one entry be read without touching the rest), and it
//! belongs with rustdoc rather than here — an unused dependency in a
//! verification binary is its own cost. A caller serving many files from one
//! large payload should read the members once and keep them, not call
//! [`read_one`] in a loop.

use crate::layerspec::DocsFormat;
use crate::sdkexport::{Member, MemberBody, SdkExportError, read_members};
use std::path::Path;

/// One documentation payload, as the exporter and the viewer see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocsPayload {
    /// The handle a command takes.
    pub name: String,
    pub version: String,
    /// What it IS, from the signed annotation — never guessed from `bytes`.
    pub format: DocsFormat,
    /// Where a reader starts, for a tree format.
    pub entry: Option<String>,
    /// The human label shown when choosing.
    pub title: Option<String>,
    /// The archive (or the single file), exactly as signed.
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum DocsExportError {
    #[error("{name}: {source}")]
    Archive {
        name: String,
        #[source]
        source: SdkExportError,
    },
    #[error("cannot write {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Asked for a document the layer does not carry. Names what IS carried,
    /// because the next thing the caller needs is the right handle.
    #[error(
        "this layer carries no documentation named {asked:?}. It carries: {carried}. \
         `varve inspect` lists every payload."
    )]
    NoSuchDocument { asked: String, carried: String },
    /// More than one document and no way to tell which was meant.
    #[error(
        "this layer carries {n} documents and none was named: {carried}. Name one — \
         a selector is only optional where there is nothing to choose between."
    )]
    Ambiguous { n: usize, carried: String },
}

/// What an export did. Reported rather than assumed: "wrote 0 files" and
/// "wrote 341 files" look the same on disk unless someone says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocsExportReport {
    pub files: usize,
    pub dirs: usize,
    /// The path a reader should open, absolute, once the export has happened.
    pub entry_path: Option<String>,
}

/// Choose one payload by name, or the only one if there is exactly one.
///
/// The no-selector case is deliberate ergonomics, borrowed from
/// `criticalup doc`: a reader has already said which layer they want by
/// pinning it, and making them name the document again is asking twice. But
/// it holds ONLY where there is nothing to choose between — guessing among
/// several would open the wrong document silently, which is worse than asking.
pub fn select<'a>(
    payloads: &'a [DocsPayload],
    asked: Option<&str>,
) -> Result<&'a DocsPayload, DocsExportError> {
    let carried = || {
        let mut names: Vec<&str> = payloads.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        if names.is_empty() {
            "nothing".to_string()
        } else {
            names.join(", ")
        }
    };
    match asked {
        Some(name) => payloads.iter().find(|p| p.name == name).ok_or_else(|| {
            DocsExportError::NoSuchDocument {
                asked: name.to_string(),
                carried: carried(),
            }
        }),
        None => match payloads {
            [only] => Ok(only),
            many => Err(DocsExportError::Ambiguous {
                n: many.len(),
                carried: carried(),
            }),
        },
    }
}

/// Read ONE file out of a tree payload, without writing anything.
///
/// `None` means the archive opened and did not contain that path — a fact the
/// caller reports as a 404, distinct from the archive failing to open, which
/// is an error. Conflating the two would turn "this page does not exist" and
/// "this payload is corrupt" into the same message.
pub fn read_one(payload: &DocsPayload, path: &str) -> Result<Option<Vec<u8>>, DocsExportError> {
    if !payload.format.is_tree() {
        // A single-file document has exactly one thing to read, and asking it
        // for an inner path is a category error rather than a miss.
        return Ok(None);
    }
    let want = path.trim_start_matches('/');
    let members = members_of(payload)?;
    Ok(members.into_iter().find_map(|m| match m.body {
        MemberBody::File { bytes, .. } if rel_path(&m.path, want) => Some(bytes),
        _ => None,
    }))
}

/// Materialise a document on disk.
///
/// A tree becomes a directory; a single-file format becomes one file named
/// `<name>-<version>.<ext>`. Returns where a reader should start, so the
/// caller can print a path rather than leave someone to find it.
///
/// Member paths are validated by `sdkexport::safe_member_path` — the SAME
/// rule the SDK exporter applies, not a second copy of it. One member is
/// enough to escape an export directory, and a tree has thousands.
pub fn export(payload: &DocsPayload, out: &Path) -> Result<DocsExportReport, DocsExportError> {
    let io = |path: &Path, source: std::io::Error| DocsExportError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(out).map_err(|e| io(out, e))?;
    let mut report = DocsExportReport::default();

    if !payload.format.is_tree() {
        let ext = payload
            .format
            .file_extension()
            .expect("a non-tree format names an extension");
        let file = out.join(format!("{}-{}.{ext}", payload.name, payload.version));
        std::fs::write(&file, &payload.bytes).map_err(|e| io(&file, e))?;
        report.files = 1;
        report.entry_path = Some(file.display().to_string());
        return Ok(report);
    }

    for m in members_of(payload)? {
        let rel = crate::sdkexport::safe_member_path(&m.path).map_err(|source| {
            DocsExportError::Archive {
                name: payload.name.clone(),
                source,
            }
        })?;
        let dest = out.join(&rel);
        match m.body {
            MemberBody::Dir => {
                std::fs::create_dir_all(&dest).map_err(|e| io(&dest, e))?;
                report.dirs += 1;
            }
            MemberBody::File { bytes, .. } => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
                }
                std::fs::write(&dest, &bytes).map_err(|e| io(&dest, e))?;
                report.files += 1;
            }
            // A document is read, never executed, so a symlink inside one buys
            // nothing and can point anywhere. Skipped rather than followed.
            MemberBody::Symlink { .. } => {}
        }
    }
    report.entry_path = payload
        .entry
        .as_deref()
        .map(|e| out.join(e).display().to_string());
    Ok(report)
}

/// Every member of a tree payload, wrapped with the payload's name so a
/// failure says which document could not be opened.
pub fn members_of(payload: &DocsPayload) -> Result<Vec<Member>, DocsExportError> {
    read_members(&payload.bytes).map_err(|source| DocsExportError::Archive {
        name: payload.name.clone(),
        source,
    })
}

/// Does this member path denote `want`, allowing for a single wrapper
/// directory and a leading `./`?
///
/// Mirrors `layerspec::docs_entry_present`'s rule for one path rather than a
/// whole listing. Kept exact for the same reason: a tail match would let
/// `eu-ai-act/index.html` answer a request for `index.html`, and varve's own
/// traceability bundle carries two such namesakes.
fn rel_path(member: &str, want: &str) -> bool {
    let m = member.trim_start_matches("./");
    m == want
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(name: &str, format: DocsFormat) -> DocsPayload {
        DocsPayload {
            name: name.into(),
            version: "0.1.0".into(),
            format,
            entry: Some("index.html".into()),
            title: None,
            bytes: Vec::new(),
        }
    }

    /// One document and no selector is the common case, and asking the reader
    /// to name what they already pinned is asking twice.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_single_document_needs_no_selector() {
        let one = vec![payload("traceability", DocsFormat::Html)];
        assert_eq!(select(&one, None).expect("selects").name, "traceability");
    }

    /// Several documents and no selector must ASK, not guess. Opening the
    /// wrong document silently is worse than a question.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn several_documents_and_no_selector_refuses_rather_than_guessing() {
        let many = vec![
            payload("traceability", DocsFormat::Html),
            payload("handbook", DocsFormat::Pdf),
        ];
        let e = select(&many, None).expect_err("must refuse");
        assert!(
            matches!(e, DocsExportError::Ambiguous { n: 2, .. }),
            "{e:?}"
        );
        // The message has to carry the handles, or the reader's next step is a
        // guess as well.
        assert!(e.to_string().contains("handbook"), "{e}");
        assert!(e.to_string().contains("traceability"), "{e}");
    }

    /// A wrong name names what IS there — the reader's next action needs the
    /// right handle, and "not found" alone does not supply it.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn an_unknown_name_reports_what_the_layer_does_carry() {
        let one = vec![payload("traceability", DocsFormat::Html)];
        let e = select(&one, Some("handbok")).expect_err("must refuse");
        assert!(e.to_string().contains("traceability"), "{e}");
    }

    /// A namesake in a subdirectory does not answer a request for the root
    /// file. The traceability bundle carries `eu-ai-act/index.html`, so a tail
    /// match would serve the wrong page and report success.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_subdirectory_namesake_is_not_the_root_file() {
        assert!(rel_path("./index.html", "index.html"));
        assert!(!rel_path("./eu-ai-act/index.html", "index.html"));
        assert!(rel_path("./eu-ai-act/index.html", "eu-ai-act/index.html"));
    }

    /// Export writes what the archive holds, and reports where to start.
    /// Built from a real tar.gz rather than a hand-made member list, so the
    /// decompression path is exercised too.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_tree_document_exports_and_names_its_starting_page() {
        use std::io::Write;
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            for (path, body) in [
                ("./index.html", "<h1>root</h1>"),
                ("./eu-ai-act/index.html", "<h1>not the root</h1>"),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, body.as_bytes())
                    .expect("append");
            }
            b.finish().expect("finish");
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).expect("compress");
        let bytes = gz.finish().expect("finish gz");

        let doc = DocsPayload {
            name: "traceability".into(),
            version: "0.34.3".into(),
            format: DocsFormat::Html,
            entry: Some("index.html".into()),
            title: None,
            bytes,
        };

        let dir = std::env::temp_dir().join(format!("varve-docs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let report = export(&doc, &dir).expect("exports");

        assert_eq!(report.files, 2);
        let entry = report.entry_path.expect("names an entry");
        assert!(entry.ends_with("index.html"), "{entry}");
        assert_eq!(
            std::fs::read_to_string(&entry).expect("entry exists on disk"),
            "<h1>root</h1>",
            "the entry must be the ROOT page, not the namesake one directory down"
        );

        // And the no-copy read path agrees with what was written.
        let served = read_one(&doc, "index.html")
            .expect("reads")
            .expect("present");
        assert_eq!(served, b"<h1>root</h1>");
        assert_eq!(
            read_one(&doc, "nope.html").expect("reads"),
            None,
            "a missing page is None, not an error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single-file document has nothing inside to address, and that is a
    /// different fact from a missing page.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_single_file_document_has_no_inner_paths() {
        let pdf = payload("handbook", DocsFormat::Pdf);
        assert_eq!(read_one(&pdf, "index.html").expect("no error"), None);
    }
}
