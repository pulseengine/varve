//! Tree-shaped payload export and relocation (REQ-SDK-001).
//!
//! A `sdk` payload is a TREE — a Yocto SDK is thousands of files — and it is
//! the first payload varve cannot simply hand over verbatim. Yocto's installer
//! runs `relocate_sdk.py`, which opens each file `"r+b"` and byte-patches in
//! place: the `PT_INTERP` dynamic-loader path, the loader's own SYSDIRS string
//! table and its parallel length array, and the `ld.so.cache` path. The wrapper
//! `toolchain-shar-relocate.sh` additionally `sed -i`s every text file and
//! re-points every symlink. After installation the bytes no longer hash to the
//! signed digest.
//!
//! # Why the store keeps the archive and the tree lives in the export
//!
//! Relocation is bounded, and the bound is read from the script rather than
//! assumed:
//!
//! ```text
//! if (len(new_dl_path) >= p_filesz):
//!     print("ERROR: could not relocate %s, interp size = %i and %i is needed.")
//!     return False
//! ```
//!
//! The new interpreter path must FIT the old one's field, so an SDK can only
//! ever move to a path NO LONGER than the one it was built with. varve's store
//! path is ~90 characters before any content
//! (`…/realms/<16hex>/core/sha256-<64hex>/…`), so relocating INTO the store
//! would frequently be impossible. That is one of two reasons the design is
//! pristine-store-plus-relocated-export rather than in-place; the other is
//! clause 2 — `verify` and `archive` hash ONE file against ONE signed digest,
//! so the store must keep exactly the bytes the producer signed. varve
//! therefore verifies only what was signed, never what relocation produced,
//! and nothing here ever writes back into the store.
//!
//! # What this module owes the caller
//!
//! The tree is materialised HERE, from an archive whose member names come out
//! of a signed blob. Signed means attributable, not benign: a tree has far more
//! path components than a single payload name, and a symlink inside one can
//! escape the export even when every component looks safe (the Cargo
//! CVE-2026-5223 class — link out, then write through it). So every
//! destination is resolved and validated BEFORE a byte is written, exactly as
//! `Store::lay_down_payloads` does, and a tree that cannot be laid out whole is
//! not laid out at all.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

/// The signed annotation naming the absolute path an SDK was BUILT for.
///
/// It is the producer's declaration, carried in the layer manifest and covered
/// by the DSSE signature, because the relocation budget is derived from it: a
/// destination longer than this prefix cannot be patched into the interpreter
/// fields, and a consumer must not be able to talk varve into trying.
pub const ANN_SDK_PREFIX: &str = "eu.pulseengine.varve.sdk.prefix";

/// What one archive member is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberBody {
    Dir,
    File { mode: u32, bytes: Vec<u8> },
    Symlink { target: String },
}

/// One validated member of a tree payload, with its path relative to the export
/// root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub path: String,
    pub body: MemberBody,
}

/// What an export actually did — reported rather than assumed, because
/// "relocated 0 fields" and "relocated 40 000 fields" look identical on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdkExportReport {
    pub dirs: usize,
    pub files: usize,
    pub symlinks: usize,
    /// NUL-padded path fields patched in place in binaries (the `relocate_sdk.py`
    /// half — total file length preserved).
    pub patched_fields: usize,
    /// Path occurrences substituted in text files (the `sed -i` half).
    pub substitutions: usize,
    /// Symlinks whose absolute target was re-pointed into the export.
    pub relocated_symlinks: usize,
}

/// Why a tree payload could not be exported or relocated.
#[derive(Debug, thiserror::Error)]
pub enum SdkExportError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the sdk payload is not a readable tar archive: {0}")]
    Archive(String),
    #[error(
        "the sdk declares no build-time prefix ({ANN_SDK_PREFIX}) — without it there is no \
         relocation budget and no path to patch; re-deposit the sdk with the prefix it was \
         built for"
    )]
    NoBuiltPrefix,
    #[error(
        "the export destination must be an absolute path, got {0:?} — the destination is \
         PATCHED INTO the SDK's binaries, and a relative path there would resolve against \
         whatever directory the compiler happens to run in"
    )]
    DestinationNotAbsolute(String),
    #[error(
        "cannot relocate this sdk to {dest}: the destination is {dest_len} characters and the \
         sdk was built for {built_prefix} ({budget}). An SDK's interpreter path is patched IN \
         PLACE into a fixed-size field, so it can only ever move to a path NO LONGER than the \
         one it was built with. Choose a destination of at most {budget} characters."
    )]
    DestinationTooLong {
        dest: String,
        dest_len: usize,
        built_prefix: String,
        budget: usize,
    },
    #[error(
        "{member}: the path field at offset {offset} needs {needed} bytes but the field holds \
         {capacity} — this is `relocate_sdk.py`'s own limit (len(new) >= field size), reached \
         after the destination-length check passed, so the sdk's fields are tighter than its \
         build prefix implies"
    )]
    FieldTooSmall {
        member: String,
        offset: usize,
        needed: usize,
        capacity: usize,
    },
    #[error("sdk member {member:?} is not a usable path ({why}) — refusing to lay the tree down")]
    UnsafeMember { member: String, why: String },
    #[error(
        "two members of this sdk both land on {path} — one would overwrite the other, and the \
         survivor would carry the wrong bytes under the right name"
    )]
    Collision { path: String },
    #[error(
        "sdk member {member:?} would be written THROUGH the symlink {link:?} — a link out of \
         the export followed by a write through it places bytes anywhere on the filesystem"
    )]
    WriteThroughSymlink { member: String, link: String },
    #[error(
        "sdk symlink {member:?} points at {target:?}, which is outside both the sdk and the \
         export — a relocated SDK is self-contained, and a link to the host is neither \
         verified nor reproducible"
    )]
    SymlinkEscapes { member: String, target: String },
    #[error("this platform cannot create the symlink {member:?} an sdk tree requires")]
    SymlinksUnsupported { member: String },
}

/// Trim a trailing `/` so `/opt/poky` and `/opt/poky/` mean one prefix and
/// budget the same number of characters.
fn normalise_prefix(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() { p } else { t }
}

/// The relocation fit check (clause 4), as a pure function so it can be run
/// EARLY — before the archive is even opened, let alone thousands of files
/// written.
///
/// Every patched field holds `<prefix><suffix>`; relocation replaces only the
/// prefix, so the new string fits every field it came from exactly when the new
/// prefix is no longer than the built one. That single comparison is therefore
/// complete for the whole tree — which is what makes the early refusal possible
/// rather than a guess that has to be re-checked file by file.
pub fn check_destination_fits(built_prefix: &str, dest: &str) -> Result<(), SdkExportError> {
    let built = normalise_prefix(built_prefix);
    if built.is_empty() {
        return Err(SdkExportError::NoBuiltPrefix);
    }
    if !dest.starts_with('/') {
        return Err(SdkExportError::DestinationNotAbsolute(dest.to_string()));
    }
    let dest_n = normalise_prefix(dest);
    if dest_n.len() > built.len() {
        return Err(SdkExportError::DestinationTooLong {
            dest: dest_n.to_string(),
            dest_len: dest_n.len(),
            built_prefix: built.to_string(),
            budget: built.len(),
        });
    }
    Ok(())
}

/// First occurrence of `needle` in `haystack`, by bytes.
fn find_sub(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// What relocating one member's bytes produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub bytes: Vec<u8>,
    /// In-place NUL-padded fields patched (binary, length preserved).
    pub fields: usize,
    /// Text occurrences substituted (length may change).
    pub substitutions: usize,
}

/// Does this payload look like a binary? The same test
/// `toolchain-shar-relocate.sh` makes with `grep -qIl`: a NUL byte anywhere.
/// A binary is patched IN PLACE inside its fixed-size fields; a text file is
/// rewritten freely, which is what lets `environment-setup-*` grow or shrink.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// Rewrite every occurrence of the SDK's build-time prefix in one member.
///
/// Binaries are patched the way `relocate_sdk.py` does: the C string containing
/// the occurrence is rewritten IN PLACE and re-padded with NULs to its original
/// field width, so the file's length and every offset in it are preserved. A
/// string that would no longer fit is refused rather than truncated — a
/// truncated interpreter path is a binary that fails to exec with no
/// explanation.
pub fn relocate_bytes(
    member: &str,
    bytes: &[u8],
    built_prefix: &str,
    dest_prefix: &str,
) -> Result<Relocation, SdkExportError> {
    let built = normalise_prefix(built_prefix).as_bytes();
    let dest = normalise_prefix(dest_prefix).as_bytes();

    if !is_binary(bytes) {
        // The `sed -i` half: no field to overflow, so the text may change length.
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut substitutions = 0;
        while let Some(hit) = find_sub(bytes, built, i) {
            out.extend_from_slice(&bytes[i..hit]);
            out.extend_from_slice(dest);
            i = hit + built.len();
            substitutions += 1;
        }
        out.extend_from_slice(&bytes[i..]);
        return Ok(Relocation {
            bytes: out,
            fields: 0,
            substitutions,
        });
    }

    let mut out = bytes.to_vec();
    let mut fields = 0;
    let mut cursor = 0;
    while let Some(hit) = find_sub(&out, built, cursor) {
        // The C string the occurrence belongs to: from just past the previous
        // NUL to the next one. `LD_LIBRARY_PATH=/opt/poky/…` is one string, and
        // patching from the occurrence rather than the string start would leave
        // the padding computation wrong.
        let start = out[..hit]
            .iter()
            .rposition(|b| *b == 0)
            .map(|p| p + 1)
            .unwrap_or(0);
        let Some(end) = out[hit..].iter().position(|b| *b == 0).map(|p| hit + p) else {
            // No terminator before end of file — not a field we can pad.
            cursor = hit + built.len();
            continue;
        };
        // Capacity is the string PLUS its NUL padding: exactly the `p_filesz`
        // the script compares against.
        let mut pad_end = end;
        while pad_end < out.len() && out[pad_end] == 0 {
            pad_end += 1;
        }
        let capacity = pad_end - start;

        // Replace every occurrence of the prefix WITHIN this one string.
        let old = out[start..end].to_vec();
        let mut new = Vec::with_capacity(old.len());
        let mut i = 0;
        while let Some(h) = find_sub(&old, built, i) {
            new.extend_from_slice(&old[i..h]);
            new.extend_from_slice(dest);
            i = h + built.len();
        }
        new.extend_from_slice(&old[i..]);

        // `if len(new_dl_path) >= p_filesz: ERROR` — transcribed, not
        // paraphrased. The destination check has already made this
        // unreachable for a well-formed SDK; it stays because the field is
        // where truncation would actually happen, and a silent truncation here
        // produces a binary that cannot exec with nothing to point at.
        if new.len() >= capacity {
            return Err(SdkExportError::FieldTooSmall {
                member: member.to_string(),
                offset: start,
                needed: new.len() + 1,
                capacity,
            });
        }
        out[start..start + new.len()].copy_from_slice(&new);
        for b in &mut out[start + new.len()..pad_end] {
            *b = 0;
        }
        fields += 1;
        cursor = pad_end;
    }
    Ok(Relocation {
        bytes: out,
        fields,
        substitutions: 0,
    })
}

/// Refuse a path component that is not a single, safe name — the same rule
/// `Store::lay_down_payloads` applies to a payload name, applied to EVERY
/// component of every member of the tree, because a tree has thousands of them
/// and one is enough to escape.
fn component_fault(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("an empty path component".into());
    }
    if value == "." || value == ".." {
        return Some("a relative path element".into());
    }
    if let Some(c) = value
        .chars()
        .find(|c| matches!(c, '/' | '\\' | '\0') || c.is_control())
    {
        return Some(format!("contains {c:?}"));
    }
    None
}

/// Validate a member path and return it normalised (no trailing slash).
fn safe_member_path(raw: &str) -> Result<String, SdkExportError> {
    let unsafe_member = |why: &str| SdkExportError::UnsafeMember {
        member: raw.to_string(),
        why: why.to_string(),
    };
    if raw.starts_with('/') {
        return Err(unsafe_member(
            "absolute — it would place bytes outside the export",
        ));
    }
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(unsafe_member("empty"));
    }
    for component in trimmed.split('/') {
        if let Some(why) = component_fault(component) {
            return Err(unsafe_member(&why));
        }
    }
    Ok(trimmed.to_string())
}

/// Decompress a gzip archive, or pass a plain tar through. An SDK ships as
/// either, and guessing from the file name would be one more thing to get
/// wrong.
fn decompress(archive: &[u8]) -> Result<Cow<'_, [u8]>, SdkExportError> {
    if archive.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(archive)
            .read_to_end(&mut out)
            .map_err(|e| SdkExportError::Archive(e.to_string()))?;
        Ok(Cow::Owned(out))
    } else {
        Ok(Cow::Borrowed(archive))
    }
}

/// Read every member of a tree payload out of its archive.
///
/// Paths are carried through VERBATIM and judged in `export_members`, which is
/// the only thing that writes. Validating in both places would look safer and
/// be worse: two copies of one rule drift, and a defect in either is masked by
/// the other, so neither can be shown to matter.
pub fn read_members(archive: &[u8]) -> Result<Vec<Member>, SdkExportError> {
    let raw = decompress(archive)?;
    let mut tar = tar::Archive::new(raw.as_ref());
    let entries = tar
        .entries()
        .map_err(|e| SdkExportError::Archive(e.to_string()))?;
    let mut members = Vec::new();
    for entry in entries {
        let mut entry = entry.map_err(|e| SdkExportError::Archive(e.to_string()))?;
        let raw_path = entry
            .path()
            .map_err(|e| SdkExportError::Archive(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        let header = entry.header().clone();
        let body = match header.entry_type() {
            tar::EntryType::Directory => MemberBody::Dir,
            // A hard link is treated as a symlink: varve is materialising a
            // fresh tree, and a link that must stay inside the export is the
            // same question either way.
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| SdkExportError::Archive(e.to_string()))?
                    .map(|t| t.to_string_lossy().into_owned())
                    .unwrap_or_default();
                MemberBody::Symlink { target }
            }
            _ => {
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|e| SdkExportError::Archive(e.to_string()))?;
                let mode = header.mode().unwrap_or(0o644);
                MemberBody::File { mode, bytes }
            }
        };
        members.push(Member {
            path: raw_path,
            body,
        });
    }
    Ok(members)
}

/// Where a symlink target lands, and whether it stays inside the export.
///
/// Three cases, and each has to be decided rather than defaulted:
///   * absolute and under the SDK's build prefix — an SDK's own internal
///     absolute link, re-pointed into the export;
///   * absolute and anywhere else — a link to the HOST, refused: a relocated
///     SDK is self-contained, and a link varve did not verify is not part of
///     what the trust root anchored;
///   * relative — resolved lexically against the link's own directory and
///     refused if it climbs out of the export root.
fn resolve_link_target(
    member: &str,
    target: &str,
    built_prefix: &str,
    dest_prefix: &str,
) -> Result<(String, bool), SdkExportError> {
    let escapes = || SdkExportError::SymlinkEscapes {
        member: member.to_string(),
        target: target.to_string(),
    };
    if target.is_empty() {
        return Err(escapes());
    }
    if target.starts_with('/') {
        let built = normalise_prefix(built_prefix);
        let dest = normalise_prefix(dest_prefix);
        if target == built {
            return Ok((dest.to_string(), true));
        }
        if let Some(rest) = target.strip_prefix(&format!("{built}/")) {
            return Ok((format!("{dest}/{rest}"), true));
        }
        return Err(escapes());
    }
    // Relative: walk it against the link's own directory, lexically. `..` past
    // the export root is the escape; `..` within it is ordinary and common.
    let mut stack: Vec<&str> = member.split('/').collect();
    stack.pop(); // the link itself
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(escapes());
                }
            }
            other => stack.push(other),
        }
    }
    Ok((target.to_string(), false))
}

/// Lay a verified tree payload out under `out`, relocated from its build-time
/// prefix to `out` (clause 3).
///
/// `out` must be ABSOLUTE: the destination is patched into the SDK's binaries,
/// so a relative one would resolve against whatever directory a compiler
/// happens to run in. Every destination is validated and resolved before any
/// byte is written, so a tree that cannot be laid out whole is not laid out at
/// all.
///
/// This never touches the store. The signed archive stays exactly as the
/// producer signed it, which is what `verify` and `archive` re-hash; the
/// relocated tree is a DERIVED artifact, deliberately outside the trust path
/// (clause 2).
pub fn export_sdk(
    archive: &[u8],
    built_prefix: &str,
    out: &Path,
) -> Result<SdkExportReport, SdkExportError> {
    let dest = out.to_string_lossy().into_owned();
    // FIRST, and before the archive is even decompressed: an SDK that cannot
    // reach this destination must be refused now, not after thousands of files
    // have been written and patched (clause 4).
    check_destination_fits(built_prefix, &dest)?;
    let members = read_members(archive)?;
    export_members(&members, built_prefix, out)
}

/// The write half, split out so a tree can be laid down from members obtained
/// any way — and so the plan-then-write discipline is testable without a tar.
pub fn export_members(
    members: &[Member],
    built_prefix: &str,
    out: &Path,
) -> Result<SdkExportReport, SdkExportError> {
    let dest = out.to_string_lossy().into_owned();
    check_destination_fits(built_prefix, &dest)?;

    // ---- plan: resolve and validate EVERY destination before writing ----
    let mut placed: BTreeSet<String> = BTreeSet::new();
    let mut links: BTreeSet<String> = BTreeSet::new();
    let mut planned: Vec<(String, &Member)> = Vec::with_capacity(members.len());
    for m in members {
        let path = safe_member_path(&m.path)?;
        if !placed.insert(path.clone()) {
            return Err(SdkExportError::Collision { path });
        }
        if let MemberBody::Symlink { .. } = m.body {
            links.insert(path.clone());
        }
        planned.push((path, m));
    }
    // A symlink out of the tree followed by a write THROUGH it places bytes
    // anywhere on the filesystem, and every component of the offending member
    // still looks perfectly safe on its own. Refuse the pair, not the shape.
    for (path, _) in &planned {
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if prefix.len() < path.len() && links.contains(&prefix) {
                return Err(SdkExportError::WriteThroughSymlink {
                    member: path.clone(),
                    link: prefix,
                });
            }
        }
    }
    // Link targets, resolved and refused before anything exists on disk.
    let mut resolved_links: Vec<(&str, String, bool)> = Vec::new();
    for (path, m) in &planned {
        if let MemberBody::Symlink { target } = &m.body {
            let (t, relocated) = resolve_link_target(path, target, built_prefix, &dest)?;
            resolved_links.push((path, t, relocated));
        }
    }
    // Relocate every file's bytes before creating the export directory: a
    // field that will not fit must leave the destination untouched.
    let mut relocated_files: Vec<(&str, Relocation, u32)> = Vec::new();
    for (path, m) in &planned {
        if let MemberBody::File { mode, bytes } = &m.body {
            let r = relocate_bytes(path, bytes, built_prefix, &dest)?;
            relocated_files.push((path, r, *mode));
        }
    }

    // ---- write ----
    let io = |path: &Path, source: std::io::Error| SdkExportError::Io {
        path: path.display().to_string(),
        source,
    };
    let mut report = SdkExportReport::default();
    std::fs::create_dir_all(out).map_err(|e| io(out, e))?;
    for (rel, m) in &planned {
        if matches!(m.body, MemberBody::Dir) {
            let path = out.join(rel);
            std::fs::create_dir_all(&path).map_err(|e| io(&path, e))?;
            report.dirs += 1;
        }
    }
    for (rel, relocation, mode) in &relocated_files {
        let path = out.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        std::fs::write(&path, &relocation.bytes).map_err(|e| io(&path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o7777))
                .map_err(|e| io(&path, e))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        report.files += 1;
        report.patched_fields += relocation.fields;
        report.substitutions += relocation.substitutions;
    }
    for (rel, target, relocated) in &resolved_links {
        let path = out.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &path).map_err(|e| io(&path, e))?;
        #[cfg(not(unix))]
        {
            let _ = target;
            return Err(SdkExportError::SymlinksUnsupported {
                member: (*rel).to_string(),
            });
        }
        report.symlinks += 1;
        if *relocated {
            report.relocated_symlinks += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The absolute path this synthetic SDK was BUILT for.
    ///
    /// Deliberately long, and that is not cosmetic: a real Yocto SDK is built
    /// for a long default installation directory PRECISELY so it can be
    /// relocated afterwards, since relocation can only ever shorten a path. The
    /// tests' own temporary directory has to fit inside that budget, which is
    /// the same arithmetic a real user does.
    const BUILT: &str = "/opt/poky/4.0.15/x86_64-pokysdk-linux/default-installation-directory-padded-so-a-temporary-directory-fits-inside-the-relocation-budget-which-can-only-ever-shrink-a-path-never-grow-it";

    /// The slack a real `PT_INTERP` field carries past its terminator.
    const SLACK: usize = 8;

    /// A NUL-padded path field, the way an ELF `PT_INTERP` segment holds one:
    /// the string, its terminator, and slack up to the field width.
    fn nul_field(s: &str, width: usize) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.resize(width, 0);
        v
    }

    /// A path field sized as an SDK's own build produced it.
    fn field(s: &str) -> Vec<u8> {
        nul_field(s, s.len() + SLACK)
    }

    fn interp() -> String {
        format!("{BUILT}/sysroots/x86_64/lib/ld-linux.so.2")
    }

    fn fake_binary() -> Vec<u8> {
        let mut v = b"\x7fELF".to_vec();
        v.extend_from_slice(&field(&interp()));
        v.extend_from_slice(&field(&format!("{BUILT}/sysroots/x86_64/usr/lib")));
        v.extend_from_slice(b"\0\0trailer\0");
        v
    }

    fn env_setup() -> Vec<u8> {
        format!(
            "export SDKTARGETSYSROOT={BUILT}/sysroots/aarch64\n\
             export PATH={BUILT}/sysroots/x86_64/usr/bin:$PATH\n\
             export CC=\"aarch64-poky-linux-gcc --sysroot={BUILT}/sysroots/aarch64\"\n"
        )
        .into_bytes()
    }

    fn synthetic_sdk() -> Vec<Member> {
        vec![
            Member {
                path: "sysroots".into(),
                body: MemberBody::Dir,
            },
            Member {
                path: "sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc".into(),
                body: MemberBody::File {
                    mode: 0o755,
                    bytes: fake_binary(),
                },
            },
            Member {
                path: "environment-setup-aarch64-poky-linux".into(),
                body: MemberBody::File {
                    mode: 0o644,
                    bytes: env_setup(),
                },
            },
            Member {
                path: "sysroots/x86_64/usr/bin/cc".into(),
                body: MemberBody::Symlink {
                    target: format!("{BUILT}/sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc"),
                },
            },
        ]
    }

    /// An export root of a chosen length, so the fit check is exercised against
    /// a REAL path rather than a string that only looks like one.
    fn out_of_len(base: &Path, len: usize) -> PathBuf {
        let base_s = base.to_string_lossy().into_owned();
        assert!(base_s.len() < len, "tempdir already longer than {len}");
        let pad = len - base_s.len() - 1;
        base.join("d".repeat(pad))
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_destination_longer_than_the_build_prefix_is_refused_before_anything_is_written() {
        // Clause 4, and the constraint the whole design turns on:
        //   if (len(new_dl_path) >= p_filesz): ERROR
        // The interpreter path is patched IN PLACE into a fixed-size field, so
        // an SDK can only ever move to a path no longer than the one it was
        // built with. Refusing here — before the archive is even opened — is
        // the difference between a one-line error and thousands of files
        // written and then abandoned.
        let tmp = tempfile::tempdir().unwrap();
        let too_long = out_of_len(tmp.path(), BUILT.len() + 1);
        let err = export_members(&synthetic_sdk(), BUILT, &too_long).unwrap_err();
        match &err {
            SdkExportError::DestinationTooLong {
                dest_len, budget, ..
            } => {
                assert_eq!(*dest_len, BUILT.len() + 1);
                assert_eq!(*budget, BUILT.len());
            }
            other => panic!("expected DestinationTooLong, got {other}"),
        }
        // Refused BY NAME: the message must carry the destination, the budget,
        // and why — an operator whose export directory is one character too
        // long has to be able to fix it without reading relocate_sdk.py.
        let msg = err.to_string();
        assert!(msg.contains(&too_long.display().to_string()), "{msg}");
        assert!(
            msg.contains(BUILT),
            "names the prefix it was built for: {msg}"
        );
        assert!(msg.contains("NO LONGER"), "states the rule: {msg}");
        // And nothing was written: not one file, not the directory itself.
        assert!(!too_long.exists(), "a refused export must write nothing");

        // Exactly at the budget is allowed — the constraint is `no longer`, and
        // an off-by-one here would refuse a legitimate destination.
        let exact = out_of_len(tmp.path(), BUILT.len());
        assert!(check_destination_fits(BUILT, &exact.to_string_lossy()).is_ok());
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_relative_or_prefixless_destination_is_refused() {
        // The destination is PATCHED INTO the binaries. A relative one would
        // resolve against whatever directory the compiler happens to run in.
        assert!(matches!(
            check_destination_fits(BUILT, "toolchains/poky"),
            Err(SdkExportError::DestinationNotAbsolute(_))
        ));
        // …and an SDK with no declared build prefix has no budget at all,
        // which is a different fault with a different fix.
        assert!(matches!(
            check_destination_fits("", "/opt/x"),
            Err(SdkExportError::NoBuiltPrefix)
        ));
        assert!(matches!(
            check_destination_fits("/", "/opt/x"),
            Err(SdkExportError::DestinationTooLong { .. })
        ));
        // A trailing slash is the same prefix, not a longer one.
        assert!(check_destination_fits("/opt/poky", "/opt/abcd/").is_ok());
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_nul_padded_field_is_patched_in_place_and_the_file_length_is_preserved() {
        // The heart of relocate_sdk.py: the field is opened "r+b" and written
        // over, so every offset in the binary stays valid. A rewrite that
        // changed the length would relocate the SDK and corrupt the ELF.
        let original = fake_binary();
        let r = relocate_bytes("gcc", &original, BUILT, "/opt/sdk").unwrap();
        assert_eq!(
            r.bytes.len(),
            original.len(),
            "an in-place patch must not change the file's length"
        );
        assert_eq!(r.fields, 2, "both path fields patched");
        assert_eq!(r.substitutions, 0, "a binary is patched, never sed'ed");

        // The new path is there, NUL-terminated, and the old one is gone.
        let text = String::from_utf8_lossy(&r.bytes).into_owned();
        assert!(text.contains("/opt/sdk/sysroots/x86_64/lib/ld-linux.so.2"));
        assert!(
            !text.contains(BUILT),
            "the build-time prefix must not survive relocation: {text:?}"
        );
        // The slack really is NUL, not leftover bytes of the old path — a
        // truncating rewrite leaves the tail of the old path behind and execs
        // something that does not exist.
        let width = interp().len() + SLACK;
        let patched = &r.bytes[4..4 + width];
        let end = patched.iter().position(|b| *b == 0).unwrap();
        assert_eq!(
            &patched[..end],
            b"/opt/sdk/sysroots/x86_64/lib/ld-linux.so.2"
        );
        assert!(
            patched[end..].iter().all(|b| *b == 0),
            "the field must be re-padded with NUL"
        );
        // The trailer past the fields is untouched.
        assert!(r.bytes.ends_with(b"trailer\0"));
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_field_too_small_for_the_new_path_is_refused_rather_than_truncated() {
        // The script's own guard, transcribed: `len(new) >= p_filesz` fails.
        // A truncated interpreter path is a binary that cannot exec with
        // nothing at all to point at, so this must never silently succeed.
        // Field width 20 holds "/opt/a/ld.so" plus padding; "/opt/aaaaaaaaaa"
        // is longer than the prefix but the destination check is bypassed here
        // to reach the field guard directly.
        let bytes = nul_field("/opt/a/ld.so", 14);
        // 13 characters of path + terminator == 14: the last width that fits.
        let ok = relocate_bytes("x", &bytes, "/opt/a", "/opt/ab").unwrap();
        assert_eq!(ok.fields, 1);
        assert_eq!(ok.bytes.len(), bytes.len());
        // One more character and it does not.
        let err = relocate_bytes("libc.so", &bytes, "/opt/a", "/opt/abc").unwrap_err();
        match err {
            SdkExportError::FieldTooSmall {
                member,
                needed,
                capacity,
                ..
            } => {
                assert_eq!(member, "libc.so", "the refusal must name the FILE");
                assert_eq!(capacity, 14);
                assert_eq!(needed, 15);
            }
            other => panic!("expected FieldTooSmall, got {other}"),
        }
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_text_file_is_substituted_and_may_change_length() {
        // `toolchain-shar-relocate.sh` seds every text file, and
        // `environment-setup-*` is the one that matters: it is SOURCED, and a
        // stale SYSROOT in it silently builds against the wrong headers.
        let original = env_setup();
        let r = relocate_bytes("environment-setup", &original, BUILT, "/opt/sdk").unwrap();
        assert_eq!(r.fields, 0, "a text file has no fixed-size field");
        assert_eq!(r.substitutions, 3, "every occurrence, not just the first");
        let text = String::from_utf8(r.bytes).unwrap();
        assert!(text.contains("export SDKTARGETSYSROOT=/opt/sdk/sysroots/aarch64"));
        assert!(text.contains("--sysroot=/opt/sdk/sysroots/aarch64"));
        assert!(!text.contains(BUILT));
        assert!(
            text.len() < original.len(),
            "a text rewrite is free to change length"
        );
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn the_whole_synthetic_tree_lands_relocated_and_the_source_bytes_are_untouched() {
        // Clause 3 end to end, and clause 2 alongside it: what the producer
        // signed is not what the export contains, and varve never records a
        // post-relocation digest — the relocator stays outside the trust path.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("sdk");
        let members = synthetic_sdk();
        let signed_binary = fake_binary();

        let report = export_members(&members, BUILT, &out).unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.symlinks, 1);
        assert_eq!(report.relocated_symlinks, 1);
        assert_eq!(report.patched_fields, 2);
        assert_eq!(report.substitutions, 3);

        let gcc = out.join("sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc");
        let on_disk = std::fs::read(&gcc).unwrap();
        assert_eq!(on_disk.len(), signed_binary.len(), "in-place patch");
        assert_ne!(
            on_disk, signed_binary,
            "the relocated bytes are NOT the signed bytes — which is exactly why \
             the store keeps the archive and verify never hashes the export"
        );
        assert!(!String::from_utf8_lossy(&on_disk).contains(BUILT));

        // The internal absolute symlink now points inside the export.
        #[cfg(unix)]
        {
            let link = out.join("sysroots/x86_64/usr/bin/cc");
            let target = std::fs::read_link(&link).unwrap();
            assert_eq!(target, gcc, "an SDK-internal link follows the SDK");
        }
        // The directory member is a directory.
        assert!(out.join("sysroots").is_dir());
        // And the members handed in are untouched: nothing wrote back.
        assert_eq!(members, synthetic_sdk());
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_member_whose_path_escapes_the_export_is_refused_and_nothing_is_written() {
        // Every component of every member gets the treatment a single payload
        // name gets in the store. A tree has thousands, and one is enough.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("sdk");
        for bad in [
            "../../evil",
            "/etc/passwd",
            "a/../../evil",
            "a//b",
            "a/./b",
            "",
            "..",
        ] {
            let members = vec![
                Member {
                    path: "good".into(),
                    body: MemberBody::File {
                        mode: 0o644,
                        bytes: b"good".to_vec(),
                    },
                },
                Member {
                    path: bad.into(),
                    body: MemberBody::File {
                        mode: 0o644,
                        bytes: b"evil".to_vec(),
                    },
                },
            ];
            let err = export_members(&members, BUILT, &out).unwrap_err();
            assert!(
                matches!(err, SdkExportError::UnsafeMember { .. }),
                "member {bad:?} must be refused, got {err}"
            );
            // A partially written tree must not be possible: the good member
            // did not land either.
            assert!(
                !out.join("good").exists(),
                "member {bad:?}: the tree must be refused whole"
            );
        }
        // …and safe paths that merely look unusual still work.
        assert!(safe_member_path("a/b/c").is_ok());
        assert!(safe_member_path("a/b/").is_ok());
        assert_eq!(safe_member_path("a/b/").unwrap(), "a/b");
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_symlink_that_leaves_the_export_is_refused_even_though_every_component_is_safe() {
        // The escape a per-component check cannot see. `link` is a fine name
        // and `link/pwned` is a fine path; the escape is the LINK's target.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("sdk");
        let outside = tmp.path().join("OUTSIDE");
        std::fs::create_dir_all(&outside).unwrap();

        // 1. an absolute link to the host, under no prefix varve relocates.
        let err = export_members(
            &[Member {
                path: "bin/link".into(),
                body: MemberBody::Symlink {
                    target: outside.to_string_lossy().into_owned(),
                },
            }],
            BUILT,
            &out,
        )
        .unwrap_err();
        assert!(
            matches!(err, SdkExportError::SymlinkEscapes { .. }),
            "got {err}"
        );

        // 2. a relative link that climbs out of the export root.
        let err = export_members(
            &[Member {
                path: "bin/link".into(),
                body: MemberBody::Symlink {
                    target: "../../OUTSIDE".into(),
                },
            }],
            BUILT,
            &out,
        )
        .unwrap_err();
        assert!(
            matches!(err, SdkExportError::SymlinkEscapes { .. }),
            "got {err}"
        );

        // 3. …and the pair that is the actual CVE class: a link out, then a
        //    write THROUGH it. Refused as a pair — neither member is unsafe on
        //    its own, and the tar order does not decide it.
        let err = export_members(
            &[
                Member {
                    path: "bin/link".into(),
                    body: MemberBody::Symlink {
                        target: "../lib".into(),
                    },
                },
                Member {
                    path: "bin/link/pwned".into(),
                    body: MemberBody::File {
                        mode: 0o644,
                        bytes: b"PWNED".to_vec(),
                    },
                },
            ],
            BUILT,
            &out,
        )
        .unwrap_err();
        assert!(
            matches!(err, SdkExportError::WriteThroughSymlink { .. }),
            "got {err}"
        );

        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing may be written outside the export"
        );
        assert!(!out.join("bin/link").exists(), "nothing written at all");

        // A relative link INSIDE the tree is ordinary and must still work.
        let ok = export_members(
            &[
                Member {
                    path: "lib/libc.so.6".into(),
                    body: MemberBody::File {
                        mode: 0o644,
                        bytes: b"libc".to_vec(),
                    },
                },
                Member {
                    path: "bin/libc".into(),
                    body: MemberBody::Symlink {
                        target: "../lib/libc.so.6".into(),
                    },
                },
            ],
            BUILT,
            &out,
        )
        .unwrap();
        assert_eq!(ok.symlinks, 1);
        assert_eq!(
            ok.relocated_symlinks, 0,
            "a relative link needs no patching"
        );
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn two_members_claiming_one_path_are_refused_before_anything_is_written() {
        // The same invariant `Store::lay_down_payloads` holds, for a tree: the
        // survivor of a silent overwrite carries the wrong bytes under the
        // right name, and nothing downstream can tell.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("sdk");
        let err = export_members(
            &[
                Member {
                    path: "bin/gcc".into(),
                    body: MemberBody::File {
                        mode: 0o755,
                        bytes: b"first".to_vec(),
                    },
                },
                Member {
                    path: "bin/gcc".into(),
                    body: MemberBody::File {
                        mode: 0o755,
                        bytes: b"second".to_vec(),
                    },
                },
            ],
            BUILT,
            &out,
        )
        .unwrap_err();
        assert!(matches!(err, SdkExportError::Collision { .. }), "got {err}");
        assert!(!out.join("bin/gcc").exists());
    }

    /// The synthetic SDK as a gzip tar, the shape a producer actually signs.
    fn synthetic_tarball() -> Vec<u8> {
        use std::io::Write;
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut dir = tar::Header::new_gnu();
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_size(0);
            dir.set_mode(0o755);
            b.append_data(&mut dir, "sysroots/", std::io::empty())
                .unwrap();

            let bin = fake_binary();
            let mut f = tar::Header::new_gnu();
            f.set_size(bin.len() as u64);
            f.set_mode(0o755);
            b.append_data(
                &mut f,
                "sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc",
                bin.as_slice(),
            )
            .unwrap();

            let env = env_setup();
            let mut t = tar::Header::new_gnu();
            t.set_size(env.len() as u64);
            t.set_mode(0o644);
            b.append_data(
                &mut t,
                "environment-setup-aarch64-poky-linux",
                env.as_slice(),
            )
            .unwrap();

            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            b.append_link(
                &mut link,
                "sysroots/x86_64/usr/bin/cc",
                format!("{BUILT}/sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc"),
            )
            .unwrap();
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn a_signed_archive_unpacks_and_relocates_and_the_archive_is_never_modified() {
        // Clause 1 and 2 together, on the bytes a producer signs: the store
        // holds ONE blob with ONE digest — which is what makes an sdk payload
        // hold like any other, and what lets `verify` and `archive` keep
        // hashing a single file — and the tree exists only in the export.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("sdk");
        let archive = synthetic_tarball();
        let before = archive.clone();

        let report = export_sdk(&archive, BUILT, &out).unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.symlinks, 1);
        assert_eq!(report.patched_fields, 2);
        assert_eq!(report.substitutions, 3);
        assert_eq!(archive, before, "the signed archive is read-only, always");

        let gcc = out.join("sysroots/x86_64/usr/bin/aarch64-poky-linux-gcc");
        assert!(!String::from_utf8_lossy(&std::fs::read(&gcc).unwrap()).contains(BUILT));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&gcc).unwrap().permissions().mode() & 0o777,
                0o755,
                "a compiler must survive the export executable"
            );
        }
        // A plain (uncompressed) tar is equally acceptable — an SDK ships as
        // either, and guessing from the file name is one more thing to get
        // wrong.
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(archive.as_slice())
            .read_to_end(&mut plain)
            .unwrap();
        let out2 = tmp.path().join("sdk2");
        assert_eq!(export_sdk(&plain, BUILT, &out2).unwrap(), report);
    }

    // rivet: verifies REQ-SDK-001
    #[test]
    fn an_archive_member_that_escapes_is_refused_before_the_tree_is_written() {
        // The tar crate's own `unpack` sanitises; this path does not use it,
        // so the refusal has to be ours and has to be tested as ours.
        use std::io::Write;
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut f = tar::Header::new_gnu();
            let payload = b"PWNED";
            f.set_size(payload.len() as u64);
            f.set_mode(0o644);
            // The name is written into the header DIRECTLY: `set_path` refuses
            // `..` itself, and an archive built by other software is under no
            // obligation to have used it. The refusal has to be varve's.
            {
                let gnu = f.as_gnu_mut().unwrap();
                let name = b"../../escape";
                gnu.name[..name.len()].copy_from_slice(name);
            }
            f.set_cksum();
            b.append(&f, &payload[..]).unwrap();
            b.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let evil = gz.finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let err = export_sdk(&evil, BUILT, &tmp.path().join("sdk")).unwrap_err();
        assert!(
            matches!(err, SdkExportError::UnsafeMember { .. }),
            "got {err}"
        );
        assert!(!tmp.path().join("escape").exists());
        // Bytes that are not an archive at all are a distinct, named failure —
        // not a silent empty export.
        assert!(matches!(
            export_sdk(b"\x1f\x8bnot really gzip", BUILT, &tmp.path().join("s2")),
            Err(SdkExportError::Archive(_))
        ));
    }
}
