//! Zephyr modules a project ADDS to its own build (REQ-ZMODEXPORT-001).
//!
//! varve carries the blocks a project adds, never Zephyr itself. A
//! `zephyr-module` payload is the module's tree as a gzip-tar, stored exactly
//! as published; `varve export-zephyr-modules` lays each one under
//! `<out>/<module-name>/` and writes a CMake script appending them to
//! `ZEPHYR_EXTRA_MODULES`, so the team's own `west.yml` is never edited.
//!
//! **No Python, anywhere in this file** (clause 5). `zephyr/module.yml` is
//! parsed in Rust. A module that declares `package-managers: pip` adds a
//! Python dependency to every build that uses it, so the deposit refuses it
//! unless the layer records an opt-in naming exactly the requirement files.
//!
//! The decisions live HERE, in a module the `--lib` mutation gate can reach,
//! and not in the CLI: a check that only a system test exercises is a check
//! the gate cannot defend.

use crate::sdkexport::{Member, MemberBody};
use std::collections::BTreeSet;
use std::path::Path;

/// Where Zephyr looks for a module's description.
pub const MODULE_YML: &str = "zephyr/module.yml";

/// The CMake script an export writes beside the module directories.
pub const CMAKE_FILE: &str = "zephyr-extra-modules.cmake";

/// Signed annotation recording the operator's opt-in to a module's pip
/// requirement files, comma-separated (REQ-ZMODEXPORT-001 clause 5).
pub const ANN_ALLOW_PIP: &str = "eu.pulseengine.varve.zephyr.allow-pip";

/// What `zephyr/module.yml` says that varve acts on. Everything else in the
/// file is Zephyr's business and is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleYml {
    /// `name:` — absent means the payload's own name is used.
    pub name: Option<String>,
    /// `build: depends:` — modules that must be present.
    pub depends: Vec<String>,
    /// `Some(requirement files)` when `package-managers: pip` is declared AT
    /// ALL, even with no files or a null value; `None` when it is not.
    pub pip: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZephyrModuleError {
    #[error("zephyr-module '{payload}' cannot be opened as a tar archive: {detail}")]
    Archive { payload: String, detail: String },
    #[error(
        "zephyr-module '{payload}' has no {MODULE_YML} — Zephyr finds a module through that file, \
         so a tree without one is not a module and would install, verify and then be ignored by \
         every build. {members} member(s) were read; the first: {saw:?}"
    )]
    NoModuleYml {
        payload: String,
        members: usize,
        saw: Vec<String>,
    },
    #[error("zephyr-module '{payload}': {MODULE_YML} does not parse: {detail}")]
    BadModuleYml { payload: String, detail: String },
    #[error(
        "zephyr-module '{payload}' declares `package-managers: pip` (requirement files: {files}), \
         which adds a Python dependency to every build that uses it. varve distributes the blocks \
         a project adds and needs no Python (REQ-ZMODEXPORT-001 clause 5), so this is refused \
         unless the layer records an explicit opt-in naming exactly those files: \
         allow-pip = [{quoted}]"
    )]
    PipWithoutOptIn {
        payload: String,
        files: String,
        quoted: String,
    },
    #[error(
        "zephyr-module '{payload}' declares pip requirement files [{declared}] and its allow-pip \
         opt-in names [{allowed}] (opt-in missing: [{missing}]; opt-in names but the module does \
         not declare: [{extra}]). The opt-in must name EXACTLY the declared files — a different \
         list is a different Python dependency than the one the operator accepted."
    )]
    PipOptInMismatch {
        payload: String,
        declared: String,
        allowed: String,
        missing: String,
        extra: String,
    },
    #[error(
        "zephyr-module '{payload}' carries allow-pip = [{allowed}] and its {MODULE_YML} declares \
         no `package-managers: pip` — an opt-in for a dependency that does not exist would be \
         signed, read by nothing, and believed. Drop it."
    )]
    PipOptInUnneeded { payload: String, allowed: String },
    #[error("allow-pip names {entry:?}, which is not a usable requirement-file path ({why})")]
    BadPipEntry { entry: String, why: &'static str },
    #[error(
        "zephyr-module '{payload}' names itself {name:?}, which is not a plain directory name \
         ({why}) — the export writes the module to <out>/<name>/, and a name that is a path \
         would write somewhere else"
    )]
    BadName {
        payload: String,
        name: String,
        why: &'static str,
    },
    #[error(
        "zephyr-module '{payload}' contains the symlink {member:?} — a module tree is laid out \
         as stored and a link in it could point anywhere on the consumer's machine, so it is \
         refused"
    )]
    Symlink { payload: String, member: String },
    #[error("zephyr-module '{payload}' lists the path {path:?} twice")]
    DuplicateMember { payload: String, path: String },
    #[error("zephyr-module '{payload}': member {member:?} is not a usable path: {detail}")]
    UnsafeMember {
        payload: String,
        member: String,
        detail: String,
    },
    #[error(
        "payloads '{first}' and '{second}' are both the Zephyr module '{name}' (compared \
         ignoring case, as a case-insensitive file system would) — they would write into one \
         directory"
    )]
    DuplicateModule {
        name: String,
        first: String,
        second: String,
    },
    #[error(
        "no zephyr-module named {asked:?} in this pin. It carries: {carried}. \
         `varve inspect` lists every payload."
    )]
    UnknownSelect { asked: String, carried: String },
    #[error(
        "zephyr module '{module}' declares `build: depends: [{dependency}]`, and '{dependency}' \
         is not among the modules this export carries ({carried}). An export with an incomplete \
         dependency closure builds only until Zephyr looks for the missing module. Add it to the \
         layer (and do not narrow --select past it); a module the workspace's own west manifest \
         already provides is not recognised yet (REQ-ZMODEXPORT-002)."
    )]
    IncompleteClosure {
        module: String,
        dependency: String,
        carried: String,
    },
    #[error(
        "the path {path:?} cannot be written into a CMake list safely: {why}. Export to a \
         directory whose absolute path avoids it."
    )]
    UnsafeCmakePath { path: String, why: &'static str },
    #[error("cannot write {path}: {detail}")]
    Io { path: String, detail: String },
}

/// A module's tree as stored, with the wrapper directory (if any) stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleTree {
    pub yml: ModuleYml,
    /// Root-relative, normalised, no archive-root entries.
    pub members: Vec<Member>,
}

/// The slice of `zephyr/module.yml` varve reads, as the YAML spells it.
#[derive(serde::Deserialize)]
struct RawYml {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    build: Option<RawBuild>,
    #[serde(default, rename = "package-managers")]
    package_managers: Option<RawPackageManagers>,
}

#[derive(serde::Deserialize)]
struct RawBuild {
    #[serde(default)]
    depends: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct RawPackageManagers {
    // Only called when the key is PRESENT, which is the point: `pip:` with a
    // null value still declares pip, and `Option<RawPip>` alone could not
    // tell it from no `pip` key at all.
    #[serde(default, deserialize_with = "pip_declared")]
    pip: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct RawPip {
    #[serde(default, rename = "requirement-files")]
    files: Option<Vec<String>>,
}

fn pip_declared<'de, D>(d: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let pip = <Option<RawPip> as serde::Deserialize>::deserialize(d)?;
    Ok(Some(pip.and_then(|p| p.files).unwrap_or_default()))
}

/// Parse `zephyr/module.yml`.
///
/// In Rust, by `serde-saphyr` (pure safe Rust, `unsafe` forbidden, with
/// resource budgets against hostile input). Nothing here shells out, so no
/// Python is needed to deposit or export a module (clause 5).
pub fn parse_module_yml(payload: &str, text: &str) -> Result<ModuleYml, ZephyrModuleError> {
    let raw: RawYml =
        serde_saphyr::from_str(text).map_err(|e| ZephyrModuleError::BadModuleYml {
            payload: payload.to_string(),
            detail: e.to_string(),
        })?;
    Ok(ModuleYml {
        name: raw.name,
        depends: raw.build.and_then(|b| b.depends).unwrap_or_default(),
        pip: raw.package_managers.and_then(|p| p.pip),
    })
}

/// The one top-level directory every member sits under, if there is one.
fn wrapper_of(members: &[Member]) -> Option<String> {
    let top = members.first()?.path.split('/').next()?.to_string();
    let prefix = format!("{top}/");
    members
        .iter()
        .all(|m| m.path.starts_with(&prefix) || (m.path == top && m.body == MemberBody::Dir))
        .then_some(top)
}

/// Open a module archive: validate every member, find `zephyr/module.yml`
/// (at the root, else inside a single wrapper directory) and parse it.
pub fn open(payload: &str, archive: &[u8]) -> Result<ModuleTree, ZephyrModuleError> {
    let raw = crate::sdkexport::read_members(archive).map_err(|e| ZephyrModuleError::Archive {
        payload: payload.to_string(),
        detail: e.to_string(),
    })?;
    let mut members: Vec<Member> = Vec::with_capacity(raw.len());
    let mut seen = BTreeSet::new();
    for m in raw {
        // `git archive` leads with a pax global header recording the commit.
        // It is metadata about the archive, not a member of the module.
        if m.path == "pax_global_header" && matches!(m.body, MemberBody::File { .. }) {
            continue;
        }
        // `tar -C dir .` writes the root itself first.
        if m.body == MemberBody::Dir && crate::sdkexport::names_archive_root(&m.path) {
            continue;
        }
        let path = crate::sdkexport::safe_member_path(&m.path).map_err(|e| {
            ZephyrModuleError::UnsafeMember {
                payload: payload.to_string(),
                member: m.path.clone(),
                detail: e.to_string(),
            }
        })?;
        if matches!(m.body, MemberBody::Symlink { .. }) {
            return Err(ZephyrModuleError::Symlink {
                payload: payload.to_string(),
                member: path,
            });
        }
        if !seen.insert(path.clone()) {
            return Err(ZephyrModuleError::DuplicateMember {
                payload: payload.to_string(),
                path,
            });
        }
        members.push(Member { path, body: m.body });
    }

    // The root first, so a module that is nothing BUT `zephyr/module.yml`
    // (one top-level directory, `zephyr`) is not mistaken for a wrapper.
    let is_yml = |m: &&Member, prefix: &str| {
        m.path == format!("{prefix}{MODULE_YML}") && matches!(m.body, MemberBody::File { .. })
    };
    let (strip, found) = match members.iter().find(|m| is_yml(m, "")) {
        Some(m) => (None, Some(m)),
        None => match wrapper_of(&members) {
            Some(w) => {
                let prefix = format!("{w}/");
                (Some(w), members.iter().find(|m| is_yml(m, &prefix)))
            }
            None => (None, None),
        },
    };
    let Some(Member {
        body: MemberBody::File { bytes, .. },
        ..
    }) = found
    else {
        return Err(ZephyrModuleError::NoModuleYml {
            payload: payload.to_string(),
            members: members.len(),
            saw: members.iter().take(8).map(|m| m.path.clone()).collect(),
        });
    };
    let text = std::str::from_utf8(bytes).map_err(|e| ZephyrModuleError::BadModuleYml {
        payload: payload.to_string(),
        detail: format!("not UTF-8: {e}"),
    })?;
    let yml = parse_module_yml(payload, text)?;

    if let Some(w) = strip {
        let prefix = format!("{w}/");
        members = members
            .into_iter()
            .filter_map(|m| {
                m.path.strip_prefix(&prefix).map(|p| Member {
                    path: p.to_string(),
                    body: m.body,
                })
            })
            .collect();
    }
    Ok(ModuleTree { yml, members })
}

/// Why `name` cannot be one directory component of the export, if it cannot.
fn plain_component_fault(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some("empty")
    } else if name.contains('/') || name.contains('\\') {
        Some("it contains a path separator")
    } else if name.chars().any(char::is_control) {
        Some("it contains a control character")
    } else if name.starts_with('.') {
        Some("it starts with '.', which names the current or parent directory or hides itself")
    } else if name.starts_with('-') {
        Some("it starts with '-', which a command line would read as a flag")
    } else if name == CMAKE_FILE {
        Some("it is the name of the CMake script written beside the modules")
    } else {
        None
    }
}

/// The directory name this module is exported under: `module.yml`'s `name:`,
/// else the payload's own name. Refused unless a plain directory component.
pub fn module_name(payload: &str, yml: &ModuleYml) -> Result<String, ZephyrModuleError> {
    let name = yml.name.clone().unwrap_or_else(|| payload.to_string());
    match plain_component_fault(&name) {
        Some(why) => Err(ZephyrModuleError::BadName {
            payload: payload.to_string(),
            name,
            why,
        }),
        None => Ok(name),
    }
}

/// `allow-pip` entries are signed into an annotation comma-separated, so one
/// containing a comma, a control character or nothing at all cannot round-trip.
pub fn check_allow_pip_entries(allow: &[String]) -> Result<(), ZephyrModuleError> {
    for entry in allow {
        let why = if entry.is_empty() {
            Some("empty")
        } else if entry.contains(',') {
            Some("it contains a comma, which separates entries in the signed annotation")
        } else if entry.chars().any(char::is_control) {
            Some("it contains a control character")
        } else {
            None
        };
        if let Some(why) = why {
            return Err(ZephyrModuleError::BadPipEntry {
                entry: entry.clone(),
                why,
            });
        }
    }
    Ok(())
}

fn join(items: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    items
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The pip rule (clause 5): declared requires an opt-in naming EXACTLY the
/// declared files; an opt-in with nothing declared is refused as inert.
pub fn check_pip(
    payload: &str,
    yml: &ModuleYml,
    allow: Option<&[String]>,
) -> Result<(), ZephyrModuleError> {
    let allowed: BTreeSet<&str> = allow
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let Some(declared_files) = &yml.pip else {
        return match allow {
            None => Ok(()),
            Some(_) => Err(ZephyrModuleError::PipOptInUnneeded {
                payload: payload.to_string(),
                allowed: join(&allowed),
            }),
        };
    };
    let declared: BTreeSet<&str> = declared_files.iter().map(String::as_str).collect();
    let Some(_) = allow else {
        return Err(ZephyrModuleError::PipWithoutOptIn {
            payload: payload.to_string(),
            files: if declared.is_empty() {
                "none listed".to_string()
            } else {
                join(&declared)
            },
            quoted: join(declared.iter().map(|f| format!("{f:?}"))),
        });
    };
    if declared != allowed {
        return Err(ZephyrModuleError::PipOptInMismatch {
            payload: payload.to_string(),
            declared: join(&declared),
            allowed: join(&allowed),
            missing: join(declared.difference(&allowed)),
            extra: join(allowed.difference(&declared)),
        });
    }
    Ok(())
}

/// Everything the deposit checks about one `zephyr-module` payload
/// (clauses 1 and 5).
pub fn check_deposit(
    payload: &str,
    archive: &[u8],
    allow_pip: Option<&[String]>,
) -> Result<(), ZephyrModuleError> {
    let tree = open(payload, archive)?;
    module_name(payload, &tree.yml)?;
    if let Some(allow) = allow_pip {
        check_allow_pip_entries(allow)?;
    }
    check_pip(payload, &tree.yml, allow_pip)
}

/// The opt-in as the signed annotation spells it, and back.
pub fn allow_pip_to_annotation(allow: &[String]) -> String {
    allow
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

pub fn allow_pip_from_annotation(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// One module ready to export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportModule {
    pub payload: String,
    pub name: String,
    pub tree: ModuleTree,
}

/// Open, name, (optionally) select and de-duplicate the modules of an export,
/// then require a complete `build: depends` closure over what is exported.
pub fn prepare(
    payloads: &[(String, Vec<u8>)],
    select: Option<&str>,
) -> Result<Vec<ExportModule>, ZephyrModuleError> {
    let mut modules = Vec::with_capacity(payloads.len());
    for (payload, bytes) in payloads {
        let tree = open(payload, bytes)?;
        let name = module_name(payload, &tree.yml)?;
        modules.push(ExportModule {
            payload: payload.clone(),
            name,
            tree,
        });
    }
    modules.sort_by(|a, b| (&a.name, &a.payload).cmp(&(&b.name, &b.payload)));
    if let Some(asked) = select {
        let carried = join(
            modules
                .iter()
                .map(|m| format!("{} (payload {})", m.name, m.payload)),
        );
        modules.retain(|m| m.name == asked || m.payload == asked);
        if modules.is_empty() {
            return Err(ZephyrModuleError::UnknownSelect {
                asked: asked.to_string(),
                carried,
            });
        }
    }
    for (i, m) in modules.iter().enumerate() {
        if let Some(first) = modules[..i]
            .iter()
            .find(|f| f.name.to_lowercase() == m.name.to_lowercase())
        {
            return Err(ZephyrModuleError::DuplicateModule {
                name: m.name.clone(),
                first: first.payload.clone(),
                second: m.payload.clone(),
            });
        }
    }
    check_closure(&modules)?;
    Ok(modules)
}

/// Every `build: depends` of every module must itself be exported.
pub fn check_closure(modules: &[ExportModule]) -> Result<(), ZephyrModuleError> {
    let names: BTreeSet<&str> = modules.iter().map(|m| m.name.as_str()).collect();
    for m in modules {
        for dep in &m.tree.yml.depends {
            if !names.contains(dep.as_str()) {
                return Err(ZephyrModuleError::IncompleteClosure {
                    module: m.name.clone(),
                    dependency: dep.clone(),
                    carried: join(&names),
                });
            }
        }
    }
    Ok(())
}

/// A path as a CMake quoted argument.
///
/// `;` is refused rather than escaped: `ZEPHYR_EXTRA_MODULES` is a LIST, and a
/// list element containing `;` is read back as two.
pub fn cmake_quote(path: &str) -> Result<String, ZephyrModuleError> {
    let unsafe_path = |why| ZephyrModuleError::UnsafeCmakePath {
        path: path.to_string(),
        why,
    };
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for c in path.chars() {
        match c {
            ';' => return Err(unsafe_path("a ';' would split the module list in two")),
            c if c.is_control() => return Err(unsafe_path("it contains a control character")),
            '\\' | '"' | '$' | '@' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Header values land in `#` comments; a line break would end the comment and
/// start CMake code.
fn comment_safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The script appending each `(name, absolute dir)` to `ZEPHYR_EXTRA_MODULES`.
///
/// It works both ways Zephyr users reach for. `include()` runs it as ordinary
/// CMake, where `list(APPEND)` is enough. `west build ... -- -C script` runs it
/// as an INITIAL CACHE script, where a plain variable never reaches the
/// project: only a cache entry does, so the list is also written to the cache.
pub fn cmake_script(
    layer: &str,
    manifest_digest: &str,
    dirs: &[(String, String)],
) -> Result<String, ZephyrModuleError> {
    let mut s = String::new();
    s.push_str("# Generated by `varve export-zephyr-modules`. Do not edit; re-run the command.\n");
    s.push_str(&format!("# Layer: {}\n", comment_safe(layer)));
    s.push_str(&format!(
        "# Manifest digest: {}\n",
        comment_safe(manifest_digest)
    ));
    s.push_str(
        "#\n\
         # Appends the verified Zephyr modules below to ZEPHYR_EXTRA_MODULES. Your west.yml is\n\
         # never touched. Use it either way:\n\
         #   west build ... -- -C <this file>\n\
         #   include(<this file>)      # in a plain CMake build\n\n",
    );
    for (name, dir) in dirs {
        s.push_str(&format!("# {}\n", comment_safe(name)));
        s.push_str(&format!(
            "list(APPEND ZEPHYR_EXTRA_MODULES {})\n",
            cmake_quote(dir)?
        ));
    }
    s.push_str(
        "list(REMOVE_DUPLICATES ZEPHYR_EXTRA_MODULES)\n\
         set(ZEPHYR_EXTRA_MODULES \"${ZEPHYR_EXTRA_MODULES}\" CACHE STRING\n\
         \x20   \"Zephyr modules added by varve\" FORCE)\n",
    );
    Ok(s)
}

/// What an export wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// (module name, absolute directory), in export order.
    pub modules: Vec<(String, String)>,
    pub files: usize,
    pub cmake: String,
}

fn io_err(path: &Path, e: impl std::fmt::Display) -> ZephyrModuleError {
    ZephyrModuleError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Write each module under `out/<name>/` and the CMake script beside them.
///
/// `out` must be absolute: the script names the module directories, and a
/// relative path there would resolve against wherever the build runs.
pub fn export(
    modules: &[ExportModule],
    out: &Path,
    layer: &str,
    manifest_digest: &str,
) -> Result<ExportReport, ZephyrModuleError> {
    if !out.is_absolute() {
        return Err(io_err(
            out,
            "the export directory must be absolute: the CMake script names it",
        ));
    }
    let mut report = ExportReport::default();
    for m in modules {
        let dir = out.join(&m.name);
        // A previous export of this module is REPLACED, not merged into: a file
        // left over from the last pin would sit in a tree the stamp then
        // vouches for. A symlink or a file where the directory belongs is
        // refused, never followed.
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => std::fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?,
            Ok(_) => {
                return Err(io_err(
                    &dir,
                    "exists and is not a plain directory (a file or a symlink)",
                ));
            }
            // Nothing there (or nothing readable there): `create_dir_all`
            // below reports any real failure, with its own error.
            Err(_) => {}
        }
        std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        for member in &m.tree.members {
            let dest = dir.join(&member.path);
            match &member.body {
                MemberBody::Dir => std::fs::create_dir_all(&dest).map_err(|e| io_err(&dest, e))?,
                MemberBody::File { mode, bytes } => {
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
                    }
                    std::fs::write(&dest, bytes).map_err(|e| io_err(&dest, e))?;
                    set_mode(&dest, *mode)?;
                    report.files += 1;
                }
                MemberBody::Symlink { .. } => {
                    return Err(ZephyrModuleError::Symlink {
                        payload: m.payload.clone(),
                        member: member.path.clone(),
                    });
                }
            }
        }
        report
            .modules
            .push((m.name.clone(), dir.display().to_string()));
    }
    report.cmake = cmake_script(layer, manifest_digest, &report.modules)?;
    let script = out.join(CMAKE_FILE);
    std::fs::write(&script, &report.cmake).map_err(|e| io_err(&script, e))?;
    Ok(report)
}

/// Executable stays executable, everything else is plain; setuid/setgid and
/// group/other write bits from an archive are never honoured.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ZephyrModuleError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io_err(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), ZephyrModuleError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ------------------------------------------------------------ fixtures

    /// A gzip-tar of `files` (path, content). Directories are implied.
    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        let raw = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap()
    }

    fn module(name: &str, depends: &[&str]) -> Vec<u8> {
        let mut yml = format!("name: {name}\nbuild:\n  cmake: .\n");
        if !depends.is_empty() {
            yml.push_str("  depends:\n");
            for d in depends {
                yml.push_str(&format!("    - {d}\n"));
            }
        }
        archive(&[
            ("zephyr/module.yml", &yml),
            ("CMakeLists.txt", "# module\n"),
            ("src/lib.c", "int x;\n"),
        ])
    }

    fn pip_module(files: &[&str]) -> Vec<u8> {
        let mut yml = String::from("name: py\npackage-managers:\n  pip:\n    requirement-files:\n");
        for f in files {
            yml.push_str(&format!("      - {f}\n"));
        }
        archive(&[("zephyr/module.yml", &yml)])
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ------------------------------------------------------- module.yml parser

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_parser_reads_name_depends_and_ignores_the_rest() {
        let y = parse_module_yml(
            "p",
            "name: gale\nbuild:\n  cmake: .\n  kconfig: Kconfig\n  depends:\n    - hal_a\n    - hal_b\n  settings:\n    board_root: .\ntests:\n  - tests\n",
        )
        .unwrap();
        assert_eq!(y.name.as_deref(), Some("gale"));
        assert_eq!(y.depends, strings(&["hal_a", "hal_b"]));
        assert_eq!(y.pip, None, "no package-managers means no pip");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_parser_reads_flow_style_comments_and_quotes() {
        let y = parse_module_yml(
            "p",
            "# a module\nname: \"quoted name\"  # trailing\nbuild: {depends: [a, 'b']}\n",
        )
        .unwrap();
        assert_eq!(y.name.as_deref(), Some("quoted name"));
        assert_eq!(y.depends, strings(&["a", "b"]));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_module_with_no_name_and_no_depends_parses_to_defaults() {
        let y = parse_module_yml("p", "build:\n  cmake: .\n").unwrap();
        assert_eq!(y, ModuleYml::default());
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn pip_is_seen_with_files_without_files_and_with_a_null_value() {
        let with = parse_module_yml(
            "p",
            "package-managers:\n  pip:\n    requirement-files:\n      - a.txt\n      - b/c.txt\n",
        )
        .unwrap();
        assert_eq!(with.pip, Some(strings(&["a.txt", "b/c.txt"])));
        let bare = parse_module_yml("p", "package-managers:\n  pip: {}\n").unwrap();
        assert_eq!(bare.pip, Some(vec![]));
        let null = parse_module_yml("p", "package-managers:\n  pip:\n").unwrap();
        assert_eq!(null.pip, Some(vec![]), "a null `pip:` still declares pip");
        let other = parse_module_yml("p", "package-managers:\n  npm: {}\n").unwrap();
        assert_eq!(other.pip, None, "only pip is a Python dependency");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_malformed_module_yml_is_refused_naming_the_payload() {
        for bad in [
            "name: [unclosed\n",
            "build:\n  depends: not-a-list\n",
            "name:\n  - a\n  - b\n",
            "",
            "\t\t: : :\n",
        ] {
            let e = parse_module_yml("gale", bad).expect_err(bad);
            assert!(
                matches!(&e, ZephyrModuleError::BadModuleYml { payload, .. } if payload == "gale"),
                "{bad:?} -> {e:?}"
            );
            assert!(e.to_string().contains("gale"), "{e}");
        }
    }

    // ---------------------------------------------------------- names

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_name_comes_from_module_yml_else_the_payload() {
        let named = ModuleYml {
            name: Some("from-yml".into()),
            ..Default::default()
        };
        assert_eq!(module_name("payload", &named).unwrap(), "from-yml");
        assert_eq!(
            module_name("payload", &ModuleYml::default()).unwrap(),
            "payload"
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_name_that_is_not_a_plain_directory_component_is_refused() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../x",
            "/abs",
            ".hidden",
            "-dash",
            "nul\0byte",
            "new\nline",
            "tab\tname",
            CMAKE_FILE,
        ] {
            let y = ModuleYml {
                name: Some(bad.into()),
                ..Default::default()
            };
            let e = module_name("p", &y).expect_err(bad);
            assert!(matches!(e, ZephyrModuleError::BadName { .. }), "{bad:?}");
        }
        // The payload name is judged by the same rule.
        let e = module_name("../evil", &ModuleYml::default()).expect_err("payload name");
        assert!(matches!(e, ZephyrModuleError::BadName { .. }));
        for ok in ["gale", "hal_stm32", "my.module", "a b", "x-1_2"] {
            let y = ModuleYml {
                name: Some(ok.into()),
                ..Default::default()
            };
            assert_eq!(module_name("p", &y).unwrap(), ok);
        }
    }

    // --------------------------------------------------------- open

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_tree_with_a_module_yml_opens() {
        let t = open("gale", &module("gale", &["hal"])).unwrap();
        assert_eq!(t.yml.name.as_deref(), Some("gale"));
        assert_eq!(t.yml.depends, strings(&["hal"]));
        let paths: Vec<&str> = t.members.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"zephyr/module.yml"), "{paths:?}");
        assert!(paths.contains(&"src/lib.c"), "{paths:?}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_tree_without_a_module_yml_is_refused() {
        let a = archive(&[("CMakeLists.txt", "x"), ("src/a.c", "y")]);
        let e = open("nomod", &a).expect_err("no module.yml");
        assert!(
            matches!(&e, ZephyrModuleError::NoModuleYml { payload, members: 2, .. } if payload == "nomod"),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(
            msg.contains("zephyr/module.yml") && msg.contains("nomod"),
            "{msg}"
        );
        // A module.yml in the WRONG place (not under zephyr/) is not one.
        let a = archive(&[("module.yml", "name: x\n"), ("zephyr/other", "y")]);
        assert!(matches!(
            open("p", &a),
            Err(ZephyrModuleError::NoModuleYml { .. })
        ));
        // Nor is a directory called module.yml.
        let a = archive(&[("zephyr/module.yml/inner", "name: x\n")]);
        assert!(matches!(
            open("p", &a),
            Err(ZephyrModuleError::NoModuleYml { .. })
        ));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_malformed_module_yml_refuses_the_open() {
        let a = archive(&[("zephyr/module.yml", "name: [unclosed\n")]);
        assert!(matches!(
            open("p", &a),
            Err(ZephyrModuleError::BadModuleYml { .. })
        ));
        let a = archive(&[("zephyr/module.yml", "\u{ff}")]);
        let bad = {
            // invalid UTF-8 bytes, not merely a non-ASCII char
            let mut tar = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(2);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut h, "zephyr/module.yml", &[0xff, 0xfe][..])
                .unwrap();
            tar.into_inner().unwrap()
        };
        drop(a);
        let e = open("p", &bad).expect_err("not utf-8");
        assert!(matches!(e, ZephyrModuleError::BadModuleYml { .. }), "{e:?}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_wrapper_directory_is_stripped_and_the_tree_is_stored_below_it() {
        let a = archive(&[
            ("gale-1.0/zephyr/module.yml", "name: gale\n"),
            ("gale-1.0/CMakeLists.txt", "x"),
        ]);
        let t = open("gale", &a).unwrap();
        let mut paths: Vec<&str> = t.members.iter().map(|m| m.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["CMakeLists.txt", "zephyr/module.yml"]);
    }

    fn dir_entry(tar: &mut tar::Builder<Vec<u8>>, path: &str) {
        let mut d = tar::Header::new_gnu();
        d.set_size(0);
        d.set_mode(0o755);
        d.set_entry_type(tar::EntryType::Directory);
        tar.append_data(&mut d, path, &[][..]).unwrap();
    }

    fn file_entry(tar: &mut tar::Builder<Vec<u8>>, path: &str, body: &str) {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, path, body.as_bytes()).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_wrapper_with_its_own_directory_entry_and_a_dot_root_entry_opens() {
        let mut tar = tar::Builder::new(Vec::new());
        dir_entry(&mut tar, "./");
        dir_entry(&mut tar, "./w/");
        file_entry(&mut tar, "./w/zephyr/module.yml", "name: w\n");
        file_entry(&mut tar, "./w/a.c", "x");
        let t = open("p", &tar.into_inner().unwrap()).unwrap();
        let mut paths: Vec<&str> = t.members.iter().map(|m| m.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.c", "zephyr/module.yml"]);
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn two_top_level_directories_are_not_a_wrapper() {
        let mut tar = tar::Builder::new(Vec::new());
        file_entry(&mut tar, "w/zephyr/module.yml", "name: w\n");
        dir_entry(&mut tar, "other/");
        let e = open("p", &tar.into_inner().unwrap()).expect_err("no wrapper");
        assert!(matches!(e, ZephyrModuleError::NoModuleYml { .. }), "{e:?}");
        let mut tar = tar::Builder::new(Vec::new());
        file_entry(&mut tar, "w/zephyr/module.yml", "name: w\n");
        file_entry(&mut tar, "other/x", "y");
        assert!(matches!(
            open("p", &tar.into_inner().unwrap()),
            Err(ZephyrModuleError::NoModuleYml { .. })
        ));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_tree_that_is_only_zephyr_module_yml_is_not_mistaken_for_a_wrapper() {
        let a = archive(&[("zephyr/module.yml", "name: tiny\n")]);
        let t = open("p", &a).unwrap();
        assert_eq!(t.members.len(), 1);
        assert_eq!(t.members[0].path, "zephyr/module.yml");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn dot_slash_paths_and_a_git_archive_header_do_not_hide_the_module_yml() {
        let a = archive(&[
            ("pax_global_header", "52 comment=abc\n"),
            ("./zephyr/module.yml", "name: dotted\n"),
            ("./README", "r"),
        ]);
        let t = open("p", &a).unwrap();
        assert_eq!(t.yml.name.as_deref(), Some("dotted"));
        assert!(t.members.iter().all(|m| m.path != "pax_global_header"));
        assert!(t.members.iter().any(|m| m.path == "README"));
    }

    /// A tar whose member path is written RAW, because `tar::Builder` itself
    /// refuses to write a `..`.
    fn raw_path_tar(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(body.as_bytes());
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_member_that_escapes_the_tree_is_refused() {
        for evil in ["../evil", "a/../../evil", "/abs/evil"] {
            let a = raw_path_tar(&[("zephyr/module.yml", "name: x\n"), (evil, "y")]);
            let e = open("p", &a).expect_err(evil);
            assert!(
                matches!(&e, ZephyrModuleError::UnsafeMember { member, .. } if member == evil),
                "{evil}: {e:?}"
            );
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_symlink_in_the_tree_is_refused() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(10);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, "zephyr/module.yml", &b"name: s\n\n\n\n"[..10])
            .unwrap();
        let mut l = tar::Header::new_gnu();
        l.set_size(0);
        l.set_entry_type(tar::EntryType::Symlink);
        tar.append_link(&mut l, "link", "/etc/passwd").unwrap();
        let e = open("p", &tar.into_inner().unwrap()).expect_err("symlink");
        assert!(
            matches!(&e, ZephyrModuleError::Symlink { member, .. } if member == "link"),
            "{e:?}"
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_path_listed_twice_is_refused() {
        let a = archive(&[
            ("zephyr/module.yml", "name: x\n"),
            ("a.c", "1"),
            ("a.c", "2"),
        ]);
        let e = open("p", &a).expect_err("duplicate");
        assert!(
            matches!(&e, ZephyrModuleError::DuplicateMember { path, .. } if path == "a.c"),
            "{e:?}"
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn something_that_is_not_an_archive_is_refused() {
        let e = open("p", b"<html>404</html>").expect_err("html");
        assert!(
            matches!(
                e,
                ZephyrModuleError::Archive { .. } | ZephyrModuleError::NoModuleYml { .. }
            ),
            "{e:?}"
        );
    }

    // ------------------------------------------------------ pip, clause 5

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn pip_without_an_opt_in_is_refused_naming_the_files() {
        let e = check_deposit("py", &pip_module(&["scripts/requirements.txt"]), None)
            .expect_err("pip, no opt-in");
        assert!(
            matches!(e, ZephyrModuleError::PipWithoutOptIn { .. }),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(msg.contains("scripts/requirements.txt"), "{msg}");
        assert!(msg.contains("allow-pip"), "{msg}");
        assert!(msg.contains("py"), "{msg}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn pip_with_the_matching_opt_in_is_accepted() {
        let allow = strings(&["scripts/requirements.txt"]);
        check_deposit(
            "py",
            &pip_module(&["scripts/requirements.txt"]),
            Some(&allow),
        )
        .unwrap();
        // Order and repetition do not matter; the SET is what is accepted.
        let allow = strings(&["b.txt", "a.txt", "a.txt"]);
        check_deposit("py", &pip_module(&["a.txt", "b.txt"]), Some(&allow)).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn pip_with_a_mismatched_opt_in_is_refused_both_ways() {
        // The opt-in names a DIFFERENT file than the one declared.
        let allow = strings(&["other.txt"]);
        let e = check_deposit(
            "py",
            &pip_module(&["scripts/requirements.txt"]),
            Some(&allow),
        )
        .expect_err("wrong file");
        match &e {
            ZephyrModuleError::PipOptInMismatch { missing, extra, .. } => {
                assert_eq!(missing, "scripts/requirements.txt");
                assert_eq!(extra, "other.txt");
            }
            other => panic!("{other:?}"),
        }
        // The opt-in covers only SOME of the declared files.
        let allow = strings(&["a.txt"]);
        let e = check_deposit("py", &pip_module(&["a.txt", "b.txt"]), Some(&allow))
            .expect_err("subset");
        match &e {
            ZephyrModuleError::PipOptInMismatch { missing, extra, .. } => {
                assert_eq!(missing, "b.txt");
                assert_eq!(extra, "");
            }
            other => panic!("{other:?}"),
        }
        // The opt-in names MORE than the module declares.
        let allow = strings(&["a.txt", "extra.txt"]);
        let e = check_deposit("py", &pip_module(&["a.txt"]), Some(&allow)).expect_err("superset");
        match &e {
            ZephyrModuleError::PipOptInMismatch { missing, extra, .. } => {
                assert_eq!(missing, "");
                assert_eq!(extra, "extra.txt");
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().contains("EXACTLY"), "{e}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn bare_pip_needs_an_explicit_empty_opt_in() {
        let a = archive(&[("zephyr/module.yml", "package-managers:\n  pip: {}\n")]);
        let e = check_deposit("p", &a, None).expect_err("bare pip, no opt-in");
        assert!(matches!(e, ZephyrModuleError::PipWithoutOptIn { .. }));
        assert!(e.to_string().contains("none listed"), "{e}");
        check_deposit("p", &a, Some(&[])).unwrap();
        let allow = strings(&["x.txt"]);
        assert!(matches!(
            check_deposit("p", &a, Some(&allow)),
            Err(ZephyrModuleError::PipOptInMismatch { .. })
        ));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn an_opt_in_for_a_module_that_declares_no_pip_is_refused() {
        let allow = strings(&["scripts/requirements.txt"]);
        let e = check_deposit("p", &module("p", &[]), Some(&allow)).expect_err("inert");
        assert!(
            matches!(e, ZephyrModuleError::PipOptInUnneeded { .. }),
            "{e:?}"
        );
        // Even an EMPTY opt-in is inert where nothing is declared.
        assert!(matches!(
            check_deposit("p", &module("p", &[]), Some(&[])),
            Err(ZephyrModuleError::PipOptInUnneeded { .. })
        ));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_module_without_pip_needs_no_opt_in() {
        check_deposit("p", &module("p", &["x"]), None).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_deposit_check_runs_all_of_it() {
        // no module.yml
        assert!(matches!(
            check_deposit("p", &archive(&[("a", "b")]), None),
            Err(ZephyrModuleError::NoModuleYml { .. })
        ));
        // a bad NAME in a good tree
        let a = archive(&[("zephyr/module.yml", "name: ../x\n")]);
        assert!(matches!(
            check_deposit("p", &a, None),
            Err(ZephyrModuleError::BadName { .. })
        ));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn allow_pip_entries_must_survive_the_annotation_encoding() {
        check_allow_pip_entries(&strings(&["a.txt", "dir/b.txt"])).unwrap();
        check_allow_pip_entries(&[]).unwrap();
        for bad in ["", "a,b", "new\nline", "tab\there", "nul\0"] {
            let e = check_allow_pip_entries(&strings(&[bad])).expect_err(bad);
            assert!(
                matches!(e, ZephyrModuleError::BadPipEntry { .. }),
                "{bad:?}"
            );
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_annotation_round_trips_sorted_and_deduplicated() {
        let raw = allow_pip_to_annotation(&strings(&["b.txt", "a.txt", "b.txt"]));
        assert_eq!(raw, "a.txt,b.txt");
        assert_eq!(
            allow_pip_from_annotation(&raw),
            strings(&["a.txt", "b.txt"])
        );
        assert_eq!(allow_pip_to_annotation(&[]), "");
        assert_eq!(allow_pip_from_annotation(""), Vec::<String>::new());
    }

    // ------------------------------------------------------ prepare / closure

    fn payloads(v: &[(&str, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
        v.iter().map(|(n, b)| (n.to_string(), b.clone())).collect()
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn prepare_names_modules_from_module_yml_and_keeps_the_payload_name() {
        let m = prepare(
            &payloads(&[
                ("pay-a", module("name-a", &[])),
                ("b", archive(&[("zephyr/module.yml", "build: {}\n")])),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(m.len(), 2);
        // Sorted by module name, so an export is the same whatever order the
        // composition handed the payloads over in.
        assert_eq!((m[0].payload.as_str(), m[0].name.as_str()), ("b", "b"));
        assert_eq!(
            (m[1].payload.as_str(), m[1].name.as_str()),
            ("pay-a", "name-a")
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn two_payloads_that_are_one_module_name_are_refused() {
        let e = prepare(
            &payloads(&[("one", module("same", &[])), ("two", module("same", &[]))]),
            None,
        )
        .expect_err("duplicate name");
        assert!(
            matches!(e, ZephyrModuleError::DuplicateModule { .. }),
            "{e:?}"
        );
        // Case-insensitively: macOS and Windows would merge the directories.
        let e = prepare(
            &payloads(&[("one", module("Gale", &[])), ("two", module("gale", &[]))]),
            None,
        )
        .expect_err("case-folded duplicate");
        assert!(
            matches!(e, ZephyrModuleError::DuplicateModule { .. }),
            "{e:?}"
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn select_picks_by_module_name_or_payload_name_and_refuses_an_unknown_one() {
        let all = payloads(&[("pa", module("alpha", &[])), ("pb", module("beta", &[]))]);
        let by_module = prepare(&all, Some("beta")).unwrap();
        assert_eq!(by_module.len(), 1);
        assert_eq!(by_module[0].name, "beta");
        let by_payload = prepare(&all, Some("pa")).unwrap();
        assert_eq!(by_payload.len(), 1);
        assert_eq!(by_payload[0].name, "alpha");
        let e = prepare(&all, Some("gamma")).expect_err("unknown");
        match &e {
            ZephyrModuleError::UnknownSelect { asked, carried } => {
                assert_eq!(asked, "gamma");
                assert!(
                    carried.contains("alpha") && carried.contains("beta"),
                    "{carried}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_dependency_outside_the_exported_set_is_refused_naming_both() {
        let e = prepare(&payloads(&[("app", module("app", &["missing_mod"]))]), None)
            .expect_err("incomplete closure");
        match &e {
            ZephyrModuleError::IncompleteClosure {
                module, dependency, ..
            } => {
                assert_eq!(module, "app");
                assert_eq!(dependency, "missing_mod");
            }
            other => panic!("{other:?}"),
        }
        let msg = e.to_string();
        assert!(msg.contains("app") && msg.contains("missing_mod"), "{msg}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_complete_closure_passes_in_any_order() {
        let m = prepare(
            &payloads(&[
                ("app", module("app", &["lib_a", "lib_b"])),
                ("lib_b", module("lib_b", &["lib_a"])),
                ("lib_a", module("lib_a", &[])),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(m.len(), 3);
        check_closure(&m).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn narrowing_select_past_a_dependency_breaks_the_closure() {
        let all = payloads(&[
            ("app", module("app", &["lib"])),
            ("lib", module("lib", &[])),
        ]);
        assert_eq!(prepare(&all, Some("lib")).unwrap().len(), 1);
        let e = prepare(&all, Some("app")).expect_err("lib not selected");
        assert!(
            matches!(&e, ZephyrModuleError::IncompleteClosure { dependency, .. } if dependency == "lib"),
            "{e:?}"
        );
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_dependency_is_matched_by_module_name_not_by_payload_name() {
        // The payload is called 'p-lib' but the module is 'lib'.
        let m = prepare(
            &payloads(&[
                ("app", module("app", &["lib"])),
                ("p-lib", module("lib", &[])),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(m.len(), 2);
        let e = prepare(
            &payloads(&[
                ("app", module("app", &["p-lib"])),
                ("p-lib", module("lib", &[])),
            ]),
            None,
        )
        .expect_err("depends names the payload, not the module");
        assert!(matches!(e, ZephyrModuleError::IncompleteClosure { .. }));
    }

    // ------------------------------------------------------------- cmake

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn cmake_quoting_escapes_what_cmake_would_interpret() {
        assert_eq!(cmake_quote("/plain/path").unwrap(), "\"/plain/path\"");
        assert_eq!(cmake_quote("/with space/x").unwrap(), "\"/with space/x\"");
        assert_eq!(cmake_quote("/q\"uote").unwrap(), "\"/q\\\"uote\"");
        assert_eq!(cmake_quote("/back\\slash").unwrap(), "\"/back\\\\slash\"");
        assert_eq!(cmake_quote("/d$ollar").unwrap(), "\"/d\\$ollar\"");
        assert_eq!(cmake_quote("/${HOME}").unwrap(), "\"/\\${HOME}\"");
        assert_eq!(cmake_quote("/at@sign").unwrap(), "\"/at\\@sign\"");
        assert_eq!(cmake_quote("/hash#x").unwrap(), "\"/hash#x\"");
        assert_eq!(cmake_quote("/paren(s)").unwrap(), "\"/paren(s)\"");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn cmake_refuses_paths_it_cannot_carry_in_a_list() {
        // `;` splits a CMake list: one path would become two modules.
        for (bad, why) in [
            ("/a;b", "semicolon"),
            ("/a\nb", "newline"),
            ("/a\rb", "carriage return"),
            ("/a\0b", "NUL"),
            ("/a\u{7}b", "control"),
        ] {
            let e = cmake_quote(bad).expect_err(why);
            assert!(
                matches!(e, ZephyrModuleError::UnsafeCmakePath { .. }),
                "{why}"
            );
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_script_appends_each_module_and_names_the_layer_and_digest() {
        let s = cmake_script(
            "2026.11.0",
            "sha256:abc123",
            &[
                ("gale".into(), "/out dir/gale".into()),
                ("hal".into(), "/out dir/hal".into()),
            ],
        )
        .unwrap();
        assert!(s.contains("2026.11.0"), "{s}");
        assert!(s.contains("sha256:abc123"), "{s}");
        assert!(
            s.lines()
                .any(|l| l == "list(APPEND ZEPHYR_EXTRA_MODULES \"/out dir/gale\")"),
            "{s}"
        );
        assert!(
            s.lines()
                .any(|l| l == "list(APPEND ZEPHYR_EXTRA_MODULES \"/out dir/hal\")"),
            "{s}"
        );
        // Usable under `-C` as well as `include()`: a plain variable set in a
        // -C script does not reach the project, so the list is also cached.
        assert!(s.contains("CACHE"), "{s}");
        assert!(s.lines().next().unwrap().starts_with('#'), "{s}");
        assert!(s.contains("west.yml is\n# never touched"), "{s}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_newline_in_the_header_values_cannot_inject_cmake() {
        let s = cmake_script(
            "evil\nmessage(FATAL_ERROR \"pwned\")",
            "sha256:x\r\nmessage(FATAL_ERROR \"pwned2\")",
            &[("m".into(), "/m".into())],
        )
        .unwrap();
        for l in s.lines() {
            assert!(
                l.starts_with('#')
                    || l.is_empty()
                    || l.starts_with("list(")
                    || l.starts_with("set(")
                    || l.starts_with("  "),
                "an injected line survived: {l:?}"
            );
        }
        assert!(!s.contains('\r'));
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_script_refuses_an_unquotable_directory() {
        let e = cmake_script("l", "d", &[("m".into(), "/a;b".into())]).expect_err("semicolon");
        assert!(matches!(e, ZephyrModuleError::UnsafeCmakePath { .. }));
    }

    // ------------------------------------------------------------ export

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "varve-zmod-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_writes_each_tree_as_stored_and_the_cmake_beside_them() {
        let out = temp("export");
        let mods = prepare(
            &payloads(&[
                ("gale", module("gale", &["hal"])),
                ("hal", module("hal", &[])),
            ]),
            None,
        )
        .unwrap();
        let r = export(&mods, &out, "2026.11.0", "sha256:dd").unwrap();
        assert_eq!(r.modules.len(), 2);
        assert_eq!(
            std::fs::read_to_string(out.join("gale/zephyr/module.yml")).unwrap(),
            "name: gale\nbuild:\n  cmake: .\n  depends:\n    - hal\n"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("hal/src/lib.c")).unwrap(),
            "int x;\n"
        );
        assert!(out.join("gale/CMakeLists.txt").is_file());
        let cmake = std::fs::read_to_string(out.join(CMAKE_FILE)).unwrap();
        assert_eq!(cmake, r.cmake);
        assert!(cmake.contains(&format!(
            "list(APPEND ZEPHYR_EXTRA_MODULES \"{}\")",
            out.join("gale").display()
        )));
        assert!(cmake.contains(&format!(
            "list(APPEND ZEPHYR_EXTRA_MODULES \"{}\")",
            out.join("hal").display()
        )));
        // 3 files per module; the cmake file is not a module file.
        assert_eq!(r.files, 6);
        // No west.yml is created.
        assert!(!out.join("west.yml").exists());
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[cfg(unix)]
    #[test]
    fn export_keeps_the_exec_bit_and_drops_setuid() {
        use std::os::unix::fs::PermissionsExt;
        let mut tar = tar::Builder::new(Vec::new());
        for (path, mode, body) in [
            ("zephyr/module.yml", 0o644u32, "name: x\n"),
            ("scripts/run.sh", 0o4755, "#!/bin/sh\n"),
            ("data.txt", 0o600, "d"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(mode);
            h.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        let a = tar.into_inner().unwrap();
        let out = temp("mode");
        let mods = prepare(&[("x".to_string(), a)], None).unwrap();
        export(&mods, &out, "l", "d").unwrap();
        let mode = |p: &str| std::fs::metadata(out.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("x/scripts/run.sh"), 0o755);
        assert_eq!(mode("x/data.txt"), 0o644);
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_replaces_a_stale_module_directory_rather_than_merging_into_it() {
        let out = temp("stale");
        std::fs::create_dir_all(out.join("x")).unwrap();
        std::fs::write(out.join("x/stale.txt"), "old").unwrap();
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        export(&mods, &out, "l", "d").unwrap();
        assert!(!out.join("x/stale.txt").exists(), "a stale file survived");
        assert!(out.join("x/zephyr/module.yml").is_file());
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[cfg(unix)]
    #[test]
    fn export_refuses_to_write_through_a_symlinked_module_directory() {
        let out = temp("link");
        let elsewhere = temp("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, out.join("x")).unwrap();
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("symlink at destination");
        assert!(matches!(e, ZephyrModuleError::Io { .. }), "{e:?}");
        assert!(
            std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "something was written through the link"
        );
        std::fs::remove_dir_all(&out).unwrap();
        std::fs::remove_dir_all(&elsewhere).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_refuses_a_module_dir_that_is_a_file() {
        let out = temp("file");
        std::fs::write(out.join("x"), "a file").unwrap();
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        assert!(matches!(
            export(&mods, &out, "l", "d"),
            Err(ZephyrModuleError::Io { .. })
        ));
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_needs_an_absolute_directory_and_refuses_a_symlink_member() {
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        let e = export(&mods, Path::new("relative/out"), "l", "d").expect_err("relative");
        assert!(matches!(e, ZephyrModuleError::Io { .. }));
        // `open` never yields a link, but the type allows one: refused anyway.
        let mut with_link = mods.clone();
        with_link[0].tree.members.push(Member {
            path: "link".into(),
            body: MemberBody::Symlink {
                target: "/etc".into(),
            },
        });
        let out = temp("symlink-member");
        let e = export(&with_link, &out, "l", "d").expect_err("link member");
        assert!(matches!(e, ZephyrModuleError::Symlink { .. }), "{e:?}");
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn empty_directories_in_the_tree_are_kept() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(8);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, "zephyr/module.yml", &b"name: e\n\n"[..8])
            .unwrap();
        let mut d = tar::Header::new_gnu();
        d.set_size(0);
        d.set_mode(0o755);
        d.set_entry_type(tar::EntryType::Directory);
        tar.append_data(&mut d, "boards/", &[][..]).unwrap();
        let out = temp("emptydir");
        let mods = prepare(&[("e".to_string(), tar.into_inner().unwrap())], None).unwrap();
        export(&mods, &out, "l", "d").unwrap();
        assert!(out.join("e/boards").is_dir());
        std::fs::remove_dir_all(&out).unwrap();
    }

    // ----------------------------------------------- the script, run by CMake

    /// Does the generated script do what it says when real CMake runs it?
    /// Three ways in: `include()`, `-C`, and `-C` after a user's own `-D`.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn real_cmake_appends_both_modules_via_include_and_via_dash_c() {
        let Some(cmake) = which_cmake() else {
            eprintln!(
                "SKIPPED real_cmake_appends_both_modules_via_include_and_via_dash_c: \
                 `cmake` is not on PATH"
            );
            return;
        };
        let out = temp("cmake dir with space");
        let mods = prepare(
            &payloads(&[("gale", module("gale", &[])), ("hal", module("hal", &[]))]),
            None,
        )
        .unwrap();
        export(&mods, &out, "2026.11.0", "sha256:dd").unwrap();
        let script = out.join(CMAKE_FILE);
        let gale = out.join("gale");
        let hal = out.join("hal");

        let project = temp("project");
        std::fs::write(
            project.join("CMakeLists.txt"),
            format!(
                "cmake_minimum_required(VERSION 3.20)\nproject(probe NONE)\n\
                 if(PROBE_INCLUDE)\n  include(\"{}\")\nendif()\n\
                 message(STATUS \"ZEM=[${{ZEPHYR_EXTRA_MODULES}}]\")\n",
                script.display()
            ),
        )
        .unwrap();

        let run = |args: &[String]| -> String {
            let build = temp("build");
            let o = std::process::Command::new(&cmake)
                .args(["-S"])
                .arg(&project)
                .arg("-B")
                .arg(&build)
                .args(args)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&o.stdout).into_owned()
                + &String::from_utf8_lossy(&o.stderr);
            assert!(o.status.success(), "cmake failed: {text}");
            let line = text
                .lines()
                .find(|l| l.contains("ZEM=["))
                .unwrap_or_else(|| panic!("no probe line: {text}"))
                .to_string();
            std::fs::remove_dir_all(&build).ok();
            line
        };

        // 1. include()
        let line = run(&["-DPROBE_INCLUDE=1".to_string()]);
        assert!(line.contains(&gale.display().to_string()), "{line}");
        assert!(line.contains(&hal.display().to_string()), "{line}");
        // 2. west's `-- -C script`
        let line = run(&["-C".to_string(), script.display().to_string()]);
        assert!(line.contains(&gale.display().to_string()), "-C: {line}");
        assert!(line.contains(&hal.display().to_string()), "-C: {line}");
        // 3. -C keeps what the user already passed with -D
        let line = run(&[
            "-DZEPHYR_EXTRA_MODULES=/users/own".to_string(),
            "-C".to_string(),
            script.display().to_string(),
        ]);
        assert!(
            line.contains("/users/own"),
            "-D then -C lost the user's: {line}"
        );
        assert!(line.contains(&gale.display().to_string()), "{line}");
        std::fs::remove_dir_all(&out).ok();
        std::fs::remove_dir_all(&project).ok();
    }

    fn which_cmake() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join("cmake"))
            .find(|p| p.is_file())
    }
}
