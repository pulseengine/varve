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

/// Written by an export into every module directory it creates. It is what
/// says "varve wrote this directory", which is the only licence to replace or
/// remove one: the export stamp lists everything under `--out`, a user's own
/// files included, so a stamp alone proves nothing about who wrote a directory.
pub const MODULE_MARKER: &str = ".varve-zephyr-module";

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
        "zephyr-module '{payload}': {MODULE_YML} carries the YAML tag {tag}. Zephyr's own \
         reader (PyYAML) treats a key tagged `!!merge` as a merge key and varve's reader does \
         not, so a tagged node can hide `package-managers: pip`, `build: depends` or `name` \
         from every check varve makes while Zephyr still honours them. Real module.yml files \
         use no tags; remove it."
    )]
    TaggedModuleYml { payload: String, tag: String },
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
    #[error(
        "zephyr-module '{payload}' lists the path {path:?} twice, or twice differing only in \
         case (compared lowercased, as a case-insensitive file system such as macOS's would). \
         One would overwrite the other at export, and which one survives is not what was \
         parsed or checked."
    )]
    DuplicateMember { payload: String, path: String },
    #[error(
        "zephyr-module '{payload}' carries {member:?} beside the {MODULE_YML} varve parsed. \
         Compared ignoring case it names the same file Zephyr reads for the module \
         description, so on a case-insensitive file system it could replace the checked \
         description with an unchecked one (a pip dependency nobody opted into). Remove it."
    )]
    ModuleYmlCollision { payload: String, member: String },
    #[error(
        "{path} exists and was not written by varve export-zephyr-modules; remove it or choose \
         another --out. varve replaces a module directory only when this --out carries a \
         zephyr-module export stamp listing files under it, so a checkout of your own is \
         never deleted."
    )]
    NotWrittenByVarve { path: String },
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
    // Decided here, not left to the YAML library: serde-saphyr 2.0.0 reads an
    // empty document as "all defaults" and 2.1.0 refuses it, so the answer
    // would change with a version bump. A module.yml that says nothing is not
    // a description of a module.
    if text.trim().is_empty() {
        return Err(ZephyrModuleError::BadModuleYml {
            payload: payload.to_string(),
            detail: "the file is empty".to_string(),
        });
    }
    refuse_yaml_tags(payload, text)?;
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

/// Refuse ANY explicit YAML tag, found by the YAML parser's own events and not
/// by scanning text, so a `!` inside a quoted string, a comment or a block
/// scalar is correctly not one.
///
/// Why this exists: PyYAML, which reads this file for Zephyr, honours a tag
/// serde-saphyr ignores (`!!merge` on any key makes it a merge key), so a tagged
/// node can carry `package-managers: pip` past varve's check while Zephyr still
/// installs it. Refusing every tag closes that whole class, not one spelling.
/// A scan error is left for the typed parse below to report.
fn refuse_yaml_tags(payload: &str, text: &str) -> Result<(), ZephyrModuleError> {
    for item in serde_saphyr::granit_parser::Parser::new_from_str(text) {
        let Ok((event, _)) = item else { break };
        if let Some(tag) = event.tag() {
            return Err(ZephyrModuleError::TaggedModuleYml {
                payload: payload.to_string(),
                tag: format!("{}{}", tag.handle(), tag.suffix()),
            });
        }
    }
    Ok(())
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
        // The name an export marks its own directories with is not the
        // module's to use: a tree carrying it would be indistinguishable from
        // one varve wrote.
        if path.to_lowercase() == MODULE_MARKER {
            return Err(ZephyrModuleError::UnsafeMember {
                payload: payload.to_string(),
                member: m.path.clone(),
                detail: "that name is reserved for varve's own marker".to_string(),
            });
        }
        // Compared LOWERCASED: macOS and Windows file systems are
        // case-insensitive, so `zephyr/Module.yml` and `zephyr/module.yml` are
        // one file there, and which of the two a tar reader writes last wins.
        // That is how an unchecked description could replace the one parsed
        // (and pip-checked). Unicode normalisation is NOT handled: it is not
        // needed for the module-description names, which are ASCII, and the
        // `create_new` write at export refuses any collision this misses.
        if !seen.insert(path.to_lowercase()) {
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
    // Nothing else may fold onto the description varve parsed (see above): the
    // case-folded duplicate check catches `Module.yml`; this catches the
    // sibling spelling Zephyr also looks for.
    for m in &members {
        let lower = m.path.to_lowercase();
        if m.path != MODULE_YML && (lower == MODULE_YML || lower == "zephyr/module.yaml") {
            return Err(ZephyrModuleError::ModuleYmlCollision {
                payload: payload.to_string(),
                member: m.path.clone(),
            });
        }
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
    /// THIS payload's own signed opt-in. Carried here and never looked up by
    /// name: two payloads of a composition can share a payload name.
    pub allow_pip: Option<Vec<String>>,
}

/// One verified `zephyr-module` payload as an export receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModulePayload {
    pub name: String,
    pub bytes: Vec<u8>,
    /// The layer's SIGNED `allow-pip` annotation, decoded; `None` where the
    /// entry carries none.
    pub allow_pip: Option<Vec<String>>,
}

impl From<(String, Vec<u8>)> for ModulePayload {
    fn from((name, bytes): (String, Vec<u8>)) -> Self {
        ModulePayload {
            name,
            bytes,
            allow_pip: None,
        }
    }
}

/// Open, name, (optionally) select and de-duplicate the modules of an export,
/// re-check the pip rule against each one's signed opt-in, then require a
/// complete `build: depends` closure over what is exported.
///
/// The pip rule is enforced HERE as well as at deposit: a layer signed by a
/// varve that predates the deposit rule carries pip modules with no opt-in, and
/// the export is the last place that can refuse them.
pub fn prepare<P: Into<ModulePayload> + Clone>(
    payloads: &[P],
    select: Option<&str>,
) -> Result<Vec<ExportModule>, ZephyrModuleError> {
    let mut modules = Vec::with_capacity(payloads.len());
    for p in payloads {
        let ModulePayload {
            name: payload,
            bytes,
            allow_pip,
        } = p.clone().into();
        let tree = open(&payload, &bytes)?;
        let name = module_name(&payload, &tree.yml)?;
        modules.push(ExportModule {
            payload,
            name,
            tree,
            allow_pip,
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
    for m in &modules {
        check_pip(&m.payload, &m.tree.yml, m.allow_pip.as_deref())?;
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
            '[' | ']' => return Err(unsafe_path("a bracket can open a CMake bracket argument")),
            '\\' => return Err(unsafe_path("a backslash is an escape in CMake")),
            c if c.is_control() => return Err(unsafe_path("it contains a control character")),
            '"' | '$' | '@' => {
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
    /// Module directories of a previous export that this one no longer
    /// carries, removed so the stamp never vouches for a leftover.
    pub removed: Vec<String>,
}

fn io_err(path: &Path, e: impl std::fmt::Display) -> ZephyrModuleError {
    ZephyrModuleError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Does `out` carry a stamp that says a zephyr-module export is what is here?
fn ours_stamp(out: &Path) -> bool {
    crate::exportstamp::read_stamp(out)
        .is_ok_and(|st| st.kind == crate::kind::PayloadKind::ZephyrModule.as_str())
}

/// Is `dir` a real directory varve marked as the module `name`?
fn is_marked_dir(dir: &Path, name: &str) -> bool {
    let is_dir = std::fs::symlink_metadata(dir).is_ok_and(|md| md.is_dir());
    let marker = dir.join(MODULE_MARKER);
    let marked = std::fs::symlink_metadata(&marker).is_ok_and(|md| md.is_file())
        && std::fs::read_to_string(&marker)
            .is_ok_and(|text| text.lines().next() == Some(&format!("module: {name}")));
    is_dir && marked
}

fn not_ours(path: &Path) -> ZephyrModuleError {
    ZephyrModuleError::NotWrittenByVarve {
        path: path.display().to_string(),
    }
}

/// Write each module under `out/<name>/` and the CMake script beside them.
///
/// `out` must be absolute: the script names the module directories, and a
/// relative path there would resolve against wherever the build runs.
///
/// Everything is decided BEFORE anything is written or removed: every path
/// CMake must carry, every destination, the script and the stamp. A refusal
/// therefore leaves neither a half export nor a deleted directory behind.
///
/// A directory is replaced or removed only if it carries varve's own marker
/// ([`MODULE_MARKER`]) AND `out` carries a zephyr-module stamp. Neither alone
/// is enough: the stamp lists whatever was under `out`, including a user's own
/// files, and a marker without our stamp is not in an export directory of ours.
///
/// Known and deferred (REQ-ZMODEXPORT-002): the script persists the list in the
/// CMake cache with `FORCE`, so a LATER build in the same build tree keeps the
/// modules after the script is no longer passed with `-C`.
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
    let ours = ours_stamp(out);
    let dirs: Vec<(String, String)> = modules
        .iter()
        .map(|m| (m.name.clone(), out.join(&m.name).display().to_string()))
        .collect();
    // Quoting is validated here, not after the trees are on disk.
    let script_text = cmake_script(layer, manifest_digest, &dirs)?;

    for m in modules {
        let dir = out.join(&m.name);
        // Nothing there (or nothing readable): `create_dir_all` below reports
        // any real failure with its own error. Anything there must be varve's.
        if std::fs::symlink_metadata(&dir).is_ok() && !(ours && is_marked_dir(&dir, &m.name)) {
            return Err(not_ours(&dir));
        }
    }
    // The script and the stamp are replaced only when they are ours: never
    // followed through a symlink, never overwritten when somebody else wrote
    // them. (The stamp is written by the caller, after this returns.)
    let script = out.join(CMAKE_FILE);
    let stamp_file = out.join(crate::exportstamp::STAMP_FILE);
    for path in [&script, &stamp_file] {
        match std::fs::symlink_metadata(path) {
            Err(_) => {}
            Ok(md) if md.is_file() && ours => {}
            Ok(_) => return Err(not_ours(path)),
        }
    }
    // Leftovers: directories a previous export of OURS made for modules this
    // export no longer carries. The stamp must never vouch for one.
    let mut leftovers = Vec::new();
    if ours && let Ok(entries) = std::fs::read_dir(out) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !modules.iter().any(|m| m.name == name) && is_marked_dir(&entry.path(), &name) {
                leftovers.push(name);
            }
        }
        leftovers.sort();
    }

    let mut report = ExportReport::default();
    for name in &leftovers {
        let dir = out.join(name);
        std::fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        report.removed.push(name.clone());
    }
    for m in modules {
        let dir = out.join(&m.name);
        if std::fs::symlink_metadata(&dir).is_ok() {
            std::fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        }
        std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        create_file(
            &dir.join(MODULE_MARKER),
            format!("module: {}\nlayer: {layer}\n", m.name).as_bytes(),
        )?;
        for member in &m.tree.members {
            let dest = dir.join(&member.path);
            match &member.body {
                MemberBody::Dir => std::fs::create_dir_all(&dest).map_err(|e| io_err(&dest, e))?,
                MemberBody::File { mode, bytes } => {
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
                    }
                    create_file(&dest, bytes)?;
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
    }
    report.modules = dirs;
    report.cmake = script_text;
    if std::fs::symlink_metadata(&script).is_ok() {
        std::fs::remove_file(&script).map_err(|e| io_err(&script, e))?;
    }
    create_file(&script, report.cmake.as_bytes())?;
    Ok(report)
}

/// `create_new`: a file is CREATED, never overwritten and never written
/// through a link. The directory is fresh, so a collision means two members
/// landed on one path, and the later must not win.
fn create_file(path: &Path, bytes: &[u8]) -> Result<(), ZephyrModuleError> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| io_err(path, e))
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
            "  \n\t\n",
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
            ("/a[b", "open bracket"),
            ("/a]b", "close bracket"),
            ("/a\\b", "backslash"),
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

    /// What the CLI does after `export`: stamp the directory, which is the
    /// record that varve wrote what is in it.
    fn stamp(out: &Path, kind: &str) {
        let st = crate::exportstamp::stamp_for(out, "l", "sha256:d", kind).unwrap();
        crate::exportstamp::write_stamp(out, &st).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_second_export_over_a_first_replaces_cleanly_rather_than_merging() {
        let out = temp("stale");
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        export(&mods, &out, "l", "d").unwrap();
        stamp(&out, "zephyr-module");
        std::fs::write(out.join("x/stale.txt"), "old").unwrap();
        export(&mods, &out, "l2", "d2").unwrap();
        assert!(!out.join("x/stale.txt").exists(), "a stale file survived");
        assert!(out.join("x/zephyr/module.yml").is_file());
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_directory_varve_did_not_write_is_refused_and_survives() {
        let out = temp("foreign");
        std::fs::create_dir_all(out.join("gale")).unwrap();
        std::fs::write(out.join("gale/MARKER"), "my own checkout").unwrap();
        let mods = prepare(
            &payloads(&[
                ("alpha", module("alpha", &[])),
                ("gale", module("gale", &[])),
            ]),
            None,
        )
        .unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("not ours");
        assert!(
            matches!(&e, ZephyrModuleError::NotWrittenByVarve { path } if path.ends_with("gale")),
            "{e:?}"
        );
        let msg = e.to_string();
        assert!(
            msg.contains("was not written by varve export-zephyr-modules")
                && msg.contains("choose another --out"),
            "{msg}"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("gale/MARKER")).unwrap(),
            "my own checkout"
        );
        // Refused BEFORE anything is written: alpha sorts first and is not there.
        assert!(!out.join("alpha").exists());
        assert!(!out.join(CMAKE_FILE).exists());
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn only_a_marked_directory_under_a_zephyr_stamp_licenses_a_replace() {
        let mods = prepare(&[("gale".to_string(), module("gale", &[]))], None).unwrap();
        let refused = |out: &Path, what: &str| {
            let e = export(&mods, out, "l", "d").expect_err(what);
            assert!(
                matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
                "{what}: {e:?}"
            );
        };
        // Another export kind's stamp, over a directory varve marked.
        let out = temp("otherkind");
        export(&mods, &out, "l", "d").unwrap();
        stamp(&out, "cargo");
        refused(&out, "a cargo stamp is not ours");
        assert!(out.join("gale/zephyr/module.yml").is_file());
        std::fs::remove_dir_all(&out).unwrap();
        // A marked directory and NO stamp at all.
        let out = temp("nostamp");
        export(&mods, &out, "l", "d").unwrap();
        refused(&out, "no stamp");
        std::fs::remove_dir_all(&out).unwrap();
        // A zephyr stamp over a directory with no marker.
        let out = temp("nomarker");
        export(&mods, &out, "l", "d").unwrap();
        std::fs::remove_file(out.join("gale").join(MODULE_MARKER)).unwrap();
        stamp(&out, "zephyr-module");
        std::fs::write(out.join("gale/MARKER"), "mine").unwrap();
        refused(&out, "no marker");
        assert!(out.join("gale/MARKER").is_file());
        std::fs::remove_dir_all(&out).unwrap();
        // A marker naming a DIFFERENT module is not this one's.
        let out = temp("wrongmarker");
        export(&mods, &out, "l", "d").unwrap();
        std::fs::write(
            out.join("gale").join(MODULE_MARKER),
            "module: other\nlayer: l\n",
        )
        .unwrap();
        stamp(&out, "zephyr-module");
        refused(&out, "marker names another module");
        std::fs::remove_dir_all(&out).unwrap();
        // A malformed stamp.
        let out = temp("badstamp");
        export(&mods, &out, "l", "d").unwrap();
        std::fs::write(out.join(crate::exportstamp::STAMP_FILE), "{nope").unwrap();
        refused(&out, "malformed stamp");
        std::fs::remove_dir_all(&out).unwrap();
    }

    /// The reviewer's reproduction. The stamp lists EVERYTHING under `--out`,
    /// the user's files included, so a stamp listing `hal/…` proves nothing
    /// about who wrote `hal/`. Only varve's own marker does.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_stamp_that_swept_up_the_users_directory_does_not_license_deleting_it() {
        let out = temp("sweep");
        std::fs::create_dir_all(out.join("hal")).unwrap();
        std::fs::write(out.join("hal/MARKER"), "my own hal").unwrap();
        // 2. export {gale}: the stamp (scan_tree) now lists hal/MARKER too.
        let gale = prepare(&[("gale".to_string(), module("gale", &[]))], None).unwrap();
        export(&gale, &out, "l", "d").unwrap();
        stamp(&out, "zephyr-module");
        let st = crate::exportstamp::read_stamp(&out).unwrap();
        assert!(st.files.iter().any(|f| f.path == "hal/MARKER"));
        // 3. export {gale, hal}: hal/ is NOT varve's.
        let both = prepare(
            &payloads(&[("gale", module("gale", &[])), ("hal", module("hal", &[]))]),
            None,
        )
        .unwrap();
        let e = export(&both, &out, "l", "d").expect_err("hal is the user's");
        assert!(
            matches!(&e, ZephyrModuleError::NotWrittenByVarve { path } if path.ends_with("hal")),
            "{e:?}"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("hal/MARKER")).unwrap(),
            "my own hal"
        );
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_tree_may_not_carry_varves_own_marker_name() {
        for name in [MODULE_MARKER, ".VARVE-ZEPHYR-MODULE"] {
            let a = archive(&[("zephyr/module.yml", "name: x\n"), (name, "module: x\n")]);
            let e = open("p", &a).expect_err(name);
            assert!(matches!(e, ZephyrModuleError::UnsafeMember { .. }), "{e:?}");
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn every_module_directory_carries_the_marker_naming_module_and_layer() {
        let out = temp("marker");
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        export(&mods, &out, "2026.11.0", "sha256:d").unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("x").join(MODULE_MARKER)).unwrap(),
            "module: x\nlayer: 2026.11.0\n"
        );
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_module_dropped_from_a_new_export_is_removed_and_the_users_directories_are_not() {
        let out = temp("leftover");
        let ab = prepare(
            &payloads(&[("a", module("a", &[])), ("b", module("b", &[]))]),
            None,
        )
        .unwrap();
        export(&ab, &out, "l", "d").unwrap();
        stamp(&out, "zephyr-module");
        std::fs::create_dir_all(out.join("mine")).unwrap();
        std::fs::write(out.join("mine/KEEP"), "k").unwrap();
        std::fs::write(out.join("note.txt"), "n").unwrap();
        let a = prepare(&[("a".to_string(), module("a", &[]))], None).unwrap();
        let r = export(&a, &out, "l2", "d2").unwrap();
        assert!(!out.join("b").exists(), "a leftover module survived");
        assert!(out.join("a/zephyr/module.yml").is_file());
        assert!(
            out.join("mine/KEEP").is_file(),
            "a user directory was touched"
        );
        assert!(out.join("note.txt").is_file());
        assert_eq!(r.removed, vec!["b".to_string()]);
        std::fs::remove_dir_all(&out).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn leftovers_are_removed_only_under_our_stamp() {
        for kind in ["cargo", ""] {
            let out = temp("leftover-foreign");
            let ab = prepare(
                &payloads(&[("a", module("a", &[])), ("b", module("b", &[]))]),
                None,
            )
            .unwrap();
            export(&ab, &out, "l", "d").unwrap();
            if !kind.is_empty() {
                stamp(&out, kind);
            }
            let a = prepare(&[("a".to_string(), module("a", &[]))], None).unwrap();
            // `a` is refused here (no zephyr stamp), and b must survive too.
            let _ = export(&a, &out, "l", "d");
            assert!(out.join("b/zephyr/module.yml").is_file(), "{kind:?}");
            std::fs::remove_dir_all(&out).unwrap();
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[cfg(unix)]
    #[test]
    fn the_script_and_the_stamp_are_never_written_through_a_link_or_over_a_foreign_file() {
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        // The script is a symlink.
        let out = temp("script-link");
        let victim = temp("victim");
        std::os::unix::fs::symlink(victim.join("target"), out.join(CMAKE_FILE)).unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("symlinked script");
        assert!(
            matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
            "{e:?}"
        );
        assert!(!victim.join("target").exists(), "written through the link");
        assert!(
            !out.join("x").exists(),
            "refused before any tree is written"
        );
        std::fs::remove_dir_all(&out).unwrap();
        // The script is somebody's regular file, with no stamp of ours.
        let out = temp("script-file");
        std::fs::write(out.join(CMAKE_FILE), "their own cmake").unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("foreign script");
        assert!(
            matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
            "{e:?}"
        );
        assert_eq!(
            std::fs::read_to_string(out.join(CMAKE_FILE)).unwrap(),
            "their own cmake"
        );
        std::fs::remove_dir_all(&out).unwrap();
        // The stamp is a symlink, or another export's.
        let out = temp("stamp-link");
        std::os::unix::fs::symlink(
            victim.join("stamp"),
            out.join(crate::exportstamp::STAMP_FILE),
        )
        .unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("symlinked stamp");
        assert!(
            matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
            "{e:?}"
        );
        assert!(!victim.join("stamp").exists());
        std::fs::remove_dir_all(&out).unwrap();
        let out = temp("stamp-other");
        stamp(&out, "cargo");
        let e = export(&mods, &out, "l", "d").expect_err("another export's stamp");
        assert!(
            matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
            "{e:?}"
        );
        assert!(!out.join("x").exists());
        std::fs::remove_dir_all(&out).unwrap();
        std::fs::remove_dir_all(&victim).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn our_own_script_is_replaced_on_a_re_export() {
        let out = temp("script-ours");
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        export(&mods, &out, "l1", "d").unwrap();
        stamp(&out, "zephyr-module");
        export(&mods, &out, "l2", "d").unwrap();
        let script = std::fs::read_to_string(out.join(CMAKE_FILE)).unwrap();
        assert!(script.contains("# Layer: l2"), "{script}");
        std::fs::remove_dir_all(&out).unwrap();
    }

    /// Nothing is written until everything is known to be writable: a path
    /// CMake cannot carry must not leave the trees behind.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn an_unquotable_out_directory_writes_no_tree_at_all() {
        let base = temp("halfexport");
        let out = base.join("o[ut");
        std::fs::create_dir_all(&out).unwrap();
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("bracket in the path");
        assert!(
            matches!(e, ZephyrModuleError::UnsafeCmakePath { .. }),
            "{e:?}"
        );
        assert!(
            std::fs::read_dir(&out).unwrap().next().is_none(),
            "something was written"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    // -------------------------------------------- pip, re-checked at export

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_rechecks_pip_against_the_signed_opt_in() {
        let pip = |allow: Option<Vec<String>>| {
            vec![ModulePayload {
                name: "py".into(),
                bytes: pip_module(&["scripts/requirements.txt"]),
                allow_pip: allow,
            }]
        };
        // A layer signed before the deposit rule existed: no annotation.
        let e = prepare(&pip(None), None).expect_err("no opt-in");
        assert!(
            matches!(e, ZephyrModuleError::PipWithoutOptIn { .. }),
            "{e:?}"
        );
        let e = prepare(&pip(Some(strings(&["other.txt"]))), None).expect_err("wrong opt-in");
        assert!(
            matches!(e, ZephyrModuleError::PipOptInMismatch { .. }),
            "{e:?}"
        );
        let ok = prepare(&pip(Some(strings(&["scripts/requirements.txt"]))), None).unwrap();
        assert_eq!(ok.len(), 1);
        // An unselected pip module does not block selecting another.
        let two = vec![
            ModulePayload {
                name: "py".into(),
                bytes: pip_module(&["a.txt"]),
                allow_pip: None,
            },
            ModulePayload {
                name: "plain".into(),
                bytes: module("plain", &[]),
                allow_pip: None,
            },
        ];
        assert_eq!(prepare(&two, Some("plain")).unwrap().len(), 1);
        assert!(prepare(&two, Some("py")).is_err());
    }

    /// Two layers of a composition can carry payloads with the SAME payload name
    /// (different versions both export). Each module is judged on ITS OWN signed
    /// opt-in: B declares the same pip files as A and has none, and must not be
    /// passed on A's.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_pip_module_cannot_borrow_the_opt_in_of_a_payload_with_the_same_name() {
        let pip_named = |module_name: &str| {
            archive(&[(
                "zephyr/module.yml",
                &format!(
                    "name: {module_name}\npackage-managers:\n  pip:\n    requirement-files:\n      - r.txt\n"
                ),
            )])
        };
        let a = ModulePayload {
            name: "py".into(),
            bytes: pip_named("py_a"),
            allow_pip: Some(strings(&["r.txt"])),
        };
        let b = ModulePayload {
            name: "py".into(),
            bytes: pip_named("py_b"),
            allow_pip: None,
        };
        for order in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
            let e = prepare(&order, None).expect_err("B has no opt-in of its own");
            assert!(
                matches!(&e, ZephyrModuleError::PipWithoutOptIn { .. }),
                "{e:?}"
            );
        }
        // A alone is fine; so is B with an opt-in of its own.
        prepare(std::slice::from_ref(&a), None).unwrap();
        let b_ok = ModulePayload {
            allow_pip: Some(strings(&["r.txt"])),
            ..b.clone()
        };
        assert_eq!(prepare(&[a.clone(), b_ok], None).unwrap().len(), 2);
        // The SAME module name from two payloads is refused outright.
        let dup = ModulePayload {
            bytes: pip_named("py_a"),
            allow_pip: Some(strings(&["r.txt"])),
            ..b
        };
        let e = prepare(&[a, dup], None).expect_err("one module name twice");
        assert!(
            matches!(e, ZephyrModuleError::DuplicateModule { .. }),
            "{e:?}"
        );
    }

    // ------------------------------------------- YAML tags (the merge bypass)

    const MERGE_SPELLINGS: &[&str] = &[
        "name: gale\npackage-managers:\n  !!merge x: {pip: {requirement-files: [scripts/requirements.txt]}}\n",
        "name: gale\npackage-managers:\n  !<tag:yaml.org,2002:merge> x: {pip: {requirement-files: [r.txt]}}\n",
        "name: gale\npackage-managers:\n  !!merge \"zz\": {pip: {requirement-files: [r.txt]}}\n",
        "name: gale\n!!merge x: {package-managers: {pip: {requirement-files: [r.txt]}}}\n",
        "name: gale\n!!merge x: {build: {depends: [ghost]}}\n",
        "name: gale\nbuild:\n  !!merge x: {depends: [ghost]}\n",
        "!!merge x: {name: other}\n",
        "name: !!str gale\n",
        "name: gale\nbuild:\n  depends: !!seq [a]\n",
        "name: gale\nbuild: !local {cmake: .}\n",
    ];

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn any_yaml_tag_in_module_yml_is_refused_at_every_depth() {
        for yml in MERGE_SPELLINGS {
            let e = parse_module_yml("gale", yml).expect_err(yml);
            assert!(
                matches!(&e, ZephyrModuleError::TaggedModuleYml { payload, .. } if payload == "gale"),
                "{yml:?} -> {e:?}"
            );
            // At deposit, at the archive root and inside a wrapper directory.
            for (path, other) in [
                ("zephyr/module.yml", "CMakeLists.txt"),
                (
                    "wrapper-1.0/zephyr/module.yml",
                    "wrapper-1.0/CMakeLists.txt",
                ),
            ] {
                let a = archive(&[(path, yml), (other, "x")]);
                let e = check_deposit("gale", &a, None).expect_err(yml);
                assert!(
                    matches!(e, ZephyrModuleError::TaggedModuleYml { .. }),
                    "{path} {yml:?}: {e:?}"
                );
            }
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_tag_refusal_names_the_tag() {
        let e = parse_module_yml("gale", MERGE_SPELLINGS[0]).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("merge") && msg.contains("gale"), "{msg}");
        let e = parse_module_yml("gale", "name: !local gale\n").unwrap_err();
        assert!(e.to_string().contains("local"), "{e}");
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_bang_that_is_not_a_tag_is_not_refused() {
        for yml in [
            "name: \"a!!merge b\"\n",
            "name: 'x !!merge y'\nbuild:\n  depends: ['!z', \"!!w\"]\n",
            "# !!merge x: {pip: {}}\nname: gale  # !!str trailing\n",
            "name: gale\ndescription: |\n  !!merge x: {pip: {}}\n  text\nbuild:\n  cmake: .\n",
            "name: gale\ndescription: >\n  !<tag:yaml.org,2002:merge> folded\n",
            "name: gale!\n",
            "name: wow!!\n",
        ] {
            let y = parse_module_yml("gale", yml).unwrap_or_else(|e| panic!("{yml:?}: {e}"));
            assert_eq!(y.pip, None, "{yml:?}");
        }
        // A normal module.yml passes.
        let y =
            parse_module_yml("gale", "name: gale\nbuild:\n  cmake: .\n  depends: [a]\n").unwrap();
        assert_eq!(y.depends, strings(&["a"]));
    }

    /// The untagged merge key `<<` is understood by both parsers, so it must
    /// not hide pip either.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn the_plain_merge_key_cannot_hide_pip_either() {
        let y = parse_module_yml(
            "p",
            "x: &a {pip: {requirement-files: [r.txt]}}\npackage-managers:\n  <<: *a\n",
        );
        // Refusing it is as safe as seeing through it.
        if let Ok(y) = y {
            assert_eq!(y.pip, Some(strings(&["r.txt"])));
        }
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[cfg(unix)]
    #[test]
    fn export_refuses_a_symlinked_module_directory_even_if_stamped() {
        let out = temp("link");
        let elsewhere = temp("elsewhere");
        let mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        export(&mods, &out, "l", "d").unwrap();
        stamp(&out, "zephyr-module");
        std::fs::remove_dir_all(out.join("x")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("x")).unwrap();
        let e = export(&mods, &out, "l", "d").expect_err("symlink at destination");
        assert!(
            matches!(e, ZephyrModuleError::NotWrittenByVarve { .. }),
            "{e:?}"
        );
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
            Err(ZephyrModuleError::NotWrittenByVarve { .. })
        ));
        assert_eq!(std::fs::read_to_string(out.join("x")).unwrap(), "a file");
        std::fs::remove_dir_all(&out).unwrap();
    }

    /// Second guard: files are created, never overwritten. Two members that
    /// land on one path (which a case-insensitive file system turns two
    /// differently-cased names into) must fail rather than let the later win.
    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn export_never_overwrites_a_file_it_wrote_a_moment_ago() {
        let mut mods = prepare(&[("x".to_string(), module("x", &[]))], None).unwrap();
        mods[0].tree.members.push(Member {
            path: "zephyr/module.yml".into(),
            body: MemberBody::File {
                mode: 0o644,
                bytes: b"name: overwritten\n".to_vec(),
            },
        });
        let out = temp("nooverwrite");
        let e = export(&mods, &out, "l", "d").expect_err("second write must fail");
        assert!(matches!(e, ZephyrModuleError::Io { .. }), "{e:?}");
        assert_eq!(
            std::fs::read_to_string(out.join("x/zephyr/module.yml")).unwrap(),
            "name: x\nbuild:\n  cmake: .\n",
            "the first write must be the one that stands"
        );
        std::fs::remove_dir_all(&out).unwrap();
    }

    // ------------------------------------------- case-insensitive collisions

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn members_that_differ_only_in_case_are_refused_at_open() {
        for twin in [
            "zephyr/Module.yml",
            "ZEPHYR/module.yml",
            "Zephyr/MODULE.YML",
        ] {
            let a = archive(&[
                ("zephyr/module.yml", "name: good\n"),
                (twin, "package-managers:\n  pip: {}\n"),
            ]);
            let e = open("p", &a).expect_err(twin);
            assert!(
                matches!(&e, ZephyrModuleError::DuplicateMember { .. }),
                "{twin}: {e:?}"
            );
            assert!(e.to_string().contains("case"), "{e}");
        }
        // Any member, not only module.yml: two files one file system merges.
        let a = archive(&[
            ("zephyr/module.yml", "name: x\n"),
            ("src/A.c", "1"),
            ("src/a.c", "2"),
        ]);
        assert!(matches!(
            open("p", &a),
            Err(ZephyrModuleError::DuplicateMember { .. })
        ));
        // Distinct names are still fine.
        let a = archive(&[
            ("zephyr/module.yml", "name: x\n"),
            ("src/a.c", "1"),
            ("src/b.c", "2"),
        ]);
        open("p", &a).unwrap();
    }

    // rivet: verifies REQ-ZMODEXPORT-001
    #[test]
    fn a_second_module_description_beside_the_parsed_one_is_refused() {
        for twin in ["zephyr/module.yaml", "Zephyr/Module.yaml"] {
            let a = archive(&[("zephyr/module.yml", "name: x\n"), (twin, "name: y\n")]);
            let e = open("p", &a).expect_err(twin);
            assert!(
                matches!(&e, ZephyrModuleError::ModuleYmlCollision { member, .. } if member == twin),
                "{twin}: {e:?}"
            );
        }
        // Also inside a wrapper directory.
        let a = archive(&[
            ("w/zephyr/module.yml", "name: x\n"),
            ("w/zephyr/module.yaml", "name: y\n"),
        ]);
        assert!(matches!(
            open("p", &a),
            Err(ZephyrModuleError::ModuleYmlCollision { .. })
        ));
        // The parsed member itself is not its own collision.
        open("p", &archive(&[("zephyr/module.yml", "name: x\n")])).unwrap();
        // A file that merely sits beside it is fine.
        open(
            "p",
            &archive(&[("zephyr/module.yml", "name: x\n"), ("zephyr/Kconfig", "")]),
        )
        .unwrap();
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
