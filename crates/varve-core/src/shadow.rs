//! PATH shadowing (REQ-SHADOW-001) — does the name actually reach our binary?
//!
//! varve's headline claim, in the README, is `varve which synth  # which binary
//! runs here`. It was not checking. With a distro-packaged tool, a
//! `cargo install`ed one, or a stale shim directory earlier in PATH, `which`
//! printed the store path, `verify` reported the layer perfect, and the shell
//! ran something else. Each answer was individually correct and the composite
//! was false (varve#66).
//!
//! The layer really is intact in that situation — so this is not a signature
//! problem and no amount of re-verification finds it. The gap is between what
//! is SIGNED and what will actually EXECUTE, which is the gap varve exists to
//! close.
//!
//! Resolution here follows the same rules a shell uses: PATH order,
//! left-to-right, first executable regular file wins. Builtins, aliases and
//! shell functions are deliberately out of scope — varve cannot see another
//! process's shell state, and pretending otherwise would produce a check that
//! is wrong in a new direction.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// What PATH does with a tool name, relative to the path varve dispatches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shadowing {
    /// PATH resolves this name to the binary varve dispatches. The claim holds.
    Agrees,
    /// PATH resolves it to something else — the shell runs `found`, not `ours`.
    Shadowed { found: PathBuf },
    /// The name is not on PATH at all. NOT shadowing: no shims installed yet
    /// is a different condition from shims overridden, and treating them alike
    /// would cry wolf on every fresh install.
    NotOnPath,
}

impl Shadowing {
    pub fn is_shadowed(&self) -> bool {
        matches!(self, Shadowing::Shadowed { .. })
    }
}

/// Resolve `name` against a PATH value, as a shell would.
///
/// Split out from the environment so it is testable without mutating the
/// process's own PATH — a test that sets `std::env::set_var("PATH", …)` races
/// every other test in the binary.
pub fn resolve_in(path_var: Option<&OsStr>, name: &str) -> Option<PathBuf> {
    // A name containing a separator is a path, not a PATH lookup — a shell
    // does not search for `./rivet`, and neither do we.
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return None;
    }
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        // POSIX: an empty PATH element means the current directory. Honour it
        // so the answer matches the shell's, however unwise the setting is.
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        // `metadata` follows symlinks, which is what we want: a shim is a
        // symlink and a shell will happily execute through it.
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    // On Windows the executable bit does not exist; presence of the file under
    // one of the PATHEXT-ish names is the practical test, and varve installs
    // copies rather than symlinks there.
    p.is_file()
}

/// Compare what varve dispatches against what PATH would run.
///
/// `dispatcher` is varve's OWN executable. This is not an optimisation — it is
/// the whole correctness of the check. A varve shim is a symlink to the varve
/// binary, not to the pinned tool: running `rivet` executes varve, which reads
/// argv[0] and dispatches the pinned binary (the argv[0] mechanism that
/// replaced the old shell scripts in v0.19.0). So a correctly installed shim
/// canonicalises to varve, NOT to the tool, and a naive path comparison flags
/// every properly configured machine as shadowed.
///
/// An earlier draft did exactly that, and its unit test passed because the
/// test symlinked to the STORE — testing a mechanism varve does not use. The
/// end-to-end run caught it.
pub fn check(
    path_var: Option<&OsStr>,
    name: &str,
    ours: &Path,
    dispatcher: Option<&Path>,
) -> Shadowing {
    let Some(found) = resolve_in(path_var, name) else {
        return Shadowing::NotOnPath;
    };
    let real = found.canonicalize().unwrap_or_else(|_| found.clone());

    // The pinned binary reached directly.
    if let Ok(b) = ours.canonicalize()
        && real == b
    {
        return Shadowing::Agrees;
    }
    // …or reached through our own shim, which is the supported route.
    if let Some(d) = dispatcher
        && let Ok(d) = d.canonicalize()
        && real == d
    {
        return Shadowing::Agrees;
    }
    Shadowing::Shadowed { found }
}

/// The user-facing report, carrying its fix (clause 4).
pub fn describe(name: &str, ours: &Path, found: &Path) -> String {
    format!(
        "`{name}` on your PATH is {found}, not the pinned {ours}.\n\
         Your shell will run the first one; varve dispatches the second, so \
         `varve which` and `varve run` disagree with what you get by typing \
         `{name}`.\n\
         Fix: run `varve shim install` and put the shim directory FIRST on \
         PATH (`. \"$VARVE_ROOT/env\"`, default ~/.varve/env), or remove the \
         earlier entry.",
        found = found.display(),
        ours = ours.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// A directory holding an executable of the given name.
    fn bin_dir(name: &str, body: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        tmp
    }

    fn path_of(dirs: &[&Path]) -> OsString {
        std::env::join_paths(dirs.iter().map(|d| d.to_path_buf())).unwrap()
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn a_different_binary_earlier_on_path_is_reported_as_shadowing() {
        // THE reported bug (varve#66). `varve which rivet` printed the store
        // path while the shell ran something else, and `verify` called the
        // layer perfect — which it was. Nothing looked wrong anywhere.
        let ours_dir = bin_dir("rivet", "#!/bin/sh\necho pinned\n");
        let other = bin_dir("rivet", "#!/bin/sh\necho WRONG\n");
        let ours = ours_dir.path().join("rivet");

        let path = path_of(&[other.path(), ours_dir.path()]);
        let verdict = check(Some(&path), "rivet", &ours, None);
        match &verdict {
            Shadowing::Shadowed { found } => {
                assert_eq!(found, &other.path().join("rivet"), "names the winner");
            }
            other => panic!("expected Shadowed, got {other:?}"),
        }
        assert!(verdict.is_shadowed());

        // Clause 4: the report must be actionable.
        let msg = describe("rivet", &ours, &other.path().join("rivet"));
        assert!(msg.contains("rivet"), "names the tool: {msg}");
        assert!(msg.contains("varve shim install"), "carries its fix: {msg}");
        assert!(
            msg.contains("FIRST on PATH"),
            "says WHERE the shim must go, not merely to install it: {msg}"
        );
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn our_own_binary_first_on_path_agrees() {
        // The correct configuration must not be reported as a conflict, or the
        // check is noise and gets switched off.
        let ours_dir = bin_dir("rivet", "#!/bin/sh\n");
        let other = bin_dir("rivet", "#!/bin/sh\n");
        let ours = ours_dir.path().join("rivet");
        let path = path_of(&[ours_dir.path(), other.path()]);
        assert_eq!(check(Some(&path), "rivet", &ours, None), Shadowing::Agrees);
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn a_real_shim_symlinked_to_varve_itself_agrees() {
        // The shim mechanism as it ACTUALLY ships: `rivet` is a symlink to the
        // varve binary, and varve reads argv[0] to decide what to dispatch. It
        // therefore canonicalises to varve, never to the tool.
        //
        // An earlier version of this test symlinked to the STORE and passed,
        // testing a mechanism varve does not use; the correctly-configured
        // machine then failed end to end with `verify` reporting every single
        // tool as shadowed. Flagging the right configuration is worse than not
        // checking, because it trains people to ignore the check.
        #[cfg(unix)]
        {
            let store = bin_dir("rivet", "#!/bin/sh\n");
            let varve_dir = bin_dir("varve", "#!/bin/sh\n");
            let dispatcher = varve_dir.path().join("varve");
            let shims = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(&dispatcher, shims.path().join("rivet")).unwrap();

            let ours = store.path().join("rivet");
            let path = path_of(&[shims.path()]);
            assert_eq!(
                check(Some(&path), "rivet", &ours, Some(&dispatcher)),
                Shadowing::Agrees,
                "a shim is a symlink to VARVE, not to the tool — it must agree"
            );
            // …and without knowing the dispatcher, the same layout looks like
            // shadowing, which is precisely the bug that shipped.
            assert!(
                check(Some(&path), "rivet", &ours, None).is_shadowed(),
                "this asserts WHY the dispatcher argument exists"
            );
        }
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn a_tool_absent_from_path_is_not_shadowed() {
        // Clause 5. Shims not installed is a DIFFERENT condition from shims
        // overridden. Reporting the first as the second would make every fresh
        // install look compromised.
        let ours_dir = bin_dir("rivet", "#!/bin/sh\n");
        let empty = tempfile::tempdir().unwrap();
        let path = path_of(&[empty.path()]);
        assert_eq!(
            check(Some(&path), "rivet", &ours_dir.path().join("rivet"), None),
            Shadowing::NotOnPath
        );
        // …and with no PATH at all.
        assert_eq!(
            check(None, "rivet", &ours_dir.path().join("rivet"), None),
            Shadowing::NotOnPath
        );
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn resolution_follows_path_order_and_the_executable_bit() {
        // Clause 1: same rules as a shell. A non-executable file of the right
        // name must not win — a shell skips it, and a check that stops there
        // would report a phantom conflict against a README or a directory.
        let first = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("rivet"), "not executable").unwrap();
        std::fs::create_dir(first.path().join("also")).unwrap();
        let second = bin_dir("rivet", "#!/bin/sh\n");

        let path = path_of(&[first.path(), second.path()]);
        assert_eq!(
            resolve_in(Some(&path), "rivet"),
            Some(second.path().join("rivet")),
            "a non-executable file of the same name is skipped, as a shell skips it"
        );

        // A directory named like the tool is not the tool either.
        let dir_named = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir_named.path().join("rivet")).unwrap();
        let path2 = path_of(&[dir_named.path(), second.path()]);
        assert_eq!(
            resolve_in(Some(&path2), "rivet"),
            Some(second.path().join("rivet"))
        );
    }

    // rivet: verifies REQ-SHADOW-001
    #[test]
    fn a_name_with_a_separator_is_not_a_path_lookup() {
        // A shell does not search PATH for `./rivet` or `bin/rivet`, and
        // neither may we — otherwise a relative name would be resolved against
        // every PATH entry and could match something unrelated.
        let d = bin_dir("rivet", "#!/bin/sh\n");
        let path = path_of(&[d.path()]);
        assert_eq!(resolve_in(Some(&path), "./rivet"), None);
        assert_eq!(resolve_in(Some(&path), "bin/rivet"), None);
        assert_eq!(resolve_in(Some(&path), ""), None);
    }
}
