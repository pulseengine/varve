//! Turning verified bytes into the files a deposit spec points at
//! (REQ-PRODUCER-002).
//!
//! Three payload kinds reach this module and they are staged differently:
//!
//! * a **tarball** is unpacked and one binary is taken out of it;
//! * a **raw per-platform** asset already IS the binary;
//! * a **vsix** is the payload itself and is never unpacked.
//!
//! What they share is the rule that the staged file must be the verified
//! bytes. For the two that are copied straight through this is trivially true.
//! For a tarball it is not — the archive is what the proof covers, and the
//! binary inside it is chosen by this program. That choice is therefore the
//! one place a verified archive can still yield an unverified file, which is
//! why [`crate::extract::choose_binary`] refuses ambiguity instead of taking
//! the first match the way `find … | head -1` did.

use crate::extract::{self, Candidate, ExtractError};
use crate::gh::CommandRunner;
use crate::plan::PayloadKind;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// No unpacker is known for this archive's name.
    UnknownArchive {
        asset: String,
    },
    Extract(ExtractError),
    Io {
        context: String,
        detail: String,
    },
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageError::UnknownArchive { asset } => write!(
                f,
                "{asset}: no unpacker is known for this archive. Refusing rather \
                 than guessing — an archive opened with the wrong tool either \
                 fails loudly or, worse, yields a file that is not what the \
                 proof covered."
            ),
            StageError::Extract(e) => write!(f, "{e}"),
            StageError::Io { context, detail } => write!(f, "{context}: {detail}"),
        }
    }
}

impl std::error::Error for StageError {}

/// How to open an archive, chosen by name.
///
/// Returned as data rather than executed here so the choice is testable
/// without unpacking anything. `.vsix` is a zip, but it is never unpacked —
/// it appears here only because getting that wrong would silently stage an
/// extension's *contents* in place of the extension.
pub fn unpack_argv(
    asset: &str,
    archive: &str,
    dest: &str,
) -> Result<(String, Vec<String>), StageError> {
    let lower = asset.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        return Ok((
            "tar".into(),
            vec!["xzf".into(), archive.into(), "-C".into(), dest.into()],
        ));
    }
    if lower.ends_with(".zip") {
        return Ok((
            "unzip".into(),
            vec!["-q".into(), archive.into(), "-d".into(), dest.into()],
        ));
    }
    Err(StageError::UnknownArchive {
        asset: asset.to_string(),
    })
}

/// Where a staged payload is written, relative to the stage root.
///
/// The platform is part of the filename because one layer carries the same
/// tool for four platforms, and a layout that collided would deposit whichever
/// arrived last under every platform's name — a payload that runs on one
/// machine and is silently wrong on three.
pub fn staged_path(kind: PayloadKind, name: &str, version: &str, platform: Option<&str>) -> String {
    match kind {
        PayloadKind::Vsix => match platform {
            Some(p) => format!("vsix/{name}-{p}-{version}.vsix"),
            None => format!("vsix/{name}-{version}.vsix"),
        },
        PayloadKind::Tarball | PayloadKind::RawPerPlatform => match platform {
            Some(p) => format!("tools/{name}-{p}"),
            None => format!("tools/{name}"),
        },
    }
}

/// Every regular file under `dir`, as extraction candidates.
///
/// Whole-tree, not a guess at the layout: repos differ on whether the binary
/// sits at the archive root or inside a versioned directory, and a walker that
/// assumed either would stage nothing for half the toolchain.
pub fn candidates(dir: &Path) -> Result<Vec<Candidate>, StageError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| StageError::Io {
            context: format!("reading {}", d.display()),
            detail: e.to_string(),
        })?;
        for e in entries {
            let e = e.map_err(|e| StageError::Io {
                context: format!("reading {}", d.display()),
                detail: e.to_string(),
            })?;
            let path = e.path();
            // Symlinks are not followed: a link can point outside the
            // extraction, and staging its target would stage a file the proof
            // never covered.
            let meta = std::fs::symlink_metadata(&path).map_err(|e| StageError::Io {
                context: format!("stat {}", path.display()),
                detail: e.to_string(),
            })?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.push(Candidate {
                    executable: is_executable(&meta),
                    path,
                });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

// No non-unix fallback, deliberately. All four platforms a layer carries are
// unix, and the only fallback available on Windows would be to report every
// file as executable — which does not weaken `choose_binary`'s check so much as
// make it vacuous, answering "is this the binary?" with yes for the README.
// A crate that will not build is a problem someone fixes; a check that always
// says yes is one nobody notices.
#[cfg(not(unix))]
compile_error!(
    "varve-producer stages payloads for unix targets only: the executable bit \
     is load-bearing in choosing a binary out of an archive, and no meaningful \
     equivalent exists to substitute for it here."
);

/// Unpack an archive and pick the one binary out of it.
pub fn extract_binary<R: CommandRunner>(
    runner: &R,
    asset: &str,
    archive: &Path,
    dest: &Path,
    binary_name: &str,
) -> Result<PathBuf, StageError> {
    std::fs::create_dir_all(dest).map_err(|e| StageError::Io {
        context: format!("creating {}", dest.display()),
        detail: e.to_string(),
    })?;
    let (prog, args) = unpack_argv(asset, &archive.to_string_lossy(), &dest.to_string_lossy())?;
    let out = runner.run(&prog, &args, &[]);
    if !out.ok() {
        return Err(StageError::Io {
            context: format!("unpacking {asset} with {prog}"),
            detail: out.stderr.trim().to_string(),
        });
    }
    let found = candidates(dest)?;
    extract::choose_binary(binary_name, &found).map_err(StageError::Extract)
}

/// Copy staged bytes into place, making a tool executable.
pub fn place(from: &Path, to: &Path, executable: bool) -> Result<(), StageError> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StageError::Io {
            context: format!("creating {}", parent.display()),
            detail: e.to_string(),
        })?;
    }
    std::fs::copy(from, to).map_err(|e| StageError::Io {
        context: format!("staging {} -> {}", from.display(), to.display()),
        detail: e.to_string(),
    })?;
    if executable {
        set_executable(to)?;
    }
    Ok(())
}

fn set_executable(p: &Path) -> Result<(), StageError> {
    use std::os::unix::fs::PermissionsExt;
    // `choose_binary` has already refused an extraction where nothing of this
    // name is executable, so this is not rescuing that case. It is here because
    // whether a copy carries permissions across is a platform detail, and a
    // shim dispatching to a file that lost its executable bit fails at the
    // worst possible moment — after install, on first use.
    let mut perm = std::fs::metadata(p)
        .map_err(|e| StageError::Io {
            context: format!("stat {}", p.display()),
            detail: e.to_string(),
        })?
        .permissions();
    perm.set_mode(perm.mode() | 0o755);
    std::fs::set_permissions(p, perm).map_err(|e| StageError::Io {
        context: format!("chmod {}", p.display()),
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn archives_are_opened_with_the_tool_their_name_implies() {
        let (p, a) = unpack_argv("x-v1-linux.tar.gz", "/d/x.tar.gz", "/e").unwrap();
        assert_eq!(p, "tar");
        assert_eq!(a, ["xzf", "/d/x.tar.gz", "-C", "/e"]);
        let (p, a) = unpack_argv("x.tgz", "/d/x.tgz", "/e").unwrap();
        assert_eq!(p, "tar");
        assert_eq!(a[0], "xzf");
        let (p, a) = unpack_argv("x.zip", "/d/x.zip", "/e").unwrap();
        assert_eq!(p, "unzip");
        assert_eq!(a, ["-q", "/d/x.zip", "-d", "/e"]);
    }

    /// Guessing an unpacker is how a verified archive yields a file the proof
    /// never covered.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_archive_with_no_known_unpacker_is_refused_rather_than_guessed_at() {
        for a in ["x.tar.bz2", "x.7z", "x", "x.tar"] {
            let e = unpack_argv(a, "/d/x", "/e").expect_err("must refuse");
            assert!(matches!(e, StageError::UnknownArchive { .. }), "{a}: {e:?}");
        }
        // A .vsix is a zip, but it is a payload, never an extraction. It has no
        // unpacker here on purpose.
        assert!(unpack_argv("ext.vsix", "/d/x", "/e").is_err());
    }

    /// One layer carries the same tool for four platforms. A layout that
    /// collided would stage whichever arrived last under every platform's
    /// name: a payload that runs on one machine and is silently wrong on the
    /// other three.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn each_platform_gets_its_own_staged_filename() {
        let paths: Vec<String> = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
            .iter()
            .map(|p| staged_path(PayloadKind::Tarball, "rivet", "0.34.0", Some(p)))
            .collect();
        assert_ne!(paths[0], paths[1]);
        assert!(paths[0].starts_with("tools/rivet-"), "{paths:?}");

        let a = staged_path(PayloadKind::Vsix, "ext", "1.0.0", Some("linux-x64"));
        let b = staged_path(PayloadKind::Vsix, "ext", "1.0.0", None);
        assert_ne!(a, b);
        assert!(a.starts_with("vsix/") && a.ends_with(".vsix"), "{a}");
        assert!(b.ends_with("ext-1.0.0.vsix"), "{b}");
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_raw_per_platform_payload_is_staged_like_a_tool_not_an_extension() {
        assert_eq!(
            staged_path(PayloadKind::RawPerPlatform, "wsc", "0.6.0", Some("linux")),
            "tools/wsc-linux"
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("varve-stage-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    /// Repos differ on whether the binary sits at the archive root or in a
    /// versioned subdirectory. A walker that assumed either would stage
    /// nothing for half the toolchain.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_binary_is_found_however_deeply_the_archive_nests_it() {
        let d = scratch("nested");
        std::fs::create_dir_all(d.join("rivet-0.34.0/bin")).unwrap();
        let bin = d.join("rivet-0.34.0/bin/rivet");
        std::fs::write(&bin, b"elf").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(d.join("README"), b"x").unwrap();
        let found = candidates(&d).expect("walks");
        let chosen = extract::choose_binary("rivet", &found).expect("finds it");
        assert!(chosen.ends_with("rivet-0.34.0/bin/rivet"), "{chosen:?}");
    }

    /// The executable bit is how `choose_binary` tells a binary from a README
    /// that happens to share its name. If the walk reported every file as
    /// executable, that check would be answering a question about nothing.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_walk_reports_the_executable_bit_it_actually_finds() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("execbit");
        for (name, mode) in [("runnable", 0o755), ("data", 0o644)] {
            let p = d.join(name);
            std::fs::write(&p, b"x").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let found = candidates(&d).expect("walks");
        let by = |n: &str| {
            found
                .iter()
                .find(|c| c.path.file_name().unwrap() == n)
                .unwrap_or_else(|| panic!("{n} missing"))
                .executable
        };
        assert!(by("runnable"), "an executable file was reported as data");
        assert!(!by("data"), "a data file was reported as executable");
    }

    /// A file sharing the binary's name but not executable must not be staged
    /// as the binary.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_non_executable_namesake_is_not_mistaken_for_the_binary() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("namesake");
        std::fs::create_dir_all(d.join("doc")).unwrap();
        let p = d.join("doc/rivet");
        std::fs::write(&p, b"not a binary").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let found = candidates(&d).expect("walks");
        let e = extract::choose_binary("rivet", &found).expect_err("must refuse");
        assert!(matches!(e, ExtractError::NoneExecutable { .. }), "{e:?}");
    }

    /// Unpacks by writing what a real `tar` would have written, so the whole
    /// path — argv, extraction, walk, choice — is exercised.
    struct FakeTar {
        writes: Vec<(String, u32)>,
        fail: bool,
    }

    impl CommandRunner for FakeTar {
        fn run(
            &self,
            program: &str,
            args: &[String],
            _e: &[(String, String)],
        ) -> crate::gh::RunOutput {
            if self.fail {
                return crate::gh::RunOutput {
                    code: 2,
                    stdout: String::new(),
                    stderr: "gzip: unexpected end of file".into(),
                };
            }
            assert_eq!(program, "tar");
            let dest = args
                .iter()
                .position(|a| a == "-C")
                .and_then(|i| args.get(i + 1))
                .expect("the argv must say where to extract");
            for (rel, mode) in &self.writes {
                let p = Path::new(dest).join(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"elf").unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(*mode)).unwrap();
                }
            }
            crate::gh::RunOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
    }

    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn extracting_a_tarball_yields_the_one_binary_inside_it() {
        let d = scratch("extract-ok");
        let runner = FakeTar {
            writes: vec![
                ("rivet-0.34.0/rivet".to_string(), 0o755),
                ("rivet-0.34.0/README".to_string(), 0o644),
            ],
            fail: false,
        };
        let got = extract_binary(
            &runner,
            "rivet-v0.34.0-linux.tar.gz",
            &d.join("archive.tar.gz"),
            &d.join("extract"),
            "rivet",
        )
        .expect("extracts");
        assert!(got.ends_with("rivet-0.34.0/rivet"), "{got:?}");
    }

    /// A failed unpack must stop the payload. Continuing would walk an empty
    /// or half-written directory and either stage nothing or stage the wrong
    /// file — the archive's failure showing up much later as a missing tool.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn an_unpack_that_failed_is_not_treated_as_an_empty_archive() {
        let d = scratch("extract-fail");
        let runner = FakeTar {
            writes: vec![],
            fail: true,
        };
        let e = extract_binary(
            &runner,
            "x.tar.gz",
            &d.join("a.tar.gz"),
            &d.join("extract"),
            "rivet",
        )
        .expect_err("must refuse");
        match &e {
            StageError::Io { context, detail } => {
                assert!(context.contains("unpacking x.tar.gz"), "{context}");
                assert!(detail.contains("unexpected end of file"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// The refusals have to say what happened; an empty message is a refusal
    /// nobody can act on.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn every_stage_refusal_explains_itself() {
        let unknown = StageError::UnknownArchive {
            asset: "x.7z".into(),
        }
        .to_string();
        assert!(
            unknown.contains("x.7z") && unknown.contains("no unpacker"),
            "{unknown}"
        );
        let io = StageError::Io {
            context: "unpacking x".into(),
            detail: "boom".into(),
        }
        .to_string();
        assert_eq!(io, "unpacking x: boom");
        let ex = StageError::Extract(ExtractError::NoneExecutable {
            name: "rivet".into(),
            found: vec!["doc/rivet".into()],
        })
        .to_string();
        assert!(ex.contains("rivet"), "{ex}");
    }

    /// A symlink can point outside the extraction. Following one would stage a
    /// file the proof never covered.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn symlinks_are_not_followed_out_of_the_extraction() {
        let d = scratch("symlink");
        let outside = scratch("symlink-outside");
        std::fs::write(outside.join("rivet"), b"not from the archive").unwrap();
        std::os::unix::fs::symlink(outside.join("rivet"), d.join("rivet")).unwrap();
        let found = candidates(&d).expect("walks");
        assert!(
            found.is_empty(),
            "a symlink was staged as if it came from the archive: {found:?}"
        );
    }

    /// Whether a copy preserves permissions is a platform detail; a shim
    /// dispatching to a file that lost its executable bit fails after install,
    /// on first use. (An archive in which NOTHING of the name is executable is
    /// refused earlier, by choose_binary — this is the copy, not that check.)
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_staged_tool_is_executable_even_if_the_archive_forgot() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("chmod");
        let src = d.join("src");
        std::fs::write(&src, b"elf").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dst = d.join("tools/rivet-linux");
        place(&src, &dst, true).expect("stages");
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "{mode:o}");
        assert_eq!(std::fs::read(&dst).unwrap(), b"elf");
    }

    /// A vsix is copied through, not made executable and not unpacked.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn a_vsix_is_staged_as_the_payload_it_is() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("vsix");
        let src = d.join("ext.vsix");
        std::fs::write(&src, b"PK\x03\x04").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dst = d.join("vsix/ext-1.0.0.vsix");
        place(&src, &dst, false).expect("stages");
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o111,
            0,
            "an extension must not be marked executable"
        );
    }
}
