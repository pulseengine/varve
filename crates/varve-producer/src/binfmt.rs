//! Does this file's architecture match the platform it is deposited under?
//! (REQ-PAYLOADSMOKE-001)
//!
//! Everything else the producer verifies answers one question: are these the
//! bytes upstream published? A signed sums file establishes that, and the
//! digest in the layer transcribes it. **None of it establishes that the bytes
//! are a working tool for the platform they are filed under.**
//!
//! An upstream that ships an x86_64 binary inside its `aarch64` tarball
//! produces a layer that assembles, signs, publishes and installs perfectly.
//! The digest is right — it faithfully records the wrong file. The failure
//! surfaces on a consumer's machine as `cannot execute binary file`, which is
//! the one place nobody can fix it.
//!
//! So the header is read. Reading, not executing: a deposit runs on one
//! machine and ships four platforms, and a check that only covers the runner's
//! own architecture would miss three quarters of the layer.

use std::fmt;

/// The machine an executable declares itself built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    /// The architecture a Rust target triple names.
    pub fn of_triple(triple: &str) -> Option<Arch> {
        match triple.split('-').next()? {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" => Some(Arch::Aarch64),
            _ => None,
        }
    }
}

/// What a file's header says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Elf(Arch),
    MachO(Arch),
    /// A `#!` script. A legitimate payload, but it is not architecture-bound,
    /// so it is reported rather than checked.
    Script,
    /// A recognised container varve deliberately does not resolve: a universal
    /// Mach-O holds several architectures at once.
    MachOUniversal,
    /// Not a format this knows. Not necessarily wrong — but the operator
    /// should see it before signing.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchError {
    /// The header says one architecture, the layer files it under another.
    Mismatch {
        path: String,
        platform: String,
        declared: Arch,
        expected: Arch,
    },
    /// Too short to have a header at all — a truncated download hashes
    /// perfectly and is not a program.
    TooShort { path: String, len: usize },
}

impl fmt::Display for ArchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchError::Mismatch {
                path,
                platform,
                declared,
                expected,
            } => write!(
                f,
                "{path} is a {} binary but is being deposited as {platform}, \
                 which needs {}. The digest of this file is correct — it is \
                 faithfully recording the wrong file, which is why nothing else \
                 in the pipeline notices. Upstream has almost certainly shipped \
                 the wrong binary inside that archive; a consumer would discover \
                 it as 'cannot execute binary file'.",
                declared.as_str(),
                expected.as_str()
            ),
            ArchError::TooShort { path, len } => write!(
                f,
                "{path} is {len} byte(s) — too short to be an executable. A \
                 truncated download hashes perfectly and is not a program."
            ),
        }
    }
}

impl std::error::Error for ArchError {}

/// What a Linux payload needs from the machine it lands on
/// (REQ-LIBCSTATED-001).
///
/// The platform key a payload is filed under says `-unknown-linux-gnu`
/// whether its bytes are glibc-linked or a static musl build, because the key
/// names the SLOT a consumer resolves by, not the libc. So the layer has been
/// stating a portability floor it does not measure: layer 2026.10.1 files
/// `ordeal` under `x86_64-unknown-linux-gnu` from an asset named
/// `...-unknown-linux-musl.tar.gz`, and nothing in the signed manifest says
/// which it is. A consumer could only tell by reading the asset FILENAME —
/// the inference varve refuses everywhere else, and here the signed
/// annotation is the misleading one.
///
/// So it is MEASURED, from the same place the architecture is: the ELF
/// program headers. A dynamic executable names its interpreter in `PT_INTERP`
/// and that string is the floor — `/lib64/ld-linux-x86-64.so.2` means glibc,
/// `/lib/ld-musl-x86_64.so.1` means musl. An executable with no `PT_INTERP`
/// needs nothing and runs on a distroless image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linkage {
    /// No `PT_INTERP`: nothing is required of the host's libc.
    Static,
    /// Dynamically linked against musl.
    Musl,
    /// Dynamically linked against glibc.
    Glibc,
    /// A `PT_INTERP` naming something else. Reported verbatim rather than
    /// guessed at, because an interpreter varve does not recognise is a fact
    /// the operator should see before signing, not one to round off.
    Other(String),
}

impl Linkage {
    /// The value recorded in the signed manifest.
    pub fn as_str(&self) -> &str {
        match self {
            Linkage::Static => "static",
            Linkage::Musl => "musl",
            Linkage::Glibc => "glibc",
            Linkage::Other(interp) => interp,
        }
    }
}

// Bounds-checked little/big-endian reads. Every ELF field below goes through
// these rather than through indexing: a malformed or truncated payload is an
// input varve is handed by an upstream, so a panic here would be a producer
// crash on someone else's bad release.
fn u16_at(b: &[u8], off: usize, little: bool) -> Option<u16> {
    let raw: [u8; 2] = b.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn u64_at(b: &[u8], off: usize, little: bool) -> Option<u64> {
    let raw: [u8; 8] = b.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

/// Read a 64-bit ELF's `PT_INTERP`, or `None` for anything that is not one.
///
/// `None` means "not measurable here" — a Mach-O, a script, a 32-bit ELF, a
/// truncated file — and is deliberately NOT reported as `Static`. Absence of
/// evidence is not a portability guarantee, and recording one would be a
/// signed claim nobody checked.
pub fn linkage(bytes: &[u8]) -> Option<Linkage> {
    const ELF_CLASS64: u8 = 2;
    const PT_INTERP: u32 = 3;

    if !bytes.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return None;
    }
    if *bytes.get(4)? != ELF_CLASS64 {
        return None;
    }
    let little = *bytes.get(5)? == 1;

    let e_phoff = u64_at(bytes, 32, little)?;
    let e_phentsize = u16_at(bytes, 54, little)? as usize;
    let e_phnum = u16_at(bytes, 56, little)? as usize;
    // A program header is 56 bytes in ELF64. A smaller `e_phentsize` cannot
    // hold one, and a file claiming otherwise is malformed rather than
    // interesting.
    if e_phentsize < 56 {
        return None;
    }
    let phoff = usize::try_from(e_phoff).ok()?;

    for i in 0..e_phnum {
        let entry = phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        let p_type = {
            let raw: [u8; 4] = bytes.get(entry..entry.checked_add(4)?)?.try_into().ok()?;
            if little {
                u32::from_le_bytes(raw)
            } else {
                u32::from_be_bytes(raw)
            }
        };
        if p_type != PT_INTERP {
            continue;
        }
        let p_offset = usize::try_from(u64_at(bytes, entry.checked_add(8)?, little)?).ok()?;
        let p_filesz = usize::try_from(u64_at(bytes, entry.checked_add(32)?, little)?).ok()?;
        let raw = bytes.get(p_offset..p_offset.checked_add(p_filesz)?)?;
        // The interpreter is a NUL-terminated string occupying the segment.
        let text = raw.split(|b| *b == 0).next().unwrap_or(raw);
        let interp = String::from_utf8_lossy(text).into_owned();
        return Some(if interp.contains("ld-musl") {
            Linkage::Musl
        } else if interp.contains("ld-linux") || interp.contains("ld.so") {
            Linkage::Glibc
        } else {
            Linkage::Other(interp)
        });
    }
    // An ELF64 with program headers and no PT_INTERP asks nothing of the host.
    Some(Linkage::Static)
}

/// Identify a file from its leading bytes.
pub fn identify(bytes: &[u8]) -> Format {
    if bytes.starts_with(b"#!") {
        return Format::Script;
    }
    // ELF: 0x7F "ELF", then class/data, and e_machine as a 16-bit field at
    // offset 18 whose endianness is declared by EI_DATA at offset 5.
    if bytes.starts_with(&[0x7F, b'E', b'L', b'F']) && bytes.len() >= 20 {
        let little = bytes[5] == 1;
        let machine = if little {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else {
            u16::from_be_bytes([bytes[18], bytes[19]])
        };
        return match machine {
            0x3E => Format::Elf(Arch::X86_64),
            0xB7 => Format::Elf(Arch::Aarch64),
            _ => Format::Unknown,
        };
    }
    if bytes.len() >= 8 {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        // Mach-O 64-bit, little-endian host order (0xFEEDFACF).
        if magic == 0xFEED_FACF {
            let cputype = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            return match cputype {
                0x0100_0007 => Format::MachO(Arch::X86_64),
                0x0100_000C => Format::MachO(Arch::Aarch64),
                _ => Format::Unknown,
            };
        }
        // A universal ("fat") binary carries several architectures; the magic
        // is big-endian by definition.
        let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if be == 0xCAFE_BABE || be == 0xCAFE_BABF {
            return Format::MachOUniversal;
        }
    }
    Format::Unknown
}

/// The check itself: refuse a payload whose architecture contradicts the
/// platform it is filed under.
///
/// A script, a universal binary, or an unrecognised format is NOT an error —
/// each can be a legitimate payload — but the caller is told, because "varve
/// cannot identify this" is a fact worth seeing before signing.
pub fn check_platform(path: &str, bytes: &[u8], platform: &str) -> Result<Format, ArchError> {
    if bytes.len() < 4 {
        return Err(ArchError::TooShort {
            path: path.to_string(),
            len: bytes.len(),
        });
    }
    let format = identify(bytes);
    let declared = match format {
        Format::Elf(a) | Format::MachO(a) => a,
        _ => return Ok(format),
    };
    // A platform varve does not map is not something to fail on here; the
    // deposit spec's own platform validation owns that.
    let Some(expected) = Arch::of_triple(platform) else {
        return Ok(format);
    };
    if declared != expected {
        return Err(ArchError::Mismatch {
            path: path.to_string(),
            platform: platform.to_string(),
            declared,
            expected,
        });
    }
    Ok(format)
}

#[cfg(test)]
mod tests {
    /// Real release binaries, not synthesised headers.
    ///
    /// The fixtures are the first 1 KiB of the x86_64 Linux `ordeal` v0.24.0
    /// binaries — the gnu one and the musl one from the SAME release, which is
    /// the pair layer 2026.10.1 files under one platform key and cannot tell
    /// apart. Everything `linkage` reads lives below offset 764, so a prefix
    /// carries all of it. `file(1)` is the independent oracle: the musl asset
    /// is "static-pie linked" with no interpreter, the gnu asset names
    /// `/lib64/ld-linux-x86-64.so.2`.
    ///
    /// REQUIRED, not skipped when absent. A gate that passes because its
    /// fixture is missing is the vacuous shape this repo keeps finding, and
    /// 2 KiB is no reason to accept one.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn real_release_binaries_report_the_libc_they_actually_need() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        for (name, want) in [
            ("ordeal-musl.elfhead", super::Linkage::Static),
            ("ordeal-gnu.elfhead", super::Linkage::Glibc),
        ] {
            let path = dir.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("fixture {} is required: {e}", path.display()));
            assert_eq!(
                super::linkage(&bytes).as_ref(),
                Some(&want),
                "{name}: measured the wrong floor"
            );
        }
    }

    /// The interpreter string is reported verbatim when varve does not know it,
    /// and a non-ELF is `None` rather than `Static`.
    ///
    /// `None` and `Static` are the distinction that matters: absence of
    /// evidence is not a portability guarantee, and recording one would be a
    /// signed claim nobody checked.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn an_unmeasurable_payload_is_not_reported_as_static() {
        assert_eq!(super::linkage(b"#!/bin/sh\necho hi\n"), None, "a script");
        assert_eq!(super::linkage(b""), None, "empty");
        assert_eq!(
            super::linkage(b"\x7fELF"),
            None,
            "truncated before EI_CLASS"
        );
        // ELF32 is not measured here rather than guessed at.
        let mut elf32 = vec![0x7F, b'E', b'L', b'F', 1, 1];
        elf32.resize(128, 0);
        assert_eq!(super::linkage(&elf32), None, "ELF32");
    }

    /// `e_phentsize` is a SIZE, not a magic number: 56 is the ELF64 minimum,
    /// and a loader-legal file may use a larger one.
    ///
    /// Both real fixtures carry exactly 56, so the comparison in `linkage` was
    /// invisible to every test — the mutation gate caught `<` flipped to `>`
    /// surviving, which would refuse a legal binary with padded program
    /// headers while still accepting a malformed one. The table is rebuilt at
    /// the wider stride from the REAL fixture's own headers, so only the
    /// stride differs from a file that is known to measure correctly.
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn a_program_header_larger_than_the_minimum_is_still_measured() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        let real = std::fs::read(dir.join("ordeal-gnu.elfhead")).expect("fixture");
        assert_eq!(
            super::linkage(&real),
            Some(super::Linkage::Glibc),
            "the unmodified fixture must measure, or this test proves nothing"
        );

        let phoff = u64::from_le_bytes(real[32..40].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(real[54..56].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(real[56..58].try_into().unwrap()) as usize;
        assert_eq!(phentsize, 56, "fixture assumption: the ELF64 minimum");

        // Re-emit the same program headers at a 64-byte stride, appended past
        // the original content so every `p_offset` still resolves.
        const WIDE: usize = 64;
        let mut wide = real.clone();
        let new_phoff = wide.len();
        for i in 0..phnum {
            let entry = &real[phoff + i * phentsize..phoff + (i + 1) * phentsize];
            wide.extend_from_slice(entry);
            wide.extend_from_slice(&[0u8; WIDE - 56]);
        }
        wide[32..40].copy_from_slice(&(new_phoff as u64).to_le_bytes());
        wide[54..56].copy_from_slice(&(WIDE as u16).to_le_bytes());

        assert_eq!(
            super::linkage(&wide),
            Some(super::Linkage::Glibc),
            "a 64-byte program header entry is legal and must still be read"
        );
    }

    /// An `e_phentsize` too small to hold an ELF64 program header is
    /// malformed, and measuring it would mean parsing at a stride the file
    /// does not use.
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn a_program_header_too_small_to_hold_one_is_not_measured() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        let mut bytes = std::fs::read(dir.join("ordeal-gnu.elfhead")).expect("fixture");
        bytes[54..56].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(
            super::linkage(&bytes),
            None,
            "a 32-byte program header cannot hold an ELF64 one"
        );
    }

    /// A musl interpreter is recognised as musl, not rounded to glibc.
    ///
    /// Built by rewriting the REAL gnu fixture's `PT_INTERP` string, so the
    /// surrounding header is a genuine one and only the one field under test
    /// differs.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_musl_interpreter_is_not_rounded_to_glibc() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        let mut bytes = std::fs::read(dir.join("ordeal-gnu.elfhead")).expect("fixture");
        let gnu = b"/lib64/ld-linux-x86-64.so.2";
        let at = bytes
            .windows(gnu.len())
            .position(|w| w == gnu)
            .expect("the real fixture names the glibc interpreter");
        let musl = b"/lib/ld-musl-x86_64.so.1\0\0\0";
        assert_eq!(
            musl.len(),
            gnu.len(),
            "same length keeps every offset valid"
        );
        bytes[at..at + musl.len()].copy_from_slice(musl);
        assert_eq!(super::linkage(&bytes), Some(super::Linkage::Musl));
    }

    use super::*;

    fn elf(machine: u16, little: bool) -> Vec<u8> {
        let mut v = vec![0u8; 20];
        v[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        v[4] = 2; // 64-bit
        v[5] = if little { 1 } else { 2 };
        let m = if little {
            machine.to_le_bytes()
        } else {
            machine.to_be_bytes()
        };
        v[18] = m[0];
        v[19] = m[1];
        v
    }

    fn macho(cputype: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
        v.extend_from_slice(&cputype.to_le_bytes());
        v
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn elf_architectures_are_read_from_the_header() {
        assert_eq!(identify(&elf(0x3E, true)), Format::Elf(Arch::X86_64));
        assert_eq!(identify(&elf(0xB7, true)), Format::Elf(Arch::Aarch64));
    }

    /// A big-endian ELF declares its own byte order at EI_DATA; reading the
    /// machine field little-endian regardless would misidentify it.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_big_endian_elf_is_read_in_its_own_byte_order() {
        assert_eq!(identify(&elf(0xB7, false)), Format::Elf(Arch::Aarch64));
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn mach_o_architectures_are_read_from_the_header() {
        assert_eq!(identify(&macho(0x0100_0007)), Format::MachO(Arch::X86_64));
        assert_eq!(identify(&macho(0x0100_000C)), Format::MachO(Arch::Aarch64));
    }

    /// THE case this module exists for: upstream ships the wrong binary inside
    /// an architecture's archive. The digest is correct and records the wrong
    /// file, so nothing else in the pipeline can see it.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn an_x86_binary_filed_as_aarch64_is_refused() {
        let err = check_platform("tools/rivet", &elf(0x3E, true), "aarch64-unknown-linux-gnu")
            .expect_err("must refuse");
        assert_eq!(
            err,
            ArchError::Mismatch {
                path: "tools/rivet".into(),
                platform: "aarch64-unknown-linux-gnu".into(),
                declared: Arch::X86_64,
                expected: Arch::Aarch64,
            }
        );
        assert!(
            err.to_string()
                .contains("faithfully recording the wrong file"),
            "{err}"
        );
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_matching_architecture_passes_for_every_platform_the_layer_carries() {
        for (triple, bytes) in [
            ("x86_64-unknown-linux-gnu", elf(0x3E, true)),
            ("aarch64-unknown-linux-gnu", elf(0xB7, true)),
            ("x86_64-apple-darwin", macho(0x0100_0007)),
            ("aarch64-apple-darwin", macho(0x0100_000C)),
        ] {
            check_platform("t", &bytes, triple)
                .unwrap_or_else(|e| panic!("{triple} rejected its own binary: {e}"));
        }
    }

    /// A deposit runs on ONE machine and ships four platforms. The check must
    /// not depend on being able to run the thing.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_foreign_platform_is_checked_without_executing_it() {
        // Reading a Mach-O arm64 header while notionally on x86 Linux.
        assert!(check_platform("t", &macho(0x0100_000C), "aarch64-apple-darwin").is_ok());
        assert!(check_platform("t", &elf(0xB7, true), "aarch64-unknown-linux-gnu").is_ok());
    }

    /// A truncated download hashes perfectly and is not a program.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_truncated_file_is_refused_rather_than_called_unknown() {
        let err = check_platform("t", b"\x7f", "x86_64-unknown-linux-gnu").expect_err("refuses");
        assert!(matches!(err, ArchError::TooShort { len: 1, .. }), "{err:?}");
    }

    /// A wrapper script is a legitimate payload and carries no architecture.
    /// It is reported, not refused — the two are different answers.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_script_is_reported_and_not_refused() {
        let f = check_platform(
            "t",
            b"#!/bin/sh\nexec real \"$@\"\n",
            "aarch64-apple-darwin",
        )
        .expect("scripts are legitimate payloads");
        assert_eq!(f, Format::Script);
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_universal_binary_is_recognised_rather_than_guessed_at() {
        let mut fat = 0xCAFE_BABEu32.to_be_bytes().to_vec();
        fat.extend_from_slice(&[0, 0, 0, 2]);
        assert_eq!(identify(&fat), Format::MachOUniversal);
        assert!(check_platform("t", &fat, "x86_64-apple-darwin").is_ok());
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn an_unknown_format_is_surfaced_not_silently_accepted() {
        assert_eq!(identify(b"MZ\x90\x00padding here"), Format::Unknown);
        let f = check_platform("t", b"MZ\x90\x00padding here", "x86_64-unknown-linux-gnu")
            .expect("not an error, but visible");
        assert_eq!(f, Format::Unknown);
    }

    /// A file that begins like an ELF but stops before the machine field is a
    /// truncated download, not an ELF. cargo-mutants found this by widening
    /// the length guard: without it, reading the header walks off the end.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn a_header_that_stops_before_the_machine_field_is_not_an_elf() {
        for len in 4..20usize {
            let mut v = vec![0u8; len];
            v[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
            assert_eq!(
                identify(&v),
                Format::Unknown,
                "len {len} claimed to be an ELF"
            );
            // And it must not panic through the checked entry point either.
            let _ = check_platform("t", &v, "x86_64-unknown-linux-gnu");
        }
    }

    /// Exactly at the length guard: four bytes is enough to look at, so it must
    /// be identified (as Unknown) rather than refused as truncated.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn four_bytes_is_short_but_not_too_short() {
        let f = check_platform("t", b"\x7fELF", "x86_64-unknown-linux-gnu")
            .expect("four bytes is inspectable");
        assert_eq!(f, Format::Unknown);
        // Three is not.
        assert!(matches!(
            check_platform("t", b"\x7fEL", "x86_64-unknown-linux-gnu"),
            Err(ArchError::TooShort { len: 3, .. })
        ));
    }

    /// The message has to NAME both architectures — it is what tells an
    /// operator which side is wrong, and it is the only output of this check.
    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn the_mismatch_message_names_both_architectures() {
        let msg = check_platform("tools/rivet", &elf(0x3E, true), "aarch64-unknown-linux-gnu")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("x86_64"), "does not name what it IS: {msg}");
        assert!(
            msg.contains("aarch64"),
            "does not name what was EXPECTED: {msg}"
        );
        assert_eq!(Arch::X86_64.as_str(), "x86_64");
        assert_eq!(Arch::Aarch64.as_str(), "aarch64");
    }

    // rivet: verifies REQ-PAYLOADSMOKE-001
    #[test]
    fn the_triple_to_arch_mapping_covers_the_layers_platforms() {
        assert_eq!(Arch::of_triple("x86_64-apple-darwin"), Some(Arch::X86_64));
        assert_eq!(
            Arch::of_triple("aarch64-unknown-linux-gnu"),
            Some(Arch::Aarch64)
        );
        assert_eq!(Arch::of_triple("riscv64-unknown-linux-gnu"), None);
        // An unmapped platform is not this check's business to fail on.
        assert!(check_platform("t", &elf(0x3E, true), "riscv64-unknown-linux-gnu").is_ok());
    }
}
