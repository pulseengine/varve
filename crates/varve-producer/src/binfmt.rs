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
