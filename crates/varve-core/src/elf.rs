//! What a Linux payload needs from the machine it lands on
//! (REQ-LIBCSTATED-001).
//!
//! IN varve-core, not in the producer, because the producer is not the only
//! thing that writes a libc into a signed layer. A deposit spec carries the
//! field, and `varve deposit --spec` will sign whatever it is given — so a
//! measurement that lives only in the producer leaves the rule
//! "never declared by hand" enforced where it cannot act, which is this
//! project's most-repeated defect shape. `SpecTool::into_deposit_tool`
//! re-measures with this, from the same bytes it is about to hash.
//!
//! Hand-rolled rather than a crate: it reads four fields of an ELF header and
//! walks the program headers, and an ELF parser in the trusted base is a
//! larger surface than the thing it would save.

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

#[cfg(test)]
mod tests {
    use super::{Linkage, linkage};

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
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn real_release_binaries_report_the_libc_they_actually_need() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        for (name, want) in [
            ("ordeal-musl.elfhead", Linkage::Static),
            ("ordeal-gnu.elfhead", Linkage::Glibc),
        ] {
            let path = dir.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("fixture {} is required: {e}", path.display()));
            assert_eq!(
                linkage(&bytes).as_ref(),
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
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn an_unmeasurable_payload_is_not_reported_as_static() {
        assert_eq!(linkage(b"#!/bin/sh\necho hi\n"), None, "a script");
        assert_eq!(linkage(b""), None, "empty");
        assert_eq!(linkage(b"\x7fELF"), None, "truncated before EI_CLASS");
        // ELF32 is not measured here rather than guessed at.
        let mut elf32 = vec![0x7F, b'E', b'L', b'F', 1, 1];
        elf32.resize(128, 0);
        assert_eq!(linkage(&elf32), None, "ELF32");
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
            linkage(&real),
            Some(Linkage::Glibc),
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
            linkage(&wide),
            Some(Linkage::Glibc),
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
            linkage(&bytes),
            None,
            "a 32-byte program header cannot hold an ELF64 one"
        );
    }

    /// An interpreter varve does not recognise is recorded VERBATIM, never
    /// rounded to one it does.
    ///
    /// Clause 3, and it had NO test until an independent review mutated the
    /// `Other` arm to return `Glibc` and watched all 311 producer tests stay
    /// green. `Linkage::Other` was constructed in one place and asserted in
    /// none, so an unrecognised `PT_INTERP` silently became a signed claim of
    /// glibc — exactly the unchecked claim this clause exists to forbid. The
    /// mutation gate could not have found it either: cargo-mutants has no
    /// operator that substitutes `Other(String)` for `Glibc`.
    ///
    /// Built by rewriting the REAL fixture's interpreter string, so the
    /// surrounding header is genuine and only the field under test differs.
    // rivet: verifies REQ-LIBCSTATED-001
    #[test]
    fn an_unrecognised_interpreter_is_recorded_verbatim_not_rounded() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/libc");
        let mut bytes = std::fs::read(dir.join("ordeal-gnu.elfhead")).expect("fixture");
        let gnu = b"/lib64/ld-linux-x86-64.so.2";
        let at = bytes
            .windows(gnu.len())
            .position(|w| w == gnu)
            .expect("the real fixture names the glibc interpreter");
        // Same length, so every offset in the real header stays valid.
        let odd = b"/opt/acme/ld-acme-x86_64.so";
        assert_eq!(odd.len(), gnu.len());
        bytes[at..at + odd.len()].copy_from_slice(odd);

        match linkage(&bytes) {
            Some(Linkage::Other(interp)) => assert_eq!(
                interp, "/opt/acme/ld-acme-x86_64.so",
                "the interpreter must be recorded exactly as the ELF names it"
            ),
            other => panic!(
                "an unrecognised interpreter was rounded to {other:?} — a signed \
                 claim about a libc nobody measured"
            ),
        }
        // And it reaches the manifest as that string, not as a label.
        assert_eq!(
            Linkage::Other("/opt/acme/ld-acme-x86_64.so".into()).as_str(),
            "/opt/acme/ld-acme-x86_64.so"
        );
    }

    /// A musl interpreter is recognised as musl, not rounded to glibc.
    ///
    /// Built by rewriting the REAL gnu fixture's `PT_INTERP` string, so the
    /// surrounding header is a genuine one and only the one field under test
    /// differs.
    // rivet: verifies REQ-LIBCSTATED-001
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
        assert_eq!(linkage(&bytes), Some(Linkage::Musl));
    }
}
