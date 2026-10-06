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
