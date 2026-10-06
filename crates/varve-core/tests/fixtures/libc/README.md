# The first 1 KiB of two real release binaries

`ordeal` v0.24.0 for `x86_64`, gnu and musl, from the SAME upstream release —
the pair layer 2026.10.1 files under one platform key and cannot tell apart.
Only the first 1024 bytes are kept: the ELF header, all program headers, and
the `PT_INTERP` segment all live below offset 764, so a prefix carries
everything `binfmt::linkage` reads and nothing else.

Real bytes, not a synthesised header — a header I built by hand would only
prove the parser agrees with my idea of ELF. `file(1)` is the independent
oracle on the full assets:

    musl: ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
    gnu:  ELF 64-bit LSB pie executable, x86-64, dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2

Provenance, so the prefixes are checkable against upstream:

| file | sha256 of the prefix | taken from |
|---|---|---|
| `ordeal-gnu.elfhead` | `ec6bed014414683dfa75779993c656298524d4ef4e8c43c63ec46a9223dd10d3` | `ordeal-v0.24.0-x86_64-unknown-linux-gnu.tar.gz` |
| `ordeal-musl.elfhead` | `cd1b78fa6a76c9bea1cd0f9ed553febf832710b9820897d6eeead1be9903215f` | `ordeal-v0.24.0-x86_64-unknown-linux-musl.tar.gz` |

Regenerate:

    gh release download v0.24.0 --repo pulseengine/ordeal \
      -p 'ordeal-v0.24.0-x86_64-unknown-linux-{gnu,musl}.tar.gz'
    # extract each, then:
    head -c 1024 <extracted>/ordeal > ordeal-<libc>.elfhead
