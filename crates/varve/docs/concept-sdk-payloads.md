# SDKs in a layer

A layer usually carries **tools**: one binary per platform, dispatched by name.
An **SDK** is a different shape. A cross-toolchain is a compiler, its binutils,
its headers and its sysroot, and it is one thing — taking a binary out of it
destroys it. So an `sdk` payload is the **whole archive**, stored exactly as
its publisher published it, and unpacked on the consumer's machine by
`varve export-sdk`, which relocates the build-time prefix to wherever you put
it.

## Which archive formats varve carries

| format | producer | `export-sdk` |
|---|---|---|
| `.tar.gz`, `.tgz` | yes | yes |
| **`.tar.xz`, `.txz`** | yes | yes |
| `.tar.bz2`, `.tbz2` | yes | **no decoder** — refused with that reason, not a tar error |
| `.zip` | yes (tools only) | n/a |
| **`.sh`, `.run` self-extracting** | **refused** | n/a |

## Why a self-extracting installer is refused

A vendor's `.sh` installer is a program. Running it to discover what it contains
means executing unreviewed vendor code on the machine that signs your layer,
*before* anyone knows what the payload is — which defeats the property the
deposit exists to establish. varve refuses it by name and says so, so nobody
adds the branch later without meeting this paragraph.

That refusal is not a judgement about your vendor. It is that "run it and see"
and "state what these bytes are" cannot both be the first step.

## Yocto: emit a tarball, not a `.sh`

Yocto's `populate_sdk` produces a self-extracting `.sh` **by default**, and that
form cannot go in a layer. Yocto lets you choose. Set, in `local.conf` or your
distro config:

```
SDK_ARCHIVE_TYPE = "tar.xz"
```

`bitbake -c populate_sdk <image>` then writes a plain `.tar.xz` under
`tmp/deploy/sdk/`, which varve carries as-is. This is a one-line change on the
producing side and avoids the whole installer question.

`tar.xz` rather than `tar.bz2`: varve decodes xz and does not decode bzip2.

## The other two SDKs, and what vouches for them

| SDK | archive | what upstream publishes |
|---|---|---|
| **Zephyr** (`zephyrproject-rtos/sdk-ng`) | `.tar.xz`, one per `<host>_<target>` | a `sha256.sum` manifest, **unsigned** |
| **WASI** (`WebAssembly/wasi-sdk`) | `.tar.gz` | **nothing** — no sums, no signature, no build provenance |
| **Yocto** (yours) | `.tar.xz` once set as above | whatever your build publishes |

These land on different rungs of the ingest ladder, and the layer records which:
an unsigned upstream digest manifest catches a truncated 90 MB download but
stops nobody who can replace both the manifest and the bytes, and an upstream
that publishes nothing at all is ingested as `unverified` with an operator's
signed reason. Neither is called a signature, because neither is one.

## Declaring one

```toml
[varve]
version = "v0.33.0"

[realm]
name     = "pulseengine"
channel  = "rolling"
registry = "oci://ghcr.io/pulseengine/layers"

[[tool]]
# `name` is the REPOSITORY basename; `binary` is what the payload is called in
# the layer. They differ here because the repo is `sdk-ng` and nobody wants to
# type `varve export-sdk sdk-ng`.
name     = "sdk-ng"
repo     = "zephyrproject-rtos/sdk-ng"
binary   = "zephyr-sdk"
version  = "v1.0.1"
layout   = "sdk"
asset    = "toolchain_gnu_%U_arm-zephyr-eabi.tar.xz"
contains = "arm-zephyr-eabi/bin"
```

> **Requires the Rust assembler.** `varve-producer deposit --manifest layer.toml`
> reads `layout = "sdk"` directly. The older path — `varve layer-spec` emitting
> environment variables for a shell assembler — has no way to express a layout,
> so an sdk entry translated through it arrives as an ordinary tarball tool and
> the tree is mined for a binary. A realm carrying SDKs must use the assembler,
> not the env encoding.

`contains` is the shape check. A tree cannot be architecture-checked the way a
binary can — an SDK holds executables for several architectures, so checking its
first ELF proves nothing. What it can be checked for is shape, and the failure
that catches is real: a 90 MB download that turns out to be an HTML error page
hashes and signs perfectly well, installs, verifies, and fails for the first
time on somebody else's machine.

The check is run with varve's own reader, so the producer proves the payload
opens with exactly the code the consumer will open it with.

## Using one

```sh
varve export-sdk zephyr-sdk --out /opt/zephyr-sdk
export ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk
```

`export-sdk` patches the build-time prefix in place, into a fixed-size field, so
the destination can only be a path **no longer** than the one the SDK was built
for. A destination that does not fit is refused before anything is written,
rather than producing a tree with truncated interpreter paths that fails later.
