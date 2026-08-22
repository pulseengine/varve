# varve export-sdk [--layer <l>] --out <dir> [--select <name>]

Unpacks the layer's verified `sdk` tree into `<dir>` and **relocates** it there:
the absolute prefix the SDK was built for is rewritten to `<dir>` throughout,
the way Yocto's own `relocate_sdk.py` and `toolchain-shar-relocate.sh` do it.

A Yocto SDK is thousands of files, and installing one is not extraction — the
installer byte-patches the ELF interpreter path and the loader's SYSDIRS table
in place, `sed -i`s every text file, and re-points every absolute symlink. After
that the bytes no longer hash to anything the producer signed, which is why the
store keeps the **archive** exactly as signed and the usable tree lives here, in
the export. What lands under `<dir>` is derived, deliberately outside the trust
path: `varve verify` re-hashes the archive in the store, never the tree.

## Depositing an SDK

`kind = "sdk"`, plus the one field this adapter cannot work without:

```toml
layer   = "2026.08.0"
channel = "qualified"
counter = 1

[[tool]]
name       = "poky-cortexa53"
version    = "4.0.15"
kind       = "sdk"
path       = "sdk/poky-glibc-x86_64-cortexa53.tar.gz"
sdk-prefix = "/opt/poky/4.0.15"      # the absolute path this SDK was BUILT for
```

`sdk-prefix` is signed into the manifest, so the relocation budget is
attributable rather than guessed. `deposit` **refuses** an `sdk` without it —
the layer would install, verify, and then be impossible to export, which a
consumer would discover on the far side of an air gap. It equally refuses the
field on any other kind: nothing else is relocated, so it would be signed,
ignored, and believed.

## Exporting

```sh
varve install
varve export-sdk --out ./toolchains/poky

# exported sdk poky-cortexa53@4.0.15 to /w/toolchains/poky — 812 dir(s),
#   9143 file(s), 402 symlink(s); relocated from /opt/poky/4.0.15
#   (37 field(s) patched in place, 1180 text substitution(s), 44 symlink(s) re-pointed)

. ./toolchains/poky/environment-setup-cortexa53-poky-linux
$CC --version
```

Use `--select <name>` when a layer carries more than one `sdk`: one destination
is patched into **one** tree, so several of them in one directory would
overwrite each other. varve refuses that by name rather than choosing.

## The destination can only get shorter

The interpreter path is patched into a **fixed-size field**, so an SDK can only
ever move to a path no longer than the one it was built with — this is
`relocate_sdk.py`'s own limit (`if len(new_dl_path) >= p_filesz: ERROR`). varve
checks it as a single comparison **before the archive is opened**, rather than
after writing thousands of files:

```sh
varve export-sdk --out /home/ci/workspace/builds/embedded/toolchains/poky
# error: cannot relocate this sdk to /home/ci/…/poky: the destination is 52
# characters and the sdk was built for /opt/poky/4.0.15 (17). … Choose a
# destination of at most 17 characters.
```

That is also why varve does not relocate into its own store: the store path is
~90 characters before any content.

## Declaring it, so verify checks it

An SDK is *entered*, not pointed at. Declare it in `varve.toml` and both halves
become automatic — `varve verify` checks the export without being told, and
`varve env` emits the sourcing in the right order:

```toml
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.08.0"

[[export]]
kind = "sdk"
out  = "toolchains/poky"

[export.env]
script = "environment-setup-cortexa53-poky-linux"
path   = "before-shims"
```

`path` says where this environment sits relative to varve's shims once sourced.
`before-shims` means the SDK's cross-compiler is meant to win on PATH; without
the declaration `varve verify` would report it as a hijacked PATH
(REQ-SHADOW-001) on a setup that is entirely correct. See `varve docs verify`
and `varve docs env`.

## What is deliberately not done

* varve never writes back into the store, and never records a
  post-relocation digest — that would put the relocator inside the trust path.
* The tree is laid down **whole or not at all**: every member's path is
  validated, every destination resolved before a byte is written, colliding
  members refused, and a symlink that leaves the export — or a member written
  *through* one — refused as well.
* varve does not run the SDK's own installer, and does not know what
  `environment-setup-*` sets. It gives you the relocated tree; sourcing it is
  yours.
