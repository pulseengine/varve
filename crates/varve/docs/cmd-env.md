# varve env [--shell sh|fish]

Prints idempotent shell code that enters this project's environment. Setup is
one line: `eval "$(varve env)"`. Never hand-edit PATH.

With no declared exports that is just the shim directory, guarded so repeated
evaluation (login shells, nested shells) never stacks PATH entries.

## One command enters the whole environment

A project that declares a **sourced** export — a Yocto SDK sets `CC`, `SYSROOT`
and `CFLAGS` and prepends its own bin to PATH — gets that sourcing emitted too
(REQ-EXPORTDECL-001 clause 4):

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

```sh
eval "$(varve env)"
$CC --version          # the SDK's cross-compiler
rivet --version        # still the pinned tool, through the shim
```

## The emitted order inverts the declared one

Sourcing a script **prepends** its bin to PATH, so whatever is sourced *last*
ends up first and wins. An export declared `before-shims` — its compiler is
meant to win — is therefore sourced **after** the shims, and one declared
`after-shims` is sourced **before** them:

```sh
varve env
# # varve's shims
# case ":$PATH:" in *:"/w/.varve/shims":*) ;; *) export PATH="/w/.varve/shims:$PATH" ;; esac
# # sdk export toolchains/poky — declared before-shims (REQ-EXPORTDECL-001 clause 5)
# . "/w/toolchains/poky/environment-setup-cortexa53-poky-linux"
```

Emitting them in declaration order would produce exactly the PATH the project
said it did not want — and `varve verify` would then report the shadowing the
project had declared away.

`--shell fish` covers the shim line only. A producer's `environment-setup-*` is
POSIX sh and fish cannot source it, so in a project that declares one, `varve
env --shell fish` **fails** rather than handing back an environment missing the
thing `varve.toml` declares.
