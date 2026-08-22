# Configuration reference

Every file you write by hand, in full. These schemas were previously discoverable only by feeding bad input to the parser and reading `expected one of …`.

## varve.toml — the pin

Committed in your project. varve walks up from the working directory to find it.

```toml
manifest-version = 1          # required; only 1 exists

[toolchain]
realm   = "pulseengine"       # optional; names the trust universe (see realms)
channel = "qualified"         # required; `qualified` or `rolling`, nothing else
layer   = "2026.08.2"         # required; always YYYY.MM.P, three parts
digest  = "sha256:83a6991d0c2f4b7e5a8d3c6f9b2e4a7d1c8f5b3e6a9d2c7f4b1e8a5d3c6f9b2e"   # EXAMPLE — `varve list` prints yours
# when present, the digest WINS over the layer name
tools   = ["rivet", "synth"]  # optional; restrict to a subset of the layer
```

`digest` makes resolution constant-time and byte-exact — prefer it. `tools` entries must be plain names: a path there would resolve outside the verified layer, so it is refused.

### `[[export]]` — what this project materialises out of the layer

The pin says which layer the project consumes; these say **how**. Declared means checked: `varve verify` looks at every one of them without being told (REQ-EXPORTDECL-001).

```toml
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.08.0"

[[export]]
kind = "crates-vendor"        # required; cargo | crates-vendor | bazel-registry |
                              # bazel-distdir | vsix | sdk — spelled exactly as the
                              # adapters stamp it in .varve-export.json
out  = "third_party/rust"     # required; RELATIVE to the directory holding varve.toml

[[export]]
kind   = "vsix"
out    = ".vscode/varve-extensions"
select = ["rust-lang.rust-analyzer"]   # optional; a SUBSET of the layer, by payload name

[[export]]
kind = "sdk"
out  = "toolchains/poky"

[export.env]                  # only on a kind that is SOURCED (today: sdk)
script = "environment-setup-cortexa53-poky-linux"   # relative to `out`
path   = "before-shims"       # required with env; before-shims | after-shims
```

| rule | why |
|---|---|
| `out` is relative and may not climb out with `..` | the declaration is committed, so it must mean the same thing on every machine and cannot address anything outside the checkout |
| two entries may not share one `out` | each adapter writes one stamp; the second would overwrite the first's, and `verify` would then check one export twice and the other never |
| `[export.env]` only on a sourced kind | on one that is pointed at — a local registry, a distdir — the block would be accepted, ignored, and believed |
| `path` is required, never defaulted | a default is a guess about PATH order made on the project's behalf; wrong in either direction is what the field exists to prevent (`varve docs env`) |

`select` entries are payload names, not paths — a selection indexes the *verified* layer.

**`select` does not shrink an export yet.** It parses and is validated, and no export adapter reads it: `varve export-vsix --out D` writes every extension in the layer whether or not the declaration names a subset, and `varve verify` reports that directory fresh. Declare it if you want the intent recorded; do not rely on it to keep a payload out. (`varve export-sdk --select <name>` is a *flag* on that one command and does work — it is what disambiguates a layer carrying several SDKs.)

## varve-realms.toml — the trust universe

Alongside the pin, found by the same upward walk. Nearest wins; definitions are not merged.

```toml
[realm.pulseengine]
registry        = "oci://ghcr.io/pulseengine/varve/layers"   # required
trust-root      = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973"
# or, instead of an inline key:
# trust-root-file = "./roots/pulseengine.pub"
signed-index    = false                                      # default
```

`registry` is required even when you never contact it — an air-gapped realm still needs the field; a placeholder is legitimate. `trust-root` is what `varve pubkey` prints.

`signed-index = true` declares that this realm publishes a signed line index (`varve sign-index`). Where it is set, `varve install` refuses to fall back to a source's unauthenticated listing: a missing index is an error naming the realm, and a source that hides a layer the index names is refused. Leave it `false` — the default — until the realm actually publishes one, or every install of it fails closed. Only turn it on once the index is on the registry AND in the layouts you hand out: a bare `manifests/`+`blobs/` directory cannot carry one at all.

## The deposit spec — producing a layer

Passed as `varve deposit --spec <file>`.

```toml
layer   = "2026.09.0"
channel = "qualified"
counter = 4                    # monotonic per LINE; you own monotonicity

[[tool]]
name     = "rivet"
version  = "0.32.0"
path     = "./dist/rivet"      # relative to this file
platform = "x86_64-unknown-linux-gnu"   # optional; absent = any platform
kind     = "tool"              # tool | crate | wit | zephyr-module | sdk | wasm-component | vsix
                               # seven; `vsix` is a VS Code extension package (`varve docs payload-kinds`)
# sdk-prefix = "/opt/poky/4.0.15"   # REQUIRED on kind = "sdk", refused on every other kind:
                               # the absolute path the tree was BUILT for, which is the
                               # relocation budget `varve export-sdk` patches against

[tool.source]                  # optional upstream provenance
repo    = "pulseengine/rivet"
release = "v0.32.0"
asset   = "rivet-v0.32.0-x86_64-unknown-linux-gnu.tar.gz"
sha256  = "9f2c1d8e5a3b7c04e6d9128f3a5b7c0d4e6f8a2b5c7d9e1f3a5b7c9d1e3f5a70"

[[include]]                    # optional table; compose another layer
digest = "sha256:8b65864f2d9c7a3e1b5f8d2c6a9e4b7d3f1c8a5e2b9d6c3f7a4e1b8d5c2f9a6e"
realm  = "bytecodealliance"    # REQUIRED in practice — see below
layer  = "2026.08.0"           # optional; used only in error messages
```

**`realm` on an `[[include]]` is required in practice**, even though the parser
accepts the table without it. Omitting it writes no `include.realm` annotation
into the signed payload, so `verify` falls back to the *pinned project's* trust
root. The layer then installs cleanly and fails verify afterwards:

```
error: composed layer 2026.11.0 failed verification against this project's own
trust root (the include names no realm) … : signature does not verify against
the trust root: No valid signatures
```

Nothing is tampered with — the included layer is correctly signed, by the realm
that owns it, which is the entire point of composing. Omit `realm` only when the
included layer is signed by the same root the project pins. Because the
annotation is inside the signed payload, adding it later means re-depositing.

**`[tool.source].sha256` is signed, and varve never verifies it.** The four
`[tool.source]` fields are recorded verbatim into the signed payload as
annotations and are not checked against anything — not at deposit, not at
`varve verify`, not at install. In particular `sha256` is **not** compared with
the hash of the file at `path`: it describes an upstream *release asset* varve
never fetches, while the entry's own digest — the one `verify` enforces — covers
the bytes you deposited. Nothing detects a `sha256` that is a typo, stale, or
copied from the wrong asset.

That matters because it does not stay inert. `varve export-bazel` emits this
value as the checksum Bazel will enforce on its own download, under a header
reading *"digests transcribed from the signed layer manifest"*. True as far as
it goes: it was signed, so nobody altered it in transit. It does not mean varve
checked it. **Whatever you paste into `sha256` becomes the hash a Bazel build
trusts**, so hash the upstream asset yourself and paste the result — a value
transcribed by hand from a release page inherits nothing from the signature but
authenticity of transcription. `varve docs payload-kinds` says the same from the
adapter's side.

**`kind = "crate"` on a `[[tool]]` table is how you deposit a crate** — there is no `[[crate]]`. That is what the export adapters and `verify --lockfile` consume.

`counter` is not checked against previous deposits; the depositor owns monotonicity and clients enforce it.

## The line-status document — advisories

Signed with `varve sign-status`, attached with `varve attach-status`.

```json
{
  "line": "2026.08",
  "counter": 3,
  "issued-at": "2026-08-14T00:00:00Z",
  "support-until": "2027-08-01",
  "yanked": { "2026.08.1": "miscompiles under -O2; use 2026.08.2" },
  "known-problems": [
    {
      "id": "VARVE-2026-0003",
      "title": "synth mis-fuses nested match arms",
      "severity": "high",
      "affected": ["2026.08.0", "2026.08.1"],
      "workaround": "build that crate with -C opt-level=1",
      "detection": "the fused block is missing its second arm",
      "mitigation": "fixed in 2026.08.2"
    }
  ]
}
```

`yanked` is a **map** from layer id to reason, not a boolean. `counter` is monotonic per line, enforced everywhere including at attach time.

### `known-problems` entries

Each is an object, not a string — `sign-status` rejects a bare string with
`invalid type: string, expected struct KnownProblem`.

| field | required | meaning |
|---|---|---|
| `id` | yes | your identifier for the problem |
| `title` | yes | one line |
| `severity` | yes | free text; varve does not interpret it |
| `affected` | yes | array of layer ids, e.g. `["2026.08.0"]` |
| `workaround` | no | what a consumer can do today |
| `detection` | no | how to tell whether you are hit |
| `mitigation` | no | where it is fixed |

Unknown fields are refused, so a typo is an error rather than a silently
dropped advisory.

### `[tool.runner]` — a payload that is not directly executable

A wasm component or a jar needs something to run it. Set it on the `[[tool]]`:

```toml
layer   = "2026.09.0"
channel = "qualified"
counter = 1

[[tool]]
name    = "checker"
version = "1.2.0"
path    = "./dist/checker.wasm"
kind    = "wasm-component"

[tool.runner]
tool       = "wasmtime"    # another tool in this layer
args       = ["run"]       # array, placed before the payload path
arg-prefix = "--dir"       # a STRING, repeated before EACH user argument
```

The dispatched command is

```
<runner> <args…> <payload> [arg-prefix] <arg1> [arg-prefix] <arg2> …
```

so the example above turns `checker a.wit b.wit` into
`wasmtime run checker.wasm --dir a.wit --dir b.wit`. `arg-prefix` is a single
string repeated per argument, not a list inserted once — an array is refused
with `invalid type: sequence, expected a string`.
