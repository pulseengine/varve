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
# …or, where two realms of one composition ship the same name:
# tools = ["bytecodealliance/wasm-tools", "rivet"]
```

`digest` makes resolution constant-time and byte-exact — prefer it.

A `tools` entry is either a plain name (`"rivet"`) or a **realm-qualified** one (`"bytecodealliance/wasm-tools"`). Anything else — a path, a deeper path, an empty half — is refused, because a tool name indexes the verified layer and a path there would resolve outside it.

The qualifier is how a pin chooses between two realms shipping one name, which is the ordinary case once a fork sits beside its upstream. It changes only what a **bare** name dispatches to; the layer you did not choose stays installed and verified, and `varve run pulseengine/wasm-tools` still reaches it. Where nothing collides, a bare name behaves exactly as it always did.

### `[toolchain.override.<tool>]` — one tool from another layer of the realm

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "rolling"
layer   = "2026.11.0"

[toolchain.override.synth]
layer  = "2026.08.0"                 # required: the layer the tool comes from
digest = "sha256:83a6991d0c2f4b7e5a8d3c6f9b2e4a7d1c8f5b3e6a9d2c7f4b1e8a5d3c6f9b2e"   # EXAMPLE — required: that layer's digest, from `varve list`
```

Takes ONE tool the pin already has from another signed layer of the **pin's own realm** — gale's case, where committed objects must stay byte-identical with an older `synth` while the rest of the toolchain moves (REQ-OVERRIDE-001). Both fields are required: the id is what a reviewer reads in the diff, the digest is the artifact. `varve install` fetches that layer through the same path an `[[include]]` takes — signed manifest against the realm's root, its line index and anti-rollback mark checked (the override's digest is not consent to go below the mark), every payload against its signed digest. Nothing reaches the store another way.

Refused with the reason, exit 1. **Where** each refusal happens matters, because a refusal that comes after a fetch has already changed the store:

- **Before any override layer is fetched** (`install`), and before anything runs (every other command): a tool the pinned layer does not provide, or that the pin's `tools` leaves out — an override **replaces**, it never adds (use the passthrough, `varve docs shim`, or add the tool to a layer).
- **When varve.toml is read**: the same tool overridden twice (names are compared without case), an override nested in another, a missing `layer` or `digest`, or any other key.
- **On the verified manifest, before any payload is laid down or the line's anti-rollback mark moves** (`install`): a digest that is another layer than the one named, a layer on another channel than the pin's (naming both), a layer that does not carry the tool as a dispatched tool for this platform, and a layer that fails verification — it is never installed, and never fetched from anywhere else. A digest no source serves is refused there too. A layer below its line's anti-rollback mark is refused by the install pipeline before anything is laid down.
- **At resolve time, before anything runs**: a digest no installed layer of the realm has, a layer installed only under another realm's root, and a layer installed for another platform (`varve install --platform …`): its payloads are that machine's, so every command refuses it, naming the platform, until `varve install` lays it down for this one. `resolve` repeats the manifest checks above against what is installed.

The key is a plain tool name: no realm qualifier, no path. A varve older than v0.48.0 refuses a varve.toml with an override (unknown key) instead of running the pinned tool. What the override layer composes is installed with it, from the realm each include names, exactly as for the pinned layer.

While any override is active the toolchain is **MIXED**. These say so rather than naming the pinned layer:

- `varve status` (`state = "mixed"` in `--json`);
- `varve which <tool>` (both layers);
- `varve inspect` (the override layer's entry DISPATCHED, the composition's OVERRIDDEN);
- `varve verify`: verifies each override layer and its anti-rollback mark, and ends with a `MIXED:` line, also under `--all`. A carried attestation made under another mix than the project's is reported as not matching this toolchain;
- `varve run` (`VARVE_LAYER` stays the pinned layer; `VARVE_OVERRIDES=tool=layer@digest,…`);
- `varve-serve context`;
- `varve export-bazel` (the overridden tool's registry is the override layer's);
- export stamps (`layer = "<layer>+mixed"` plus the recorded overrides);
- attestations: `check-attestation` refuses a statement that does not record the same overrides.

Every address of an overridden tool reaches the override layer: `synth` and the pin's own `realm/synth` both run it. Another realm's `other/synth` is refused, naming the override. `varve run --varve <layer>` is refused in a project with overrides, because a one-off layer plus the project's overrides is a mix nobody declared. `varve sbom` of a mixed project is refused — ask for each layer with `--layer`. `varve seed` carries the override layers, and what they compose, with the pin.

**What stays about the pinned layer only.** `varve status` reports the pinned line's line-status; the override layers' lines are not covered, so a yanked override layer is not flagged there. `varve outdated` asks about the pinned line only. `varve-serve`'s documentation pages and `export-docs` come from the pinned composition. Every other export carries crates, extensions, WIT, SDK or Zephyr payloads, which an override (a dispatched tool) does not replace; their stamps still record the mix.

**The limit of a stamp or statement read by an older varve.** An export stamp keeps the pinned layer's `manifest_digest` as its join key, and records the mix in `layer` (`<layer>+mixed`) and `overrides`. The mix is visible to **v0.47.0 and later**: v0.47.0 refuses such a stamp as malformed (it denies fields it does not know), and later readers compare the recorded overrides with the project's. A varve **before v0.47.0** cannot parse a pin with an override at all, but it reads a leftover mixed export's stamp as the pure layer's: it ignores the extra fields and compares `manifest_digest` alone. An attestation statement records the overrides with the same limit — v0.47.0 refuses it, an earlier reader takes it for the pure layer's.

### `[[export]]` — what this project materialises out of the layer

The pin says which layer the project consumes; these say **how**. Declared means checked: `varve verify` looks at every one of them without being told (REQ-EXPORTDECL-001).

```toml
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.08.0"

[[export]]
kind = "crates-vendor"        # required; cargo | crates-vendor | bazel-registry |
                              # bazel-distdir | vsix | sdk | wit — spelled exactly as the
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

## config.toml — your user-level configuration

Not committed, not in any repository: `$XDG_CONFIG_HOME/varve/config.toml` (absolute `XDG_CONFIG_HOME`), else `~/.config/varve/config.toml`. Unknown keys are errors. A file inside a repository (a directory holding `varve.toml`, `.git`, `.hg`, `.jj` or `.svn`) is ignored, so a version-controlled `$HOME` refuses the default location: point `XDG_CONFIG_HOME` at a directory outside it.

```toml
[shim]
passthrough = ["just"]   # tools the layer does not carry that a shim may run from PATH; ["*"] for any
```

A `varve.toml` cannot carry this key. See `varve docs shim` (REQ-PASSTHROUGH-001).

What a session allowed is recorded in exports and attestations. The export stamp is unsigned, so its ambient record can be stripped; the signed attestation is the durable record. A record reflects the configuration at the time the export ran or the statement was signed, not the configuration now.

## varve-realms.toml — the trust universe

Alongside the pin, found by the same upward walk. Nearest wins; definitions are not merged.

```toml
[realm.pulseengine]
registry        = "oci://ghcr.io/pulseengine/layers"   # required
trust-root      = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"
# or, instead of an inline key:
# trust-root-file = "./roots/pulseengine.pub"
signed-index    = false                                      # default
# mirrors       = ["oci://mirror.example/layers"]   # see "mirrors" below
# Roots this realm used to sign with. DIAGNOSTIC ONLY — see below.
retired-roots   = [
  { key = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973", retired = "2026-09-07", last-layer = "2026.09.1" },
]
```

`registry` is required even when you never contact it — an air-gapped realm still needs the field; a placeholder is legitimate. `trust-root` is what `varve pubkey` prints.

`signed-index = true` declares that this realm publishes a signed line index (`varve sign-index`). Where it is set, `varve install` refuses to fall back to a source's unauthenticated listing: a missing index is an error naming the realm, and a source that hides a layer the index names is refused. Leave it `false` — the default — until the realm actually publishes one, or every install of it fails closed. Only turn it on once the index is on the registry AND in the layouts you hand out: a bare `manifests/`+`blobs/` directory cannot carry one at all.

### `mirrors` — what a mirror may and may not answer

```toml
[realm.acme]
registry = "oci://registry.example/acme/layers"   # the PRIMARY
mirrors  = ["oci://mirror.example/acme/layers", "/srv/varve/acme-archive"]
trust-root = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"   # ONE root, for every source
```

`mirrors` are extra places to fetch the realm's bytes from, tried in the order written after `registry` when it cannot answer. A mirror is **transport, not authority**: every manifest, blob, index and status it serves must still verify against the realm's ONE `trust-root`, so a mirror can make an install unavailable but cannot make a forged layer acceptable. A source is an `oci://` or `oci+http://` registry or an absolute directory path; any other URL scheme, and a relative path, is refused.

What verification cannot show is that a mirror's copy is *current*. A lagging mirror can serve a genuine layer with a genuine but older line-status, and nothing in the bytes says it is old. So varve limits what a mirror may answer:

* **A machine with no history for a line cannot install from a mirror at all.** "First contact" means no high-water mark and no cached line-status for the line; it is answered only by the realm's primary, and refused otherwise. A fresh checkout or CI runner needs the primary at least once per line.
* **A machine that has installed from the line before** (it has a mark or a cached status) can be served by a mirror, and varve says so on stderr. What it can be served is *a state no older than what this machine last recorded*, bounded as follows. With a **high-water mark**, anything below the mark is refused as a rollback, and anything at or above it is accepted: the cached status's floor (`min-counter`) is NOT consulted. With **no mark but a cached status**, the floor is the `min-counter` of the higher-counter verified status among the cached one, the one the source serves and any verified earlier in the same run (which supplies the floor but does not count as history: only a mark or a cached status does), so an older status leaves the recorded floor in force (a newer realm-signed status supersedes it, whatever floor it states). A **yank** recorded in a cached status binds only on the rollback-consent path (a digest pin below the mark), not on an ordinary install. It is **not** a promise that the state is the newest. A realm that demoted a layer's channel, raised a first-contact floor, or yanked a layer after this machine last looked can still be served stale by a lagging mirror, until the primary is reachable.
* **Rollback consent is never taken from a mirror.** A digest pin below the mark needs the realm's line-status to say the layer is still supported; only the primary may give that, and a status taken from a mirror is never cached for it.
* **Status documents for `varve support-horizon` come only from the primary.** Both the layer's baseline status and any published correction are the primary's: an older document on a mirror (a lower counter, a later `support-until`) could lengthen a support window, and a mirror's silence proves nothing about what the primary holds. If the primary cannot supply them, `support-horizon` refuses ("could not be established"). A mirror may still supply the layer bytes (the manifest and its includes) for the walk.
* **`varve outdated`** with no cached line index treats an answer from a mirror as "could not be established", not as "nothing newer". With a cached index it behaves as for an install.
* **An `[[include]]`** is fetched from a mirror only if this machine already has history for the included layer's line, decided before the mirror is contacted; an include that names no layer cannot be taken from a mirror.
* **A mirror without a line index** cannot run the omission check (a layer the signed index names but the source hides); where history lets the install proceed, varve says the check could not run. A line index verified earlier in the same run does not change that: a source that serves none is not bounded by it unless the realm requires `signed-index`.

Two things are operator acts that change what counts as "primary" and "history", and are deliberate:

* **`varve install --from <url-or-path>` makes that one source the primary for that run.** It skips the first-contact refusal and may grant rollback consent, because you named the source yourself. Use it only for a source you trust as you would the realm's registry.
* **`varve status --from-file <envelope>` caches a verified line-status**, and a cached status counts as history for its line: it lets a mirror answer later. For a line with no high-water mark, its floor then bounds what a mirror may serve (a mirror cannot lower it); once the line has a mark, the mark is what bounds a mirror, and the cached status matters only to rollback consent. Cache only a status you obtained from the realm.

A mirror on a different origin than the primary is also never sent your registry credential (`VARVE_REGISTRY_AUTH`), and a cleartext `oci+http://` mirror is never sent any credential.

### `ignorable` — fields an older varve may skip

A varve refuses a realms file that carries a key it does not know: a newer file may add a security field (`signed-index` was one), and a binary that dropped it would skip the check the file asks for. So an unknown key is an error by default, and the error names the version (`this is varve X.Y.Z`) and says the file may come from a newer varve.

A file can mark the keys that are safe to skip:

```toml
[realm.acme]
registry   = "oci://registry.example/acme/layers"
trust-root = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"
ignorable  = ["retired-roots"]
```

* `ignorable` is a list of strings, inside the realm whose keys it covers. A top-level `ignorable` (before the first `[realm.*]` table) covers top-level keys only.
* A key this varve does **not** know and that `ignorable` names is skipped (silently). A key it does not know and that is not named is refused.
* **A key this varve knows is always parsed and enforced, even if `ignorable` names it.** `ignorable` cannot switch off `trust-root`, `signed-index` or anything else the binary understands.
* Only varve 0.47.0 and later honour it. **A varve before 0.47.0 refuses `ignorable` itself as an unknown key**, so adding `ignorable` to a file breaks it for those binaries. varve's own published file does not carry it yet: `retired-roots` is known to every supported binary and needs no marking. Mark only fields that are diagnostic or advisory; anything a consumer must act on stays unmarked, so an older binary refuses rather than guesses.

### `retired-roots` — what it is, and emphatically what it is not

`key-roles = true` (default `false`) and `delegation-file = "trust-roots/<realm>.delegation.dsse"` declare that this realm scopes its keys by role (REQ-KEYROLES-001): the root signs only a delegation, and the delegated keys sign layers and statuses. The delegation file is read relative to the realms file, like `trust-root-file`. With `key-roles = true`, a missing, unreadable or refused delegation is an error, never a fallback to root-only. `delegation-file` without `key-roles = true` is refused at load rather than ignored. **Roles are enforced at every verification site** (install, status, line-index, attestation, composition, self-update, `varve-serve`). The role a signature claims is the authenticated payload type of what it signs, never its `keyid`: a LAYER key signs layer manifests, attestations and release sums; a STATUS key signs line-status (advisories included) and line-index; the root signs only the delegation, and a root signature on anything else is refused. The store partition and the SBOM author stay the root's fingerprint. A realm that declares no roles behaves exactly as before. The delegation is read from `delegation-file` only: carrying it with a layer, and refusing a rolled-back delegation, come later. An older varve refuses a realms file that carries either key, rather than verifying a roles realm as root-only. `VARVE_TRUST_ROOT` without a pin is root-only trust and cannot carry a delegation, so a roles realm must be used through a pin (a `varve.toml` naming the realm); only the absence of a `varve.toml` falls back to `VARVE_TRUST_ROOT`, and a `varve.toml` that exists but cannot be loaded is an error naming it. See `varve docs sign-delegation`.

**varve still has no key rotation.** Nothing signs "this new root replaces the old one", and no consumer would check such a statement if you produced it (`varve docs threat-model`). Changing a realm's root still means every consumer edits their own `varve-realms.toml`, and every layer signed by the old root stops verifying. `retired-roots` does not change any of that.

What it changes is the **message**, never the **verdict**. Without it, a consumer whose pin was signed by the previous root sees:

```
error: manifest signature verification failed: … No valid signatures
```

which is indistinguishable from a forgery by a stranger — and their previously-installed layers simultaneously appear under a bare fingerprint in `varve list`, because the store partitions by root and no realm names that partition any more. Two symptoms, neither naming the cause, and the cause is not something they can deduce.

With it, the same rejection explains itself: which root signed those bytes, when the realm retired it, what supersedes it, which layers used it, and that the fix is to move the pin.

Three properties worth being explicit about, because a diagnostic that quietly widened trust would be far worse than the confusing error it replaces:

* **A retired root never verifies anything.** It is not a second accepted key. The layer is rejected exactly as it was before.
* **An unknown signer is not excused.** A signature that matches none of the declared retired roots gets the plain error — otherwise the diagnostic would tell an operator a rotation happened while they were being attacked.
* **Listing the realm's live `trust-root` as retired is refused at parse.** It has no legitimate use and is precisely the slip a half-finished rotation makes.

Omit the field entirely and nothing changes; every realms file written before this feature keeps working.

`last-layer` is optional and worth setting: "layers up to and including 2026.09.1 were signed by the retired root" is the sentence that tells someone which of their pins are affected.

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
kind     = "tool"              # tool | crate | wit | zephyr-module | sdk | toolchain | wasm-component | vsix | docs
                               # `vsix` is a VS Code extension package (`varve docs payload-kinds`)
                               # `toolchain` is a compiler and its libraries, laid down and
                               # pointed at — NEVER relocated, so it takes no sdk-prefix
# sdk-prefix = "/opt/poky/4.0.15"   # REQUIRED on kind = "sdk", refused on every other kind:
                               # the absolute path the tree was BUILT for, which is the
                               # relocation budget `varve export-sdk` patches against
# docs-format    = "rustdoc"   # REQUIRED on kind = "docs", refused on every other kind:
                               # html | rustdoc | pdf | markdown | reqif
# docs-entry     = "varve_core/index.html"   # where a reader starts, for a tree format
# docs-title     = "varve-core API"          # the label shown when choosing
# docs-documents = "varve-core"  # the payload this documents; must name a non-docs
                               # payload of THIS deposit, or the deposit is refused
# allow-pip = ["scripts/requirements.txt"]   # kind = "zephyr-module" only. The tree must hold
                               # zephyr/module.yml, or the deposit is refused. A module
                               # declaring `package-managers: pip` is refused unless this
                               # names EXACTLY its requirement files (`varve docs
                               # export-zephyr-modules`)

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

**`kind = "crate"` on a `[[tool]]` table is how you deposit a crate** — the deposit spec has no `[[crate]]`. That is what the export adapters and `verify --lockfile` consume. (A realm's `layer.toml` does have `[[crate]]`; `varve-producer` turns it into exactly this.)

**`docs-documents` is checked against the layer being deposited.** A name that
matches no payload signs as cleanly as a right one, and would then answer every
`varve export-docs --for <name>` with nothing, so `varve deposit` refuses it
while it can still be fixed. A document cannot document another document, and a
payload in a *composed* layer cannot be named yet — the deposit cannot see it.

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
