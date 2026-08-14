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
digest  = "sha256:83a699…"    # optional; when present it WINS over the name
tools   = ["rivet", "synth"]  # optional; restrict to a subset of the layer
```

`digest` makes resolution constant-time and byte-exact — prefer it. `tools` entries must be plain names: a path there would resolve outside the verified layer, so it is refused.

## varve-realms.toml — the trust universe

Alongside the pin, found by the same upward walk. Nearest wins; definitions are not merged.

```toml
[realm.pulseengine]
registry        = "oci://ghcr.io/pulseengine/varve/layers"   # required
trust-root      = "83a699…"                                  # 64 hex characters
# or, instead of an inline key:
# trust-root-file = "./roots/pulseengine.pub"
```

`registry` is required even when you never contact it — an air-gapped realm still needs the field; a placeholder is legitimate. `trust-root` is what `varve pubkey` prints.

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
kind     = "tool"              # tool | crate | wit | zephyr-module | sdk | wasm-component

[tool.source]                  # optional upstream provenance
repo    = "pulseengine/rivet"
release = "v0.32.0"
asset   = "rivet-v0.32.0-x86_64-unknown-linux-gnu.tar.gz"
sha256  = "…"

[[include]]                    # optional; compose another layer
digest = "sha256:8b6586…"
realm  = "bytecodealliance"
layer  = "2026.08.0"
```

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
  "known-problems": ["synth: nested match arms may mis-fuse (#412)"]
}
```

`yanked` is a **map** from layer id to reason, not a boolean. `counter` is monotonic per line, enforced everywhere including at attach time.
