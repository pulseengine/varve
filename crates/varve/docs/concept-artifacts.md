# Shipping artifacts that are not executables

A tool is bytes with an exec bit; a crate, a WIT package, an SDK, a wasm
component, a VS Code extension are also just bytes. varve verifies all of them
identically — a signed digest checked against the pinned root. What differs is
only how a consumer gets them back out, and that is an **export adapter**.

## The shape, end to end

```sh
# 1. PRODUCE — declare the payload and its kind in the deposit spec
cat > deposit.toml <<'SPEC'
layer   = "2026.09.0"
channel = "qualified"
counter = 4

[[tool]]
name    = "rivet"          # kind absent = tool, dispatched by name
version = "0.32.0"
path    = "./dist/rivet"

[[tool]]
name    = "serde"          # a crate: held, never dispatched
version = "1.0.210"
kind    = "crate"
path    = "./crates/serde-1.0.210.crate"
SPEC
varve deposit --spec deposit.toml --issued-at 2026-09-01T00:00:00Z \
  --key root.key --key-id acme-root-1 --out ./layout

# 2. CONSUME — install once, then export for each build system that needs it
varve install
varve export-crates-vendor --out ./vendor/rust
varve export-vsix          --out ./.vscode/extensions
varve verify --export ./vendor/rust     # fails if the pin moved and this did not
```

## Dispatched versus held

This distinction decides everything else:

- A **tool** is dispatched by name — `varve run`, `varve which`, the PATH
  shims — so one name must resolve to exactly one binary per platform. It lands
  at `bin/<name>`, and depositing two versions of one tool is refused.
- Every other kind is **held**: nothing runs it, so its identity is
  `(name, version, platform)` and it lands at `payloads/<name>/<version>`.
  Several versions of one name coexist, because that is the ordinary shape of a
  dependency graph — varve's own lockfile has 14 names at more than one version.

`varve which <crate>` therefore does not resolve. That is deliberate; it used to,
accidentally, and dispatching a `.crate` tarball was never meaningful.

## Which adapter

| Your consumer is | Run | Takes |
|---|---|---|
| Cargo, offline | `varve export-crates-vendor` | `kind = "crate"` |
| Bazel `rules_rust`, air-gapped | `varve export-bazel-distdir` | `kind = "crate"` |
| Bazel `rules_wasm_component` | `varve export-bazel` | any entry with `platform` + `[tool.source]` |
| VS Code | `varve export-vsix` | `kind = "vsix"` |
| Cargo, single crate | `varve export-cargo` | `kind = "crate"` — **see the limit below** |

Every adapter writes a `.varve-export.json` stamp binding the directory to the
layer that produced it, so `varve verify --export` catches an export that went
stale when the pin moved.

## What this does and does not do today

**`export-cargo` cannot build a real dependency graph.** Its registry index
emits `"deps":[]` and `"features":{}` for every crate, and Cargo resolves the
graph *from the index* — so it works for a crate with no dependencies and no
features, and fails on anything else. Use `export-crates-vendor`, which carries
each crate's real `Cargo.toml`. Tracked as varve#73.

**Exports do not follow composition.** If your layer composes another realm's,
`varve which` sees the composed tools but an export contains only your own
layer's payloads — silently. Tracked as varve#79.

**`sdk`, `wit` and `zephyr-module` are declarable, not distributable.** They
deposit, install and verify like anything else, and no adapter consumes them
yet. An SDK also needs tree-shaped storage and relocation (varve#67).

## The worked example: varve's own release

Measured, not illustrative. Layer `2026.08.2` carries **35 entries across four
platforms**, every one with upstream provenance recorded at deposit —
`source.repo`, `source.release`, `source.asset`, `source.sha256` — so each
binary traces to the exact upstream release asset it came from.

```sh
$ varve export-bazel --out ./bz
wrote ./bz/kilnd.json … 9 registry files
```

Nine checksum registries, every digest transcribed from the signed manifest
rather than trusted on first use.

And the honest part: that layer carries **no crate payloads**, so
`varve export-cargo` against it says

```
error: nothing exported — layer 2026.08.2 carries no `crate` entries
```

varve distributes its own tools this way and does not yet distribute its own
crates this way. The crate path is exercised by tests and by a 250-package
offline build of varve itself — not by the published layer.
