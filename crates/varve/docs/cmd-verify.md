# varve verify [--all] [--export DIR]...

Re-checks the pinned layer offline — or every installed layer with `--all`.

## What it checks

- The retained DSSE envelope verifies against the pinned trust root, and the signed payload is byte-identical to the stored `layer.json`.
- Every manifest entry **for this platform** is present and hashes to its signed digest.
- Each composed layer, recursively, against its own realm's root.
- The pin does not resolve **below its line's high-water mark** — the anti-rollback verdict `install` applies, now applied here too (varve#76), so the CI gate and the install agree.
- **Every export the pin declares**, without being told to (REQ-EXPORTDECL-001). See below.
- No binary earlier on `PATH` shadows a pinned tool (REQ-SHADOW-001) — unless the pin declared that it would.

## What it does not check

- **Other platforms.** Entries annotated for another target triple are skipped silently and there is no `--platform` override on `verify`. A three-entry layer with one Linux entry reports `2 tool(s) match` and exits 0 on macOS. `verify` says nothing about the third.
- **Files the manifest does not name.** A binary planted in an installed layer's `bin/` passes verify untouched — and is dispatched. See `varve docs threat-model`.
- **Yank, support window, `issued-at`.** A yanked layer verifies clean; `varve status` is where withdrawal lives. `issued-at` is never evaluated at all.

`--all` widens the *set of layers*, not the set of checks: the platform and unnamed-file limits above still hold for each one.

## Declared exports

An `[[export]]` entry in `varve.toml` is checked on **every** `verify`, with no flag:

```toml
manifest-version = 1

[toolchain]
channel = "qualified"
layer   = "2026.08.0"

[[export]]
kind = "crates-vendor"
out  = "third_party/rust"
```

```sh
varve verify
# declared export /w/third_party/rust (crates-vendor) — fresh: bound to the layer the pin resolves
```

Anything but *fresh* **fails**, including a declared directory that is not there at all:

```sh
rm -rf third_party/rust
varve verify
# error: 1 declared export(s) in /w/varve.toml are not current (REQ-EXPORTDECL-001):
#   /w/third_party/rust (crates-vendor) — MISSING: varve.toml declares this export and
#   there is no .varve-export.json in it. Generate it with
#   `varve export-crates-vendor --out third_party/rust`.
```

"I forgot to generate it" and "it is stale" are the same severity to anyone relying on the export, so they are the same verdict. A directory stamped by a *different* adapter fails too: freshness there says nothing, because the declared export was never produced.

`--export DIR` (repeatable) also checks a committed export directory against the current pin: the `.varve-export.json` stamp written by `varve export-*` must name the layer the pin resolves to. If the pin has moved on, the export is stale and verify **fails** (non-zero exit); an absent or malformed stamp is likewise a failure. Run it in CI so a stale vendored tree cannot silently keep serving the old crates (REQ-EXPORT-SYNC-001).

`--lockfile FILE` also checks a project's Cargo lockfile against the pinned layer's `crate` entries. A package the layer pins must resolve to the same version, and to the same bytes when both record a checksum; a disagreement fails verify. Packages the layer does not pin are ignored — the layer never claimed to cover every dependency.

The boundary is deliberate: varve cannot intercept a Cargo build and cannot guarantee the compiler used the bytes it pins. Provenance for a dependency compiled *into* your artifact is by **asserted agreement** — the lockfile and the layer must say the same thing, mechanically — not by dispatch (REQ-LOCKPIN-001).
