# varve verify [--all] [--export DIR]...

Re-runs the install-time verdict offline against the retained signature and signed digests — for the pinned layer, or every installed layer with `--all`. The gate, repeated.

`--export DIR` (repeatable) also checks a committed export directory against the current pin: the `.varve-export.json` stamp written by `varve export-*` must name the layer the pin resolves to. If the pin has moved on, the export is stale and verify **fails** (non-zero exit); an absent or malformed stamp is likewise a failure. Run it in CI so a stale vendored tree cannot silently keep serving the old crates (REQ-EXPORT-SYNC-001).

`--lockfile FILE` also checks a project's Cargo lockfile against the pinned layer's `crate` entries. A package the layer pins must resolve to the same version, and to the same bytes when both record a checksum; a disagreement fails verify. Packages the layer does not pin are ignored — the layer never claimed to cover every dependency.

The boundary is deliberate: varve cannot intercept a Cargo build and cannot guarantee the compiler used the bytes it pins. Provenance for a dependency compiled *into* your artifact is by **asserted agreement** — the lockfile and the layer must say the same thing, mechanically — not by dispatch (REQ-LOCKPIN-001).
