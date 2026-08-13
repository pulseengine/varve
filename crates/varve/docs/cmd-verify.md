# varve verify [--all] [--export DIR]...

Re-runs the install-time verdict offline against the retained signature and signed digests — for the pinned layer, or every installed layer with `--all`. The gate, repeated.

`--export DIR` (repeatable) also checks a committed export directory against the current pin: the `.varve-export.json` stamp written by `varve export-*` must name the layer the pin resolves to. If the pin has moved on, the export is stale and verify **fails** (non-zero exit); an absent or malformed stamp is likewise a failure. Run it in CI so a stale vendored tree cannot silently keep serving the old crates (REQ-EXPORT-SYNC-001).
