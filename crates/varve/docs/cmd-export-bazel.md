# varve export-bazel [--layer <l>] --out <dir>

Compiles rules_wasm_component checksum registries from a verified layer — every hash Bazel enforces becomes a transcription from the signed manifest instead of TOFU.

`--layer` defaults to the resolved project pin, so the export tracks the pin. Every export writes a `.varve-export.json` stamp binding it to the producing layer; `varve verify --export <dir>` fails if the pin later moves and the export goes stale (REQ-EXPORT-SYNC-001).
