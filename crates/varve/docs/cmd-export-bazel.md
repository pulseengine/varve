# varve export-bazel [--layer <l>] --out <dir>

Compiles rules_wasm_component checksum registries from a verified layer — every hash Bazel enforces becomes a transcription from the signed manifest instead of TOFU.

`--layer` defaults to the resolved project pin, so the export tracks the pin. Every export writes a `.varve-export.json` stamp binding it to the producing layer; `varve verify --export <dir>` fails if the pin later moves and the export goes stale (REQ-EXPORT-SYNC-001).

In a MIXED project (`[toolchain.override.<tool>]`, REQ-OVERRIDE-001) the overridden tool's registry is written from the OVERRIDE layer's signed entry, so Bazel fetches the tool `varve run` dispatches. An override layer that records no source provenance for the tool gets no registry file for it — never the pinned layer's — and stderr says so, as for any tool without provenance. Re-exporting into a directory that still holds that tool's registry from an earlier export removes it, if the earlier export's stamp recorded it, so the new stamp cannot seal it; a file no earlier export recorded is refused rather than removed or sealed. Two composition layers disagreeing about an overridden tool refuse nothing: the override replaces it. The stamp records the mix.
