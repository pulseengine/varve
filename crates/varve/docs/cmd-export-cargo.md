# varve export-cargo [--layer <l>] --out <dir>

Materialises a Cargo local registry from the layer's verified crate entries plus a .cargo/config.toml source-replacement, so a consumer builds fully offline against varve-signed crates. The cksum Cargo verifies is varve's signed sha256.

`--layer` defaults to the resolved project pin, so the export tracks the pin. Every export writes a `.varve-export.json` stamp binding it to the producing layer; `varve verify --export <dir>` fails if the pin later moves and the export goes stale (REQ-EXPORT-SYNC-001).
