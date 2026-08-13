# varve export-cargo --layer <l> --out <dir>

Materialises a Cargo local registry from the layer's verified crate entries plus a .cargo/config.toml source-replacement, so a consumer builds fully offline against varve-signed crates. The cksum Cargo verifies is varve's signed sha256.
