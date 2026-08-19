# Payload kinds, and which export adapter to run

A layer entry declares its kind: `tool` (an executable), `crate` (a Rust
`.crate`), `wit` (a WIT package), `zephyr-module`, `sdk`, `wasm-component`, or
`vsix` (a VS Code extension package).

Only a `tool` is **dispatched by name** — `varve run`, `varve which` and the
argv[0] shims resolve a bare name — so only a tool is laid down at `bin/<name>`
with the execute bit. Every other kind is *held*: its identity is
(name, version), it lands under `payloads/<name>/<version>`, and it is data
varve hands to another program (mode 0644). That is why one layer can carry
`serde` at two versions, or one extension at two versions, and why a `.vsix` is
never executable.

The kind does **not** change verification — every kind is a signed digest
checked against the trust root, exactly as a tool binary is. An unknown kind is
refused where it is consumed; install is kind-agnostic, so a layer using a kind
your varve does not know still installs.

## Choosing an adapter

The kind does not by itself select the adapter. Three adapters key on
`kind = "crate"`; `export-bazel` ignores kind entirely and keys on **`platform`
plus `[tool.source]`**, both set at deposit time.

| Your consumer is | Run | It produces | Entries it takes |
|---|---|---|---|
| Cargo, offline | `varve export-cargo --out D` | `D/registry/` + a `.cargo/config.toml` redirecting crates.io | `kind = "crate"` |
| `cargo vendor`-style tree | `varve export-crates-vendor --out D` | unpacked crate sources + a vendor config | `kind = "crate"` |
| Bazel `rules_rust`, air-gapped | `varve export-bazel-distdir --out D` | `.crate` tarballs for `bazel build --distdir=D` | `kind = "crate"` |
| Bazel `rules_wasm_component` | `varve export-bazel --out D` | one `<tool>.json` checksum registry per tool | any entry with a **platform** and **`[tool.source]`** |
| VS Code / VSCodium | `varve export-vsix --out D` | `publisher.name-version.vsix` files for `code --install-extension` | `kind = "vsix"` |

`export-bazel` is the exception because a Bazel toolchain repository rule
fetches from the upstream URL itself — so varve can only emit a registry for an
entry whose upstream repo, asset name and sha256 were recorded when it was
deposited. Without those it prints `skipped <tool> (<platform>): no source
provenance recorded at deposit`, and if nothing qualifies it fails with
`nothing exported`. Record them with `[tool.source]` and `platform` in the
deposit spec (`varve docs config-reference`).

Every adapter writes a `.varve-export.json` stamp binding the directory to the
layer that produced it, so `varve verify --export DIR` fails when your pin moves
and the export does not.
