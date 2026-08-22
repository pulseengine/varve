# varve export-vsix [--layer <l>] --out <dir>

Lays the layer's verified `vsix` entries out as `publisher.name-version.vsix`
files — the marketplace's own asset name — so `code --install-extension <file>`
installs an editor extension whose bytes varve signed, with no marketplace
round-trip.

A reproducible development environment pins its compiler, its linker and its
test runner, and then installs editor extensions from a marketplace with no
verification at all. A `.vsix` is one zip file, so it is a payload kind like
any other: signed digest, checked against the trust root, refused when it does
not match (`varve docs payload-kinds`).

`--layer` defaults to the resolved project pin, so the export tracks the pin.
Every export writes a `.varve-export.json` stamp binding it to the producing
layer; `varve verify --export <dir>` fails if the pin later moves and the
export goes stale (REQ-EXPORT-SYNC-001).

## Depositing an extension

`kind = "vsix"` in the deposit spec, with the extension's marketplace id as the
payload name. A layer may hold several extensions, and several **versions** of
one extension — an extension is not dispatched by name, so its identity is
(name, version), exactly as for a crate.

```toml
layer = "2026.08.0"
channel = "qualified"
counter = 1

[[tool]]
name = "rust-lang.rust-analyzer"
version = "0.3.2260"
kind = "vsix"
path = "vsix/rust-analyzer-0.3.2260.vsix"

[[tool]]
name = "vadimcn.vscode-lldb"
version = "1.11.4"
kind = "vsix"
path = "vsix/codelldb-1.11.4.vsix"
```

## Exporting and installing

```sh
varve install
varve export-vsix --out ./extensions

# exported 2 verified VS Code extension(s) to /w/extensions — install them with:
#   code --install-extension /w/extensions/rust-lang.rust-analyzer-0.3.2260.vsix
#   code --install-extension /w/extensions/vadimcn.vscode-lldb-1.11.4.vsix

code --install-extension ./extensions/rust-lang.rust-analyzer-0.3.2260.vsix
```

The printed lines name every file, one per extension: `code` installs one
`.vsix` per invocation, and it dispatches on the `.vsix` suffix — an argument
without it is read as a marketplace id and **fetched from the network**, which
is what this export exists to avoid.

Later, when the pin moves and the committed export does not:

```sh
varve verify --export ./extensions
# export ./extensions — STALE: stamped from layer 2026.07.0 (sha256:…)
```

## What is deliberately not done

* The `.vsix` files carry **no execute bit** (mode 0644), in the store and in
  the export. They are zips handed to `code`, not programs varve dispatches —
  `varve which` and `varve run` do not resolve them.
* varve does not run `code` for you and does not manage an extensions
  directory. It hands you verified bytes under a name your editor accepts; the
  install is yours to run, script, or bake into an image.
* varve does not read inside the zip. The name and version come from the
  **signed manifest**, not from the extension's own `package.json`, so what
  the export is named is what the trust root anchored.
* An extension id that could not be a safe file name — one containing `/`, or
  starting with `-`, which `code` would read as a flag — is refused before
  anything is written, whole, rather than half-exported.
