# varve export-crates-vendor [--layer <l>] --out <dir>

Materialises a cargo-vendor-shaped directory from the layer's verified crate entries — consumed offline by bare Cargo and Corrosion (CMake to Cargo). rules_rust needs BUILD files on top (see export-bazel-distdir + REQ-VENDOR-002).

`--layer` defaults to the resolved project pin, so the export tracks the pin. Every export writes a `.varve-export.json` stamp binding it to the producing layer; `varve verify --export <dir>` fails if the pin later moves and the export goes stale (REQ-EXPORT-SYNC-001).
