# varve export-crates-vendor --layer <l> --out <dir>

Materialises a cargo-vendor-shaped directory from the layer's verified crate entries — consumed offline by bare Cargo and Corrosion (CMake to Cargo). rules_rust needs BUILD files on top (see export-bazel-distdir + REQ-VENDOR-002).
