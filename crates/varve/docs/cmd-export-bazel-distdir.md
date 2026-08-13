# varve export-bazel-distdir --layer <l> --out <dir>

Writes the layer's verified .crate tarballs into a Bazel distdir. Because varve's signed digest is the crate_universe pin, 'bazel build --distdir=<dir>' resolves each crate from varve's verified bytes with no network — the air-gap rules_rust byte source.
