# Pins

A project declares the toolchain it uses in `varve.toml` — the pin. varve walks
up from the working directory to find it, resolves the exact layer it names, and
fails with the corrective `varve install` command if that layer is not installed.
A pin names a `realm`, a `channel` (qualified | rolling), and a `layer`
(`YYYY.MM.P`); optionally a manifest digest for byte-exact freezing. varve never
falls back to another layer or to binaries on PATH — a pin resolves exactly or
the command fails.

Prefer pinning the `digest` as well as the layer name. Beyond byte-exact
freezing, it is what makes resolution constant-time: with a digest varve reads
exactly one manifest, while a name-only pin must read every installed layer's
manifest to find the one you meant. Measured on a release build: digest-pinned
resolve stays at ~37 microseconds whether the core holds 3 layers or 200, while
a name-only pin costs ~74 microseconds at 3 layers and ~2.5 milliseconds at 200.
Layers coexist on purpose, so a long-lived machine drifts into the slow case.

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "qualified"
layer   = "2026.08.2"
digest  = "sha256:83a6991d0c2f4b7e5a8d3c6f9b2e4a7d1c8f5b3e6a9d2c7f4b1e8a5d3c6f9b2e"   # example; `varve list` prints the real one
tools   = ["rivet", "synth"]    # optional; a subset, plain names only
```

Full field reference: `varve docs config-reference`.
