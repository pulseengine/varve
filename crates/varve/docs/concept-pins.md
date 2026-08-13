# Pins

A project declares the toolchain it uses in `varve.toml` — the pin. varve walks
up from the working directory to find it, resolves the exact layer it names, and
fails with the corrective `varve install` command if that layer is not installed.
A pin names a `realm`, a `channel` (qualified | rolling), and a `layer`
(`YYYY.MM.P`); optionally a manifest digest for byte-exact freezing. varve never
falls back to another layer or to binaries on PATH — a pin resolves exactly or
the command fails.
