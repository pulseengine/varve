# Payload kinds

A layer entry declares its kind: `tool` (an executable), `crate` (a Rust
`.crate`), `wit` (a WIT package), `zephyr-module`, `sdk`, or `wasm-component`.
The kind selects which export adapter applies; it does NOT change verification —
every kind is a signed digest checked against the trust root, exactly as a tool
binary is. An unknown kind is refused where it is consumed; install is
kind-agnostic (forward-compatible).
