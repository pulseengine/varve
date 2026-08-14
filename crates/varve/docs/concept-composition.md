# Composition

One pin, two trust universes. Your layer holds the tools you qualify; it *composes* an upstream layer holding tools you do not control — and each keeps its own root, cadence and qualification claim.

## Producing one

An `[[include]]` in the deposit spec, naming the included layer by the digest of its signed manifest:

```toml
layer   = "2026.09.0"
channel = "qualified"
counter = 1

[[tool]]
name = "acmetool"
version = "1.0.0"
path = "./dist/acmetool"

[[include]]
digest = "sha256:8b65864f2d9c7a3e1b5f8d2c6a9e4b7d3f1c8a5e2b9d6c3f7a4e1b8d5c2f9a6e"          # the included layer's manifest digest
realm  = "bytecodealliance"        # whose trust root verifies it
layer  = "2026.08.0"               # for error messages before it is fetched
```

The include lives inside the signed payload, so the composition itself is signed and cannot drift.

## Installing

Install the included layer first, then the layer that composes it:

`install` resolves **the project's pin** against `--from`, so you cannot install
two different layers from one project directory by changing `--from` alone. The
included layer needs its own pin:

```sh
# 1. a directory pinned to the UPSTREAM layer
mkdir -p upstream && cd upstream
cat > varve.toml <<'EOF'
manifest-version = 1

[toolchain]
realm   = "bytecodealliance"
channel = "qualified"
layer   = "2026.08.0"
EOF
varve install --from ../upstream-layout

# 2. back in your own project, pinned to the composing layer
cd .. && varve install --from ./our-layout
```

Both land in the same `$VARVE_ROOT`, partitioned by realm, which is why step 2
then finds what step 1 installed.

Order matters: installing a composition whose includes are absent is refused, naming each missing layer and its realm. varve does **not** fetch includes transitively — it names what it needs by digest and leaves obtaining it to you.

## What verify does

```sh
$ varve verify
layer 2026.09.0 sha256:97f920… verified: signature OK, 1 tool(s) match their signed digests
  composes 2026.08.0 sha256:5be938… — verified against realm 'beta': 1 tool(s) match
```

Each included layer is checked against **its own** realm's trust root, recursing. Your root does not vouch for another realm's bytes, and that separation is the reason to compose rather than merge everything into one layer.

## The rules

- A **cycle** — a layer reappearing on its own path — is refused.
- A **diamond**, where two layers share a base, is legal and walked once.
- Depth is bounded at 8.
- A tool exposed by **two** layers is an error naming both. varve does not choose a winner, for the same reason a pin that does not resolve uniquely is an error rather than a fallback.
