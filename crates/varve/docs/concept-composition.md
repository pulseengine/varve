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
digest = "sha256:8b6586…"          # the included layer's manifest digest
realm  = "bytecodealliance"        # whose trust root verifies it
layer  = "2026.08.0"               # for error messages before it is fetched
```

The include lives inside the signed payload, so the composition itself is signed and cannot drift.

## Installing

Install the included layer first, then the layer that composes it:

```sh
varve install --from ./upstream-layout    # pinned to the upstream realm
varve install --from ./our-layout         # pinned to ours
```

Order matters: installing a composition whose includes are absent is refused, naming each missing layer and its realm. varve does **not** fetch includes transitively — it names what it needs by digest and leaves obtaining it to you.

## What verify does

```sh
$ varve verify
layer 2026.09.0 sha256:97f920… verified: signature OK, 1 tool(s) match
  composes 2026.08.0 sha256:5be938… — verified against realm 'beta': 1 tool(s) match
```

Each included layer is checked against **its own** realm's trust root, recursing. Your root does not vouch for another realm's bytes, and that separation is the reason to compose rather than merge everything into one layer.

## The rules

- A **cycle** — a layer reappearing on its own path — is refused.
- A **diamond**, where two layers share a base, is legal and walked once.
- Depth is bounded at 8.
- A tool exposed by **two** layers is an error naming both. varve does not choose a winner, for the same reason a pin that does not resolve uniquely is an error rather than a fallback.
