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

## What composition does not carry

Composition is followed by `install`, `verify`, `run`, `which` and shims —
and by nothing else. Three commands you might reasonably expect to walk the
graph do not, and each gap is invisible until it bites on the far side of an
air gap or in an assessor's reading:

**`varve archive` archives one layer, not the graph.** The `[[include]]`
reference itself survives — it is inside the signed payload and cannot be
dropped — but the included layer's manifest and payloads do not cross.
Installing the archive on the far side succeeds for the composing layer and
then fails with `composes 1 layer(s) that are not installed`, naming each
missing layer and realm. Carry **one archive per layer of the graph** and
install them included-layers-first, exactly as online:

```sh
varve archive 2026.09.0 ./arch-own       # the composing layer
cd upstream && varve archive 2026.08.0 ../arch-up   # the included one, separately
```

**`varve sbom` omits composed tools entirely.** The SBOM is transcribed from
the layer's own signed manifest, and in that manifest an included layer is
one entry: a component whose name is the manifest digest
(`sha256-4ac5fd749abf9083…`, type `platform`), with no tool names, no
versions, nothing an SBOM consumer can match a CVE against. The composed
tools appear in **the included layer's own SBOM** — emit one per layer of the
graph:

```sh
varve sbom --layer 2026.09.0 --out own.cdx.json
varve sbom --layer 2026.08.0 --out upstream.cdx.json   # its realm's qualification, its SBOM
```

**`varve which` and the `run` provenance stamp attribute a composed tool to
the COMPOSING layer.** The printed path is honest — it points into the
included layer's store partition — but the `layer …` line under it, and the
`VARVE_LAYER` / `VARVE_LAYER_MANIFEST_DIGEST` a dispatched tool receives,
name the layer the PIN resolves to, even when the binary came from an
included realm:

```sh
varve which uptool
# /…/realms/7fee098c…/core/sha256-4ac5fd…/bin/uptool   ← the included layer's bytes
# layer 2026.09.0 (qualified) sha256:40083c48…          ← the composing layer's identity
```

For provenance purposes that is a defensible statement — "produced under
this composition" — but it is not "produced by layer 2026.08.0", and tooling
that joins `VARVE_LAYER` against an SBOM will join against the one document
that (see above) does not list the tool. If the record must name the layer
that owns the binary, resolve it from the printed path or pin the included
layer directly in a separate project directory.
