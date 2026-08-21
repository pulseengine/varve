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
- A tool provided by **two** layers is an error naming both, unless the pin has chosen between them (below). varve does not choose a winner, for the same reason a pin that does not resolve uniquely is an error rather than a fallback.

## Two realms shipping one name

This is the ordinary case, not an edge case: a fork exists precisely where upstream does not attest, so `pulseengine/wasm-tools` and `bytecodealliance/wasm-tools` are both real and both wanted. Composing them collides on the name `wasm-tools`.

The pin chooses, with a **realm qualifier** in `tools`:

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "qualified"
layer   = "2026.09.0"
tools   = ["bytecodealliance/wasm-tools", "rivet"]
```

Three things that follow, and they are the point:

**The bare name is decided by the pin, never by install order.** `varve run wasm-tools` runs upstream's. Adding a tool to some other realm cannot silently change which binary a build runs — that is why realm *precedence* was considered and rejected.

**Exactly one shim exists per name.** The qualifier is pin syntax; the shim directory stays a flat namespace of bare names.

**The layer you did not choose stays installed and verified, and stays addressable:**

```sh
varve run   pulseengine/wasm-tools --version   # the fork
varve run   bytecodealliance/wasm-tools --version   # upstream
varve which pulseengine/wasm-tools             # where its bytes are
# /…/realms/7fee098c…/core/sha256-4ac5fd…/bin/wasm-tools
# layer 2026.09.0 (qualified) sha256:40083c48…        ← the layer the PIN resolves to
# provided by realm 'pulseengine' layer 2026.09.0 sha256:40083c48…   ← the layer that OWNS it
```

The third line appears only for a qualified query, and it is the one that answers "which layer owns this binary" — see the note at the end of this topic on why the second line cannot.

Comparing a fork against its upstream is a real workflow; losing the other binary would be a worse answer than refusing.

Where the pin has **not** chosen, the refusal names both providers with their realms and shows the line to copy:

```
error: tool 'wasm-tools' is provided by more than one layer of this composition —
realm 'pulseengine' layer 2026.09.0 and realm 'bytecodealliance' layer 2026.08.0 —
and the pin has not chosen between them. varve does not pick a winner: what a bare
name runs is decided by the pin, never by install order. Choose one in varve.toml:
tools = ["pulseengine/wasm-tools"] — or tools = ["bytecodealliance/wasm-tools"].
```

A qualifier separates **realms**. Two layers of the *same* realm exposing one name cannot be separated by one, and the refusal says so rather than printing a form that would not work.

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
that owns the binary, ask `which` a REALM-QUALIFIED name — it prints a
`provided by realm '…' layer …` line naming the owning layer and its digest —
or resolve it from the printed path, or pin the included layer directly in a
separate project directory. The `VARVE_LAYER` stamp a dispatched tool receives
is still the composing layer's, qualified query or not.
