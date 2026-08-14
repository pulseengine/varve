<div align="center">

# varve

<sub>the PulseEngine toolchain layer manager</sub>

&nbsp;

**Pinned, signed, dated toolchain bundles. One layer per release — read the one your project pins.**

</div>

---

> **Status: implemented, rolling channel.** varve is released (see the
> [releases](https://github.com/pulseengine/varve/releases)) and dogfooded —
> the PulseEngine toolchain ships as signed layers on
> `ghcr.io/pulseengine/varve/layers`. The **qualified** channel is not open
> yet: it awaits the trust-root ceremony (the v1.0 gate), so today's layers
> are signed with a provisional rolling key and make no qualification
> promise. The release plan lives in rivet (`rivet release status`); see
> [SECURITY.md](SECURITY.md) for the current trust posture and its limits —
> or `varve docs threat-model`, which carries the same limits inside the
> binary and so travels across an air gap.

## Getting started

Install one PulseEngine toolchain layer, verified, and dispatch its tools —
the zero-config path uses a **realm**, so no environment variable is needed:

```sh
# 1. In your project, pin a layer and name the realm:
cat > varve.toml <<'PIN'
manifest-version = 1
[toolchain]
realm   = "pulseengine"
channel = "rolling"
layer   = "2026.08.2"
PIN

# 2. Drop in the canonical realm definitions (registry + trust root).
#    Ships as `varve-realms.toml` with every release, and lives at
#    trust-roots/ in this repo:
curl -LO https://github.com/pulseengine/varve/releases/latest/download/varve-realms.toml

# 3. Install (verified against the realm's root — no env var), then shim:
varve install
varve shim install        # then: . "$HOME/.varve/env"
rivet --version           # dispatched from the pinned layer
```

Without a realm, point `VARVE_TRUST_ROOT` at the published root key
(`rolling.pub`, a release asset) and pass `--from oci://ghcr.io/pulseengine/varve/layers`.
The rolling channel is provisional and makes no qualification promise — see
[SECURITY.md](SECURITY.md), or `varve docs threat-model` where the network is
not available. New to varve? `varve docs getting-started` is the five-minute
transcript; `varve docs config-reference` is every file you will hand-write.

## The problem

Three consumers, two toolchains, one afternoon:

| consumer | needs |
|---|---|
| relay | the August toolchain |
| jess | the August toolchain |
| wohl | the **July** toolchain |

They are frozen on different toolchains **on purpose**. Once a project takes a
qualified toolchain it stays there, because re-qualification costs money. A tool
that quietly moves them forward destroys evidence they paid for.

At the same time, being stale silently is expensive in the other direction: a
capability gap was once filed against this toolchain *thirteen days after the fix
shipped*, because the reporter's binary was one release behind and nothing said so.

`varve` exists to make both failures impossible: the pin is honoured exactly, and
divergence from it is loud.

## Why "varve"

A **varve** is an annual layer of sediment laid down in still water. Varve
chronology dates by *counting layers back*, like tree rings — absolute dates you
can correlate between sites.

| varve | here |
|---|---|
| one annual layer, dated | one bundle release — `2026.07`, `2026.08` |
| immutable once deposited | digest-pinned, signed, never rewritten |
| the whole column is preserved | every qualified line stays reconstructible |
| you read the layer you need | wohl reads July while relay reads August |
| counting back gives absolute dates | *"which layer produced this artifact?"* |
| a **core** is extracted and archived | the offline bundle — the artifact of record |

## What it will do

```sh
varve install                      # resolve this project's pin, fetch, verify, lay down
varve verify                       # re-check an installed layer against its signature
varve which synth                  # which binary runs here — and which layer it came from
varve list                         # layers present locally, and which projects pin them
varve archive 2026.07 core.tar     # extract the core: the offline artifact of record
varve run --varve 2026.09 -- synth # one-off, without editing the pin
varve deposit                      # (CI) assemble and sign a layer, locally — see
                                   #      `varve docs deploy` to publish it
```

A project declares its layer in a checked-in manifest; shims on `PATH` resolve it
by walking up from the working directory, then exec the real binary. Switching
projects is `cd`.

## Scope

**In scope — `varve` selects, verifies, and hands over tools.**

- resolve a project's pinned layer and install it, verifying every signature and
  digest against the PulseEngine trust root
- keep many layers side by side in a content-addressed core, so switching costs nothing
- dispatch per project via shims, and answer *which binary am I actually running*
- archive a layer for offline reconstruction, independent of any registry
- stamp the layer identity into build outputs, so an artifact records the toolchain
  that produced it

**Out of scope — deliberately.**

- **It never transforms your code.** `varve` selects and verifies; every
  compilation, fusion, optimisation and proof belongs to the tools it hands you.
  This boundary is what keeps its qualification scope small and separate.
- **No auto-update, ever.** Moving a project between layers is an edit to a
  checked-in file, reviewed like any other change. A background updater would be a
  defect, not a feature.
- **No silent fallback.** If a pinned layer is missing, `varve` fails and tells you
  how to install it. It never runs "whatever else is on `PATH`".
- **No server of our own.** An OCI registry is the transport. Access control, when
  it is ever needed, is registry authentication — see below.

## Shape

**A CLI and a library. No service.**

| crate | role |
|---|---|
| `varve` | the CLI, the shims, and `deposit` for CI |
| `varve-core` | manifest format, resolution, the core store, verification wiring |

Distribution is an **OCI image index** on a registry (public GHCR by default), signed
by digest, with attestations and qualification evidence attached as OCI *referrers*.
Verification is [`sigil`](https://github.com/pulseengine/sigil), used as a library.

Where the bytes come from is pluggable — a public registry, a private one, an
archived core. **Whether they are accepted is not.** Signature and digest checks run
against our trust root on every path, and swapping the source must never change a
verdict.

## Decisions (formerly open questions)

Both shaped the manifest format, so both were settled before it freezes
(2026-08-07, after a research pass over criticalup/Ferrocene, TUF, Uptane,
SUIT/RFC 9019, DO-330 and qualified-vendor patch practice — the evidence lives
in the rivet artifacts, DD-004/DD-005 and CA-*/AR-*):

1. **Anti-rollback → monotonic per-line counters.** Every layer manifest carries a
   release counter and issued-at timestamp inside the signed payload; the client
   keeps a high-water mark per line and rejects anything below it, warning past a
   staleness threshold. The SUIT/Uptane pattern: works on static hosting and in
   air gaps, survives registry compromise, no re-signing treadmill. tuf-on-ci is
   the recorded upgrade path if a connected freshness channel is ever needed.
2. **Patching a frozen line → three-part identifiers.** A layer is always
   `YYYY.MM.P` — `2026.07.0` deposits the July line, `2026.07.1` patches it *in
   place*, carrying a signed qualification-delta attestation scoped to what
   changed, plus known-problems referrers as the no-patch mitigation path. The
   frozen-line model every qualified-tool vendor converges on, made mechanical.

## Documentation, embedded and queryable

varve's docs ship *inside the binary* — no files, no network, so they work
air-gapped. `varve docs` lists topics; `varve docs <topic>` shows one (every
subcommand, plus concepts: pins, realms, layers, trust-roots, payload-kinds,
air-gap); `varve docs --grep <q>` searches; `varve docs --format json` emits the
same content for machine queries (modelled on `rivet docs`). Coverage is a
**checked invariant**, not review discipline: `varve docs check --coverage
--strict` fails if any top-level subcommand lacks a topic, so an undocumented
command cannot ship (CI-gated, like the review and claim checks).

## Independent review

varve is largely authored through an AI-driven feature loop, so "verified" must
never rest on the author's own word (REQ-INDEP-001). From v0.14.0 each release
carries a **recorded independent-review verdict**: a fresh-context clean-room
reviewer re-derives every claimed result from evidence — runs the named tests,
re-checks the oracles, tries to refute — and its verdict is recorded **as a
first-class rivet artifact**: a `method: review` verification (e.g.
`VER-REVIEW-v0.14.0`) whose `verifies` links name the reviewed requirements and
whose `baseline` records the reviewer, date, outcome, and findings. Because it
lives in the rivet graph, `rivet validate` checks its coherence natively — no
parallel file format. `tools/review-check.py` adds one advisory query over
`rivet … --format json`: which released, verified requirements still lack a
review.

The record is **advisory at v0.x** (DD-019): a missing review only warns — the
auditable trail is the deliverable, not yet a hard gate. The refute-and-block
release gate (no verdict, no tag) lands at v1.0 alongside the root ceremony.
Recording first, then gating, keeps the claim honest at each stage: *independent
review is recorded* now, *independence is enforced* at v1.0.

## Distributing more than binaries

A tool binary is just bytes with an exec bit; a Rust crate, a WIT package, a
Zephyr module, an SDK are also just bytes. From v0.15.0 a layer entry declares
its **payload kind** (`tool | crate | wit | zephyr-module | sdk |
wasm-component`) in its signed annotations — verification is unchanged (every
kind is a signed digest checked against the trust root; an unknown kind is
refused, never guessed), and per-consumer **export adapters** wire the
*verified* store path into each build system's native mechanism. No git server:
a content-addressed, signed, anti-rollback path is the feature, not a hack.

First adapter — **`varve export-cargo`** (REQ-CRATE-001): it materialises a
Cargo **local registry** (the `.crate` files plus an index) from a layer's
verified `crate` entries and emits a `.cargo/config.toml` source-replacement, so
a consumer builds **fully offline** against crates whose bytes varve signed. The
cksum Cargo verifies *is* varve's signed sha256 of the `.crate`, so Cargo
re-checks the integrity on its own terms. Proven end to end by a real
`cargo build --offline` against an exported registry.

```sh
varve export-cargo --layer 2026.08.0 --out ./vendored
# copy ./vendored/.cargo/config.toml into your project's .cargo/, then:
cargo build --offline
```

Every export is **pinned to the layer that produced it**: `--layer` defaults to
the resolved project pin, and each export writes a `.varve-export.json` stamp
recording that layer's manifest digest. `varve verify --export <dir>` re-derives
the pin and **fails** if a committed export has gone stale — so a vendored tree
that silently lags the pin is a CI failure, not a surprise at build time
(REQ-EXPORT-SYNC-001). The same anti-stale discipline varve applies to the
toolchain, applied to the byte-sources it exports.

WIT + wasm-components, Zephyr modules, and C SDKs follow the same shape in later
releases; Bazel gets an export per kind (extending `varve export-bazel`).

## Related

- [pulseengine.eu#157](https://github.com/pulseengine/pulseengine.eu/issues/157) — the design thread
- [sigil](https://github.com/pulseengine/sigil) — signing, attestation, air-gapped trust bundles
- [rivet](https://github.com/pulseengine/rivet) — traceability; a layer manifest is a typed artifact

## License

Apache-2.0

<div align="center">
<sub>Part of <a href="https://github.com/pulseengine">PulseEngine</a> — a WebAssembly toolchain for safety-critical systems, with formally verified components</sub>
</div>
