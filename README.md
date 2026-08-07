<div align="center">

# varve

<sub>the PulseEngine toolchain layer manager</sub>

&nbsp;

**Pinned, signed, dated toolchain bundles. One layer per release — read the one your project pins.**

</div>

---

> **Status: design.** Nothing is implemented yet. The architecture is settled
> ([pulseengine.eu#157](https://github.com/pulseengine/pulseengine.eu/issues/157));
> two decisions are open (see [Open questions](#open-questions)). Do not depend on
> anything here yet.

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
varve deposit                      # (CI) assemble, sign and publish a layer
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

## Open questions

Both shape the manifest format, so both are cheap now and expensive later:

1. **Anti-rollback.** Nothing yet prevents serving an older, validly-signed layer.
   Consuming Sigstore's TUF root does not give us snapshot/timestamp roles over our
   own release stream.
2. **Patching a frozen line.** A serious defect in the July layer cannot be answered
   with *"move to August"* — that is precisely the cost the consumer froze to avoid.
   `2026.07.1` must be expressible, with the qualification delta scoped to what changed.

## Related

- [pulseengine.eu#157](https://github.com/pulseengine/pulseengine.eu/issues/157) — the design thread
- [sigil](https://github.com/pulseengine/sigil) — signing, attestation, air-gapped trust bundles
- [rivet](https://github.com/pulseengine/rivet) — traceability; a layer manifest is a typed artifact

## License

Apache-2.0

<div align="center">
<sub>Part of <a href="https://github.com/pulseengine">PulseEngine</a> — a WebAssembly toolchain for safety-critical systems, with formally verified components</sub>
</div>
