# diff — what changing to another layer would change

A toolchain bump raises one question: *what actually moves if I take it?*
Before this, the answer was `varve inspect --layer` twice and your own eyes,
across a payload table that runs to dozens of rows and, for a composition,
several layers.

`varve diff` answers it from the two **signed manifests**. It is a
transcription, not a judgement — both sides are signed, and the diff states
what two trust roots already attested.

```sh
varve diff 2026.09.15 2026.09.16
```

```
layer 2026.09.15 -> 2026.09.16

  CHANGED  ordeal  0.21.0 -> 0.22.0  aarch64-apple-darwin       cosign-sums
  CHANGED  ordeal  0.21.0 -> 0.22.0  aarch64-unknown-linux-gnu  cosign-sums
  CHANGED  rivet   0.38.0 -> 0.39.0  x86_64-unknown-linux-gnu   cosign-sums
  CHANGED  synth   0.74.0 -> 0.75.0  x86_64-apple-darwin        cosign-sums

13 changed, 0 added, 0 removed
```

One tool on four platforms is four payloads, and each is reported. A pin
resolves per platform, so a bump that lands on three of four is a thing you
need to see.

## The proof of origin is a finding, not a column

The most consequential thing a bump can carry is not a version. It is a
payload that **stopped being vouched for** — and no version number shows it.
So it is reported on its own line rather than as a column to scan past:

```
! CHANGED  wac  0.11.0 -> 0.12.0  x86_64-unknown-linux-gnu  cosign-sums -> unverified

1 changed, 0 added, 0 removed
! wac (x86_64-unknown-linux-gnu) LOST its proof of origin: cosign-sums -> unverified
```

Two findings exist, and they say different things:

| finding | meaning |
|---|---|
| `lost-proof-of-origin` | something vouched for these bytes before; **nothing** does now |
| `stopped-recording-proof` | the older layer recorded how it was vouched for; the newer records nothing |

What varve will **not** do is rank two accepted proofs against each other.
`cosign-sums` and `build-provenance` both vouch, and they carry different
claims — provenance says where bytes came from, a sums file says what they
hash to. Moving between them is reported as a change and never as a finding,
because collapsing that distinction would be varve inventing a judgement on
your behalf. An ingestion mechanism this varve does not recognise is likewise
reported verbatim and never guessed about.

## Gating a bump in CI

`--json` is the only producer of delta data in varve; the table above is one
rendering of it. Refuse any bump that drops a proof of origin:

```sh
varve diff "$OLD" "$NEW" --json \
  | jq -e '[.findings[] | select(.finding == "lost-proof-of-origin")] | length == 0' \
  > /dev/null || {
      echo "refusing the bump: a payload lost its proof of origin" >&2
      exit 1
  }
```

The document's shape:

```json
{
  "from": {
    "layer": "2026.09.15",
    "manifest_digest": "sha256:fd5944569898b4ea719256f415d273875d58baa5578c9529665451dcbed65e52"
  },
  "to": {
    "layer": "2026.09.16",
    "manifest_digest": "sha256:800dd32958e498d4217f302da3cb9db2ced36902c0e0b81993ff8f4798d3519d"
  },
  "added": [],
  "removed": [],
  "changed": [
    {
      "payload": {
        "name": "ordeal",
        "kind": "tool",
        "platform": "aarch64-apple-darwin",
        "target": null,
        "realm": "pulseengine"
      },
      "version": {
        "from": "0.21.0",
        "to": "0.22.0",
        "moved": true
      },
      "digest": {
        "from": "sha256:7c05552bbec3f2c153e753e1dad1ee55f5af56e9bde0e74720ed3607857ef200",
        "to": "sha256:0bbf78e6ee947c7dd154fa67d461125e6039b2bc5387e0a3ade8d477abaf9fe1"
      },
      "ingest_proof": {
        "from": "cosign-sums",
        "to": "cosign-sums",
        "moved": false
      }
    }
  ],
  "findings": [
    {
      "finding": "lost-proof-of-origin",
      "payload": {
        "name": "wac",
        "kind": "tool",
        "platform": "x86_64-unknown-linux-gnu",
        "target": null,
        "realm": "pulseengine-wasm"
      },
      "from": "cosign-sums",
      "detail": "these bytes were vouched for in the older layer and are explicitly vouched for by nothing in the newer one"
    }
  ]
}
```

## What it does not do

**It does not fetch.** Both layers must already be installed; a side that is
not is reported as absent —

```
error: layer 2026.09.12 is not installed — varve install it first
```

— rather than quietly reaching for a registry. Asking what a bump would change
must never be the thing that performs it.

**It does not touch the pin or the store.** `diff` is read-only, in both
directions. Changing your pin is `varve.toml`, and it stays the only way a
project changes layers.

**It does not tell you whether a newer layer exists.** That is the other half
of REQ-LAYERDIFF-001 and it is `varve outdated`, which reads the realm's
SIGNED index — never an unauthenticated tag listing, because a registry that
*hides* a layer is undetectable that way. `varve docs outdated`.

## Composition

Each payload carries the realm that vouched for it, so a diff across a
composed layer attributes every change to the root that signed it. A tool
appearing in the `bytecodealliance` realm and one appearing in `pulseengine`
are different payloads even under the same name.

See also: `varve docs inspect`, `varve docs composition`, `varve docs exit-codes`.
