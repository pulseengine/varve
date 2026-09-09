# The ingest ladder — how a payload is vouched for

Every payload enters a layer on exactly one rung, and the rung is **signed into
the manifest**. A consumer reads how the bytes were vouched for rather than
assuming they were.

| rung | what it establishes | what it does not |
|---|---|---|
| `cosign-sums` | a signed digest list, verified against the repository's own workflow identity | — |
| `build-provenance` | a SLSA attestation binding the bytes to the build that made them | — |
| `upstream-sums` | the bytes are the bytes that list names | **anything about who produced them** |
| `unverified` | nothing | everything |

The ladder is ordered, and the producer takes the highest rung a release
actually offers. It never silently descends: a release that offered
`cosign-sums` yesterday and offers nothing today stops the run rather than
quietly entering on a weaker rung.

## `upstream-sums` is deliberately named, not promoted

Some upstreams publish a digest list beside their assets and sign nothing —
zephyrproject-rtos publishes `sha256.sum`. Transcribing it establishes exactly
one fact: **the bytes are the bytes that list names.** For a 90 MB toolchain
over a CDN that is the failure which actually happens, so it is worth having.

It establishes **nothing** about who produced them, because the same host serves
the list and the bytes. That is why it is its own rung rather than being folded
into `cosign-sums` — the name has to keep saying what it does not prove.

The realm states the asset's name rather than the producer guessing it. A file
that is not the digest manifest, parsed as one, vouches for nothing while
looking like it does.

## `unverified` requires a written reason

Not a boolean. The reason is signed into the layer and shown by `varve inspect`,
so every consumer reads the operator's own words next to the bytes they were
written about. "We could not verify this" must never be the silent path.

Two entries for the same repository with different reasons is an error: the
realm has to have one position on why a source is unverified.
