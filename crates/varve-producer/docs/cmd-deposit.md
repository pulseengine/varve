# varve-producer deposit

Assemble a layer: fetch every payload the manifest names, verify each release,
stage the bytes, and write the deposit spec `varve deposit` consumes.

```sh
varve-producer deposit --manifest layer.toml --stage ./stage \
  --layer 2026.09.3 --counter 4
```

This is the one subcommand that touches the network. It does **not** deposit,
sign or publish — those need the signing key, and keeping them in a separate
step keeps this program runnable by anyone who wants to see what a layer would
contain.

## What it verifies before staging a byte

Each release against its own repository's cosign identity, once per release
rather than once per payload. The rung that verified it is recorded in the spec
and signed into the layer, so a consumer reads how a payload was vouched for
rather than assuming.

A payload whose platform the upstream does not build is reported by name and
omitted. A payload matching **nothing on any platform** stops the run — going
green with four notices is exactly how a tool went missing from a published
layer.

## Carry-forward

`--previous <spec>` and `--present-digests <file>` let an unchanged payload be
reused: its bytes come from the **destination registry** rather than upstream —
one host instead of four CDNs, no upstream rate limits, and no re-verification
of an unchanged release.

Fetched by the digest the CURRENT proof states, never the one the previous layer
recorded, and re-hashed against it: the destination is a source like any other
and gets no more trust for being ours. Absent, unreachable or wrong falls back
to upstream rather than aborting — a presence check can race a garbage
collection, and a deposit that failed because a cache was pruned would be worse
than a slower one.
