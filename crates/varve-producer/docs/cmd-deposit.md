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

## License and upstream SBOM (REQ-SBOMFIELDS-001)

Two more facts are recorded in `[tool.source]` when upstream actually states
them, and never guessed when it does not:

* **`license`** — the repository's own DECLARED SPDX license
  (`GET /repos/<repo>`). Fetched once per distinct repository, however many
  payloads of it this run resolves. GitHub's `license: null` and
  `spdx_id == "NOASSERTION"` both read as "nothing declared" and record
  nothing — never a license this assembler invents.
* **`sbom`** / **`sbom-sha256`** — the file name and sha256 of a CycloneDX
  SBOM (`*.cdx.json`) the SAME release publishes. Recorded only when exactly
  one such asset exists; zero is a release that ships none, and several are
  ambiguous unless exactly one of them names the release's own version —
  guessing between the rest would be signed into the layer as fact, so
  nothing is recorded instead and a one-line note says why.

A layer deposited before this requirement, or a repo/release that genuinely
carries neither, has all three fields absent — absence that must never be
read as "no license" or "no SBOM" rather than "nobody said".

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
