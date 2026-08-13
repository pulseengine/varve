# varve sbom [--layer <l>] [--format cyclonedx] [--out FILE]

Emits a CycloneDX 1.6 SBOM for a verified layer. `--layer` defaults to the resolved pin.

The document is a **transcription of the signed manifest**, not a scan. Every component name, version and SHA-256 is copied from the DSSE-signed layer manifest the trust root anchored, so the SBOM is exactly as trustworthy as the layer — and `varve verify` already decides that. A scanner can miss a component or invent one; a transcription cannot.

Output is deterministic: components are ordered by digest, the serial number is derived from the manifest digest, and the timestamp is the layer's own issued-at rather than the wall clock. Re-emitting the same layer produces byte-identical output, so a diff means the layer changed.

The document binds itself to what it describes — the manifest digest, channel and anti-rollback counter are recorded in its metadata — so an SBOM can be checked against the artifact it claims to cover.
