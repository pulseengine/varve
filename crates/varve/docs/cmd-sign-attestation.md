# varve sign-attestation --kind <k> --file <f> --key <k> --out <o>

(CI) Signs a statement binding an attestation to a layer: *this digest, of this kind, from this producer, accompanies this layer*. `--layer` defaults to the resolved pin.

A statement signed in a session whose user-level configuration allowed shim passthrough records the allowed tools in the signed statement (`ambient_tools`, REQ-PASSTHROUGH-001); one signed in a pure session is unchanged. See `varve docs shim`.

varve vouches for the **association** and for the bytes' integrity. It does not re-attest what the producer claimed — re-signing someone else's judgement under this root would launder it into ours, and an assessor reading the chain could no longer tell who asserted what. The document is carried verbatim; whatever it claims is verified with the producer's own key.

Kinds: `sbom`, `provenance`, `audit`, `vex`, `qualification`. An unknown kind is refused, not guessed.

## In a realm that declares key roles

`--delegation FILE` makes this command sign as the LAYER role and refuses, before
signing, a key that is not delegated to it (including the realm root).
`--key-id` then defaults to the delegation's entry for the key. See `varve docs
sign-delegation`. Without it the command behaves exactly as before.
