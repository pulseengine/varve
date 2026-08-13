# varve sign-attestation --kind <k> --file <f> --key <k> --out <o>

(CI) Signs a statement binding an attestation to a layer: *this digest, of this kind, from this producer, accompanies this layer*. `--layer` defaults to the resolved pin.

varve vouches for the **association** and for the bytes' integrity. It does not re-attest what the producer claimed — re-signing someone else's judgement under this root would launder it into ours, and an assessor reading the chain could no longer tell who asserted what. The document is carried verbatim; whatever it claims is verified with the producer's own key.

Kinds: `sbom`, `provenance`, `audit`, `vex`, `qualification`. An unknown kind is refused, not guessed.
