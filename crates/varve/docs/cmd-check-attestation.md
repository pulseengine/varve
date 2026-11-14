# varve check-attestation --statement <dsse> --file <bytes>

Checks that an attestation belongs to the layer pinned here. Two things must hold: the statement verifies against the trust root (offline, against the pinned key), and it actually describes these bytes and this layer — the carried bytes are re-hashed, and a statement naming a different layer is refused rather than quietly accepted.

When the statement records that its signing session allowed ambient tools, the output says so (REQ-PASSTHROUGH-001).

That second check is the confused-deputy guard: a validly-signed statement about layer A must never pass as evidence about layer B.

What this does NOT tell you is whether the producer's claim is true. varve verified the association; the claim inside the document is verified with the producer's own key. The split is deliberate — it is what lets a disconnected site check a vendor attestation whose issuer it cannot reach.

A MIXED project (`[toolchain.override.<tool>]`, REQ-OVERRIDE-001) is attested only by a statement that records the same overrides: `sign-attestation` in a mixed project signs them into the statement, and `check-attestation` refuses a statement made for the pure pin, for another mix, or a mixed statement in a pure project — evidence about one toolchain is not evidence about another.

The overrides are recorded in the signed statement. A varve v0.47.0 refuses a statement that carries them (it denies fields it does not know); one **before** v0.47.0 ignores them and takes a mixed statement for the pure layer's. That limit is stated rather than closed: the statement's join key stays the pinned layer's digest.
