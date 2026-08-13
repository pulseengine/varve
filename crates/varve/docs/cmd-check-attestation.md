# varve check-attestation --statement <dsse> --file <bytes>

Checks that an attestation belongs to the layer pinned here. Two things must hold: the statement verifies against the trust root (offline, against the pinned key), and it actually describes these bytes and this layer — the carried bytes are re-hashed, and a statement naming a different layer is refused rather than quietly accepted.

That second check is the confused-deputy guard: a validly-signed statement about layer A must never pass as evidence about layer B.

What this does NOT tell you is whether the producer's claim is true. varve verified the association; the claim inside the document is verified with the producer's own key. The split is deliberate — it is what lets a disconnected site check a vendor attestation whose issuer it cannot reach.
