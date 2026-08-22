# Trust roots

The trust root is the ed25519 public key varve verifies every layer signature
and artifact digest against, on every path — registry pull, authenticated pull,
or archived core — before any byte is used. It is pinned (via a realm or
`VARVE_TRUST_ROOT`), never fetched at acceptance time. Verification is
independent of where the bytes came from: a source can change availability,
never a verdict.
