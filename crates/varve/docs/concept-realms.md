# Realms

A realm is a trust universe: a name bound to a trust root (a signing public key)
and, usually, a registry. Pinning a realm means "accept only layers signed by
this realm's root." Cross-realm acceptance is impossible by construction — a
layer signed by one realm's root will not verify under another. The canonical
`varve-realms.toml` ships with every release; `pulseengine` is the default realm.

```toml
[realm.pulseengine]
registry        = "oci://ghcr.io/pulseengine/varve/layers"
trust-root      = "83a6991d0c2f4b7e5a8d3c6f9b2e4a7d1c8f5b3e6a9d2c7f4b1e8a5d3c6f9b2e"
# trust-root-file = "./roots/pe.pub"   # or a key file, relative to this one
```

Found by walking up from the working directory, like the pin. Nearest wins; definitions are **not** merged. `registry` is required even for an air-gapped realm you never contact — a placeholder is legitimate.

`trust-root` is what `varve pubkey` prints. To run your own, see `varve docs own-realm`.
