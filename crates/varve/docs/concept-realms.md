# Realms

A realm is a trust universe: a name bound to a trust root (a signing public key)
and, usually, a registry. Pinning a realm means "accept only layers signed by
this realm's root." Cross-realm acceptance is impossible by construction — a
layer signed by one realm's root will not verify under another. The canonical
`varve-realms.toml` ships with every release; `pulseengine` is the default realm.

```toml
[realm.pulseengine]
registry        = "oci://ghcr.io/pulseengine/varve/layers"
trust-root      = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973"
# trust-root-file = "./roots/pe.pub"   # or a key file, relative to this one
```

Found by walking up from the working directory, like the pin. Nearest wins; definitions are **not** merged. `registry` is required even for an air-gapped realm you never contact — a placeholder is legitimate.

`trust-root` is what `varve pubkey` prints. To run your own, see `varve docs own-realm`.

## Several realms, one file

"Not merged, nearest wins" has a consequence worth spelling out: a project
that needs TWO realms — the normal state of a composing consumer, whose own
layer includes one from an upstream realm — must define **both in the same
file**, because a nearer file naming only one realm hides every other file
entirely. Multiple `[realm.*]` tables in one `varve-realms.toml` is exactly
how that looks:

```toml
[realm.pulseengine]
registry   = "oci://ghcr.io/pulseengine/varve/layers"
trust-root = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973"

[realm.yourorg]
registry        = "oci://ghcr.io/your-org/layers"
trust-root-file = "./yourorg.pub"   # or inline: the 64 hex chars `varve pubkey` prints
```

The pin names ONE of them (`realm = "yourorg"`); the other is looked up when
an `[[include]]` or a `verify` of a composed layer names it. A composed layer
whose include names a realm this file does not define fails verify with *"that
realm is not defined here — add it to varve-realms.toml"* — the file above is
what "add it" means. Each realm keeps its own trust root and store partition;
sharing a file never merges trust.
