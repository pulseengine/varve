# Realms

A realm is a trust universe: a name bound to a trust root (a signing public key)
and, usually, a registry. Pinning a realm means "accept only layers signed by
this realm's root." Cross-realm acceptance is impossible by construction — a
layer signed by one realm's root will not verify under another. The canonical
`varve-realms.toml` ships with every release; `pulseengine` is the default realm.
