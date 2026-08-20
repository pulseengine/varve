# The root ceremony — generating and holding a realm root

> PLACEHOLDER. The authored text for this topic lives on the documentation
> branch (REQ-CUSTODY-001 clause 1) and replaces this file at merge. This stub
> exists only so the topic RESOLVES: it was shipped as a file that no topic
> registered, so `varve docs root-ceremony` answered "unknown topic" while two
> other topics linked to it.

A realm's trust root is an ed25519 keypair. Everything a consumer of that realm
will ever accept is accepted because this key signed it, and varve has no
rotation and no revocation — so the ceremony that produces it is the whole of
the key's security.

```sh
# On a machine that has never been on a network, and will not be again:
varve keygen --out root.key --pub root.pub
varve pubkey root.key            # the value a realm pins as `trust-root`
```

`root.pub` is published. `root.key` never leaves the ceremony.

See also: `varve docs signing-keys`, `varve docs own-realm`,
`varve docs threat-model`.
