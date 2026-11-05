# Signing keys

A varve signing key is **128 hex characters**: a 32-byte ed25519 seed followed by its 32-byte public key. The public half alone — 64 hex characters — is what a realm pins as `trust-root`. Stated here once, because it used to be discoverable only by brute force.

```sh
varve keygen --out root.key --pub root.pub   # mint one
varve pubkey root.key                        # re-print the public half
```

`keygen` writes the key mode 0600 and refuses to overwrite either file: a signing key and a published trust root are both things you lose quietly and expensively.

## What the key is

It is the whole of a realm's authority. Every layer a realm publishes is accepted because it verifies against this one value, so the key's custody *is* the realm's security. varve's own rolling key is provisional and marked as such; a real root is generated in a ceremony, not on a build machine.

## What varve checks

Before signing anything, varve round-trips a probe through the key: it signs, then verifies with the public half the file carries. A key whose halves disagree is refused outright, because it signs happily and produces layers **no trust root can ever verify** — a permanently broken release artifact that looks successful. That check runs at every signing command, not just `deposit`.

## Rotation and revocation — the honest state

varve has neither yet. There is one root per realm, no expiry, and no revocation channel. A realm may opt into key roles (`key-roles = true`, `varve docs sign-delegation`): the root then signs only a delegation naming a LAYER key (layers, attestations, release sums) and a STATUS key (line-status, line-index), so a leaked depositor key cannot sign a yank. A realm that declares none has one flat key signing everything, and there a compromised key means publishing a new realm definition and having consumers re-pin it. A signed revocation record is part of the v1.0 trust-root ceremony; until then, treat the root as a single point of failure and store it accordingly.
