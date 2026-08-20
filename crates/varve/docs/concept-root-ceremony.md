# The root ceremony — generating and holding a realm root

`varve keygen` takes about a millisecond. The ceremony around it is everything
else: where the key is generated, who holds it afterwards, how it survives a
decade, and what you do the day it leaks. This topic is that procedure, and an
honest list of what varve does not do for you.

Read `varve docs signing-keys` first for the key FORMAT. This topic assumes it.

## Why a ceremony at all

A realm root is not "a credential". It is the entire definition of the realm:
every layer a consumer accepts is accepted because it verifies against this one
64-hex value, and consumers hold that value in a file they wrote by hand. There
is no authority above it that could correct it, and — see the limits below —
nothing that can retire it. It is the longest-lived secret your organisation
will own.

## 1. Generate it on a machine that is off the network

Every command here is offline; none of them contacts a registry, an API, or a
transparency log (`varve docs air-gap`). So generate on a machine that has
never been and never will be connected — a wiped laptop, a live USB image, an
existing air-gapped build host. Two people present, and the transcript recorded
on paper.

```sh
varve keygen --out root.key --pub root.pub
varve pubkey root.key            # refuses a key whose halves disagree
```

`keygen` writes `root.key` mode 0600 and refuses to overwrite either file: it
would rather fail than silently destroy a realm.

`pubkey` is the ceremony's first check, not a convenience. It signs and
verifies with the pair, then prints the public half the file CARRIES — it does
not re-derive that half from the seed — and **refuses a key whose halves
disagree**:

```
error: root.key is not a consistent keypair: the public half it carries is not
the one its seed derives. Signing with it produces layers NO trust root can
verify. Mint a fresh key with `varve keygen`.
```

Run it and compare its output, character by character, against the value you
are about to publish. That value is the realm's `trust-root` forever.

## 2. Know which bytes are the secret

A varve key file is 128 hex characters: **the first 64 are the ed25519 seed,
the last 64 are the public key derived from it.**

That has one consequence people get wrong: **splitting the file in half is not
split custody.** The first half is the whole secret — the public half is a
deterministic function of the seed, so a custodian holding characters 1–64 can
reconstruct the complete key alone, and the custodian holding 65–128 holds
something you are about to publish anyway. A "two-person" split of that shape
has exactly one person's worth of security.

Real split custody means an **M-of-N secret sharing over the first 64
characters**, or N shares of a passphrase that encrypts the whole file — and
**varve ships neither**. There is no `varve` command that splits a key, that
combines shares, or that verifies a share is genuine. Use a secret-sharing tool
your organisation already trusts, and treat the reconstructed key as something
that exists only inside the ceremony room.

Whatever scheme you pick, the check at the end is the same one: reconstruct the
128 characters, run `varve pubkey` on the result, and confirm it prints the
published root. A reconstruction that is wrong in any single character is
refused rather than accepted, because the two halves stop agreeing.

## 3. Paper backup, and how to restore from one

Digital media outlive nothing. Write the 128 characters down, on paper, in a
tamper-evident envelope, in more than one location — plus the 64-character
public half separately, so a restore has something to check against.

varve accepts a restored key as long as the file holds exactly the 128 hex
characters. Two rules the transcription must respect:

* **Case does not matter.** `AB12…` and `ab12…` both work.
* **Line breaks do.** Only the leading and trailing whitespace is trimmed, so
  hex typed back in four groups of 32 on four lines is rejected — *"holds 131
  hex character(s); a varve signing key is 128"*, the newlines counted along
  with the digits. Join it into one unbroken line; the `tr` below does it for
  you.

The restore, and its check:

```sh
tr -d '[:space:]' < typed-from-paper.txt > root.key
chmod 600 root.key
varve pubkey root.key            # MUST print the published trust-root, exactly
```

If it prints the published root, the transcription is correct in all 128
characters — a single wrong digit anywhere makes the halves disagree and the
command fails. If you stored only the seed and not the public half, you have no
such check: the file is 64 characters, varve rejects it as the wrong length,
and there is nothing to compare a reconstruction against. Store both halves.

## 4. Long-term storage

The key is offline media plus paper, and nothing else:

* Two or more geographically separate safes, each holding one share (or one
  full copy under a different control, if you accepted single custody).
* An access log with two-person rule. Every use of the key is a ceremony
  entry, because there is no revocation to fall back on if a use was not
  authorised.
* A **read test on a schedule** — annually is a reasonable floor. Restore from
  the medium onto an air-gapped machine and run `varve pubkey`; the failure
  mode you are looking for is a safe full of unreadable USB sticks, discovered
  the year you need them.
* Never on a build machine, never in a repository, never in a chat message.
  In CI the key lives in the secret store and reaches varve through a file
  descriptor, never a workspace file — `varve docs ci`, "Getting the key into
  CI", has the two patterns that avoid writing it to disk at all.

## 5. Use it as rarely as possible

Signing is the only thing the key is for, and each of those commands is a
ceremony:

```sh
varve deposit --spec deposit.toml --issued-at 2026-09-01T00:00:00Z \
              --key root.key --key-id acme-root-1 --out ./layout
varve sign-status --file status.json --key root.key --out status.dsse.json
varve sign-index  --file index.json  --key root.key --out index.dsse.json
varve sign-sums   --sums SHA256SUMS.txt --key root.key --out sums.dsse.json
```

Nothing else in varve reads the secret half. `varve verify`, `varve install`,
`varve status` and every export need only the 64-character public value.

## What varve does NOT do — read this before you publish the root

These are limits, not omissions to be worked around. `varve docs threat-model`
states the same list from the consumer's side.

* **No key rotation.** There is one root per realm and no mechanism to succeed
  it. Nothing signs "this new root replaces the old one", and no consumer would
  check such a statement if you produced it.
* **No revocation.** There is no revocation channel, no CRL, no kill switch.
  A leaked key stays valid for every consumer until each of them edits their
  own `varve-realms.toml`.
* **No expiry, no key roles, no thresholds.** One key, unlimited lifetime,
  signing everything. varve will not refuse a layer because the root is old.
* **No transparency log.** Nothing outside your consumers ever sees what you
  signed, so a compromised signer serving different bytes to different
  consumers is not detectable by varve (signer equivocation).

**So the compromise plan is manual, and you should write it down before you
need it.** Generate a new realm root by this same ceremony, publish it as a
new realm definition, and reach every consumer through the channel that
bootstrapped them in the first place — your repository, your onboarding, your
configuration management. Each consumer edits `trust-root` and re-installs.
Layers signed by the old key stop being acceptable at exactly the moment each
consumer makes that edit and not before, which is why *"who are my consumers,
and how do I reach all of them within a day"* is part of the ceremony record
rather than an incident-time question. Anti-rollback does not help here: the
attacker holds your key and can sign a higher counter than you can.

## HSMs, PKCS#11, KMS — absent, not excluded

varve reads a signing key from a **file**, and `--key <FILE>` is the only key
input there is. There is no PKCS#11 provider, no KMS backend, no YubiKey or
smartcard support, and no signing-service hook: at some moment the raw 128
characters exist in a file or on a pipe, which is what the ceremony above is
designed around.

This is *not* a permanent scope decision. It is simply not built. The
requirement that would cover it is **REQ-CEREMONY-001, scheduled for v1.0.0** —
the real trust-root ceremony that defines custody, rotation, revocation and
expiry, dual-signs one release to migrate the old-verifies-new chain, and adds
a transparency mechanism that makes key compromise detectable. Hardware-backed
signing is where it would land. Until that ships, assume file-based keys and
plan custody accordingly; do not design a process around a PKCS#11 URI that
varve has no way to accept.

varve's own published root (`trust-roots/`) is labelled a **provisional rolling
key** for exactly these reasons: it has no rotation, revocation or threshold
story, and it is not the product of the ceremony REQ-CEREMONY-001 describes.
That is why varve's qualified channel is not open. Do not read the fact that
varve ships a root as evidence that the ceremony problem is solved — it is the
same problem, deferred to the same requirement.

## Where to go next

* `varve docs signing-keys` — the key format and what varve checks
* `varve docs own-realm` — the whole realm, key to consumer, end to end
* `varve docs ci` — the producer pipeline, and getting the key into CI
* `varve docs threat-model` — the same limits, from the consumer's side
* `varve docs deploy` — publishing, and what consumers must be handed
