# Trust-root custody and succession — a concept for v1.0

**Status: draft, under review. Nothing here is decided.**

This document exists because the decisions were being made incrementally across
three issues and a dozen comments, which is not a form anybody can review. It
states the problem, the options, the trade-offs, and the questions we cannot
answer ourselves, in one place.

## Tracked artifacts

This document is the prose behind typed artifacts in `artifacts/requirements.yaml`;
the artifacts are authoritative and this is the argument for them.

| artifact | status | what it holds |
|---|---|---|
| **DD-027** | `proposed` | this concept — the ORDER of the decisions, not the answers |
| **REQ-SUCCESSION-001** | `draft`, v1.0.0 | §3 — a root can be succeeded without stranding consumers |
| **REQ-SIGNERSEAM-001** | `draft`, v0.31.0 | §8 step 1 — signing through `DsseSigner`, the gate for both paths |
| REQ-CEREMONY-001 | `approved`, v1.0.0 | the ceremony DD-027 satisfies |
| DD-026 | `accepted` | keyless rejected; §5 records which premise expired |
| DD-005 | `accepted` | offline anti-rollback, the counter §3 mirrors |

Verify the trace with `rivet validate --explain DD-027`.

Related issues: [#110] (the problem), [#112] (custody design), [sigil#268]
(upstream asks), and `varve docs root-ceremony` (what we tell users to do).

---

## 1. The problem, concretely

A varve **realm** is defined by one root public key. Every layer a consumer
accepts is accepted because it verifies against that key, which the consumer
pins by hand as 64 hex characters. There is no authority above it.

The `pulseengine` realm's root was generated on 2026-08-07 straight into CI. Its
commit message records the whole custody model in one sentence:

> Secret half exists only as the `VARVE_ROLLING_KEY` repo secret.

Verified: never committed, no copy on any machine we control, and GitHub
repository secrets are write-only — nobody can read one back, by design.

So the key that signs every layer in the realm:

* **cannot be backed up** — there is nothing to back up from;
* **cannot be moved** — which is why the layers repository can hold the realm's
  *contents* but not sign them;
* **cannot be recovered** — if that secret or that repository is lost, the realm
  can never be signed again, and every pinned consumer is frozen on the layer
  they already installed;
* **cannot be rotated or revoked** — varve has neither mechanism, so a leak is
  as terminal as a loss.

`varve docs root-ceremony` prescribes paper backup in two locations, split
custody, an access log and an annual read test. varve's own root has none of
them. The document was honest that the root is "provisional"; it never said
"unrecoverable", which is what provisional turned out to mean.

**A key with a single write-only copy is not in custody.**

## 2. What must be decided at v1.0

v1.0 is already the moment varve mints a real root and opens the qualified
channel (REQ-CEREMONY-001). Because minting a root is the only moment the
format, the algorithm and the custody model can change cheaply, four decisions
land together:

1. **Does a long-lived secret exist in CI at all?** (keys vs keyless)
2. **Where does the long-lived key live?** (file, HSM, or a Sigstore bundle key)
3. **How is a root succeeded** without stranding consumers?
4. **How many backups, of what, held by whom?**

Decision 3 is the one that makes the others reversible, so it is treated first.

## 3. The invariant: succession makes every other choice reversible

Today a root is forever. That single fact inflates every other decision — it is
why "buy the FIPS device because validation cannot be retrofitted" sounded
compelling, and why choosing an algorithm feels irreversible.

The solved version of this problem is **TUF root rotation**:

> A new root is signed by a threshold of BOTH the old and the new root keys. A
> client holding only the old root verifies the chain forward to the new one,
> with no out-of-band contact.

For varve concretely:

* a **succession statement** carrying the new root's public key, signed by the
  old root *and* by the new root — the latter proving possession, so a typo
  cannot enthrone a key nobody holds;
* `varve` verifies it against the currently pinned root and updates
  `varve-realms.toml` as an explicit, logged action — never silently;
* it carries a **counter**, and an older statement is refused, or an attacker
  replays a retired root;
* **thresholds are what make it safe.** With one root key, whoever holds it can
  redirect the realm permanently. That is already true today for signing layers,
  but succession makes redirection *durable*, so a threshold (say 2-of-3, each
  key in its own device) is what stops one compromised holder carrying the realm
  away.

**Thresholds are a ceremony input.** The number of root keys is decided when the
root is minted; it cannot be added afterwards.

If succession exists, then: the hardware choice is not permanent, the FIPS
choice is not permanent, and the algorithm choice is *nearly* not permanent
(succession can carry a new algorithm if the verifier supports both).

## 4. Path A — a long-lived key, held properly

Keep an ed25519 root. Move it out of CI and into hardware, under a real
ceremony.

**What it fixes:** the key becomes backupable, restorable, and split across
custodians. #110 stops being true.

**What it does not fix:** a long-lived secret still exists, and CI still needs
*something* to sign with. Either the HSM is reachable from a self-hosted runner
(a network path to the signing key, which is the thing an air-gapped ceremony
exists to avoid), or deposits become a manual step someone performs.

**That tension is the honest weakness of Path A**, and it is not addressed by
better hardware. It is addressed by deciding that layer signing is a deliberate
act rather than a CI side-effect — which is what `docs root-ceremony` already
says ("use it as rarely as possible"), and which today's daily-scan-then-propose
workflow is already shaped for: the scan proposes, a human merges, and only the
merge dispatches a deposit.

**Implementation:** entirely ours. `wsc-dsse` already exposes
`pub trait DsseSigner { fn sign(&self, pae: &[u8]) -> …; fn key_id(&self) -> … }`
and `DsseEnvelope::sign(payload, type, &dyn DsseSigner)`. varve does not use it
as a seam — `verify.rs` hardcodes `Ed25519DsseSigner::from_bytes`. Refactoring
to the trait unblocks a hardware signer with **no upstream dependency**.

## 5. Path B — keyless

No long-lived secret in CI. Each deposit gets an ephemeral Sigstore identity via
OIDC; verification uses Fulcio roots and a Rekor key from an offline trust
bundle.

**What it fixes:** the thing we actually fear. A compromised CI cannot sign
anything after the compromise ends, because there is no durable key to steal.

**What it does not fix:** the trust bundle is itself signed with a long-lived
key that every consumer must pin. In `wsc`'s own words:

> The bundle is signed with a long-lived offline key. Devices verify the
> signature against a pre-provisioned public key before using.

So keyless **relocates** the long-lived secret rather than abolishing it. But
relocation is close to the whole point: a bundle-signing key is used rarely,
changes rarely, and can be held under exactly the ceremony this document
describes. **The question is not "keys or no keys", it is which key has to be
online.**

**Status of the earlier rejection.** DD-025 proposed keyless; DD-026 rejected
it, partly because wsc 0.10.0's air-gapped verifier was a stub that failed open.
**That premise expired.** Verified against 0.11.0 source: the verifier performs
certificate-chain validation to a bundle Fulcio root, leaf validity at Rekor's
`integrated_time`, mandatory Rekor SET verification, ECDSA-P256 over the digest,
revocation and identity checks, and Rekor body binding — all offline — and it
documents the two things it deliberately skips (the Rekor Merkle inclusion
proof, because the verifier computes the wrong shard root for Rekor v2 and
failing closed would reject legitimate signatures; and SCT/CT, for want of a
provisioned CT key).

**Implementation:** needs sigil. Signing over an arbitrary digest (sigil#256),
a cosign-bundle adapter (#260), the trust-bundle rotation story, and a
non-vacuous air-gapped test (#258). We offered to build the code; two of those
are design decisions that are sigil's to make.

## 6. Custody and backup model (applies to either path)

The framing that makes this tractable: **with no revocation, loss and compromise
are both terminal.** More copies reduce loss risk and raise compromise risk.
Secret sharing breaks the trade-off — one share is useless, so copies of shares
are cheap.

With an HSM the split is not of the key but of the **wrap key**, which changes
the arithmetic usefully:

| artifact | how many | why |
|---|---|---|
| HSM devices | 2 | primary + restore target; the second is what makes the read test real |
| wrap-key shares | 3-of-5, paper, tamper-evident, separate custodians and locations | one share is worthless; three must fail together to lose it |
| wrapped key backup | ≥3 copies, ≥2 media types, ≥1 offsite | inert without the wrap key, so redundancy is cheap here |
| public half | stored separately, and published | the restore check needs something to compare against |

3-of-5 rather than 4-of-7 because **the threshold should be chosen for the worst
realistic day**, not the median one — 4-of-7 fails closed as soon as two people
are unreachable.

**The read test is the step everyone skips and the one that matters.** Annually:
restore onto the second device, sign a throwaway payload, and confirm
`varve pubkey` prints the published root character for character. A safe full of
unreadable media, discovered in the year you need it, is the failure this
prevents.

**Durability comes from the wrapped blob plus the split wrap key, not from the
second device.** The second device buys availability and a non-destructive
restore test.

## 7. Hardware

| option | ed25519 | backupable | verdict |
|---|---|---|---|
| YubiKey (PIV) | 5.7+ only | **no** — non-exportable | recreates #110 in hardware |
| TPM 2.0 | no (P-256) | no | plus `wsc` cannot persist/reload TPM keys (sigil#268) |
| Nitrokey HSM 2 | **no, and no plans** | yes (DKEK n-of-m) | would force an algorithm change |
| **YubiHSM 2** | **yes** | **yes** (wrap key, M-of-N) | fits |

Prices (yubico.com/de, incl. VAT): YubiHSM 2 **€773.50**; YubiHSM 2 FIPS 140-3
**€1130.50**. Two devices: **€1547** or **€2261**.

**FIPS is not required for us** — we are an EU project and CRA is our regime,
not US federal procurement. It buys a certificate number an assessor can check,
which matters to a project whose whole thesis is checkable evidence. But given
succession (§3), it is **not a permanent choice**, so the cheaper device now and
a rotation later is defensible.

Prior art worth copying rather than inventing: Oxide Computer's
[`offline-keystore`](https://github.com/oxidecomputer/offline-keystore) — Rust,
YubiHSM2, wrap-key splitting, built for exactly this ceremony.

## 8. Sequencing

Hardware is **not** the first purchase, because varve cannot drive it yet:
`--key <FILE>` is the entire key input.

1. **`DsseSigner` seam in varve** — behaviour-preserving refactor; existing
   signing tests are the oracle. Unblocks *both* paths.
2. **Root succession** — design, requirement, implementation. Makes every later
   choice reversible, so it should precede the choices.
3. **Decide keys vs keyless**, with sigil's answers in hand.
4. **Then buy hardware**, and rehearse a full ceremony with a key we intend to
   throw away before minting the real one.

## 9. What we are NOT proposing

* Not extracting the current secret from CI. It is technically possible with
  repository write access and would expose the root permanently, with no
  revocation to recover. The inability to read it back is a property worth
  keeping.
* Not minting a new key for the current realm outside a ceremony. Consumers pin
  the old root; without succession, a new key strands them.
* Not adopting TUF wholesale. Only its root-rotation semantics.
* Not blocking layer publication on any of this. Deposits continue from
  `pulseengine/varve` meanwhile.

## 10. Questions we cannot answer ourselves

1. **Is CI-signed layer publication acceptable at all** for a qualified channel,
   or must qualified layers be signed by a deliberate human act? This determines
   whether Path A's weakness (§4) is fatal.
2. **How many root keys**, and what threshold? A ceremony input; cannot be
   changed later.
3. **Is the succession statement's trust model sound**, or does it hand an
   attacker holding one root key a durable realm takeover that layer-signing
   alone does not?
4. **Does an assessor actually credit** a FIPS-validated module here, or is a
   documented ceremony with split custody sufficient evidence?
5. **Is 3-of-5 right** for an organisation this size, or does it fail closed
   too often to be run honestly?

[#110]: https://github.com/pulseengine/varve/issues/110
[#112]: https://github.com/pulseengine/varve/issues/112
[sigil#268]: https://github.com/pulseengine/sigil/issues/268
