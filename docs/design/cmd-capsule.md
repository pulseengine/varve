# varve archive --capsule, varve reconstruct

> **DRAFT — NOT SHIPPED.** This page describes a design proposed for v0.49.0
> (DD-044, REQ-CAPSULE-001, bet A of `docs/plan-v0.49.0.md`). Neither command
> exists in any released varve. It is written as the user-facing page would
> read once shipped, so the design can be reviewed against the words a user
> would get. It lives in `docs/design/` and not in `crates/varve/docs/` on
> purpose: that directory is compiled into the binary, and every page there is
> gated as a real, reachable command (`every_shipped_doc_file_is_reachable_as_a_topic`,
> `every_documented_command_is_a_real_command`). It moves there with the code.

A **capsule** is one file that lets an assessor rebuild the exact toolchain an
evidence bundle names, in an empty store, with no network and no credential, and
re-check it. It covers **the pinned tools of one project on one platform**. The
compiler is not in a layer today and is not in a capsule.

```sh
# on the producing side, in the project, with the pin installed
varve archive --capsule ./evidence/toolchain-x86_64-unknown-linux-gnu.capsule

# on the assessor's machine: no network, no credential, an empty directory
varve reconstruct ./toolchain-x86_64-unknown-linux-gnu.capsule \
  --statement ./bundle/layer.attestation.dsse.json \
  --file      ./bundle/layer.attestation.bytes \
  --root covalent=sha256:5c1e…(64 hex) \
  --root pulseengine=sha256:9a07…(64 hex) \
  --root pulseengine-wasm=sha256:e2d4…(64 hex) \
  --into ./assess
```

## What you trust, and what you do not

You bring **one full fingerprint per realm** in the toolchain: the sha256 of the
realm's 32-byte ed25519 root public key, all 64 hex characters, obtained from a
source you trust independently of the capsule (the realm's published
`trust-roots/` file, its root ceremony record, your own earlier verified
install). That is the only thing `reconstruct` trusts.

Everything in the capsule is **untrusted transport**, exactly like a mirror:

| in the capsule | how it is accepted |
|---|---|
| each realm's root public key (and its delegation, for a realm with key roles) | only if its sha256 equals the fingerprint you passed for that realm |
| the attestation you pass (`--statement`, `--file`) | verifies against the pinning realm's trust; it — not the capsule — names the target layer, its digest and its overrides |
| every layer manifest (DSSE envelope) | verifies against its own realm's trust, and its digest must be the one the attestation names, an include in an already-verified manifest names, or an override in the attestation names |
| every payload | hashes to the digest its verified manifest signs |
| each line's signed line index and line-status | verify against that line's realm trust; never chosen by the capsule |
| `varve-capsule.json` (the packing list) | never trusted: every claim in it is cross-checked, and a mismatch is a refusal |

The 16-hex partition id you see under `~/.varve/realms/` is **refused** as a
`--root` value. It is 64 bits of a hash, which is a store namespace, not a trust
anchor.

A composed toolchain needs every realm's fingerprint because each composed
layer's line index and line-status — and so its yank state — are signed by its
own realm, not by the realm that composes it. If you leave one out,
`reconstruct` refuses and names the realm and the fingerprint the capsule
carries for it, so you can compare it with your independent source:

```sh
# error: realm 'pulseengine-wasm' (composed by covalent 2026.11.16) has no --root.
#   The capsule carries a root whose fingerprint is sha256:e2d4…; check it against
#   a source you trust and pass --root pulseengine-wasm=sha256:<64 hex>.
```

## Reconstruction is not first contact

A normal `varve install` into a store that has never seen a line makes **first
contact**, and first contact is answered only by the realm's primary
(REQ-FIRSTCONTACT-001, REQ-SEED-001 clause 2): with no history, nothing bounds
how old a mirror's answer is. A capsule is a mirror's answer. It does not change
that rule, and a capsule cannot be used to make first contact for a normal store.

`reconstruct` asks a different question. An install asks *"is this the current
layer?"*; an assessor asks *"is this exactly the layer the evidence names, and
what does the realm say about it?"*. The target is fixed by the signed
attestation, so an older layer is not an attack on the assessor — it is the
point. What remains freshness-sensitive is the yank and support picture, and
`reconstruct` does not pretend to know it is current. It reports it **as of the
newest realm-signed document it holds**, with its counter and issue date:

- the line-status and line index the capsule carries;
- any newer ones you bring with `--status <envelope>` and `--index <envelope>`
  (fetched separately, from anywhere; they are verified against the same root,
  and the highest counter wins — an older one you bring changes nothing).

The realm's first-contact floor (`min-counter`) and the line's newest counter are
**reported, not enforced**: a layer below the floor, superseded, yanked or out of
support still reconstructs, and the verdict says which.

## Assessor stores do not leak

`reconstruct` writes into `--into`, which must be new or empty and must not be,
contain, or sit inside your varve store (`VARVE_ROOT` or `~/.varve`). It never
reads or writes your store's high-water marks, its caches, or `VARVE_ROOT`.

```
assess/
  varve.toml            the pin, by layer AND digest, with the attestation's overrides
  varve-realms.toml     one realm per fingerprint you passed, trust-root from the capsule
  evidence/             the statement and bytes you passed, copied
  store/                the reconstructed store
  store/varve-assessor.json   the record: capsule digest, statement digest,
                              fingerprints, documents used, varve version, time
```

The record makes the store an **assessor store** for good:

- `varve install`, `varve seed`, `varve archive` and `varve shim install` refuse
  an assessor store, naming the record. Nothing installed for assessment can
  become a source of tools for normal use.
- `varve verify`, `varve check-attestation`, `varve which`, `varve status` and
  `varve run` work, and say on their first line that the store is an assessor
  store reconstructed from capsule `sha256:…`.
- The relaxed rules (no first-contact refusal, floor and rollback reported not
  enforced) exist only inside `varve reconstruct`. There is **no flag on
  `install`, no `varve.toml` or realms key and no environment variable** that
  selects them.

Your own store is exactly as it was. If it has seen a newer layer on the line, a
normal install of the reconstructed layer **by name** is still refused as a
rollback. (A pin **by digest** of a layer the realm still reports supported and
not yanked installs by consent, REQ-ROLLBACK-002, from the realm's primary — that
rule is unchanged and unrelated to capsules.)

## The verdict

`reconstruct` re-runs the checks of `varve verify` and `varve check-attestation`
in the new store and prints one verdict (illustrative output; the layer ids and
digests are real covalent layers, the counters and the yank are invented):

```sh
# reconstructed covalent 2026.11.16+mixed sha256:a38d3e34… for x86_64-unknown-linux-gnu
#   composed: pulseengine 2026.11.25 sha256:cda008bb…, pulseengine-wasm 2026.11.4 sha256:42b6934b…
#   override: synth → covalent 2026.11.7 sha256:ba7bd891… — YANKED: "synth miscompiles …"
#   yanks:    none for covalent 2026.11 as of line-status #16 (2026-11-18, carried)
#             none for pulseengine 2026.11 as of line-status #25 (2026-11-19, brought with --status)
#   newest:   covalent 2026.11 lists counter 17 (2026.11.17); this layer is counter 16 — superseded
#   floor:    at or above every first-contact floor
#   attestation: matches layer, digest and overrides
# VERDICT covalent 2026.11.16+mixed sha256:a38d3e34…: reconstructed and verified; 1 override; 1 yank
```

Then, as any other user would:

```sh
cd assess
VARVE_ROOT="$PWD/store" varve verify
VARVE_ROOT="$PWD/store" varve check-attestation \
  --statement evidence/statement.dsse.json --file evidence/statement.bytes
```

`--json` prints the same verdict as one object (`layer`, `digest`, `mixed`,
`overrides[]`, `composed[]`, `yanks[]` with the document each comes from,
`superseded`, `below_floor`, `attestation`).

## Refusals, each with a named cause

Nothing lands in `--into` unless the whole reconstruction succeeds.

| cause | refusal |
|---|---|
| a composed layer the verified manifest includes is not in the capsule | `capsule is missing composed layer <realm> <layer> <digest>` |
| a line in the toolchain has no signed line index in the capsule (and none brought with `--index`) | `capsule carries no signed line index for <realm> line <line>` |
| a payload, manifest or document does not hash or verify | the same verification error the registry would earn, naming the entry |
| the attestation records a pure toolchain and the capsule was made for a mixed one (or the reverse, or another mix) | `the attestation is for <layer>, the capsule for <layer>+mixed (…): evidence about one toolchain is not evidence about another` |
| an override the attestation records is not in the capsule | `capsule is missing override layer for <tool>: <layer> <digest>` |
| a realm with no `--root`, or a root that does not hash to it | named above |
| the capsule was made for another platform than this host | `this capsule carries <triple>; reconstruct it on <triple>` |
| `--into` is not empty, or is or touches your store | named, nothing written |
| a capsule entry that is a link, a device, an absolute path or escapes with `..` | refused before anything is extracted |

## Making a capsule

`varve archive --capsule <file>` takes the current project's pin: the pinned
layer, every layer it composes (transitively), the source layer of every
`[toolchain.override.<tool>]` and the layers those compose, each line's signed
line index and newest cached line-status, every attestation carried at install,
and each realm's root key and delegation from `varve-realms.toml`. It refuses —
and writes nothing — when any of them is not in this store, rather than writing
a capsule that will fail on the far side.

It prints the capsule's sha256 and size. The digest is stable: the same pin on
the same platform from the same store gives a byte-identical capsule (sorted
entries, zero timestamps and owners), so the evidence bundle can name it.

### The file

A capsule is an uncompressed POSIX tar. Unpacked, it is exactly a `varve seed`
directory (one OCI image layout per layer, `varve-seed.json`) plus:

- `varve-capsule.json` — the packing list: pin, platform, overrides, the layers
  with their realm and role (pinned, composed, override), the documents carried;
- `realms/<name>/trust-root` and, for a realm with key roles,
  `realms/<name>/delegation.dsse.json`.

So the unpacked capsule also serves as a mirror for a store that has installed
those lines before (`varve docs seed`). It is not compressed: varve does not add
a decompressor to what it trusts, and the size budget below is met without one.
Compress it for transport if you like.

### Size

Measured on 2026-11-20 from an installed store (aarch64-apple-darwin):
covalent 2026.11.16 composes pulseengine 2026.11.25 (≈150 MB) and
pulseengine-wasm 2026.11.4 (≈177 MB); the covalent layer itself is ≈20 kB. A
capsule is ≈327 MB (≈312 MiB) uncompressed, ≈112 MB with `zstd -3`. The budget
is **2 GiB** for a covalent capsule on one platform; above it the design is
reconsidered.

## Scope

- **One platform.** A capsule holds what this store installed. A mixed site
  needs one per platform, each reconstructed on its platform.
- **Pinned tools only.** The compiler (REQ-TOOLCHAIN-001) is not in a layer.
- **Ambient tools** a passthrough allowed (REQ-PASSTHROUGH-001) are not in the
  capsule; the verdict repeats what the attestation records about them.
- **Where capsules are kept** is the layer repositories' decision
  (REQ-ARCHIVE-002). CI artifacts expire after 90 days.
