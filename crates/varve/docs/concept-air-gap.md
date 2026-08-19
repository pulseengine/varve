# Air-gapped operation

varve is built for environments with no network to a public registry or
transparency log — the safety-critical norm. Install runs from an archived core
(`varve archive` / an oci-layout) with verification unchanged; the Cargo/Bazel
exports produce local, offline-consumable byte sources; and the trust root is
pinned, not fetched. A varve operation must never REQUIRE reaching a public API.
This is the core thesis: a phone-home that fails on a network blip is exactly
the fragility varve exists to remove.

## The whole workflow, with commands

Two entry points, because two kinds of facility exist: one where a connected
machine prepares media (this section), and one with **no connected machine at
all**, where the layer is born inside the gap (next section).

On a connected machine:

```sh
varve install                       # get the layer normally
varve archive 2026.08.2 ./core      # write the offline artifact of record
```

`archive` requires the layer to be INSTALLED, and one directory holds exactly one layer. Carry `./core` across on whatever media you use.

**One archive carries one platform.** `archive` exports what the archiving machine installed, and `install` fetches only its own platform's payloads, so an archive of a four-platform layer holds the payloads for the archiving host and nothing for the other three. `archive` prints the count it carried and the entries it omitted. A mixed site needs one archive per platform, each made on that platform — nothing in varve can produce a cross-platform archive offline, because the other platforms' bytes are not on the machine. Installing an archive on a platform it does not carry is refused before anything lands, naming both triples.

Inside the gap:

```sh
varve install --from ./core         # same verification, no network
varve verify                        # the install-time verdict, repeated
```

Verification is identical on both sides because it depends on the signature and the pinned root, not on the transport. Nothing here contacts a registry or a transparency log.

What crosses in an archive and what does not — the baseline line-status
travels, the signed line-index does NOT and must be re-attached, composed
layers need their own archives — is a contract, tabulated in `varve docs
archive`. Read it before the media leaves.

Advisories cross the gap as files too:

```sh
varve status --from-file ./line-status.dsse
```

## No connected machine at all: a layer born inside the gap

The workflow above assumes a connected side that prepares media. A facility
with none does not need one: **the entire producer path is offline**.
`varve deposit` writes the same oci-layout shape `install --from` consumes,
signing needs only the key file, and a realm's `registry` field is required
but never contacted — a placeholder is legitimate. So a toolchain can come
into existence, be signed, and be consumed without any machine ever having
had a network:

```sh
varve keygen --out realm.key --pub realm.pub        # once, at the facility
varve deposit --spec deposit.toml \
              --issued-at 2026-09-01T00:00:00Z \
              --key realm.key --out ./layout        # the signed artifact
varve sign-status --file status.json --key realm.key --out status.dsse.json
varve attach-status --layout ./layout --status status.dsse.json

# any project inside the gap, pinning a realm whose trust-root is realm.pub:
varve install --from ./layout                       # same pipeline, no network
varve verify
```

The realms file consumers pin gets `trust-root` from `realm.pub` and a
placeholder registry (`oci://registry.invalid/...` works — the field names a
transport that is simply never used). The producer sequence and its ordering
constraints are `varve docs ci`; they apply unchanged inside the gap, because
none of the (CI) subcommands reaches a network.

What still needs care: `varve self-update` reaches a public API by default (set `VARVE_UPDATE_API` at a mirror) — inside the gap, update varve itself by carrying the release file and its signed sums across and checking them with `varve self-verify`.
