# Air-gapped operation

varve is built for environments with no network to a public registry or
transparency log — the safety-critical norm. Install runs from an archived core
(`varve archive` / an oci-layout) with verification unchanged; the Cargo/Bazel
exports produce local, offline-consumable byte sources; and the trust root is
pinned, not fetched. A varve operation must never REQUIRE reaching a public API.
This is the core thesis: a phone-home that fails on a network blip is exactly
the fragility varve exists to remove.

## The whole workflow, with commands

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

Advisories cross the gap as files too:

```sh
varve status --from-file ./line-status.dsse
```

What still needs care: `varve self-update` reaches a public API by default (set `VARVE_UPDATE_API` at a mirror), and a realm definition requires a `registry` field even when you never contact one — a placeholder is fine.
