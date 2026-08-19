# varve archive <layer> <dest>

Exports an installed layer as a directory-shaped OCI image layout — the offline artifact of record. Installs from that archive need no registry, with verification unchanged.

## One archive carries ONE platform

An archive is single-platform by construction. `archive` exports what this machine has, and `varve install` fetches only its own platform's payloads, so the bytes for any other triple were never on this machine to export. A layer manifest that names 35 entries across four platforms produces an archive with the nine payloads for the archiving host and no others — the archive is complete for that platform and carries nothing for the rest.

`archive` prints exactly what it carried and what it left out:

```sh
varve archive 2026.08.2 ./core
# archived layer 2026.08.2 sha256:… as oci-layout at ./core
#   9 payloads for aarch64-apple-darwin
#   26 entries omitted — this core holds no payload for them: …
```

A mixed air-gapped site needs **one archive per platform**, each made on (or installed for) that platform. There is no `--platform` that fetches another platform's bytes: that would be a registry operation, and `archive` never reaches the network. `--platform <triple>` only names the platform this core was installed for, and you need it when the core was laid down with `varve install --platform`.

Installing an archive on a platform it does not carry fails with `this archive carries no payload for <triple> — it was archived for <other triple>`, before anything lands. That is an honest absence, not a tampering verdict: nothing is corrupt and re-copying the media will not help.

## What an archive carries — the contract

What crosses the gap and what does not, so the packing list is decided on
the near side rather than discovered on the far one:

| in the layer's evidence | crosses in the archive? |
|---|---|
| the signed layer manifest + its DSSE envelope | yes — verification is identical on the far side |
| payloads for the archiving platform | yes (and only these — above) |
| payloads for any other platform | **no** — one archive per platform |
| the baseline line-status (advisories, yanks) | yes, when this machine's cache holds one for the line |
| attestations carried at install time | yes — re-emitted as referrer entries beside the layer |
| the signed **line-index** | **no** — re-attach it on the far side with `varve attach-index` |
| layers this layer **composes** | **no** — one archive per layer of the graph (`varve docs composition`) |
| anti-rollback high-water marks | no — client state, never part of the artifact |

Check the evidence rows on the artifact itself before the media leaves:

```sh
jq '[.manifests[].artifactType]' ./core/index.json
# expect the signature envelope, the line-status if the line has one, and an
# attestation-statement/attestation-bytes pair per carried attestation
```

The line-status row has a precondition worth knowing: `archive` exports the
newest verified document from **this machine's cache**, which `varve install`
fills automatically when the source carried a baseline. A layer installed
before any advisory existed archives without one — run `varve status
--from-file <envelope>` first to ingest the newer document, then archive.
