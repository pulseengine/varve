# varve seed <dir>

Writes the layers this store has installed into a directory that another store can install from — with no network and no registry credential. Each layer's directory inside it is in the form a realm's `mirrors` entry accepts: an absolute directory path.

The case it exists for: a container's store (a Docker volume) is a separate store from its host's. After a pin change the container refetched a composed layer from the registry, and needed the registry credential, although the host store already held every byte. Seed from the host, name the seed as a mirror in the container, and the pin change installs from disk.

```sh
# on the host, in a project whose pin is installed
varve seed /srv/varve-seed
# seeded layer 2026.08.1 sha256:… : 9 payloads for x86_64-unknown-linux-gnu, baseline line-status, no signed line index
#   mirror: /srv/varve-seed/2026.08.1-1f0c2a9d4b7e
# seeded layer 2026.09.1 sha256:… : …
#   mirror: /srv/varve-seed/2026.09.1-a83e0c5512d9
```

Then, in the other store's `varve-realms.toml`, add each printed `mirror` path to the `mirrors` of the realm that signs that layer:

```toml
[realm.acme]
registry = "oci://registry.example/acme/layers"
mirrors  = ["/srv/varve-seed/2026.08.1-1f0c2a9d4b7e", "/srv/varve-seed/2026.09.1-a83e0c5512d9"]
trust-root = "7d3b892e6a33c70043becc708e08042e1cef0d54dd5ae6f23d7d4c68de1da1a0"
```

and run `varve install` there as usual. The registry is still the primary: a mirror answers when the primary cannot, which is exactly the state of a container with no network or no credential.

## Which layers

By default the current project's pinned layer **and every layer it composes**, transitively, each from the realm partition that holds it. A seed that left one out would send the other store back to the registry for exactly that layer, so a composed layer that is not installed here is a refusal that names it, not a smaller seed.

To seed one installed layer instead, name it by id **and** digest (both, so a name is never taken for a layer it does not belong to). It still brings the layers it composes:

```sh
varve seed /srv/varve-seed --layer 2026.08.1 --digest sha256:<hex>
```

`--platform <triple>` names the platform this store installed for, as in `varve archive`. A seed carries **one platform's** payloads: it holds what this store installed, and an install fetches only its own platform's bytes. A mixed site needs **one seed per platform**, each made on (or installed for) that platform.

## The directory

`<dir>` must be an absolute path: a relative one is refused, because a realm's `mirrors` entry has to be absolute (it would otherwise resolve against whatever directory varve happens to run in).

`<dir>` must be new, empty, or a seed a previous `varve seed` wrote (it holds a `varve-seed.json`). Any other non-empty directory is refused untouched: mixing a seed into somebody else's files leaves a directory that is neither. Seeding the same layer again replaces its subdirectory and leaves the others. A `<dir>` that is itself a symbolic link is refused.

All layers are written into a staging directory inside `<dir>` first (`.varve-seed-staging-…`), and moved into place only when every layer succeeded: a refusal in any layer leaves `<dir>` as it was. An existing layer subdirectory is removed and replaced, never written into, and a symbolic link in its place is removed, not followed. The final moves are not one atomic step: if one fails partway, the layers before it are already replaced. If the process is killed mid-seed into a new `<dir>`, a staging directory without `varve-seed.json` remains, and the next run refuses `<dir>` as not a seed; remove it and seed again.

Each layer goes in its own subdirectory, `<layer>-<12 hex of its digest>`, and each subdirectory is one OCI image layout — the same shape `varve archive` writes and `varve install --from` reads. `<dir>` itself is therefore not a `mirrors` entry — each subdirectory is, one entry per layer. One layout per layer because a layout's referrers (the baseline status, the carried attestations) are not keyed by layer.

## A seed is transport, not authority

Nothing in `varve seed` signs, re-encodes or vouches for anything. It copies the bytes this store already holds:

| in the seed | where it comes from |
|---|---|
| the signed layer manifest, as a DSSE envelope | the envelope the store retained at install — byte for byte |
| each payload for this platform | the installed file, re-hashed against the digest the manifest signs before it is written |
| the baseline line-status | this store's cache, verbatim, when it holds one for the line |
| the realm's signed line index | this store's cache, verbatim, when it holds one for the line |
| attestations carried at install | re-emitted as referrers beside the layer |

The store that reads the seed verifies every one of them against **its own realm's trust root**, exactly as it would from the registry (REQ-MIRROR-002). A seed altered in transit — one flipped byte in a payload or in the manifest envelope — is refused with the same verification error the registry would earn, and the next source is asked. The anti-rollback high-water mark, the first-contact rule and the realm's signed-index obligation all apply to a mirror unchanged, so:

- a store that has **never** installed a line does not accept it from a mirror: first contact is the primary's, because a mirror cannot prove it is current (`first contact … needs the realm's primary`). That is the container-with-a-volume case the other way round: the seed serves a store that has installed that line from the realm before and whose pin moved. For a store's very first install, `varve install --from <mirror path>` makes the seed that install's only source, which works for a pin whose layer composes nothing. A pin that **composes** layers cannot be installed offline into a never-installed store this way: `--from` names the root layer only, and the layers it composes are fetched through the realm's own sources, where a seed is a mirror. Install once from the registry first.
- a realm that declares `signed-index = true` needs the index in the seed. `varve seed` carries the one this store cached, and when it knows the layer's realm (the project's pin, or a composed layer whose realm the project's `varve-realms.toml` defines) and that realm requires one but this store holds none, it refuses, naming the layer and the realm, and writes nothing. It never makes one up. Install the layer from a source that carries the index, then seed again. It cannot refuse what it cannot see: with `--layer`/`--digest`, or for a composed layer whose realm is not defined here, it carries the index if the store holds one and says `no signed line index` if not, and the other store will then refuse the seed itself.

## What is not copied

Shims, the `env` script and anything else that holds this store's absolute path live outside a layer's directory and are never read. The store that uses the seed lays down its own (`varve shim install`).

If this store cached no baseline line-status for a line, the seed carries none and says so on stderr: a store seeded from it has no `varve status` for that line until it reaches the realm's registry. This store's *published* line status (the correction a realm issues after a deposit) is not part of a seed.

## Exit codes

`0` on success; `1` when a refusal above applies (relative or foreign directory, a layer not installed, a missing index the realm requires); `2` for a usage error. `--json` prints the layers, their `mirror` paths and what each carries.
