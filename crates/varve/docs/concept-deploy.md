# Deploying a layer

`varve deposit` assembles and **signs** a layer, and writes an OCI image layout directory. It stops there. varve runs no server and pushes nothing — an OCI registry is the transport, and access control is the registry's job ("No server of our own"). Publishing therefore uses an ordinary OCI client, and that client never joins the trust path: whatever it uploads is accepted by a consumer only because the signature verifies against the pinned root.

Its `--help` used to say "publish", which sent people looking for a push command that does not exist.

## The push

This is the sequence varve's own release pipeline runs, with `oras`:

```sh
oras login ghcr.io -u "$USER" --password-stdin <<< "$TOKEN"

REPO=ghcr.io/your-org/layers
cd layout                       # the directory deposit wrote

# every blob the manifest references, then the manifest itself under the layer tag
for b in blobs/sha256/*; do oras blob push "$REPO" "$b"; done
oras manifest push "$REPO:2026.08.0" <your artifact manifest>
```

`oras cp --from-oci-layout ./layout:2026.08.0 "$REPO:2026.08.0"` is the shorter form where your registry accepts it. Any OCI client works; nothing about the bytes is varve-specific once they are signed.

## What consumers need

Two things, and only two:

1. **The registry reference** — `oci://ghcr.io/your-org/layers`, which goes in the realm's `registry`.
2. **The trust root** — the 64 hex characters `varve pubkey` prints, which goes in the realm's `trust-root`.

Hand them a `varve-realms.toml` containing both. That file is the whole bootstrap: it names where bytes come from and which key makes them acceptable. Everything else — digests, counters, support windows — travels inside the signed manifest.

## Bootstrapping trust the first time

A consumer has to obtain the realms file through a channel they already trust — your repository, your onboarding, your configuration management. varve cannot verify the first realms file for you; it is the root of the chain, not a link in it. After that, every layer is checked against it offline.

## Air-gapped delivery

No registry is required. `varve archive <layer> <dir>` writes the same OCI layout, and `varve install --from <dir>` reads it. Carry the directory across on whatever media you use; verification is identical on both sides, because it depends on the signature and not on the transport.
