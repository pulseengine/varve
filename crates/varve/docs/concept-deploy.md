# Deploying a layer

`varve deposit` assembles and **signs** a layer, and writes an OCI image layout directory. It stops there. varve runs no server and pushes nothing — an OCI registry is the transport, and access control is the registry's job ("No server of our own"). Publishing therefore uses an ordinary OCI client, and that client never joins the trust path: whatever it uploads is accepted by a consumer only because the signature verifies against the pinned root.

Its `--help` used to say "publish", which sent people looking for a push command that does not exist.

## The push

A varve layer is not a plain blob dump: the consumer side (`RegistrySource`)
finds the envelope, the payload and the baseline advisory by their **role
annotations** on `layers[]`. Push the blobs and a manifest without those
annotations and the upload succeeds while every consumer fails to read it.

This is what varve's own release pipeline runs
(`.github/workflows/deposit-layer.yml`), reduced to the parts you need:

First, a prerequisite the sequence below depends on: `varve deposit` does
**not** attach a baseline line-status, and this push reads one. Attach it to the
layout before pushing, or `STATUS_DIGEST` resolves to `null` and both the blob
push and the manifest build fail on a nonexistent path:

```sh
varve sign-status --file status.json --key root.key --out status.dsse
varve attach-status --status status.dsse --layout ./layout
```

Then:

```sh
oras login ghcr.io -u "$USER" --password-stdin <<< "$TOKEN"
REPO=ghcr.io/your-org/layers
LAYER=2026.08.0
SIG='application/vnd.pulseengine.varve.signature.v1+json'
STATUS='application/vnd.pulseengine.varve.line-status.v1+json'

# 1. Pick the three roles out of the layout deposit wrote.
PAYLOAD_DIGEST=$(jq -r --arg t "$SIG" --arg s "$STATUS" \
  '[.manifests[] | select(.artifactType != $t and .artifactType != $s)][0].digest' layout/index.json)
ENVELOPE_DIGEST=$(jq -r --arg t "$SIG" \
  '[.manifests[] | select(.artifactType == $t)][0].digest' layout/index.json)
STATUS_DIGEST=$(jq -r --arg s "$STATUS" \
  '[.manifests[] | select(.artifactType == $s)][0].digest' layout/index.json)
blob() { echo "layout/blobs/sha256/${1#sha256:}"; }

# 2. Push every blob: an empty config, the envelope, the payload, each tool,
#    and the baseline line-status.
printf '{}' > empty-config.json
oras blob push "$REPO" empty-config.json
oras blob push "$REPO" "$(blob "$ENVELOPE_DIGEST")"
oras blob push "$REPO" "$(blob "$PAYLOAD_DIGEST")"
for d in $(jq -r '.manifests[].digest' "$(blob "$PAYLOAD_DIGEST")"); do
  oras blob push "$REPO" "$(blob "$d")"
done
oras blob push "$REPO" "$(blob "$STATUS_DIGEST")"

# 3. Build the artifact manifest — the role annotations are the load-bearing
#    part — and push it under the layer tag.
jq -n --arg e "$ENVELOPE_DIGEST" --argjson es "$(wc -c < "$(blob "$ENVELOPE_DIGEST")")" \
      --arg p "$PAYLOAD_DIGEST"  --argjson ps "$(wc -c < "$(blob "$PAYLOAD_DIGEST")")" \
      --arg s "$STATUS_DIGEST"   --argjson ss "$(wc -c < "$(blob "$STATUS_DIGEST")")" \
      --slurpfile payload "$(blob "$PAYLOAD_DIGEST")" '{
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  artifactType: "application/vnd.pulseengine.varve.layer.v1+json",
  config: { mediaType: "application/vnd.oci.empty.v1+json",
            digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            size: 2 },
  layers: ([
    { mediaType: "application/json", digest: $e, size: $es,
      annotations: {"eu.pulseengine.varve.role": "envelope"} },
    { mediaType: "application/vnd.oci.image.index.v1+json", digest: $p, size: $ps,
      annotations: {"eu.pulseengine.varve.role": "payload"} },
    { mediaType: "application/json", digest: $s, size: $ss,
      annotations: {"eu.pulseengine.varve.role": "line-status"} }
  ] + [ $payload[0].manifests[] |
        { mediaType: "application/octet-stream", digest: .digest, size: .size } ])
}' > artifact-manifest.json

oras manifest push "$REPO:$LAYER" artifact-manifest.json
```

`oras cp --from-oci-layout ./layout:2026.08.0 "$REPO:2026.08.0"` is the shorter
form. varve tags the layout with the standard
`org.opencontainers.image.ref.name`, so the `:2026.08.0` reference resolves —
but whether the role annotations survive the copy is your registry's business.
Check with `varve install --from oci://$REPO` before you rely on it.

None of this joins the trust path. Whatever the client uploads is accepted by a
consumer only because the signature verifies against the pinned root, so a
compromised push produces bytes that fail verification rather than bytes that
are trusted.

## What consumers need

Two things go in the file:

1. **The registry reference** — `oci://ghcr.io/your-org/layers`, which goes in the realm's `registry`.
2. **The trust root** — the 64 hex characters `varve pubkey` prints, which goes in the realm's `trust-root`.

Hand them a `varve-realms.toml` containing both. That file is the whole bootstrap: it names where bytes come from and which key makes them acceptable. Everything else — digests, counters, support windows — travels inside the signed manifest.

And, **if your registry is private, a third thing that does not go in the file**: a credential. varve reads `$VARVE_REGISTRY_AUTH` as `username:password`, or falls back to Docker/podman config files; it never executes a `credsStore` helper, so cloud registries need the credential handed over directly:

```sh
export VARVE_REGISTRY_AUTH="$USER:$GHCR_TOKEN"
export VARVE_REGISTRY_AUTH="AWS:$(aws ecr get-login-password --region eu-central-1)"
```

Without it a pull fails with *"offered no credential"*, naming `VARVE_REGISTRY_AUTH` — distinct from *"rejected it"*, which means the one you gave is wrong. Full precedence: `varve docs environment`. The credential is a *transport* secret: it decides whether the bytes arrive, never whether they are accepted.

## Bootstrapping trust the first time

A consumer has to obtain the realms file through a channel they already trust — your repository, your onboarding, your configuration management. varve cannot verify the first realms file for you; it is the root of the chain, not a link in it. After that, every layer is checked against it offline.

## Air-gapped delivery

No registry is required. `varve archive <layer> <dir>` writes an OCI layout of the same shape `deposit` does — `oci-layout`, `index.json`, `blobs/sha256/<hex>`, the layer manifest tagged with `org.opencontainers.image.ref.name` — and `varve install --from <dir>` reads it. Carry the directory across on whatever media you use; verification is identical on both sides, because it depends on the signature and not on the transport.

The **same three roles** travel: layer payload, DSSE signature envelope, and the baseline line-status. Until varve#77 the archive dropped that third one — three manifests in, two out — so an air-gapped consumer's `varve status` was permanently broken and a yank never arrived by the one transport that cannot fall back on a registry. Confirm it on a layer that carries one:

```sh
jq '[.manifests[].artifactType]' layout/index.json    # deposit side
varve archive 2026.10.0 ./archived
jq '[.manifests[].artifactType]' archived/index.json  # same three
```

Two ways an archive is legitimately *not* byte-identical to the deposit layout: attestations that entered at install time are re-emitted beside it as extra referrer entries, and the index is re-serialized. Both add evidence; neither changes the layer's identity, because the manifest digest is what the tag points at.

`archive` requires the whole layer to be present locally, so it **fails on a multi-platform layer** installed on one platform — the skipped entries were never laid down (`payload 'gamma@1.0.0' … is not present in the installed layer`). Archive from a machine the layer covers wholly.
