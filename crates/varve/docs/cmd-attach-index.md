# varve attach-index (CI)

Attaches a signed line-index envelope to a deposit layout as a referrer, so an
offline consumer of a realm declaring `signed-index = true` can obtain it.
Nothing about the layer is touched — no blob, no digest — the index is added
beside the artifact, exactly as `attach-status` adds the baseline advisory.

```sh
varve sign-index --file index-2026.08.json --key root.key --out index.dsse
varve attach-index --layout ./layout --index index.dsse
jq '[.manifests[].artifactType]' layout/index.json   # the index type is now listed
```

Two producer mistakes are refused here rather than left for the consumer:
attaching an index whose counter is lower than the one the layout already
carries, and attaching an index for a different line than the layout's layer.

## On a registry

The index is addressed **per line**, not per layer: a consumer has to be able
to fetch it when the layer being hidden is the one they asked for. It goes
under the tag `line-index-<line>` — `line-index-2026.08` — in an artifact
manifest with one layer annotated `"eu.pulseengine.varve.role": "line-index"`:

```sh
REPO=ghcr.io/your-org/layers
IDX=index.dsse
oras blob push "$REPO" "$IDX"
D=sha256:$(sha256sum "$IDX" | cut -d' ' -f1)
jq -n --arg d "$D" --argjson s "$(wc -c < "$IDX")" '{
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  artifactType: "application/vnd.pulseengine.varve.line-index.v1+json",
  config: { mediaType: "application/vnd.oci.empty.v1+json",
            digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            size: 2 },
  layers: [ { mediaType: "application/json", digest: $d, size: $s,
              annotations: {"eu.pulseengine.varve.role": "line-index"} } ]
}' > index-manifest.json
oras manifest push "$REPO:line-index-2026.08" index-manifest.json
```

Re-push it whenever the line gains a layer. An index that stops naming the
line's newest layers is not wrong — it is a floor, and extra layers a source
serves are never an error — but it stops being able to catch the layer that
matters being hidden.

## Limits worth knowing before you set `signed-index = true`

* A plain `manifests/`+`blobs/` directory (`DirSource`) cannot carry an index
  at all, so installs of a declaring realm from one fail closed. Hand out an
  oci-layout instead.
* Omission is only detected against a source that *purports to list the line* —
  a registry. A layout is a hand-carried subset, so it is never accused of
  hiding what it was simply not given.
* `varve archive` does not yet carry the index back out of an installed layer
  the way it carries the baseline line-status, so a re-archived layout must be
  re-attached with `attach-index`.
