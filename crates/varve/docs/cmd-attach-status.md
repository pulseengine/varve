# varve attach-status (CI)

Attaches a signed line-status envelope to a deposit layout as its baseline,
so `varve status` works after an offline install and the registry push can
carry it. The line is derived from the document itself; nothing about the
layer is touched — no blob, no digest — the advisory is added beside the
artifact, exactly as `attach-index` adds the line index.

```sh
varve sign-status --file status-2026.08.json --key root.key --out status.dsse.json
varve attach-status --layout ./layout --status status.dsse.json
# attached baseline line-status #3 for line 2026.08 to ./layout
jq '[.manifests[].artifactType]' layout/index.json   # the line-status type is now listed
```

`--status` takes the SIGNED envelope from `varve sign-status`, not the raw
JSON — passing the unsigned document is refused with the fix named. Attach
before pushing and before archiving: the documented registry push reads this
referrer out of the layout (`varve docs deploy`), and re-running `varve
deposit` into the same `--out` would silently drop it (`varve docs ci`).

## What attach-status refuses, deliberately

Producer mistakes are refused here, where re-signing is cheap, rather than
left for a consumer on the far side of an air gap:

* **A counter regression** — an envelope older than the one the layout
  already carries. A re-run CI step must not downgrade the baseline to a
  pre-yank document that tells fresh consumers "not yanked" about a yanked
  layer. Re-attaching the SAME counter is allowed, so re-runs stay
  idempotent.
* **A document for a different line than the layout's layer** — a 2099.01
  status on a 2026.08 layout attaches nowhere.
* **A yank or `affected` id that is not a layer of the line** — the advisory
  would never fire (`varve status` matches ids exactly). `sign-status`
  refuses this too; attach re-checks because the envelope may come from an
  older signer.
* **A directory that is not an oci-layout** — refused before anything is
  written; point `--layout` at the directory `varve deposit --out` produced.

## Limits worth knowing

* Replaces any previous document for the same line: a deposit layout carries
  exactly one baseline.
* The signature is NOT verified here — the deposit pipeline produced the
  envelope moments earlier with its own key, and `install` re-verifies the
  bytes against the consumer's trust root, which is the verdict that counts.
* The baseline is a floor, not a feed. Consumers get the advisory state as
  of the attach; newer documents reach them from the line's own tag (below)
  or `varve status --from-file`.


## On a registry: saying something NEW about a published layer

A yank, an advisory and a support-window correction are the same act — saying
something about a layer *after* it is published — and the baseline cannot carry
any of them. The baseline is a blob inside a **layer's** artifact manifest, so
reissuing it means re-pushing that manifest with a different blob digest, which
changes the manifest digest. That is the republish `varve deposit` refuses under
REQ-IMMUTABLE-001, reached by a well-intentioned route. **Yanking a layer must
not require mutating it.**

So the correction goes under the **line's own tag**, `line-status-<line>`,
exactly as the signed index goes under `line-index-<line>` — independent of any
layer, touching no layer digest:

```sh
REPO=ghcr.io/your-org/layers
ST=status.dsse
oras blob push "$REPO" "$ST"
D=sha256:$(sha256sum "$ST" | cut -d' ' -f1)
jq -n --arg d "$D" --argjson s "$(wc -c < "$ST")" '{
  schemaVersion: 2,
  mediaType: "application/vnd.oci.image.manifest.v1+json",
  artifactType: "application/vnd.pulseengine.varve.line-status.v1+json",
  config: { mediaType: "application/vnd.oci.empty.v1+json",
            digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            size: 2 },
  layers: [ { mediaType: "application/json", digest: $d, size: $s,
              annotations: {"eu.pulseengine.varve.role": "line-status"} } ]
}' > status-manifest.json
oras manifest push "$REPO:line-status-2026.08" status-manifest.json
```

Bump the document's `counter` every time you re-push. That counter is what
decides the outcome below.

### What a consumer does with two documents

It fetches **both** — the baseline beside the layer, and the tag document — then
**verifies each against the realm root, and only then compares counters**,
keeping the newer. The order is the security property, not an implementation
detail:

* **Ranking before verifying** would hand the choice to whoever serves the tag.
  Write a large counter, win the comparison, and a forged document displaces a
  real one — or, failing verification afterwards, denies the consumer the good
  baseline it already had.
* **A stale tag document cannot walk a consumer backwards.** Clause 2 says
  prefer the *newer*, not "prefer the tag", so a registry cannot suppress a yank
  by serving an older document under the tag.
* **An unverifiable tag document is discarded, not fatal.** The good baseline
  still lands. Serving junk under the tag is not a way to deny service.
* **A validly-signed document for a different line is refused**, by the same
  guard the baseline path uses rather than a second rule that could drift.

The baseline therefore stays exactly as useful as it was: an offline install and
`varve install --from` keep working unchanged, and the tag is what makes a layer
speakable-about afterwards.
