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
  of the attach; newer documents reach them via a re-pushed registry
  baseline or `varve status --from-file`.
