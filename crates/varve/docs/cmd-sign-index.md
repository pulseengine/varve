# varve sign-index (CI)

Validates a line-index JSON through the typed model and signs it into a DSSE
envelope with the realm root. The index is the realm's statement of *which
layers a line contains* — the one thing a registry's `/tags/list` cannot be
trusted for, because a host that simply HIDES a layer serves nothing that fails
verification.

The document names every layer of one line, each with the digest of its signed
payload (what a pin's `digest` names), its channel, and its manifest counter.
`counter` at the top level is the document's own monotonic number: a consumer
refuses an index older than the one it already holds.

```sh
cat > index-2026.08.json <<'JSON'
{
  "line": "2026.08",
  "counter": 3,
  "issued-at": "2026-08-19T00:00:00Z",
  "layers": [
    { "layer": "2026.08.0", "digest": "sha256:aa…", "channel": "qualified", "counter": 1 },
    { "layer": "2026.08.1", "digest": "sha256:bb…", "channel": "qualified", "counter": 2 }
  ]
}
JSON

varve sign-index --file index-2026.08.json \
                 --key root.key --key-id varve-root-1 \
                 --out index-2026.08.dsse.json
```

Then publish it: `varve attach-index` for a layout, or push the same envelope
to the registry under the `line-index-<line>` tag (see `varve docs
attach-index`). Signing it and leaving it in CI protects nobody.

Consumers only look for it when their realm declares `signed-index = true`;
see `varve docs config-reference`.
