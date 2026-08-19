# varve sign-status (CI)

Validates a line-status JSON through the typed model and signs it into a DSSE
envelope with the realm root. The line-status is the evidence that changes
AFTER a layer is deposited — yanks, known problems, the support window — one
document per release line, carried beside the immutable layers and re-signed
whenever it changes. `varve status` is its consumer.

The full schema — every field of `yanked` and `known-problems`, with the
required/optional table — lives in `varve docs config-reference`, "The
line-status document". The shape in brief:

```json
{
  "line": "2026.08",
  "counter": 3,
  "issued-at": "2026-08-14T00:00:00Z",
  "support-until": "2027-08-01",
  "yanked": { "2026.08.1": "miscompiles under -O2; use 2026.08.2" },
  "known-problems": [
    {
      "id": "VARVE-2026-0003",
      "title": "synth mis-fuses nested match arms",
      "severity": "high",
      "affected": ["2026.08.0", "2026.08.1"],
      "workaround": "build that crate with -C opt-level=1"
    }
  ]
}
```

```sh
varve sign-status --file status-2026.08.json \
                  --key root.key --key-id varve-root-1 \
                  --out status-2026.08.dsse.json
# signed line-status #3 for line 2026.08 -> status-2026.08.dsse.json
```

Then attach it: `varve attach-status` puts it in a deposit layout as the
baseline, and the registry push carries it under the `line-status` role
annotation (`varve docs deploy`). Signing it and leaving it in CI warns
nobody. In CI, `--key /dev/stdin` accepts the key from a pipe — see `varve
docs ci` for the whole pipeline and the key-handling patterns.

## What sign-status refuses, deliberately

* **A document that does not match the schema** — unknown fields, a string
  where `known-problems` wants an object, a missing `counter`. CI must not be
  able to sign a malformed advisory and discover it at the far end.
* **A yank or `affected` id that is not a layer of the document's `line`** —
  `"2026.8.0"` for `"2026.08.0"`, or a layer from another line. `varve
  status` matches ids exactly, so such an entry signs fine and then fires for
  nobody; the refusal names the id, the line, and the fix (re-sign).
* **A key whose halves disagree** — refused before signing, so an envelope no
  trust root could verify is never produced.

## Limits worth knowing

* `counter` monotonicity is enforced where documents MEET — the consumer
  cache, `attach-status`, install — not here: sign-status sees one document
  and cannot know what the world already holds. You own the increment.
* The signature binds the document under its own payload type; a signed
  line-status cannot be replayed as a layer manifest or a line-index, and
  vice versa.
