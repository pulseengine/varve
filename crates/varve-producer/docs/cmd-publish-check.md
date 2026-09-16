# varve-producer publish-check

Is this layer id already published, and would this push replace it with
different bytes?

```sh
varve-producer publish-check --repo ghcr.io/pulseengine/layers \
  --layer 2026.09.3 --digest sha256:... --format json
```

Run it **before** pushing. `varve deposit` cannot: it contacts no network by
design, and spending that property to fix a publisher's bug would be a bad
trade.

## Absence is established, never inferred

From an authoritative **tag listing**, not from an error message. An earlier
version matched `404` in the failure text, and a clean-room review found that a
repository path containing `404`, a port `:4040`, or the layer id `2026.09.404`
all read as absent — a green verdict to publish over an existing layer.

So a registry that cannot ANSWER stops the push. "Unreachable" is not "empty".

## The first push to a new repository

On a registry path nothing has ever been pushed to, both reads fail and this
command refuses — correctly, since absence cannot be established. Make the
question answerable by creating the repository first: push a manifest under a
tag that is not a layer id, after which the listing returns and absence is
established the ordinary way.

## Exit codes

| | |
|---|---|
| 0 | verdict decided — `publish` or `already-published` |
| 1 | refused, or could not determine |
| 2 | bad usage, including an unknown `--format` |
| 127 | oras is not installed — **not** a refusal; nothing was checked |

127 and 1 must not be conflated. A check that did not run is not a check that
passed, and reporting them alike sends an operator hunting for a republish that
never happened.
