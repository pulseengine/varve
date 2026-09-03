# `varve support-horizon` (CI)

Print the date a layer's support window closes, derived from its channel's
stated policy.

```sh
varve support-horizon --channel rolling --issued-at 2026-09-03T00:00:00Z
# 2027-03-03
```

`--json` emits `{"channel", "issued_at", "support_until"}` for a pipeline.

## Why this is derived and not typed

`support-until` has existed since v0.5.0. It is part of the line-status
document, DSSE-signed, attached as an OCI referrer so it can be added after a
deposit without changing the layer's digest. `varve status` has always printed
it.

Nothing ever set it. Every layer varve published carried the field as `None`,
so every consumer was told **"no stated support window"** while
`docs/manifest-format.md` said a qualified channel "selects a line with a
stated support window". The capability was complete and the promise was empty —
which is worse than the feature being absent, because the code, the tests and
the documentation all implied a guarantee that no artifact carried.

A window typed by hand each release drifts, and the drift is invisible: every
value looks plausible. So the horizon comes from the channel:

| channel | window |
|---|---|
| `rolling` | 6 months |
| `qualified` | 24 months |

`rolling` is short deliberately. It makes no qualification promise and moves
continuously; a long window would imply a stability it does not have.
`qualified` is where a long horizon belongs, because that is the channel an
assessor is pointed at.

An unknown channel is refused rather than given a default. A horizon nobody
decided is a promise nobody made, and it would be signed with the realm's root.

## What it does not do

It does not sample a clock beyond the `--issued-at` you give it, and it does
not write anything. The caller puts the result in the status document, and
`varve sign-status` refuses a document without one.

## Reading it back

`varve status` reports where the pinned layer stands, not just the date:

```
layer 2026.09.1 is supported until 2027-03-03 (181 days)
```

and past the window:

```
layer 2026.03.0 passed its stated support window on 2026-09-01, 2 day(s) ago.
It still installs and still verifies — nothing about the bytes has changed.
What has changed is that no one has undertaken to publish advisories or fixes
for it …
```

varve **warns and does not refuse**. An expired layer is a maintenance signal,
not a broken artifact: the bytes verify exactly as before. A tool that bricks a
working build over a date gets removed from the build, and then it protects
nobody.

`--format json` on `varve status` carries `support_standing`, which is `null`
when no window is stated — so a consumer can tell *"not supported any more"*
from *"nobody said"*. Collapsing those two is the reason this exists.
