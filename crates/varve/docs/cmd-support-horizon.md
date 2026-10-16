# `varve support-horizon` (CI)

Print the date a layer's support window closes, derived from its channel's
stated policy.

```sh
varve support-horizon --channel rolling --issued-at 2026-09-03T00:00:00Z
# 2027-03-03
```

`--json` emits `{"channel", "issued_at", "support_until", "policy_until",
"bound_by"}` for a pipeline.

A layer that composes others passes its `layer.toml`:

```sh
varve support-horizon --channel rolling --issued-at 2026-10-02T10:00:00Z \
  --manifest layer.toml
# support capped at 2026-10-24 by included layer 2026.09.0 (realm 'pulseengine-wasm'); ...   (stderr)
# 2026-10-24                                                                                 (stdout)
```

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
| `rolling` | **1 month** |
| `qualified` | 24 months |

`rolling` is one month, and that is not a placeholder to be grown later. The
rolling line ships monthly, so a layer is superseded roughly a month after it
is issued, and **nobody has undertaken to publish advisories or fixes for a
superseded rolling layer**. The first value written here was six months, which
promised five months of attention no one had agreed to give. A support window
is a commitment; stating one longer than the commitment is the same class of
untruth as stating none while the docs promise one.

`qualified` is where a long horizon belongs — that is the channel an assessor
is pointed at, and the one whose contents are deliberately frozen.

An unknown channel is refused rather than given a default. A horizon nobody
decided is a promise nobody made, and it would be signed with the realm's root.

## A composition cannot outlast what it composes

covalent 2026.10.0 signed support until **2026-11-02** while the wasm-layers
layer it includes was supported only until **2026-10-24** (varve#254). The
composition promised nine days of support for bytes whose own realm had stopped
vouching for them, and signed that promise with its root.

With `--manifest`, every `[[include]]` is read from **its own realm**: the
include's manifest is fetched by digest and verified against that realm's
root, then its current line-status (the baseline, or a later published
correction, whichever verifies and is newer) supplies its window. The horizon
is the earliest of the channel's policy and every include's window.

- **Capping is the default**, so an automatic deposit states the true window
  without a person.
- **An include that states no window refuses.** Skipping it would make the cap
  vacuous: the include nobody vouched for is exactly the one that would have
  bound it.
- **`--past-includes "<reason>"` promises longer anyway.** The reason is
  printed beside the date, so a longer promise is a decision on the record.
  An empty reason is refused.

The realms the includes name must be defined in a `varve-realms.toml` found
from the working directory, exactly as for `install`.

## What it does not do


It does not sample a clock beyond the `--issued-at` you give it, and it does
not write anything. Without `--manifest` it makes no network request; with
one, it reads only the includes' manifests and line-statuses. The caller puts the result in the status document, and
`varve sign-status` refuses a document without one.

## Reading it back

`varve status` reports where the pinned layer stands, not just the date:

```
layer 2026.09.1 is supported until 2026-10-06 (30 days)
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
