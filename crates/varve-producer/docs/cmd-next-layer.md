# varve-producer next-layer

What layer id and counter should the next deposit use?

```sh
varve-producer next-layer --repo ghcr.io/pulseengine/layers
2026.09.3	4

varve-producer next-layer --repo ghcr.io/pulseengine/layers --format json
{"command":"next-layer","counter":4,"layer":"2026.09.3","line":"2026.09"}
```

Read out of the **published record**, never guessed. An id that is wrong is
unrecoverable: varve has neither revocation nor deletion, so a spent id is
spent.

## How each number is decided

**The layer id** is `<line>.<P>`, where `P` is one past the highest already
published on that line — numerically, not lexicographically, because `2026.09.10`
sorts before `2026.09.2` as a string and answering `.2` would spend an id that
exists. A line nobody has published starts at `.0`.

Only a bare decimal suffix counts. `2026.09.2-rc1` is not this line's layer 2,
and treating it as one would spend an id nobody meant to spend.

**The counter** comes from the highest published layer's baseline line-status —
**not** from `P`. Advisories issued by `varve sign-status` between deposits also
advance the line counter, so a deposit reusing one of those numbers would break
the per-line anti-rollback ordering. They are already unequal in practice: layer
`2026.09.2` carries counter `3`.

A new line starts at counter `1`.

## Every failure refuses

Nothing falls back to a guess, because with an unattended depositor a guess gets
signed:

* the registry cannot be listed → refuse, rather than derive an id from a record
  this program could not read;
* the computed id already exists → the record moved under us; refuse rather than
  dispatch a deposit that would overwrite a layer;
* the highest layer carries no baseline → the line's counter cannot be
  established without inventing one;
* the counter is unreadable → refuse rather than choose a number for it.

## The line

Defaults to the current UTC `YYYY.MM`. UTC deliberately: a depositor whose line
rolled over at local midnight would pick a different line depending on where it
ran, and layer ids are global. Override with `--line` to deposit onto a line
that is not this month's.
