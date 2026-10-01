# outdated — is there a newer layer for this line?

```sh
varve outdated
```

```
2 newer layer(s) for line 2026.10, signed by realm 'pulseengine' (index #21):
  2026.10.0 rolling sha256:aa…
  2026.10.1 rolling sha256:bb…

`varve diff --to <layer>` shows what changing would change.
Nothing here changed the pin or the store.
```

A pinned consumer has had no way to ask this. The signal existed — `varve
install` prints the realm's signed high-water counter beside the one it
accepted — but only while installing, so the only way to find out was to run an
install you did not want. `varve status` answers a different question: the
support window, yanks and known problems of the layer you already have.

## The answer comes from the signed index, or not at all

`varve outdated` reads the realm's **signed line index** and nothing else. A
registry's `/tags/list` would answer faster, and it is refused.

A host that simply **hides** a layer serves nothing that fails verification:
every artifact it does hand over is correctly signed, so an unauthenticated
listing cannot tell *"there is nothing newer"* from *"I am not telling you"*.
Those are different answers, and presenting the first when the truth is the
second is the failure this whole mechanism exists to prevent — see
`varve docs attach-index`.

So where the realm publishes no index, this says so and reports nothing:

```
cannot answer: realm 'acme' publishes no signed line index for 2026.10, so
whether a newer layer exists cannot be established.
```

That is not a bug to work around. A realm starts publishing one with
`varve sign-index` and `varve attach-index` at deposit; until then the question
is genuinely unanswerable, and varve would rather say so than guess.

## It changes nothing

Not the pin, not the store, not the anti-rollback mark. Asking what would
change must never be what changes it — so there is no `--update`, and a newer
layer is reported, never installed. Moving is a reviewed edit to `varve.toml`,
as it always is.

`--json` gives the same facts with an `answerable` flag, so a pipeline can tell
"nothing newer" from "could not be established" without parsing prose.

## Ordering

Layers are ordered by `(year, month, patch)` numerically, never as strings — a
string compare puts `2026.09.12` before `2026.09.2`. An index entry this varve
cannot parse is reported on stderr rather than dropped: a layer it cannot order
is one it cannot promise is not newer.

See also: `varve docs diff`, `varve docs status`, `varve docs attach-index`.
