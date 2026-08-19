# Layers

A layer is one signed, dated bundle of tools and artifacts — `YYYY.MM.P`. The
initial deposit of a line is `.0`; a patch inside a frozen line is `.1`, `.2`, …
Layers are content-addressed by their signed manifest digest and coexist in the
core, so switching a project between layers costs no download — it is a pin edit.
Every layer carries a monotonic release counter and an issued-at date inside the
signed payload. **The counter is what stops a stale-but-valid layer**: `install`
refuses one below its line's high-water mark, and since varve#76 `verify`
refuses a pin that *resolves* to one, so the CI gate and the install agree.

`issued-at` is **not** part of that verdict. It feeds one advisory at install —
`warning: layer 1990.01.0 was issued 13379 days ago` past 90 days, exit 0 — and
nothing at all in `verify`. Nor is a *future* date questioned: a layer stamped
`2099-01-01` installs and verifies clean. Treat issued-at as a label on the
layer, not a control.

## Composition

A layer may compose another: a signed entry of payload kind `layer` whose digest is the included layer's manifest digest, and whose annotations name the realm that verifies it. One pin then spans two trust universes — the tools that check your work and the upstream tools that build it — while each layer keeps its own root, cadence and qualification claim. Because the include sits in the signed payload and is named by digest, the composition is signed and cannot drift.

varve does not choose between layers: a tool exposed by two of them is an error naming both, exactly as a pin that does not resolve uniquely is an error rather than a fallback. A cycle — a layer reappearing on its own path — is refused; a *diamond*, where two layers share a base, is walked once and is perfectly legal. Depth is bounded at 8.

`varve verify` walks the composition and verifies each included layer against its own realm's trust root, recursing — a composition is only as trustworthy as every layer in it, and the included layer's tools are on PATH exactly like the root's.

Produce one with `[[include]]` tables in a deposit spec file: `digest` **and
`realm`**, plus an optional `layer` used only in error messages. An included
layer must already be installed; fetching one transitively is not yet
implemented, so resolution and verification both fail naming the missing layer
and its corrective `varve install` (REQ-COMPOSE-001).

The parser will accept an include without `realm`. It is nonetheless
**required in practice**.
Omit it and no `include.realm` annotation is written into the signed
payload, so `verify` falls back to the *pinned project's* trust root. That is
right only when the included layer happens to be signed by the same key — and
composition exists precisely because it usually is not. In the cross-realm case
the layer installs cleanly, then `verify` reports the included layer's signature
as failing, which is untrue: the bytes are perfectly signed, by a root nobody
asked. Because the annotation lives inside the signed payload, the only fix is
to re-deposit.
