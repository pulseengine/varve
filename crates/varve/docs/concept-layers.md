# Layers

A layer is one signed, dated bundle of tools and artifacts — `YYYY.MM.P`. The
initial deposit of a line is `.0`; a patch inside a frozen line is `.1`, `.2`, …
Layers are content-addressed by their signed manifest digest and coexist in the
core, so switching a project between layers costs no download — it is a pin edit.
Every layer carries a monotonic release counter and issued-at inside the signed
payload, so a stale-but-valid layer cannot be passed off as current.

## Composition

A layer may compose another: a signed entry of payload kind `layer` whose digest is the included layer's manifest digest, and whose annotations name the realm that verifies it. One pin then spans two trust universes — the tools that check your work and the upstream tools that build it — while each layer keeps its own root, cadence and qualification claim. Because the include sits in the signed payload and is named by digest, the composition is signed and cannot drift.

varve does not choose between layers: a tool exposed by two of them is an error naming both, exactly as a pin that does not resolve uniquely is an error rather than a fallback. A cycle — a layer reappearing on its own path — is refused; a *diamond*, where two layers share a base, is walked once and is perfectly legal. Depth is bounded at 8.

`varve verify` walks the composition and verifies each included layer against its own realm's trust root, recursing — a composition is only as trustworthy as every layer in it, and the included layer's tools are on PATH exactly like the root's.

Produce one with `[[include]]` tables in a deposit spec file (`digest`, and optionally `realm` and `layer`). An included layer must already be installed; fetching one transitively is not yet implemented, so resolution and verification both fail naming the missing layer and its corrective `varve install` (REQ-COMPOSE-001).
