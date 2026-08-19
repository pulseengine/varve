# Discovery — learning what exists

varve has no `search`. A pin names exactly what it wants, and resolution that
is not exact is an error — that is the design. But "name exactly what you
want" presupposes you can LEARN the name, and three people hit that wall from
three directions: a consumer who needs a layer name for their first pin, a
producer composing an upstream realm who needs an `[[include]]` digest they
never deposited, and a realm operator who signed the one document that
answers the question and has no command that reads it back. This topic says
what is possible today, and — just as load-bearing — what is not.

## What a consumer can learn, and from where

**A layer name comes from the realm operator, out of band.** Release notes,
onboarding, the same trusted channel that delivered `varve-realms.toml` (see
`varve docs deploy`, "Bootstrapping trust the first time"). There is no
command that lists a registry's layers: the registry's `/tags/list` is
unauthenticated, and varve does not build features on listings it would
refuse to trust for anything else.

**The authoritative in-band answer is the signed line-index** — the realm's
own statement of which layers a line contains. Consumers do not browse it;
they meet it during `varve install`, which reports what the realm asserts
beside what the install accepted:

```sh
varve install
# installed layer 2026.08.1 (counter 2) sha256:…
#   realm 'pulseengine' signed index for line 2026.08: greatest counter 3; this
#   install accepted counter 2 (reported, not enforced — your pin stays installable)
```

A greater counter in that report is how you learn a newer layer exists
without trusting the registry's word for it.

**What is already installed is `varve list`:**

```sh
varve list
# 2026.08.0  qualified  sha256:4ac5fd749abf9083…  realm=up
# 2026.09.0  qualified  sha256:40083c48caaa470b…  realm=own
```

Every realm partition is listed, labelled by realm name where a realms file
in scope maps the trust-root fingerprint back to one.

## The composing producer: where an `[[include]]` digest comes from

An `[[include]]` names the included layer by the digest of its **signed
manifest** — a value you did not produce and cannot compute from the tool
bytes. The answer is: install the upstream layer, then read `varve list` —
its digest column is exactly the value the include takes. This is stated
nowhere else, so here it is as a transcript:

```sh
# a directory pinned to the upstream layer (see `varve docs composition`)
cd upstream && varve install
varve list
# 2026.08.0  qualified  sha256:4ac5fd749abf90837089844c8f09563d255321db480401769187e8455e22f98e  realm=up
```

and that digest goes verbatim into your deposit spec:

```sh
grep -A3 'include' deposit.toml
# [[include]]
# digest = "sha256:4ac5fd749abf90837089844c8f09563d255321db480401769187e8455e22f98e"
# realm  = "up"
# layer  = "2026.08.0"
```

If the upstream realm publishes a signed line-index, the index document also
carries every layer's manifest digest — see the operator section below for
how to read one.

## The realm operator: reading back what you signed

There is **no varve command that reads a line-index back** — not from the
file you signed, not from a layout it was attached to, not from the registry
(varve#59). `varve sign-index` writes a DSSE envelope; the payload inside it
is plain base64-encoded JSON, so until a read-back command exists, standard
tools do it:

```sh
jq -r .payload index-2026.08.dsse.json | base64 -d | jq .
# {
#   "line": "2026.08",
#   "counter": 3,
#   "layers": [
#     { "layer": "2026.08.0", "digest": "sha256:aa…", "channel": "qualified", "counter": 1 },
#     …
#   ]
# }
```

Note what that pipeline does not do: verify the signature. It shows you what
the envelope claims, on the honour system — fine for checking what you just
signed in CI, not a substitute for the verification `varve install` performs.
The same recipe reads a line-status envelope.

## Not possible today

Stated plainly, so nobody reconstructs it from absence:

* No `varve search`, and no command that lists a **registry's** layers or
  lines. Names arrive out of band or via the signed index at install time.
* No command prints the manifest digest of a layer that is **not installed**.
  Install it (any realm, any project directory), then `varve list`.
* No command reads back, verifies, or diffs a signed **line-index** — the
  `jq` recipe above is the current answer (varve#59).
* `varve status` answers for the **pinned layer's line only**, from the local
  cache — it does not enumerate other lines' advisories.
