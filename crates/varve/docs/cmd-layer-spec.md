# `varve layer-spec` — a realm's contents, from the realm's own repository

```sh
varve layer-spec --manifest layer.toml >> "$GITHUB_ENV"
```

Reads a realm's `layer.toml` and prints the `KEY=value` lines the layer
assembler reads. It contacts nothing, writes nothing, and never touches a
signing key — it is a translation, and the step after it is what downloads,
verifies and signs.

## Why this exists

Before it, a layer's contents lived in varve's own deposit workflow: bumping
`rivet` to v0.34.0 meant a commit to **the tool that signs the layer**. That is
backwards. The realm's contents are the realm's business, and varve is
supposed to be the thing that vouches for them, not the thing that lists them.

With this command the list moves to the realm's repository — `pulseengine-layers`
for the `pulseengine` realm — and a version bump becomes a one-line reviewed
diff there. varve gets no commit at all.

The adapter lives **here**, in varve, and not in the realm's repository. That is
deliberate: the assembler it feeds is system-tested in varve, and a realm running
a *copy* of that logic inherits none of the testing. One writer, one set of
tests, every realm.

## The manifest

```toml
[varve]
version = "v0.28.0"        # the varve release that builds this layer

[realm]
name     = "pulseengine"
channel  = "rolling"
registry = "oci://ghcr.io/pulseengine/varve/layers"

[[tool]]
name    = "rivet"
version = "v0.34.0"

[[tool]]
name    = "kiln"
version = "v0.4.4"
binary  = "kilnd"           # the executable, when it differs from the tool

[[tool]]
name    = "wsc"
repo    = "pulseengine/sigil"
version = "v0.11.0"
layout  = "raw-per-platform"

[[vsix]]
name    = "rivet-sdlc"
repo    = "pulseengine/rivet"
version = "v0.34.0"
asset   = "rivet-sdlc-%V.vsix"
```

`repo` defaults to `pulseengine/<name>`, `binary` to `<name>`, `layout` to
`tarball`. In an `asset` template `%V` is the bare version, `%T` a Rust target
triple, `%U` a short upstream platform tag, and `%P` a VS Code platform tag; a
`vsix` template with no `%P` is one portable package.

**The trust root is not in this file.** It is the public half consumers already
pin, and the secret half is a CI secret, never a committed file — see
`varve docs root-ceremony`.

## What it refuses, and why refusing is the point

The assembler reads space-separated entries of colon-separated fields. That
encoding cannot represent a value containing a space or a colon, and a shell
will not complain — it will split one tool into two, or truncate a version.
**A layer assembled from a mangled list still signs, still verifies, and carries
the wrong bytes.** So every value is checked against the encoding before it
reaches it, and anything that cannot be carried faithfully is an error rather
than a best-effort translation:

* **A mistyped key** — `verison = "v0.34.0"` — is rejected, not ignored. If it
  were ignored, the real `version` would be missing or stale and the layer would
  ship the wrong release under a good signature. Every table is
  `deny_unknown_fields` for this one reason.
* **A second `raw-per-platform` tool** is rejected. The assembler has exactly one
  slot for that shape (`WSC_VERSION`), so a second would be silently dropped from
  a layer that still publishes successfully.
* **A `vsix` under a foreign owner** is rejected. The assembler resolves extension
  repositories as `pulseengine/<name>`, so a foreign owner would quietly fetch a
  *different* repository's release of the same name.
* **A tool whose `repo` basename disagrees with its `name`** is rejected. The
  assembler takes a tarball tool's identity from the repository basename — it
  names the payload, the extract directory and the default asset template after
  it — so `name = "wsc"` with `repo = "pulseengine/sigil"` would deposit a tool
  called `sigil`, and a consumer asking for `wsc` would find nothing in a layer
  that deposited and verified cleanly. A foreign *owner* is fine:
  `bytecodealliance/wasm-tools` is exactly what the second realm needs. Set
  `binary` when only the executable's name differs, as `kiln` does for `kilnd`.
* **An unknown `layout`** is rejected, and the message names the two that work.
* **Two entries of one name**, and **a manifest with no payloads at all**, are
  both rejected.

Each of these is the same defect class: a check that cannot see the thing it
checks is worse than no check, because it is believed.

## Using it

The realm's deposit workflow fetches the pinned varve release, verifies it, then:

```sh
varve layer-spec --manifest layer.toml >> "$GITHUB_ENV"
```

`--manifest` defaults to `layer.toml`. The output is `KEY=value` lines, one per
line, in a stable order — appended to `$GITHUB_ENV` directly, with no `eval` and
no quoting round-trip, so nothing in a manifest can execute.

To see what a manifest would produce without committing anything, run it and
read stdout.

`--json` prints the same values as an object, for a pipeline that wants to
inspect the translation rather than apply it:

```sh
varve layer-spec --json | jq -r .tarball_tools
```

The `KEY=value` form exists for `$GITHUB_ENV`; `--json` exists for programs.

## Where to go next

* `varve docs ci` — the producer pipeline this feeds
* `varve docs deploy` — publishing the layer it produces
* `varve docs layers` — what a layer is
* `varve docs root-ceremony` — the key the deposit step uses, and its custody
