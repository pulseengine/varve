# varve-serve context

An orientation for the pin, for an agent told to "check in here".

```sh
varve-serve context                  # Markdown
varve-serve context --format json    # the same data, for a program
```

It answers "what does this pin hold and where do I look" without reading or
running every tool: the realm, layer, channel and the **Layer manifest
digest**; a **First move** section naming `varve-serve ask`; every tool on PATH
with the purpose line, warning and subcommands it prints about itself; the names
of each tool's built-in documentation topics; the held payloads with the exact
command that gets each out; the documentation payloads, in `varve inspect`'s own
words; and any tool a warning points at that the pin does not carry.

## Where the words come from

Nothing is written by hand. Each pinned tool's `--help` is run, and what it
prints is copied: a description is cut at a sentence and never mid-word, and a
caveat ("NOT YET IMPLEMENTED", "deprecated", "always exits 2") always survives,
even when a tool has more than 12 subcommands and the list collapses to names.

Every harvested field says `harvested` (`"source": "harvested"` in JSON).

**Signed values are not part of this yet.** REQ-AGENTDOCS-001 clause 2 gives a
`[[tool]]` entry in `layer.toml` optional `summary` and `docs-command` fields,
signed with the manifest, which would take precedence over anything harvested
and be labelled `signed`. Those fields do not exist, so nothing here is signed.
The seam is `harvest::Signed`, which `context::build` consults first.

## What is run, and in what box

Only the pinned binary from the verified store, never one found on PATH. It is
run with `--help`, and ONLY when that help lists a `docs` subcommand, with `docs`
and `docs <topic>`. A tool whose help does not list `docs` is never asked: some
tools start doing real work when handed an unknown subcommand.

Each call has a scrubbed environment (`PATH=/usr/bin:/bin`, `HOME` a fresh empty
directory), a fresh working directory, no stdin, and a 5 second timeout after
which it is killed and the tool is shown as "no help available". This is hygiene,
not a security boundary: the binary is already one the signed manifest vouches
for.

## The cache

The result is cached per layer manifest digest under the store
(`cache/agent-context/`), bound to each tool's signed binary digest, so a second
`context` runs nothing. The cache is read only after the layer has verified, an
entry for different bytes is ignored, and a cache that cannot be written is not
an error.

## Rules it keeps

- **Metadata and topic names only.** Never a documentation body: the output is
  loaded into an agent's context unasked, and docs text can carry a prompt
  injection. `ask` returns pointers for the same reason.
- **If any layer fails verification** it exits non-zero with empty stdout. Flip
  one byte in the store and see.
- **Deterministic.** Two runs print the same bytes, harvested entries included.
- **Offline.** No network is touched.

The size stays within about 4k tokens for the pulseengine layer; a test checks
the budget.
