# Agent-orientation eval

What `varve-serve context` and `varve-serve ask` (REQ-AGENTDOCS-001 and -002)
are for is measured here, not assumed. This directory holds the task set and
the protocol; the harness that drives fresh agents is not part of the repo.

`tasks.toml` is 9 questions a user could ask of a pinned toolchain, each with
`must`: patterns a correct answer contains (alternatives separated by `|`).
They are fixed against one pin: realm `pulseengine`, layer `2026.10.31`,
manifest digest `sha256:f6bb7788f247c534c16d7d5d0c466c44f05a6d470f277dde79a05b05c54279ae`.
Two of them are traps: T6 (`kiln` is not in the pin, only the deprecated
`kilnd`) and T9 (`loom verify` is listed but NOT YET IMPLEMENTED and always
exits 2).

## Protocol

Two arms of FRESH agents (Sonnet, two runs per arm). Each agent answers all
9 questions in one session, and no memory is shared between runs:

- **baseline**: the agent has the pin (a project directory with `varve.toml`,
  the shims on PATH) and no orientation. It finds out for itself.
- **orientation**: the same, plus the output of `varve-serve context` placed in
  its context, and `varve-serve ask` available.

For each run record:

1. **calls**: how many tool calls the agent made across the 9 questions;
2. **tokens**: how many it spent;
3. **correctness**: whether the final answer matches every `must` pattern of the
   task. Mechanical; an answer that is right in other words and misses a pattern
   counts as wrong, and the miss is read by a person before it is believed.

A run is only counted if the agent ran against the shipped pin; a run that read
the repository for the answer is discarded.

## Measured so far

2026-10-28, pin above, Sonnet, two runs per row. Tokens are the agent's whole
session including the orientation it read. Correct is out of 9.

| arm | calls | tokens | correct | T4 exact page | T7 `verifies` |
|---|---|---|---|---|---|
| baseline: `varve inspect` and `--help` only | 5–6 | ~54.5k | 8, 8 | 0/2 | 2/2 |
| Python prototype v1 (no `ask`) | 2 | ~46k | 7, 7 | 0/2 | 0/2 |
| Python prototype v3 + `ask` | 3–6 | ~46k | 8, 7 | 0/2 | 1/2 |
| Rust round 1 | 2–4 | ~48k | 8, 8 | 2/2 | 0/2 |
| Rust round 2 | 3–4 | ~48k | 7, 8 | 0/2 | 1/2 |
| Rust round 3 | 2–4 | ~48k | 8, 8 | 2/2 | 0/2 |
| Rust round 4 (this code) | 2 | ~48k | 8, 8 | 2/2 | 0/2 |

Read it honestly:

- **Correctness held, it did not rise.** The orientation cut calls by 2–4 and
  tokens by about 6k per session.
- **It is the only arm that finds the exact page for a named type** (T4), once
  the docs section says, where agents read it, that pages are not listed and
  `ask "<Name>"` finds them (round 2 lacked that line and lost T4).
- **T7 resists every change on this side.** Agents check flags with
  `rivet link --help`, which lists only example link types; the baselines found
  `verifies` through `rivet schema list`. Filed as pulseengine/rivet#1146
  rather than worked around here.

## What the earlier drafts taught

Each rule in `crates/varve-serve/src/` is a failure from an earlier arm:

- A **template** (`--for <payload>`) produced a wrong flag, so the orientation
  copies commands varve itself prints and never writes a placeholder to be filled
  in. Agents also trust a complete-looking orientation and stop early, which is
  why it says plainly that flags are not listed.
- A helper named only at the bottom was never used, so the orientation **opens**
  with a "First move" naming `varve-serve ask`.
- A description cut mid-word, or a caveat dropped when a long subcommand list was
  collapsed to names, would tell an agent `loom verify` exists and not that it always
  exits 2 (T9). Caveats always survive.
- Running `<tool> docs` blindly is unsafe: `kilnd docs` starts the runtime. Only
  `--help` is run, and `docs` only where that help lists it.
- A tool's own warning (`kilnd` is deprecated, use `kiln`) must be shown, and the
  name it points at, when the pin lacks it, is called out (T6).
- In `ask`, **stopword filtering** was the biggest single retrieval gain: top-3
  on full-sentence questions went from 0 of 9 to 7 of 9. Then an exact item name
  (`struct.Store.html` for "Store") had to outrank pages merely in a module of
  that name, and hits about a tool the question names had to outrank other tools'.
- spar's purpose line was parsed as `Commands:`; the purpose is the first
  paragraph of the help, and a help that opens with a heading states none.

## Running the Rust version

```sh
cd <project pinning a layer>
varve-serve context            # the orientation
varve-serve ask "sign wasm module"
```

The unit and integration tests in `crates/varve-serve` hold the rules above in
place; this directory is where the outcome with real agents is measured.
