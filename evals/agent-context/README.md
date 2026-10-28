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

Two arms of FRESH agents, the same 9 questions, one agent per question per arm,
no memory shared between them:

- **baseline**: the agent has the pin (a project directory with `varve.toml`,
  the shims on PATH) and no orientation. It finds out for itself.
- **orientation**: the same, plus the output of `varve-serve context` placed in
  its context, and `varve-serve ask` available.

For each run record:

1. **calls**: how many tool calls the agent made before answering;
2. **tokens**: how many it spent;
3. **correctness**: whether the final answer matches every `must` pattern of the
   task. Mechanical; an answer that is right in other words and misses a pattern
   counts as wrong, and the miss is read by a person before it is believed.

A run is only counted if the agent ran against the shipped pin; a run that read
the repository for the answer is discarded.

## Measured so far

These come from the Python prototype the Rust code was written from
(`orient3.py` and `ask.py`), not from the Rust binaries; re-running the
orientation arm with the Rust output is the next measurement.

| arm | calls per question | correct |
|---|---|---|
| baseline | 5 to 6 | 8 of 9 |
| orientation v3 + `ask` | 3 to 6 | 7 to 8 of 9 |

Read that table honestly: the orientation did not raise correctness. It lowered
the number of calls, and the cases it got wrong are what the rules in the code
come from.

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
