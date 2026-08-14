# Documentation friction audit

Ten personas try to **use** varve from its embedded docs alone, and report where
they get stuck. Run it **before tagging each minor release** (decision,
2026-08-14).

## Why this exists

varve already has a mechanical docs gate — `varve docs check --coverage --strict`
asserts every subcommand has a topic. The first run of this audit showed why that
is not enough:

> *"All 24 subcommands have a topic and `varve docs check --coverage` reports OK,
> which is exactly the problem: the invariant measures presence per subcommand,
> and every real gap is workflow-shaped."*

Five of ten personas could not finish their job. Four were blocked by the same
thing — no way to obtain a signing key's public half, so an organisation could
not stand up its own realm at all. Six clean-room reviews had not found it,
because reviewers read diffs while these personas try to accomplish a job.

## Running it

The script is a Claude Code `Workflow`. From the repo root:

```
Workflow({ scriptPath: "tools/audit/docs-friction-audit.js" })
```

Roughly 17 minutes and ~840k subagent tokens per run.

## The rules that make it work

Two constraints do the heavy lifting; do not relax them:

1. **Docs only.** Personas may read `varve docs`, `--help` and `README.md`. They
   may **not** read the Rust source — if they need it to proceed, that is
   recorded as a documentation failure rather than worked around.
2. **Actually run the tool.** No theorising. Each persona works in a scratch dir
   with its own `VARVE_ROOT`, and quotes real command output as evidence.

## Reading the result

The headline metric is **how many personas were blocked**, and whether the same
root cause blocks several — a single wall behind four personas is worth more
than four unrelated nits. Compare against the previous run.

The synthesis also names what is *fine*, deliberately: a false-positive audit
that sends you rewriting working docs costs more than it saves.
