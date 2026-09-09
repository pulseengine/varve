# Consuming varve from Rust — `varve-core`

If you are writing a gate, a build rule, or a CI check that asks varve a
question, **use the crate, not the CLI**. `varve-core` is published on
crates.io and gives you typed answers that cannot be confused with each other.

This topic exists because a consumer wrote four failure reports in one day
without finding the API (varve#130). An undiscoverable typed interface loses to
a discoverable shell one every time.

## Why not the CLI

All four of those failures were CONSUMPTION failures. The tools behaved
correctly; the contract broke.

| what happened | why it passed |
|---|---|
| `objcopy` missing, printed a format error, wrote nothing | the value became `""`, and `[ "" -gt N ]` **errors AND evaluates false** — both range tests fell through and the script printed `ok`, exit 0 |
| a stale binary resolved ahead of the shim | the error said `Unknown command: codegen` — naming the subcommand when the fault was *which binary* |
| `cmd \| tail` | a pipeline reports **tail's** status; that was quoted as the tool's verdict |
| `set -e` | aborted the script at the very command whose failure was being measured, so the assertion never ran |

Every one has the same shape: **absence and failure arrived looking alike.**

## The one call

```rust
use varve_core::consumer::{payload_status, PayloadStatus};

match payload_status(&store, &layer, &verifier, "meld", varve_core::host_platform()) {
    PayloadStatus::Verified { path, digest, .. } => run(&path, &digest),

    // Opposite facts. Do not merge these two arms.
    PayloadStatus::DigestMismatch { signed, found, path, .. } =>
        bail!("{} does not match its signed digest: {signed} != {found}", path.display()),
    PayloadStatus::AbsentFromLayer { available, .. } =>
        bail!("this layer carries none; it has: {}", available.join(", ")),

    PayloadStatus::NoEntryForPlatform { platforms, .. } =>
        bail!("built for {} — not for this host", platforms.join(", ")),
    PayloadStatus::MissingFromStore { .. }  => bail!("incomplete install; run `varve install`"),
    PayloadStatus::LayerNotAuthentic { reason, .. } => bail!("the LAYER is not authentic: {reason}"),
    PayloadStatus::Unreadable { reason, .. } => bail!("could not decide: {reason}"),
}
```

**There is no `verify()` to forget.** The trust root is a *parameter*, so a
verified answer cannot be obtained by skipping a step. "Call verify first" is
the shell contract wearing types: a two-call protocol with an implicit ordering
whose omission fails **open**.

## The distinctions that matter

* **`DigestMismatch` is never `AbsentFromLayer`.** "I could not find it" says
  nothing about integrity. "I found it and it did not verify" is an integrity
  failure. A consumer that folds the second into the first fails open — that is
  the objcopy bug, in Rust.
* **`NoEntryForPlatform` is not absence.** The payload is in the layer and not
  for you: a different thing to tell a user and a different thing to fix.
* **`MissingFromStore` is not tampering.** The signed manifest names it and the
  store does not hold it — an incomplete install.
* **`LayerNotAuthentic` voids everything.** The fault is the layer, so no answer
  about its contents means anything.
* **`is_verified()` is the only predicate**, deliberately. An `is_ok()` that
  also returned true for absence would rebuild the bug one helper at a time.

## Knowing what you understand

```rust
varve_core::consumer::VERSION               // which varve answered
varve_core::consumer::PIN_MANIFEST_VERSION  // the pin format this build reads
```

`PIN_MANIFEST_VERSION` is the constant the parser itself enforces, not a second
copy that can drift. A consumer built once and run for months can compare it
against what it meets and record *"I met a pin newer than I know"* as a fact —
rather than meeting it as a parse error it has to pattern-match on prose. varve
moves; your pin does not.

## If you must shell out anyway

Read `varve docs exit-codes` and gate on the **exit code**, never on stdout.
Every varve command takes `--format json`. And never end a measured command
with a pipe: `cmd | tail` reports tail's status, not cmd's.
