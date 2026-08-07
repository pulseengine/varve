# Changelog

## v0.1.0 — 2026-08-07

Local resolution and the core, fail-closed. First implemented release; the
v0.1.0 scope in rivet is fully `verified`/`accepted` (`rivet release status
v0.1.0`).

- `varve-core`: three-part layer identifiers (`YYYY.MM.P`, DD-004 grammar,
  two-part rejected with corrective guidance), strict `varve.toml` pin parsing
  (unknown keys/channels, malformed digests, empty tools all hard errors),
  walk-up pin discovery, content-addressed core store (`core/sha256-…/`),
  pure fail-closed resolution — no PATH fallback, no partial layers, digest
  wins over name, ambiguity refuses
- `varve` CLI: `which` (resolved binary + layer + digest), `list`
- 37 tests, each carrying a `// rivet: verifies REQ-…` marker; resolution and
  listing proven read-only against the core (REQ-SCOPE-001)
- Falsification: a pin whose layer is absent, partial, ambiguous, or
  digest-mismatched CANNOT resolve — the error type has no fallback variant

## Unreleased

Design decisions closed and the release plan landed in rivet. Still design
only — nothing is implemented.

- Decided (DD-004): layer identifiers are three-part from day one
  (`YYYY.MM.P`); patches stay inside a frozen line and carry a signed
  qualification-delta attestation (the DO-330 mechanism)
- Decided (DD-005): anti-rollback via monotonic per-line release counters +
  issued-at inside the signed layer metadata (SUIT/Uptane pattern); tuf-on-ci
  recorded as the upgrade path
- Research evidence captured as rivet artifacts: criticalup source-level
  analysis (CA-CRITICALUP) and SUIT/Uptane/TUF/DO-330 references (AR-*)
- STPA-Sec seed for the distribution attack surface: 2 security losses,
  4 hazards (rollback, freeze, source-influences-acceptance, mixed toolchain),
  4 constraints, each satisfied by a requirement
- Release plan (`rivet release status vX.Y.Z`): v0.1.0 local resolution +
  core, v0.2.0 verified install + anti-rollback, v0.3.0 offline archive,
  v0.4.0 deposit + provenance, v0.5.0 known-problems/support-window/yank
  metadata + self-verification
- New requirements: REQ-DEPOSIT-001 (v0.4.0), REQ-KP-001 and REQ-SELF-001
  (v0.5.0 — the criticalup gaps worth owning)
- rivet schemas wired: stpa, stpa-sec, aspice, supply-chain, research

### Bootstrap

- README: problem statement, scope and explicit non-goals
- `docs/manifest-format.md`: the two manifests (the pin, and the signed layer index)
- rivet project seeded with the invariants and the decisions taken so far
- workspace skeleton: `varve` (CLI) + `varve-core` (library)
