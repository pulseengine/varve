# Changelog

## Unreleased (v0.5.0 — tag held on REQ-PROV-001 / sigil#221)

Known-problems evidence and self-verification (REQ-KP-001 + REQ-SELF-001
verified, DD-008 + DD-009 accepted; the release gate holds until
REQ-PROV-001's attestation half lands via pulseengine/sigil#221).

- Line-status documents (DD-008): per-line signed advisories — known
  problems in the Ferrocene shape (workaround/detection/mitigation/affected),
  support window, yank markers — DSSE envelopes under their own payload type
  with their own monotonic counter; attachable to an existing oci-layout
  WITHOUT touching any layer blob or digest (tested byte-for-byte); cached
  per line; a stale advisory cannot replace a newer one
- `varve status [--from-file]`: "layer 2026.07.0: YANKED …, supported until …,
  N known problems, M with workarounds" — offline, from the verified cache
- `varve sign-status` (CI): validates through the typed schema before signing
- Self-verification (DD-009): releases gain `SHA256SUMS.txt.dsse.json`
  signed with the varve root; `varve self-verify --archive --envelope`
  checks a downloaded release offline against the pinned root, failing
  closed (absent envelope, tampered file, impostor key, wrong payload type
  all refused). `varve sign-sums` is the producing half — the same code the
  verifier tests against. Release workflow signs when the root ceremony
  provisions VARVE_ROOT_KEY (v1.0 gate); until then the asset is visibly
  absent, never silently skipped

## v0.4.0 — 2026-08-07

Deposit and dispatch (`rivet release status v0.4.0`: cuttable —
REQ-DEPOSIT-001 verified, DD-007 accepted).

- `varve deposit` (CI): assemble the layer manifest from per-tool binaries,
  embed line/counter/issued-at in the signed payload, sign into a DSSE
  envelope, and write the same OCI image layout `archive` produces — a fresh
  deposit and an archived core are byte-compatible, and deposits install
  through the one verified pipeline. Deterministic: identical specs yield
  identical digests. Empty or duplicate tool lists refused
- `varve run [--varve LAYER] -- <tool> …`: exec the pinned layer's tool with
  the layer identity in the environment (`VARVE_LAYER`,
  `VARVE_LAYER_MANIFEST_DIGEST`) — the dispatch half of the provenance
  contract; exit codes propagate; `--varve` is a one-off that never touches
  the checked-in pin
- Upstream: pulseengine/sigil#221 adds `toolchain` +
  `toolchain_manifest_digest` to wsc-attestation ToolInfo and populates them
  from the varve dispatch environment (implements sigil#217)
- Scope move (logged): REQ-PROV-001 → v0.5.0; its varve half (dispatch env)
  ships here, the attestation half rides sigil#221

## v0.3.0 — 2026-08-07

The offline core (REQ-OFFLINE-001 verified; `rivet release status v0.3.0`:
cuttable).

- `varve archive <layer> <dest>` exports an installed layer as a standard
  directory-shaped OCI image layout (`oci-layout`, `index.json`,
  `blobs/sha256/<hex>`), with the DSSE signature envelope carried as a blob
  and referenced from the index (`…varve.signature.v1+json`, signs-digest
  annotation) — the artifact of record travels with its evidence
- Export refuses a layer whose envelope was not retained: an unsigned
  archive is not an artifact of record
- `varve install --from` auto-detects oci-layout archives; installing from
  an archive runs the same pipeline against the same trust root — the
  archive path cannot relax acceptance (tested), and a reinstalled layer
  re-verifies offline
- Falsification: a layer that cannot be reconstructed and re-verified from
  its archive alone, with no registry and no network, fails these tests

## v0.2.0 — 2026-08-07

Verified install and anti-rollback. `rivet release status v0.2.0`: cuttable
(REQ-VERIFY-001 + REQ-ROLLBACK-001 verified, DD-003 + DD-005 accepted).

- Layer manifests travel as DSSE envelopes signed with the PulseEngine root
  ed25519 key (sigil's `wsc` library); acceptance authenticates payload AND
  payload type. Only the verified payload reaches disk — the envelope is
  retained beside it for offline re-verification
- `LayerSource` trait (DD-003): access is pluggable (`DirSource` archive,
  in-memory double), acceptance is not — the kill-criterion test runs the
  same bytes through two transports and asserts identical verdicts, and a
  tampering source is caught by the signed digests
- Anti-rollback (DD-005): monotonic per-line counters + issued-at inside the
  signed manifest; persisted per-line high-water marks; a lower counter is
  refused at install; corrupt state refuses rather than resets; failed
  installs never advance the mark; staleness surfaced as a warning
- `varve install --from <archive>` (fetch → verify signature → cross-check
  pin → anti-rollback → verify blob digests → lay down → advance mark) and
  `varve verify [--all]` (repeat the install-time verdict offline)
- Trust root via `VARVE_TRUST_ROOT` (hex ed25519 public key); no built-in
  default, no acceptance without it
- Falsification: bytes not signed by the trust root, or a counter below the
  line's high-water mark, CANNOT reach the core through any source
- Friction filed upstream: sigil#218 (dsse dependency weight), sigil#219
  (airgapped keyless verifier is a stub), sigil#220 (crates.io publish stale
  at 0.9.0); scope note: the OCI-registry source lands with deposit (v0.4)

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
