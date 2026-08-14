# Changelog

## v0.25.0 — 2026-08-14

The documentation release. Two ten-persona audits reached the same verdict:
varve documented its CONCEPTS and its COMMANDS, and neither its FILES nor its
TASKS — 10 of 10 personas reverse-engineered at least one file format by
feeding bogus input to serde, and several said the parse errors were the best
documentation in the product.

- Six new topics — `getting-started`, `config-reference`, `environment`,
  `own-realm`, `composition`, `threat-model` — each with copy-pasteable
  examples rather than prose, plus `recovery` (repair, deliberate rollback and
  its cost, removal, re-keying, reset). `manifest-version` was required and
  appeared in no topic; `kind = "crate"` — how a crate is deposited — was
  documented nowhere, which made three of four export adapters unexercisable
  outside the project
- `concept-payload-kinds.md` claimed "the kind selects which export adapter
  applies", false in both directions; replaced with a consumer-to-adapter table
- **REQ-LAYOUT-001**: the emitted `index.json` now carries
  `org.opencontainers.image.ref.name`, so `oras cp --from-oci-layout
  ./layout:<layer>` resolves. Purely additive — verified byte-identical blob
  trees and layer digests
- The docs gate now checks what the docs must TEACH: workflow topics must
  exist, act-on topics must carry a **non-empty** fence, every fenced block is
  parsed with the SHIPPING parser, and every `varve <sub>` in a shell block is
  checked against the real subcommand list
- Persona audit: 0 of 9 blocked, from 5/10 two releases ago

Fixed in review, and worth naming: a **fabricated trust root** was shipped in
`getting-started` labelled as the published `rolling.pub`. A user copying it
got "No valid signatures". The earlier elided form had been "fixed" by padding
the placeholder until the parser accepted it — a shape check certifying a false
fact. The published key is now compared against `trust-roots/rolling.pub`.

## v0.14.0 – v0.24.0

Not written up here at the time. Each release's substance is in its git tag,
its release notes, and its rivet requirements (`rivet release status <ver>`);
this file went eleven releases stale before the v0.25.0 review caught it.

## v0.13.1 — 2026-08-08

Cold-start onboarding (REQ-ONBOARD-001) — fixes pulseengine/varve#34,
found by an external consumer cold-starting from the tarball.

- The trust root (`rolling.pub`) and a canonical `varve-realms.toml` now
  ship as **release assets**, and the README has a **Getting started**
  section — a consumer with only the binary can reach a verified install
- The no-trust-root error now names the **zero-config realm path** (the
  stronger mechanism) and where the key is published, instead of steering
  to a bare `VARVE_TRUST_ROOT` with nowhere to get the key
- `varve install` **auto-caches** a line-status carried in the installed
  layout, so `varve status` works with no `--from-file` step; the status
  error describes the real path. Registry-side line-status distribution is
  tracked as REQ-STATUS-DIST-001 (v0.14.0)

## v0.13.0 — 2026-08-08

Adversarial inputs (REQ-FUZZ-001 + REQ-PROP-001 + REQ-MATRIX-001 verified).

- **Fuzzing**: five cargo-fuzz targets on the untrusted-input parsers
  (layer-id grammar, layer-manifest JSON, DSSE envelope, varve.toml,
  varve-realms.toml); PR smoke + nightly campaign (`fuzz.yml`). It earned
  its keep on the first run — found a real canonicalization bug: the
  layer-id grammar accepted leading-zero patches (`2026.07.052` parsed to
  patch 52 but Displayed as `2026.07.52` — two pin strings for one
  identity). Fixed, regression-seeded, re-fuzzed clean past 1.6M runs
- **Property tests**: proptest laws across the whole input space — layer-id
  round-trip, rollback verdict monotonicity (accept iff counter >= mark),
  advance-never-lowers, platform-match totality + wasm universality
- **Matrix**: CI now tests linux AND macos (was ubuntu-only while shipping
  4 platforms), pins an MSRV (1.89) build, and publishes cargo-llvm-cov
  coverage as advisory evidence
- Kani proofs of the same invariants split to REQ-KANI-001 (v1.0, the
  scry advisory→required pattern) — not claimed here

## v0.12.1 — 2026-08-08

Audit hardening. Independent ASPICE/ISO-26262 and cybersecurity audits
(2026-08-08) found honesty, potency, and one fail-open defect; fixed here.

- **F2 fail-open fixed (security)**: a signed manifest with a malformed
  `issued-at` parsed fine and silently disabled the staleness warning
  (voiding SH-002). issued-at is now validated as a real RFC 3339 date at
  parse — malformed is refused; `epoch_days` rejects impossible dates
  (Feb 31 no longer accepted). One shared validator for producer + verdict
- **Potency fixed**: the cargo-mutants trust-critical gate and strict
  policy are now REQUIRED merge checks — REQ-MUTATE-001's "verified" status
  finally matches enforcement (the audit found it bypassable)
- **Honesty fixed**: README no longer says "Nothing is implemented yet"
  (false against 13 releases); claim-check now covers the status banner
- **SECURITY.md** added — disclosure policy + the invariants a report
  should target + the current provisional-trust limitations (the DM
  practice the audit scored near zero, and varve's own criticalup critique)
- **Two unmodeled hazards named**: SH-005 (root-key compromise — single
  online key, no rotation/revocation/threshold) + SH-006 (deposit-pipeline
  compromise), with SC-005/SC-006; both discharged at the v1.0 ceremony
- **Supply-chain**: Cargo.lock now tracked, releases build `--locked`;
  cargo-deny in CI (advisories/licenses/sources); `cross` pinned to a tag;
  ci.yml + release.yml actions SHA-pinned; the rivet cosign identity
  regexp anchored (`^https://…/rivet/`, was matching `rivet-evil`)

## v0.12.0 — 2026-08-08

Close the graph, make claims mechanical (REQ-VGATE-001 + REQ-MUTATE-001
+ REQ-CLAIM-001 verified) — the 2026-08-08 audit's findings, fixed.

- The requirement→test graph is CLOSED: verification artifacts with
  `verifies` links for all 21 requirements, each naming its concrete
  tests; `rivet check verification-evidence` (76 named steps, all
  audited against sources) gates CI so renamed/deleted tests go red
- Mutation testing is a GATE: cargo-mutants per-PR over the six
  trust-critical modules (rollback, layer, platform, verify, pin,
  realm) with zero survivors required, nightly full-workspace advisory
  (org template). The first run proved the audit right: 33 surviving
  mutants found and killed — including the entire civil-date
  arithmetic of the staleness check and wrong-length-but-pure-hex
  key/digest acceptance in pin and realm parsing
- Claim-check: claims.yaml binds seven load-bearing doc claims to
  named tests/files/workflow steps; tools/claim-check.py gates CI
- Rivet debt paid: eight missing design decisions (DD-010..017)
  authored with their real rationale, schema-enum and id fixes —
  `rivet validate` reached zero warnings for the first time
- varve#7 fixed: pin errors no longer print their cause twice

## v0.11.0 — 2026-08-08

Portable wasm entries + layer runners (REQ-RUNNER-001 verified).

- Entries whose platform is a wasm32 target are PORTABLE — they ride to
  every host with zero per-platform gaps
- A wasm entry may carry, inside the signed payload, a runner contract:
  `[tool.runner]` in the deposit spec — the layer tool that executes it,
  prefix args, and an optional per-user-argument flag (kilnd's
  --wasi-arg shape). `varve run` and the shims dispatch through the
  runner FROM THE SAME VERIFIED LAYER, never from PATH; a missing
  runner fails closed (mutation-checked e2e)
- First real payload: scry via kilnd, pending the meld↔kilnd
  entry-point contract (kiln#480; scry#118 asks for a pre-fused core
  artifact) — a one-line roster addition once resolved

## v0.10.0 — 2026-08-08

Realms (REQ-REALM-001 verified): the pin names its trust universe;
parallel toolchain universes coexist without cross-talk.

- `realm = "name"` in varve.toml + a committed `varve-realms.toml`
  (walk-up discovered, so trust travels with the code) defining each
  realm's registry and trust root (inline hex or a relative key file)
- A named realm is AUTHORITATIVE: its trust root applies (the ambient
  environment cannot substitute one) and `varve install` defaults to
  its registry — a realm project needs no --from and no env vars
- All per-realm state (core, high-water marks, status cache) lives
  under `$VARVE_ROOT/realms/<trust-root-fingerprint>/`: two realms
  with identical layer names and counters are isolated by construction,
  and cross-acceptance is cryptographically impossible (tested: one
  shim, two projects, two universes; acme's layer refuses to install
  into a pulseengine project)
- Realmless pins keep the existing layout and env-based trust root

## v0.9.0 — 2026-08-07

Bazel interop groundwork (REQ-BAZEL-001 verified): Bazel uses varve,
never reimplements it.

- Deposits record source provenance INSIDE the signed payload — upstream
  repo, release, asset name, and the sha256 of the asset AS DOWNLOADED
  (the bytes Bazel hashes) — via `[[tool]] [tool.source]` in the new
  deposit spec file (`varve deposit --spec deposit.toml`)
- `varve export-bazel --layer <id> --out <dir>`: compiles
  rules_wasm_component-shaped checksum registries from a verified
  installed layer (trust root required, re-verified before export;
  platform keys mapped to the rules vocabulary; tools without
  provenance skipped loudly). Every hash Bazel enforces becomes a
  transcription from the signed, counter-protected manifest instead of
  trust-on-first-use — the fallback path for consumers without varve;
  the primary integration (a varve module extension so one pin governs
  terminal AND Bazel) lands in rules_wasm_component

## v0.8.0 — 2026-08-07

Updating the updater (REQ-UPDATE-001 verified): explicit, verified,
fail-closed — never automatic, never phoning home.

- `varve self-update [--check] [--to PATH]`: check the latest release,
  download the host platform's archive + its varve-native signed sums,
  verify with the RUNNING binary against the pinned trust root
  (old-verifies-new, the TUF-rotation shape), replace atomically,
  report old → new. Unsigned releases, impostor signatures, and
  unparseable versions all refuse; a refused update leaves the current
  binary untouched (tested, mutation-checked)
- No passive network calls: varve makes no request the user did not
  explicitly command; `--check` is the staleness answer
- Release sums are now signed with the PROVISIONAL rolling root
  (labeled in the workflow) until the ceremony provisions the
  qualified root; the ceremony release will be dual-signed so the
  old-verifies-new chain migrates without a flag day
- `VARVE_UPDATE_API` overrides the release endpoint (mirrors,
  air-gapped relays) — availability only, never acceptance

## v0.7.0 — 2026-08-07

Environment integration (REQ-ENV-001 verified): varve sets up its own
environment; users source it, never hand-edit PATH.

- `varve env [--shell sh|fish]`: idempotent shell code putting the shim
  directory on PATH — `eval "$(varve env)"`; double evaluation cannot
  stack duplicate entries (tested)
- `varve shim install` now writes a sourceable `$VARVE_ROOT/env`
  (rustup-style) and prints the one-liner instead of a hand-edit
  instruction
- `varve completions <shell>`: zsh/bash/fish (and friends) completion
  scripts via clap_complete

## v0.6.1 — 2026-08-07

Patch: registry pulls of real-sized tool binaries.

- The transport read limit rejected blobs over 10 MiB (ureq default) —
  caught on the first real GHCR pull of layer 2026.08.0, whose tools are
  tens of MB. Raised to an 8 GiB sanity bound; the signed digests remain
  the actual acceptance criterion. Regression-tested with a 12 MB blob
  through the in-process registry double

## v0.6.0 — 2026-08-07

The adoption arc: shims, the platform dimension, and the public registry
(REQ-SHIM-001 + REQ-PLATFORM-001 + REQ-REGISTRY-001 verified).

- `varve shim install`: thin dispatchers in `$VARVE_ROOT/shims` that
  re-resolve the pin from the invocation's working directory and exec with
  the provenance environment — switching toolchains is `cd`, proven by a
  test running the same shim from two projects pinning different layers;
  a pinless directory fails closed
- Platform dimension: deposit stamps a target triple per entry
  (`NAME@VERSION@PLATFORM=PATH`); install and verify select host-matching
  entries only (foreign blobs are never even fetched); a fully-stamped
  layer with nothing for the host fails closed; unstamped entries remain
  platform-independent, so existing layers keep working
- Registry source: anonymous OCI-distribution pull (`install --from
  oci://ghcr.io/...`) — token dance, artifact manifest by tag, blobs by
  digest with transport-level digest fail-fast. Tags are discovery only;
  the kill-criterion now spans registry, archive, and directory transports
  (identical accept AND reject verdicts, tested against an in-process
  registry double over real TCP). Publishing stays CI-side with standard
  tooling, outside the client trust path

## v0.5.0 — 2026-08-07

Known-problems evidence, self-verification, and the closed provenance
contract (REQ-KP-001 + REQ-SELF-001 + REQ-PROV-001 verified, DD-008 +
DD-009 accepted — the full v0.1..v0.5 plan is now delivered).

- Provenance closed end-to-end: sigil#221 merged and released as wsc 0.10.0;
  wsc-attestation ToolInfo now carries `toolchain` +
  `toolchain_manifest_digest`, populated from the environment `varve run`
  exports. An integration test pins both halves to the same contract
  (mutation-checked: renaming a variable on either side goes red)
- varve-core's wsc dependency bumped 0.9.0 → 0.10.0

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
