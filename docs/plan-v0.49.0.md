# varve v0.49.0 plan: what moves the North Star

Status: **planning draft, work in progress**. Nothing here is shipped or claimed. Scope decisions are the maintainer's; this records a proposal for his decision window.

Method: a planner proposed bets against pulseengine.eu's `data/north-star.toml`. A second reviewer, given only that file and the draft, checked each bet: does it move an indicator as the file defines it, can its acceptance fail, is anything overclaimed. This version applies its required changes.

## Baseline

The indicator values, read on 2026-11-19, not typed:

| | Indicator (north-star.toml) | Value |
|---|---|---|
| O2 | consumer repositories whose latest release carries the full bundle and passes the verify command | **1 of 2** (`data/north-star/O2.json`, measured 2026-11-17: wohl v0.7.0 counts; relay has no bundle). Blind spot recorded there: the outer cosign/SLSA chain is not checked. |
| O5 | our tools and CI gates that run as signed WASI components under kiln, with wasmtime as the differential | **unmeasured**: no indicator script exists, and no denominator list is agreed. |

The 2026-Q4 O2 commitment (one wohl release with the full bundle passing one verify command) is met by wohl v0.7.0 on that file. Nothing below delays it.

## Already decided for v0.49.0

These ship regardless of the bets:
- #374: component-prefixed release tags. This goes first, and it unblocks temper-triage.
- #256: per-project anti-rollback marks.
- #378: MIXED reporting.
- #379: macOS ACLs on the `--with` TMPDIR.
- #380: `main.rs` wiring under the mutation gate.
- #381: yanked override layer not reported.

Also open: #382 (the ETXTBSY test flake class) and #384 (leaked test temp dirs).

## Bet A: the toolchain capsule (enables O2; moves no count in v0.49.0)

**What ships.** `varve archive` gains a capsule mode. One file, for one pin on one platform, carries:
- every composed layer, not only the root;
- the signed line index and the baseline line-status;
- carried attestations;
- the realm trust root;
- every override layer of a MIXED project.

A second command takes only the capsule, a layer attestation from an evidence bundle, and the realm root fingerprint. It rebuilds that toolchain in an empty store with no network and no credential, then re-checks it. The re-check prints one verdict naming the layer, the digest, every override and every yank. What it covers: **the pinned tools, single platform, compiler excluded.**

**Why.** O2's bundle carries a sigil attestation naming a layer. Today an assessor cannot rebuild that layer offline from one artifact (cmd-archive.md: an archive is single-platform, and the line index and composed layers do not cross). Whether the capsule becomes part of "the full bundle" is the North Star owner's call. If it does, north-star.toml changes first and the capsule joins after the Q4 commitment.

**Acceptance** (a script in a network-less container, empty store, no credentials):
1. reconstruct, then `varve verify`, then `varve check-attestation`: all exit 0;
2. the verdict names the layer, digest, overrides and yanks;
3. a layer one counter behind the newest reconstructs on a machine that has seen the newer one;
4. afterwards, a *normal* install of that superseded layer is still refused: assessor mode does not leak;
5. four negative controls exit non-zero, each with a named cause: drop one composed layer, drop the line index, flip one payload byte, present a pure-pin attestation for a MIXED project.

**Kill criteria.**
- Reconstruction of a covalent pin needs any network call: the claim is false.
- First contact cannot be made sound offline. REQ-SEED-001 keeps first contact on the realm's primary; an assessor's empty store is exactly first contact.
- A covalent capsule for one platform exceeds **2 GiB**.

**Precondition, with owner.** A durable home for capsules, per deposit. The layer repos own it. REQ-ARCHIVE-002 is backlog, and CI artifacts last 90 days today.

**Depends on:** #256 (or an explicit, recorded assessor mode), #378, #381; the layer repos for the durable home; pulseengine.eu if the capsule joins the bundle. **Size:** L.

## Bet B: embedded-signature ingestion and runnable components (precondition for O5; adds nothing to the numerator)

**What ships.** A producer rung that verifies a wasm component's embedded wsc signature at ingestion, against a publisher key committed in the operator's producer input. Its custody rule is that of `pgp-key-file`: never fetched, never read from beside the artifact, no fallback on failure. The rung and signer are signed into the layer. `varve verify` re-checks the signature offline. A component with a runner contract runs through the layer's own kiln.

**Spike first, before this bet is adopted.** One day, three probes. Each can kill a bet:
1. **wsc key-based embedded verify.** Probed 2026-11-19 by reading wsc 0.11.0 source: `lib.rs` says "`PublicKey::verify()` is what most runtimes should use", but no such key-based module verify was found outside the keyless (Fulcio/Rekor) path; `airgapped::bundle` has key-based `verify(data, public_key)`. **Open question for sigil:** is there, or will there be, a stable key-based verify of an embedded module signature?
2. **kiln** runs a wasip2 CLI component that reads a preopened directory and writes stdout (kiln#480 was the recorded blocker; state unconfirmed).
3. **sieve or plant** builds for `wasm32-wasip2` without a feature cut.

**Acceptance.**
1. A deposit of a signed component exits 0, and `varve inspect --json` shows the rung and signer.
2. Three negative controls abort the deposit with no fallback rung: strip the signature section, sign with another key, alter one code byte after signing.
3. After install, a real invocation runs under the layer's kiln with no kiln on PATH: it reads a preopened directory and writes stdout.
4. `varve verify` goes red when the installed component is tampered with.
5. The tool and the published layer are named.

**Kill criteria.**
- Probe 1 or 2 fails.
- The rung cannot also satisfy REQ-INGEST-001's release binding (decide this at design time; it is not an observation).

**Accepted debt, stated.** No rotation or revocation for the publisher key. It is the same gap DD-034 records for PGP.

**Depends on:** sigil/wsc (the API and a crates.io release), kiln (a release that runs wasip2 CLI components), loom and meld (signed component in release CI, from the tag), pulseengine-layers (entry and committed key). **Size:** M to L.

## Bet C: the first gate on our own chain (targets the O5 guard)

**What ships.**
- One existing CI gate, sieve or plant, runs in varve's CI as a wasip2 component through `varve run` under kiln, carried on bet B's rung.
- A required equivalence job runs the same inputs under wasmtime (the differential) and fails on any difference.
- A layer JSON listing lets an indicator script count components.

**Preconditions, with owners:**
- pulseengine.eu: the O5 indicator script and an agreed, committed denominator list ("all our tools and gates").
- The candidate is an existing gate with an old version to compare against.
- Probe 3 passes.

Without these, the honest outcome is "one gate meets the O5 guard; O5 stays unmeasured".

**Acceptance.**
1. A required check named for the gate; its log shows kiln resolved from the layer.
2. The equivalence job is a required check, green on main.
3. A divergence planted on one runner's side only (a patched component or an injected output difference) turns it red.
4. Removing the component from the layer makes the gate fail closed, not skip.
5. The component was built, optimised and signed by our chain, and its attestation says so.

**Kill criteria.**
- The candidate needs what wasip2 lacks, or only builds behind a GAP-like feature cut: it counts as not running.
- kiln and wasmtime differ on valid input with no resolution in the release.
- The component gate is more than 3 times slower than native and is made non-required.

**Depends on:** bet B, #374, kiln, wasmtime in wasm-layers, pulseengine.eu. **Size:** M, after B.

## Not in v0.49.0

- **The compiler in the layer** (REQ-TOOLCHAIN-001, varve#106). It moves no indicator, and its first stage would be report-only. It returns with a falsifiable reproducibility check (a required job whose only pass is "same sha256").
- **REQ-EVIDENCE-001** (an evidence payload kind) follows bet A.

## Order

1. #374.
2. The spike (half a day to a day).
3. Bet A.
4. Bet B, if the spike passes.
5. Bet C, only if B landed and its preconditions have owners.

Realistically: bet A complete; B conditional on the spike; C only with sigil, kiln, the wasip2 build and the O5 script confirmed.
