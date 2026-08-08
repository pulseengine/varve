# Manifest formats

`varve` has **two** manifests, and keeping them distinct is the whole design.

| | written by | lives in | answers |
|---|---|---|---|
| **the pin** | a human | the consuming repo, checked in | *which layer does this project use?* |
| **the layer manifest** | CI, at deposit | the registry, signed | *what exactly is that layer?* |

The pin is a preference expressed once and reviewed like code. The layer manifest
is evidence, immutable and signed. Conflating them is how toolchains drift.

---

## 1. The pin — `varve.toml`

Checked into the consuming repo, next to `rust-toolchain.toml`. Discovered by
walking up from the working directory.

```toml
manifest-version = 1

[toolchain]
# Optional: name this project's trust universe. A committed varve-realms.toml
# (same walk-up discovery) maps the name to (registry, trust root); the realm
# is then authoritative — per-realm state is namespaced by the trust root's
# fingerprint, so parallel universes cannot cross-talk (REQ-REALM-001).
realm   = "pulseengine"
channel = "qualified"     # "qualified" | "rolling"
layer   = "2026.07.0"     # the dated layer this project is frozen on — always
                          # three-part: YYYY.MM.P, where .0 is the initial
                          # deposit of a line and .1+ are in-line patches (DD-004)

# Optional: pin the exact manifest digest as well as the name. Recommended for a
# qualified line — the name is a label, the digest is the artifact.
digest  = "sha256:…"

# Optional: restrict to a subset. Default is every tool in the layer.
tools   = ["rivet", "synth", "meld", "witness"]
```

**Rules**

- A missing or unresolvable pin is an **error**. `varve` never falls back to
  whatever is on `PATH`.
- `channel = "qualified"` selects a line with a stated support window and
  qualification evidence attached. `rolling` has neither and may move.
- If `digest` is present it wins; a name that resolves to a different digest is a
  hard failure, not a warning. That is the anti-rollback lever available today.

## 2. The layer manifest — an OCI image index

Produced by `varve deposit`, pushed to the registry, signed by `sigil` **by digest**.
Not hand-edited, ever.

```jsonc
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "artifactType": "application/vnd.pulseengine.varve.layer.v1+json",
  "annotations": {
    "eu.pulseengine.varve.layer":   "2026.07.0",
    "eu.pulseengine.varve.line":    "2026.07",
    "eu.pulseengine.varve.channel": "qualified",
    // Anti-rollback (DD-005): monotonic per-line release counter. The client
    // persists a high-water mark per line and rejects any layer below it.
    // Lives here — inside the signed payload — never in mutable tag state.
    "eu.pulseengine.varve.counter": "1",
    // Staleness (DD-005): signed issued-at; drives a configurable-age warning.
    "org.opencontainers.image.created": "2026-07-31T09:14:00Z"
  },
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:…",
      "size": 1234,
      "platform": { "os": "linux", "architecture": "amd64" },
      "annotations": {
        "eu.pulseengine.tool":         "synth",
        "eu.pulseengine.tool.version": "0.45.0"
      }
    }
    // … one per (tool × platform)
  ]
}
```

**Why an OCI index rather than a bespoke format**

- content-addressed digests — pinning is native
- one index → N artifacts is exactly the bundle shape
- per-platform selection is the index's own mechanism, so no `${host}` substitution
  language to invent
- attestations, SBOMs and qualification evidence attach as **referrers** (OCI 1.1)
- registry authentication becomes the access-control seam, with no server to write
- `oci-layout` export gives the offline core for free

## 3. Referrers — the evidence

Attached to the layer manifest rather than embedded in it, so evidence can be added
after the fact without changing the layer's digest:

| artifactType | contents |
|---|---|
| `…varve.attestation.v1+json` | build provenance for the layer |
| `…varve.sbom.v1+json` | SBOM across every tool in the layer |
| `…varve.qualification.v1+json` | qualification report + **scope statement**: what was qualified, for which use, under which standard |
| `…varve.qualification-delta.v1+json` | on a patch layer (`2026.07.1`): the change-impact analysis against its baseline — what changed, which qualification claims are affected, the verification evidence (the DO-330 mechanism; DD-004) |
| `…varve.known-problems.v1+json` | signed known-problems entries: description, scope, workaround, detection, mitigation, affected releases — plus support-window and yank markers (REQ-KP-001, v0.5) |

A layer is *qualified* precisely when a qualification referrer is present and
verifies. Absent that, it is a dated layer and nothing more.

## 4. The core — on disk

```
~/.varve/
  core/
    sha256-a1b2…/        # layer 2026.07, keyed by manifest digest
      bin/{rivet,synth,meld,…}
      layer.json         # the verified manifest, kept for `verify` and `archive`
    sha256-c3d4…/        # layer 2026.08
  shims/                 # on PATH: rivet, synth, meld, …
```

Keyed by manifest digest, so layers coexist by construction, switching is free, and
`varve list` can report which projects pin what. `varve archive` writes a
directory-shaped `oci-layout` tarball — the artifact of record, installable with no
registry and no network.

## Decided (2026-08-07)

Both former open questions are settled; the full evidence trail lives in the
rivet artifacts (DD-004, DD-005, and the CA-*/AR-* research artifacts).

1. **Anti-rollback → monotonic per-line counters (DD-005).** Every layer manifest
   carries a release counter and issued-at *inside the signed payload*; the client
   keeps a high-water mark per line and hard-rejects anything below it, and warns
   past a staleness threshold. The SUIT (RFC 9019) / Uptane pattern — built for
   offline verifiers on static hosting, survives registry compromise, no metadata
   re-signing treadmill. tuf-on-ci is the recorded upgrade path if a connected
   freshness channel is ever needed.
2. **Patch releases → three-part identifiers (DD-004).** `layer` is always
   `YYYY.MM.P`; `2026.07.0` is the initial deposit of the July line, `2026.07.1` a
   patch inside it, carrying a qualification-delta referrer scoped to what
   changed. The frozen-line model every qualified-tool vendor converges on
   (Ferrocene `YY.MM.P`, AdaCore sustained branches, IAR service packs), made
   mechanical.
