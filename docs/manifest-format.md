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
channel = "qualified"     # "qualified" | "rolling"
layer   = "2026.07"       # the dated layer this project is frozen on

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
    "eu.pulseengine.varve.layer":   "2026.07",
    "eu.pulseengine.varve.channel": "qualified",
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

## Open

1. **Anti-rollback.** `digest` pinning defends a project that uses it. It does not
   stop a *fresh* consumer being handed a stale-but-valid layer. Needs a
   snapshot/timestamp role over our own stream, or an equivalent.
2. **Patch releases inside a frozen line.** `2026.07.1` must be expressible with a
   qualification delta scoped to the change. This decides whether `layer` is a
   two- or three-part identifier — settle it before the first qualified deposit.
