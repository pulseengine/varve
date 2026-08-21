# Pins

A project declares the toolchain it uses in `varve.toml` — the pin. varve walks
up from the working directory to find it, resolves the exact layer it names, and
fails with the corrective `varve install` command if that layer is not installed.
A pin names a `realm`, a `channel` (qualified | rolling), and a `layer`
(`YYYY.MM.P`); optionally a manifest digest for byte-exact freezing. varve never
falls back to another layer or to binaries on PATH — a pin resolves exactly or
the command fails.

Prefer pinning the `digest` as well as the layer name. Beyond byte-exact
freezing, it is what makes resolution constant-time: with a digest varve reads
exactly one manifest, while a name-only pin must read every installed layer's
manifest to find the one you meant. Measured on a release build: digest-pinned
resolve stays at ~37 microseconds whether the core holds 3 layers or 200, while
a name-only pin costs ~74 microseconds at 3 layers and ~2.5 milliseconds at 200.
Layers coexist on purpose, so a long-lived machine drifts into the slow case.

Add it *after* a successful install, from `varve list` — never by hand, and
never copied out of documentation. The example below therefore starts without
one:

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "rolling"             # what the pulseengine realm actually publishes today
layer   = "2026.08.2"
tools   = ["rivet", "synth"]    # optional; a subset, plain or realm-qualified
```

Copy this one as-is; it is installable. Two ways an earlier version of this
example was not, which are the two ways a hand-written pin fails:

**The channel must match what the realm published.** The `pulseengine` realm
signs on `rolling` until the v1.0 root ceremony; a pin saying `qualified` for
the same layer is refused, correctly, at both ends:

```
error: manifest is on channel 'qualified', the pin selects 'rolling' — refusing
error: layer 2026.08.2 is installed on channel 'qualified', but this project's
pin selects 'rolling' — refusing.
```

**Never copy a `digest` from documentation.** A made-up digest of the right
shape does not fail as a typo — it fails as a missing artifact, and if it shares
a plausible prefix with the real one the message reads like tampering:

```
error: source has no layer matching Digest("sha256:83a6991d0…")
error: pin digest sha256:83a6991d0… is not installed — run `varve install` …
```

Install by name first, then paste the digest `varve list` prints for the layer
you actually got.

Full field reference: `varve docs config-reference`.
