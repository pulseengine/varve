# What verification does and does not prove

Shipped inside the binary deliberately: the reviewer who most needs this is often the one who cannot reach a website.

## What `varve verify` proves

- The retained DSSE envelope verifies against the **pinned** trust root — offline, with no transparency log and no network.
- The signed payload is byte-identical to the stored `layer.json`.
- Every tool the signed manifest names **for this platform** is present and hashes to its
  signed digest. Entries annotated for another platform are skipped, so on a multi-platform
  layer `verify` exits 0 having checked only your own.
- Under composition, each included layer verifies against **its own** realm's root, recursively.

## What it does not prove

- **It does not seal the directory, and unnamed files ARE dispatched.** A file
  planted in an installed layer's `bin/` that the manifest does not name is not
  detected, and it is not inert. Dispatch enumerates the **directory**, not the
  manifest. Observed end to end:

  ```
  $ cp evil $VARVE_ROOT/core/sha256-…/bin/planted && chmod +x …/bin/planted
  $ varve verify
  layer 2026.09.0 sha256:… verified: signature OK, 2 tool(s) match their signed digests   # exit 0
  $ varve which planted
  …/core/sha256-…/bin/planted
  layer 2026.09.0 (qualified) sha256:…                                                    # exit 0 — varve VOUCHES for it
  $ varve run -- planted
  I-AM-PLANTED-AND-UNSIGNED                                                               # exit 0
  $ varve shim install
  installed 3 shim(s) …                                                                   # 3, for a 2-entry manifest
  $ planted                     # via the shim dir on PATH
  I-AM-PLANTED-AND-UNSIGNED
  ```

  So write access to the core is enough to get an unsigned binary dispatched by
  name, shimmed onto every shell's `PATH`, and attributed to a signed layer by
  `varve which` — with `verify` reporting OK throughout. **The signature covers
  the bytes varve was told about, not the directory they live in.** Treat write
  access to `$VARVE_ROOT` as equivalent to code execution, and keep the core on
  a filesystem where only the installing identity can write.
- **`which`, `run` and the shims do not re-verify.** They resolve the pin and exec. Verification is a thing you run, not a thing that happens on every dispatch — the cost would be paid on every compiler invocation.
- **Yank and support window are not part of the verdict.** A yanked layer verifies fine; `varve status` is where withdrawal lives, and it exits 0 today even when it prints YANKED.
- **Anti-rollback is enforced at install *and* at verify** (varve#76: `verify`
  used to pass a pin edited back to an already-installed older layer, exit 0,
  while the docs told you to run it as the CI gate). It rests on local state
  that is not itself signed — under `$VARVE_ROOT/realms/<fingerprint>/state/`
  when the pin names a realm, `$VARVE_ROOT/state/` when it does not. An attacker
  with write access to your store can reset the high-water mark.
- **The first realms file is unverified by construction.** It is the root of the chain; you must obtain it through a channel you already trust.

## What varve does not have yet

- No key rotation, no key roles or thresholds, no revocation channel. One root per realm.
- No transparency log and no inclusion proofs, so the counter stops rollback but **not signer equivocation** — a compromised signer serving different bytes to different consumers is not detected.
- No reproducibility claim. varve signs what its build produced; it does not prove the build was deterministic.

These are honest gaps, not oversights, and several are the substance of the v1.0 trust-root ceremony. Pin varve's root knowing them.
