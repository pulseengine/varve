# What verification does and does not prove

Shipped inside the binary deliberately: the reviewer who most needs this is often the one who cannot reach a website.

## What `varve verify` proves

- The retained DSSE envelope verifies against the **pinned** trust root — offline, with no transparency log and no network.
- The signed payload is byte-identical to the stored `layer.json`.
- Every tool the signed manifest names is present and hashes to its signed digest.
- Under composition, each included layer verifies against **its own** realm's root, recursively.

## What it does not prove

- **It does not seal the directory.** Files planted in an installed layer that the manifest does not name are not detected. They will not be dispatched by name from the manifest, but they are present.
- **`which`, `run` and the shims do not re-verify.** They resolve the pin and exec. Verification is a thing you run, not a thing that happens on every dispatch — the cost would be paid on every compiler invocation.
- **Yank and support window are not part of the verdict.** A yanked layer verifies fine; `varve status` is where withdrawal lives, and it exits 0 today even when it prints YANKED.
- **Anti-rollback is enforced at install**, against local state under `$VARVE_ROOT/state/` that is not itself signed. An attacker with write access to your store can reset the high-water mark.
- **The first realms file is unverified by construction.** It is the root of the chain; you must obtain it through a channel you already trust.

## What varve does not have yet

- No key rotation, no key roles or thresholds, no revocation channel. One root per realm.
- No transparency log and no inclusion proofs, so the counter stops rollback but **not signer equivocation** — a compromised signer serving different bytes to different consumers is not detected.
- No reproducibility claim. varve signs what its build produced; it does not prove the build was deterministic.

These are honest gaps, not oversights, and several are the substance of the v1.0 trust-root ceremony. Pin varve's root knowing them.
