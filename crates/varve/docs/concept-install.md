# Bootstrap — getting varve itself, verified

varve verifies everything it hands you. Nothing hands varve to you. This page is
that first hop: the routes to a varve binary, what each one proves, and what it
does not.

All of them install **one** binary. Every update after it is `varve self-update`,
which downloads the successor, verifies it with the **running** binary against
the pinned trust root (old-verifies-new), and replaces atomically. Nothing on
this page reimplements that, and nothing here ever runs in the background.

## Supported targets

Release binaries exist for exactly four triples:

    aarch64-apple-darwin        x86_64-apple-darwin
    aarch64-unknown-linux-gnu   x86_64-unknown-linux-gnu

`install.sh` maps `uname -s` / `uname -m` onto these and **stops** on anything
else rather than guessing. Elsewhere, build from source (route 4).

## 1. Verify the script, then run it

`install.sh` ships as a release asset, so its own sha256 is a line in that
release's `SHA256SUMS.txt` — and cosign signs `SHA256SUMS.txt`. That is the
whole point: the script can be checked *before* a shell reads it.

```sh
B="https://github.com/pulseengine/varve/releases/latest/download"
curl -fsSLO "$B/install.sh"
curl -fsSLO "$B/SHA256SUMS.txt"
curl -fsSLO "$B/SHA256SUMS.txt.cosign.bundle"

# Who wrote the sums file (skip only if you have no cosign):
cosign verify-blob \
  --bundle SHA256SUMS.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/pulseengine/varve/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt

# Is this script one of the bytes it covers? (macOS: shasum -a 256 -c …)
sha256sum -c --ignore-missing SHA256SUMS.txt

sh install.sh            # or: sh install.sh --version v0.26.0
```

`--ignore-missing` is what lets you check one asset against a sums file that
lists all of them. A tampered file prints `FAILED` and exits non-zero; do not
run it.

## 2. The one-liner (convenience, not the same thing)

```sh
curl -fsSL https://github.com/pulseengine/varve/releases/latest/download/install.sh | sh
```

This is faster and it is **weaker**: the bytes reach `sh` before anything checks
them, so you are trusting the transport and GitHub, not a signature. varve's
entire argument is that strings should not reach interpreters unverified, so
this form is offered second and named for what it is. Use route 1 on anything
you would not re-image.

What the script does either way: refuse to run as root unless
`VARVE_ALLOW_ROOT=1`; detect the target or stop; download the archive **and**
`SHA256SUMS.txt`; compare the archive's sha256 against that file **before**
extracting anything; refuse outright if no `sha256sum`/`shasum` exists rather
than proceed unverified; verify `SHA256SUMS.txt` with cosign when cosign is
installed, and say plainly that it did not when it is not; install to
`${VARVE_INSTALL_DIR:-$HOME/.varve/bin}`.

## 3. No script at all

Twelve lines, nothing hidden. This is the route to read if you are deciding
whether to trust the script.

```sh
V=v0.25.0                       # any released tag
T=aarch64-apple-darwin          # one of the four above
B="https://github.com/pulseengine/varve/releases/download/$V"
curl -fsSLO "$B/varve-$V-$T.tar.gz"
curl -fsSLO "$B/SHA256SUMS.txt"
curl -fsSLO "$B/SHA256SUMS.txt.cosign.bundle"
curl -fsSLO "$B/rolling.pub"
curl -fsSLO "$B/SHA256SUMS.txt.dsse.json"

cosign verify-blob \
  --bundle SHA256SUMS.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/pulseengine/varve/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt

sha256sum -c --ignore-missing SHA256SUMS.txt     # macOS: shasum -a 256 -c …
tar -xzf "varve-$V-$T.tar.gz"
mkdir -p "$HOME/.varve/bin"
install -m 0755 ./varve "$HOME/.varve/bin/"
export PATH="$HOME/.varve/bin:$PATH"
```

Then have varve check the same release the way it checks a layer — DSSE
envelope, pinned root, no cosign and no network:

```sh
VARVE_TRUST_ROOT=./rolling.pub \
  varve self-verify --archive "varve-$V-$T.tar.gz" --envelope SHA256SUMS.txt.dsse.json
```

which prints, on success:

```
varve-v0.25.0-aarch64-apple-darwin.tar.gz verified against the signed release
sums (sha256:5adfbf4140a602f3ff3721745c0a71328b390481e2facb661b6907e4892dc74e)
```

`rolling.pub` is the **provisional rolling root** (the root ceremony is the v1.0
gate — see `varve docs threat-model`). Verify it out of band: it is committed at
`trust-roots/rolling.pub` in the repo and shipped as a release asset, and both
are covered by the cosign signature over `SHA256SUMS.txt`.

## 4. From source

```sh
cargo install varve
```

crates.io is the third route on purpose. It gets you a binary on any target Rust
supports, including the ones with no release archive — but it is a **source**
build, so nothing about it is covered by the release signature or the DSSE
envelope. crates.io publishes no signatures today (`varve docs threat-model`).
Use it when the four triples do not include you, or when your organisation
already vendors crates; use route 1 or 3 when the signature is the point.

`varve-core` is the library half if you are embedding resolution and
verification rather than running the CLI.

## After the first hop

```sh
varve self-update --check     # is there a newer release? nothing changes
varve self-update             # verify with the running binary, then replace
varve docs getting-started    # pin a layer and dispatch its tools
```

## What the first hop cannot prove

The first install is **trust on first use**, and no route on this page removes
that. cosign tells you the sums file came from this repository's release
workflow; it does not tell you the repository was not compromised. What the
first hop buys is that every install *after* it is anchored: `self-update`
verifies the successor against a root the running binary already holds, so an
attacker has to win the very first fetch, not any later one.

That is also why the script refuses rather than degrades. No sha256 tool means
no install, not a warning — an unverified install of a verification tool is
worse than no install at all.
