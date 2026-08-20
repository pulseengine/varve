# CI — the producer pipeline, in order

Seven subcommands are tagged "(CI)". Each is documented alone; this topic is
the one that composes them, because the ordering constraints are load-bearing
and were previously discovered only by experiment. The short form:

1. `deposit` **first** — it creates the layout everything else attaches to.
2. `sign-status` → `attach-status` — the baseline advisory.
3. `sign-index` → `attach-index` — only if the realm declares `signed-index`.
4. `sign-attestation --attach-to` — needs the layer **installed** first.
5. Push (`varve docs deploy`) or `archive`.
6. **Never re-run `deposit` into the same `--out` after attaching anything.**

`sign-sums` is a separate track: it signs a release's `SHA256SUMS.txt` for
`self-verify`, and touches no layout.

## The whole pipeline as one transcript

```sh
set -e
ISSUED=2026-09-01T00:00:00Z

# 1. deposit — a FRESH directory every build, never a reused one
varve deposit --spec deposit.toml --issued-at "$ISSUED" \
              --key "$KEYFILE" --out ./layout

# 2. baseline advisory: sign, then attach to the layout
varve sign-status --file status.json --key "$KEYFILE" --out status.dsse.json
varve attach-status --layout ./layout --status status.dsse.json

# 3. the realm's line index (only where the realm declares signed-index)
varve sign-index --file index.json --key "$KEYFILE" --out index.dsse.json
varve attach-index --layout ./layout --index index.dsse.json

# 4. attestations need the layer INSTALLED and a trust root in scope:
#    install what you just deposited, from a project directory pinning it
( cd consumer-pin && varve install --from ../layout )
( cd consumer-pin && varve sign-attestation --kind sbom --file ../sbom.json \
      --key "$KEYFILE" --out ../sbom-statement.dsse.json --attach-to ../layout )

# 5. the gate the pipeline ends on
( cd consumer-pin && varve verify )
```

Step 4's install is not busywork: it is the same consumer-side acceptance
your users run, so a layer that cannot install never leaves CI.

## Why the order is this way

**deposit first, exactly once per directory.** `deposit` writes the whole
layout, including `index.json`, so running it again into the same `--out`
would drop every referrer attached since: the baseline line-status, the
line-index, attestations. Since v0.28.0 varve REFUSES that (exit 1), names
what it found and the re-attach sequence, and leaves the layout
byte-identical; `--force` overwrites deliberately. Before v0.28.0 it
succeeded silently, the layer manifest digest was unchanged, and nothing
looked wrong until a consumer's `varve status` came up empty. Deposit into a
fresh directory anyway; treat the layout as append-only from then on.

**sign before attach.** `attach-status` and `attach-index` take the signed
DSSE envelope, not the raw JSON. Handing them the unsigned document is
refused with the fix named (`sign it first`). The attach commands also refuse
a counter regression, a document for a different line than the layout's, and
— for status — a yank or `affected` id that is not a layer of the line (an
advisory that would never fire).

**`sign-attestation --attach-to` has two prerequisites** the other producer
commands do not: the layer it binds to must be INSTALLED (it verifies the
layer before asserting an association with it), and a trust root must be in
scope — a realm-pinned project directory, or `VARVE_TRUST_ROOT`. Run from a
bare CI workspace it fails with `no trust root configured`; the fix is the
`cd consumer-pin` in the transcript.

**Attach before push and before archive.** The documented push reads the
status referrer out of the layout, and `archive` carries forward what the
installed layer had. One exception to "attach travels": the line-index does
NOT survive `archive` — re-attach it on the far side (`varve docs
attach-index`, Limits).

## Getting the key into CI

`--key <FILE>` is the only key input — there is no environment variable and
no keychain integration. Every adopter therefore invents
`echo "$SECRET" > key.tmp`, which leaves the realm's one secret on disk in
the workspace. Two forms that avoid the file entirely work today:

```sh
# a pipe: /dev/stdin is a readable file
printf '%s' "$VARVE_SIGNING_KEY" | \
  varve sign-status --file status.json --key /dev/stdin --out status.dsse.json

# process substitution (bash/zsh): one key, several commands
varve deposit --spec deposit.toml --issued-at "$ISSUED" \
              --key <(printf '%s' "$VARVE_SIGNING_KEY") --out ./layout
```

If a file is unavoidable, make it short-lived and owner-only:

```sh
KEYFILE=$(mktemp) && chmod 600 "$KEYFILE" && trap 'rm -f "$KEYFILE"' EXIT
printf '%s' "$VARVE_SIGNING_KEY" > "$KEYFILE"
```

Know what you are carrying: this key is the realm's trust root. There is no
rotation and no revocation below replacing the realm file in every consumer's
hands (`varve docs threat-model`, "No key rotation"), so treat the CI secret
store holding it as part of the root ceremony, not as ordinary plumbing. The
signing key never needs to exist anywhere but the secret store and the
signing step's file descriptor.

## What each (CI) command needs

| command | needs the layout | needs the layer installed | needs a trust root | needs the key |
|---|---|---|---|---|
| `deposit` | creates it | no | no | yes |
| `sign-status` | no | no | no | yes |
| `attach-status` | yes | no | no | no |
| `sign-index` | no | no | no | yes |
| `attach-index` | yes | no | no | no |
| `sign-attestation --attach-to` | yes | **yes** | **yes** | yes |
| `sign-sums` | no | no | no | yes |

## The consumer gate

Everything above is the PRODUCER half — you have a key and you publish a
layer. The other half is the job every project that *consumes* a layer
should run, and until v0.28.0 this chapter did not show it while three
other topics told you to write it (`docs verify`: "run it in CI";
`verify --export --help`: "run it in CI").

```sh
varve install                       # resolves the pin, fails closed
varve verify --all                  # every layer in the store, every realm
varve verify --lockfile Cargo.lock  # the lockfile agrees with the layer
varve status                        # exits 3 if the pinned layer is YANKED
```

Four commands, four different questions:

- **`install`** — do the bytes match what the realm signed, and is the pin
  not a downgrade? Anti-rollback is enforced here.
- **`verify --all`** — is *anything* in this store unverifiable? Scoped to
  the pinned realm before v0.28.0, which meant a tampered layer in another
  realm passed (varve#84). It now walks every partition and prints
  `checked N of M layer(s) across P partition(s)` so you can see the scope
  it covered.
- **`verify --lockfile`** — do the versions your project resolved agree,
  package by package, with the crates the layer pins? varve cannot
  intercept a build, so provenance for compiled-in dependencies is by
  asserted agreement, not by dispatch. This is that assertion.
- **`status`** — has the realm since said something about this layer?
  `install` and `verify` are offline and cannot know.

### Declared exports need no flag

If your `varve.toml` declares `[[export]]` entries, plain `varve verify`
already checks every one of them for drift against the current pin — you
do not have to name them, and a directory nobody remembered to name is
exactly how an export goes stale.

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "rolling"
layer   = "2026.08.3"

[[export]]
kind = "crates-vendor"
out  = "third_party/vendor"
```

`varve verify --export <DIR>` remains for a directory that is not
declared yet.

### Gate on the exit code, not on the text

```sh
varve status || case $? in
  3) echo "::error::pinned layer is YANKED"; exit 1 ;;
  *) echo "::error::varve status failed"; exit 1 ;;
esac
```

`varve exit-codes` prints the contract, and `varve exit-codes --json`
gives it to a script. Every `(CI)` command takes `--json`, so nothing
here needs you to parse prose — before v0.28.0 a pipeline had to scrape
the layer digest out of an English sentence.
