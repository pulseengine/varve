# The ingest ladder — how a payload is vouched for

Every payload enters a layer on exactly one rung, and the rung is **signed into
the manifest**. A consumer reads how the bytes were vouched for rather than
assuming they were.

| rung | what it establishes | what it does not |
|---|---|---|
| `cosign-sums` | a signed digest list, verified against the repository's own workflow identity | — |
| `build-provenance` | a SLSA attestation binding the bytes to the build that made them | — |
| `pgp-sums` | a digest list signed with OpenPGP, verified against a certificate **you pinned in the producer input**: the holder of that key published these digests | that the publisher is trustworthy; key expiry |
| `upstream-sums` | the bytes are the bytes that list names | **anything about who produced them** |
| `unverified` | nothing | everything |

The ladder is ordered, and the producer takes the highest rung a release
actually offers. It never silently descends: a release that offered
`cosign-sums` yesterday and offers nothing today stops the run rather than
quietly entering on a weaker rung.

## `pgp-sums` — a digest list somebody signed

Some upstreams sign their digest list with OpenPGP: Rust publishes
`channel-rust-stable.toml` with a detached `.asc`. That is the claim
`cosign-sums` makes, reached by a different mechanism, and it has its own rung
between `build-provenance` and `upstream-sums`. The ladder order is
`cosign-sums`, `build-provenance`, `pgp-sums`, `upstream-sums`, `unverified`;
the producer takes the highest rung the release offers, and a release that
offers `cosign-sums` or `build-provenance` never consults the signed list.

It is declared on the `[[tool]]` entry of the producer's input (`layer.toml`):

| field | meaning |
|---|---|
| `pgp-sums` | the release asset carrying the digest list. A name or a template (`%V`, `%R`; not `%T`: one list per release). |
| `pgp-sums-signature` | the asset carrying the **detached** signature. Default: the list's name plus `.asc`. |
| `pgp-sums-format` | how to read the list once it verified: `sha256sums` (the `sha256sum` format; the default) or `rust-channel` (a `channel-rust-*.toml`, whose entries are keyed by the basename of their `url`). Declared, never guessed from the content. |
| `pgp-key-file` | the OpenPGP certificate, armored or binary, as a path **relative to the input file**. |

`pgp-sums` and `pgp-key-file` go together: either without the other is refused
at plan time, as are `pgp-sums-signature` or `pgp-sums-format` without
`pgp-sums`, and `pgp-sums` on an entry that also names `upstream-sums` (the
unsigned list could never be consulted). The key file is read from disk at
ingestion, before anything is fetched. A file that is missing or unreadable
stops the run; it never falls back to a weaker rung. The key is never fetched
and never read from beside the artifact: a key found next to the thing it
vouches for is not a proof.

A signature that does not verify aborts the run. It is never read as "no
signed list" and never descends to `upstream-sums` or `unverified`. These are
all refusals: a signature by another key, a certificate carrying its own
revocation, a text-type signature (it covers the line-ending-normalised form,
not the bytes), a digest below SHA-256, a list that is not published or cannot
be fetched. A payload the verified list does not name, or whose bytes differ
from the digest it names, is refused like any other.

The manifest records `pgp-sums` as the proof, the **primary key's
fingerprint** as the signer (a user ID is text the key's own holder typed, so
it is shown as a label after the fingerprint and never as the identity), and a
one-line assertion; a signature made by a subkey names that subkey as well.

A signature says who published a list, not **which release** it belongs to: a
host that controls the release could serve an older, validly signed list with
the older assets. So the list is bound to the release the entry declares:

- with `sha256sums`, every asset name of the entry (`asset`, each `asset-for`
  value) must carry `%V` or `%R`, refused at plan time otherwise, so a list for
  another release cannot name this release's files. (An entry with no `asset`
  uses the default tarball template, which embeds the version.)
- with `rust-channel`, the manifest's own version must match: the declared
  version or release tag, ignoring a leading `v`, must equal the version of the
  manifest's `rust` package (`1.98.1` out of `1.98.1 (48a229cea 2026-09-01)`),
  or the manifest's `date` must equal the declared version or release tag as
  written. Anything else is refused as a different release.

The recorded assertion names that release. Every entry that ingests from one
repository release must declare the same `pgp-sums` (and the same
`upstream-sums`); entries that disagree are refused before anything is fetched,
because a release is verified once and one entry's declared verification would
otherwise silently not run.

What it proves: the holder of that key published a list naming these bytes.
What it does **not** prove: that the upstream is trustworthy, or that the key
was valid when it signed. Key **expiry is deliberately not checked**, because
deciding it needs a clock and none is available that is not absent, wrong, or
attested by the key in question.

`pgp-sums` can only be written in `layer.toml`; the shell assembler's
environment encoding has no field for it and refuses an entry that uses one.

## `upstream-sums` is deliberately named, not promoted

Some upstreams publish a digest list beside their assets and sign nothing —
zephyrproject-rtos publishes `sha256.sum`. Transcribing it establishes exactly
one fact: **the bytes are the bytes that list names.** For a 90 MB toolchain
over a CDN that is the failure which actually happens, so it is worth having.

It establishes **nothing** about who produced them, because the same host serves
the list and the bytes. That is why it is its own rung rather than being folded
into `cosign-sums` — the name has to keep saying what it does not prove.

The realm states the asset's name rather than the producer guessing it. A file
that is not the digest manifest, parsed as one, vouches for nothing while
looking like it does.

## `unverified` requires a written reason

Not a boolean. The reason is signed into the layer and shown by `varve inspect`,
so every consumer reads the operator's own words next to the bytes they were
written about. "We could not verify this" must never be the silent path.

Two entries for the same repository with different reasons is an error: the
realm has to have one position on why a source is unverified.
