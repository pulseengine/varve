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

## A proof is bound to the release it is ingested for

A proof says who published bytes, not **which release** they are for. Without a
binding, an older release's validly signed sums and the older bytes they name,
served under a newer tag, would be recorded as the newer version. Every rung
therefore binds its proof to the release tag being ingested:

| rung | binding |
|---|---|
| `cosign-sums` | the certificate identity must be the release tag's workflow: `^https://<host>/<owner>/<repo>/\.github/workflows/[^@]+@refs/tags/<tag>$`, with the host, repository and tag escaped. The repository's other workflows, other repositories, other tags and branches are refused. `--certificate-github-workflow-repository <owner>/<repo>` is passed too, so a reusable workflow of this repository called from another repository (same workflow path, the caller's code) is refused. |
| `build-provenance` | `gh attestation verify --repo <repo>`, with **no** source-ref pin, and the attestation subject's name: the digest that vouches for an asset is the one of the subject whose name is that asset, and that name must carry the release (below). An attestation built from a branch is accepted when a subject names this release's asset with the matching digest; an older release's attestation names the older asset and cannot vouch for this release's. |
| `pgp-sums` | the list and every asset name carry the release (see below), and a Rust channel's own version must match. |
| `upstream-sums` | the asset names only. Nothing signed the list, so nothing else binds it. |

For every rung that has a name rule (all of them), each asset template of an
entry (`asset` and every `asset-for` value, or the default template of the
layout) must carry `%V` or `%R`, and the version or release it expands from
must name exactly one release (`1.2.3`, `v1.2.3`, `2026-10-01`; not `latest`,
`nightly`, `v4`, `3.x`). A template or value that does not is refused at
`plan` and `deposit`. Only a template that produces a planned asset is judged:
for a per-platform entry that is each carried platform's `asset-for` override
or else the template. A template every carried platform overrides is never
expanded and is not judged; a platform that falls back to it is planned (even
if the upstream publishes no build for it) and counts, so an entry that
overrides only some platforms either names every one it carries or restricts
itself with `platforms = [...]`. The same applies to extension, document and crate
entries. The rule is not applied to a Rust channel (which binds through its
own manifest version) or to an entry that is itself an `unverified` opt-in
and declares no list. Ingestion checks again, independently of the plan, that
each expanded asset name contains, on a token boundary, the release tag the
group is fetched under (or the payload's version, where the plan has shown the
version and the tag to name the same release). That check runs after the
release is verified and is skipped only when the release was actually accepted
as `unverified`: an `unverified-reason` exempts nothing once a signed or listed
rung vouches for the release. An entry that declares `unverified-reason` and
also `pgp-sums` or `upstream-sums` is refused at plan time, because the two
contradict each other.

The payload's `version` and the release tag must also name the same release:
after dropping a leading `v`, the tag must equal the version or contain it on a
token boundary (`0.2.2` and `v0.2.2`; not `0.2.2` and `v0.7.2`). A hub that tags
one release for payloads of several versions (`with-device` 0.2.2 under
`v0.7.2`) cannot satisfy that and carries `unbound-release-reason`.

This is a **name heuristic**, not a cryptographic binding: a publisher who
reuses a numbered tag, or who names an older asset after the newer version,
defeats it. For `cosign-sums` the certificate-identity check on the proof
itself is the stronger half, and it holds only for an upstream that releases
from a tag: an upstream that signs from a branch is refused. For
`build-provenance` the source ref is deliberately **not** pinned, because
upstreams such as `bytecodealliance/wasm-tools` sign every release from a
workflow on a branch (`publish.yml@refs/heads/main`) and a tag pin would refuse
all of them. What binds that rung is the subject name: `gh` confirms an
attestation from the named repository covers the downloaded bytes, and the
digest recorded for an asset is then looked up by that asset's name among the
attestation's subjects, so an attestation for an older release's asset (a
different name, its own digest) never covers this release's asset. `gh` returns every attestation from the repository that covers the digest, and
all of them are read: an asset is vouched for only by a statement with a subject
named for that asset, and two statements that give one name different digests
are refused. A statement built from `refs/pull/*` is set aside (a pull-request
build is never a release); when nothing else remains the release is refused.
A pull-request statement is set aside before it is validated, so a malformed one
cannot refuse a release. Two kept statements that give one subject name
different digests are still refused (fail closed); that means anyone who can run
a workflow on a branch of the upstream repository can block a release by
attesting the same name at another digest.
The record (`proof-signer`, `proof-asserts`) names the `buildSignerURI`, the ref
and the commit of the statements that vouched for the planned assets.

The limit, plainly: with no ref pin, an attestation built from **any branch or
tag of the repository**, by any workflow in it, is accepted when one of its
subjects carries this release's asset name and the matching digest. The
producer does not check that the workflow is the upstream's release workflow, or
that the ref is the release. What stops an older release's attestation is the
subject name carrying the release; what it does not stop is a build of the same
name and digest from a branch.

For `cosign-sums` the recorded `proof-signer` is the repository's identity
prefix, `https://<host>/<owner>/<repo>/`, the same from one release to the next
(`varve diff` reports a moved signer, and a tag in it would move on every
bump); the exact identity regexp that cosign enforced, tag included, is in
`proof-asserts`. For `build-provenance` the signer is the attestation's build
signer URI.

The release each proof was bound to is part of the recorded assertion
(`proof-asserts`).

### `unbound-release-reason` — an entry that cannot be bound

An upstream that names its files with no version (`wsc-linux-x86_64`) cannot
satisfy the name rule. The entry can be carried anyway by saying why:

```toml
[[tool]]
name = "wsc"
version = "v0.12.0"
layout = "raw-per-platform"
unbound-release-reason = "upstream names its binaries with no version; tracked in <issue>"
```

At `plan` the reason lets the entry past the name check, because the plan does
not yet know which mechanism will vouch for the release. **Ingestion decides**,
once the release is verified:

| mechanism that vouched | a versionless name under the reason |
|---|---|
| `upstream-sums` | accepted; the name was the only binding there was, and it is waived |
| `unverified` | accepted (the opt-in is its own recorded exception) |
| `cosign-sums`, `build-provenance` | **refused**: a signed proof cannot be bound to the release by name. A signed name and digest vouch for whichever release produced them, so an older release's file and attestation would satisfy a versionless name |
| `pgp-sums` | never waived; the combination is refused at `plan` |

When it is honoured it prints a warning at `plan` and `deposit`, and is signed
into the layer: the entry's `proof-asserts` ends with `NOT BOUND TO ITS
RELEASE`, says the name binding was `WAIVED`, and gives the reason in the
operator's words. It is per entry, never inherited, and an empty reason is
refused. It is accepted on `[[tool]]`, `[[docs]]` and `[[crate]]` entries. It
can only be written in `layer.toml`; the environment encoding refuses it.

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

The version or release a `sha256sums` template expands from must name exactly
ONE release: after one leading `v`, `MAJOR.MINOR[.PATCH]` with an optional
`-prerelease` or `+build` suffix, or a full date `YYYY-MM-DD`. A moving tag
(`latest`, `nightly`, `main`), a bare number, a wildcard (`3.x`) or a fused word
(`3lts`) is refused, because the expanded names would be the same for every
release. This is a name heuristic, not a cryptographic binding: a publisher who
reuses a numbered tag defeats it. The list or its signature name must carry
`%V` or `%R` too, and ingestion re-checks that every asset name contains the
concrete version or release it is bound to. Cycle labels (`nightly`, `snapshot`, `dev`, `daily`,
`weekly`, `tip`, `trunk`, `develop`, `unstable`, `latest*`) count only when a
build number follows (`1.2.3-nightly.20261108`), a token holding `/`, `%` or
whitespace is refused, and at ingestion the version must sit on a token
boundary in the asset name (`1.2` is not found in `tool-v1.2.3.tar.gz`). A Rust
channel whose version has a
prerelease part (`1.99.0-nightly`, `-beta.2`) binds by its `date` only, since
every build of the cycle carries the same version.

The signing key is recorded as its own annotation, `proof-signing-key`, beside
the signer: the primary's fingerprint when the primary signed, the subkey's
otherwise. A subkey the primary has revoked (in any entry carrying its fingerprint), an
encryption-only subkey (a same-second tie between bindings goes to the one
without SIGN), a subkey whose binding or back-signature uses a hash below 256
bits, and a primary whose newest self-signatures state flags without SIGN do
not vouch. A list signature must state its creation time, and a critical
hashed subpacket other than creation time and issuer refuses it. Signature
and binding expiry are not checked, for the same reason key expiry is not.
The digest floor is deliberately not applied to the primary's own
certification: it grants the pinned key nothing, and Rust's release key
certifies itself with SHA-1.

The recorded assertion names that release. Every entry that ingests from one
repository release must declare the same `pgp-sums` (and the same
`upstream-sums`); entries that disagree are refused before anything is fetched,
because a release is verified once and one entry's declared verification would
otherwise silently not run.

**Known limit, fails closed:** the declaration includes the payload version, so
a hub repository whose payloads carry different versions under one release tag
(`pulseengine/jess`: `with-device` 0.2.2 under `v0.7.2`) is always refused as a
disagreement when those entries use `pgp-sums`. Give each such entry its own
release, or leave `pgp-sums` off the hub.

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
