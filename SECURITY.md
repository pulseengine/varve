# Security Policy

varve's purpose is trustworthy toolchain distribution, so its own security
process must meet the bar it sets for others.

## Reporting a vulnerability

Report privately via GitHub Security Advisories
(https://github.com/pulseengine/varve/security/advisories/new) or, if that
is unavailable, by opening an issue that says only "security — request
private contact" (no details) so a maintainer can open a private channel.

Please include: affected version(s) / layer(s), the property you believe is
violated (see the invariants below), and a reproduction. We aim to
acknowledge within 3 working days and to ship a fix or a documented
mitigation on a patch release of the affected line.

## Supported versions

The latest tagged release is supported. Layers carry their own
support-window and known-problems advisories as signed line-status
documents (`varve status`).

## The invariants a report should target

varve is built fail-closed around these; a bypass of any is a vulnerability:

- **Acceptance is independent of source.** No registry, mirror, archive, or
  transport may change whether bytes are accepted — only signature (against
  the pinned trust root) and digest decide.
- **No silent fallback.** A missing, partial, or ambiguous pin fails with a
  corrective error; varve never runs "whatever else is on PATH".
- **Anti-rollback.** A layer whose per-line counter is below the recorded
  high-water mark is refused.
- **No downgrade of the verifier.** `self-update` verifies its successor
  against the trust root before replacing the running binary.
- **Realm isolation.** Bytes signed by one realm's root cannot be accepted,
  resolved, or executed in a project pinned to another realm.

## Known limitations (current posture, tracked)

- The **qualified-channel trust root does not yet exist**; releases and
  layers are signed with a *provisional rolling key* (`trust-roots/`), which
  has no rotation/revocation/threshold story pending the root ceremony
  (the v1.0 gate). See `SH-005` in `artifacts/security.yaml`.
- **First-contact rollback**: a fresh consumer resolving a line by name has
  no high-water mark yet; pin a digest on the `qualified` channel. See
  `SH-001`.
- Report drift between this file and reality as a vulnerability — the
  claim-check gate (`claims.yaml`) covers load-bearing claims but not all
  prose.
