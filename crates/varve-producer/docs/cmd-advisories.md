# varve-producer advisories

For every committed line of a layer repository, check what is published
against GHSA and RustSec, and prepare the next `line-status` document for
anything a person has not already stated.

```sh
varve-producer advisories                       # reads ./layer.toml
varve-producer advisories --manifest layer.toml --today 2026-10-15
varve-producer advisories --json
```

Run it from a layer repository's root — the directory holding `layer.toml`,
`line-index/<line>.json` and `line-status/<line>.json`. It:

1. Reads each `line-index/<line>.json`, fetches the SIGNED manifest of every
   layer it names from the realm registry (`layer.toml`'s `[realm] registry`),
   and checks the fetched payload's own sha256 against the digest the index
   recorded — a mismatch is refused, never silently trusted.
2. Skips a line whose committed `line-status` states a `support-until`
   already before `--today`. A line with no committed status yet, or no
   stated `support-until`, is never skipped on that basis.
3. For every payload a layer's manifest names (`eu.pulseengine.tool` +
   `eu.pulseengine.tool.version` + `eu.pulseengine.source.repo`), asks GitHub's
   repository security advisories for that repo and matches them against the
   package range that NAMES the payload (its `eu.pulseengine.tool`) — not
   against every package range in the repository. Advisories that name only
   other packages of the repository are not matched, and are listed as
   unchecked for that payload. A payload of kind `crate` is also checked
   against RustSec by its own crate name and version. When the manifest
   recorded an upstream SBOM annotation, or the release publishes one, it is
   read for that payload's own release (two releases sharing a repository and
   version each have their own), its sha256 is checked, and every component
   is either checked against RustSec or reported unchecked:
   - the ecosystem is the purl type, never the bare name: only `pkg:cargo/...`
     is looked up, and the crate is the one the purl names, so an npm package
     called `serde` never matches a crate advisory;
   - components nested inside components are walked;
   - a component with no version, no purl, an unreadable purl, or of an
     ecosystem RustSec does not cover is printed as unchecked with that
     reason, under the payload that carries it.
4. Turns every match into a prepared `line-status/<line>.json` — never
   signed, never published. A pull request against it, and merging THAT, is
   what signs and publishes (REQ-ADVISORYWATCH-001 clause 3).

## Fail closed, not "nothing moved"

A source that cannot be read — GHSA rate-limited, the registry unreachable,
an upstream SBOM whose sha256 does not match what `layer.toml` recorded — fails
the WHOLE run and writes nothing, even when some other line already computed
a perfectly good document. Reporting "nothing moved" from an incomplete check
is the covalent scanner's #16/#17 lesson this command exists not to repeat.

A 404 from the RustSec advisory-db is different: most crates have never had
an advisory, and that absence is not a failure to ask.

## Undecidable is reported, never silently cleared

A GHSA advisory whose version range this program cannot parse, or whose range
and `patched_versions` disagree about whether the queried version is
affected, is neither a finding nor a clearance — it is printed as
undecidable, with its reason, so a person resolves it rather than a silent
"not affected" standing in for "we could not tell".

## Severity

GHSA's own `severity` field, lower-cased; a RustSec advisory's severity is
computed from its `cvss` vector using the CVSS 3.1 base-score formula. An
advisory stating neither defaults to `medium`, and the report says which ids
got that default rather than a stated severity.

## Exit codes

| | |
|---|---|
| 0 | every line processed; see the report for what, if anything, was written |
| 1 | a source could not be read — nothing was written for this run |
| 2 | bad usage |
