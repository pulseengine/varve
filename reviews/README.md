# Independent-review records (REQ-INDEP-001, DD-019)

One file per release, `reviews/<version>.yaml`, recording the **independent
clean-room review** of that release's scope. A fresh-context reviewer (a human,
or a clean-room agent with no inherited framing) re-derives every claimed result
from evidence — runs the named tests, re-checks the oracles, attempts to refute
— and records the verdict here. `tools/review-check.py` validates these records
in CI.

The record is **advisory at v0.x**: a malformed or dangling record hard-fails
the checker; a *missing* record only warns. The refute-and-block gate (no
verdict, no tag) lands at v1.0.

## Format

```yaml
release: v0.14.0            # must equal the filename stem
reviewer:
  id: <name-or-agent-id>    # who reviewed — required
  kind: clean-room-agent    # clean-room-agent | human — required
date: 2026-08-11            # RFC 3339 date — required
commit: <sha>              # the reviewed commit (optional but recommended)
verdict: pass              # pass | dissent — required
summary: >                 # one line; shown on a dissent warning
  ...
scope:                     # the requirement ids reviewed — required, must exist
  - REQ-STATUS-DIST-001
  - REQ-INDEP-001
evidence: >                # what was re-run / re-derived (free text)
  ...
findings:                  # defects/gaps/overclaims found (free text/list)
  - ...
```

A `dissent` verdict is recorded, not hidden — it surfaces as a prominent CI
warning and in the release notes. Recording the disagreement *is* the mechanism
working.
