#!/usr/bin/env python3
"""A requirement claiming `verified` is connected to its evidence (REQ-TRACEGATE-001).

`rivet validate` reports a disconnected artifact as a WARNING — 212 of them, in
which the one that matters is invisible. A gate that cannot fail is the shape
this release exists to fix, so this one exits non-zero.

WHAT COUNTS AS EVIDENCE, and why there are two kinds:

  * a source marker — `// rivet: verifies REQ-X` on a test. This is how a
    property of the CODE is discharged, and it is the cheap path the loop
    prescribes.
  * an incoming `verifies` edge from a verification artifact. This is how a
    property of the PIPELINE is discharged — that fuzzing runs, that the
    release matrix covers four platforms, that the mutation gate is required.
    No unit test can assert those, and demanding a marker for them would push
    people to write a fake one.

Both are real. Requiring only the graph edge would mean writing a VER- artifact
for all 85 requirements that already carry markers; requiring only the marker
would leave the 12 pipeline requirements with no way to be verified at all.

Measured before this was written: 97 verified requirements — 85 with a marker,
75 with an edge, 63 with both, and ZERO with neither. The gate is satisfiable
today, so it is turned on as an error rather than deferred behind a backlog.

WHY THIS IS PYTHON, and what would change it. Reading the artifacts from Rust
needs a YAML parser, and the obvious one — `serde_yaml` — is unmaintained
(0.9.34+deprecated, last published 2024-03-25). Adding it to a supply-chain tool
to satisfy a test-only need is the wrong trade, so the gate lives here instead
and varve's dependency graph stays as it is.

That is a stopgap, not a preference. rivet has a rowan-based LOSSLESS YAML CST
parser with two fuzz targets — it is what lets `rivet modify` rewrite an
artifact without destroying its comments — and pulseengine/rivet#930 asks for it
as its own crate. When that lands, this belongs in Rust beside the other gates,
where `cargo test` runs it without anyone remembering to.
"""
import os
import re
import sys

try:
    import yaml
except ModuleNotFoundError:
    print("::error::PyYAML is not installed — the traceability gate cannot run, "
          "and a gate that cannot run must not report success")
    sys.exit(1)

ARTIFACTS = "artifacts"
SOURCES = "crates"
MARKER = re.compile(r"rivet:\s*(?:partially-)?verifies\s+([A-Z][A-Z0-9-]+)")


def load():
    """Every artifact, and every incoming `verifies` target."""
    artifacts, incoming = {}, set()
    for fn in sorted(os.listdir(ARTIFACTS)):
        if not fn.endswith(".yaml"):
            continue
        doc = yaml.safe_load(open(os.path.join(ARTIFACTS, fn))) or {}
        for a in doc.get("artifacts") or []:
            artifacts[a["id"]] = a
            for link in a.get("links") or []:
                if isinstance(link, dict) and link.get("type") in (
                    "verifies",
                    "partially-verifies",
                ):
                    incoming.add(link.get("target"))
    return artifacts, incoming


def markers():
    """Requirement ids named by a source marker."""
    found = set()
    for root, _, files in os.walk(SOURCES):
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = os.path.join(root, f)
            with open(path, errors="ignore") as fh:
                found |= set(MARKER.findall(fh.read()))
    return found


def main() -> int:
    artifacts, incoming = load()
    marked = markers()
    reqs = {i: a for i, a in artifacts.items() if a.get("type") == "requirement"}
    verified = {i for i, a in reqs.items() if a.get("status") == "verified"}

    if not verified:
        print("::error::no verified requirements found — the gate is reading the "
              "wrong thing, and finding nothing must not read as passing")
        return 1

    failures = []

    # 1. Every `verified` requirement has evidence of one kind or the other.
    for r in sorted(verified):
        if r not in marked and r not in incoming:
            failures.append(
                f"{r} is `verified` with NO evidence: no `// rivet: verifies {r}` "
                f"marker on any test, and no incoming `verifies` link. Either "
                f"discharge it or move it back to `implemented` — a status is a "
                f"claim, and this one has nothing behind it."
            )

    # 2. A marker naming a requirement that does not exist is a rename's
    #    leftover: it discharges nothing while looking like it discharges
    #    something, and `rivet coverage` will happily count it.
    for ghost in sorted(marked - set(reqs)):
        failures.append(
            f"a source marker names {ghost}, which is not a requirement — a "
            f"rename or deletion left it behind, and it verifies nothing."
        )

    both = len(verified & marked & incoming)
    print(
        f"traceability: {len(verified)} verified — "
        f"{len(verified & marked)} by source marker, "
        f"{len(verified & incoming)} by verification artifact, "
        f"{both} by both"
    )

    if failures:
        for f in failures:
            print(f"::error::{f}")
        print(f"::error::{len(failures)} traceability failure(s)")
        return 1
    print("OK — every verified requirement is connected to its evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
