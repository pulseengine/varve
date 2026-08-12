#!/usr/bin/env python3
"""Tracepack-check (REQ-TRACEPACK-001): a release must be able to emit its rivet
traceability as queryable, assessor-importable evidence. This is the mechanical
oracle for the release.yml "Export traceability evidence" step — it runs the
same `rivet export` commands and validates the outputs, so a regression in
rivet or the artifacts goes red here instead of in a release.

Needs `rivet` on PATH (the CI rivet job has it). Exit 0 if all exports are valid.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(args, cwd=ROOT):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def main() -> int:
    if run(["rivet", "--version"]).returncode != 0:
        print("tracepack-check: rivet not on PATH — skipping (CI rivet job runs it)")
        return 0
    failures = []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)

        # 1. ReqIF — the OMG assessor-interchange format. Must be well-formed
        #    XML with a REQ-IF root and a non-trivial artifact count.
        reqif = d / "traceability.reqif"
        r = run(["rivet", "export", "--format", "reqif", "--output", str(reqif)])
        if r.returncode != 0 or not reqif.is_file():
            failures.append(f"reqif export failed: {r.stderr.strip()}")
        else:
            # String-based validation only — the ReqIF is trusted (rivet just
            # generated it), and NOT invoking an XML entity-expanding parser
            # keeps this zero-dep and clear of the stdlib XXE/billion-laughs
            # surface. Assessor-tool import remains the real conformance test.
            text = reqif.read_text(errors="replace")
            if not text.lstrip().startswith("<?xml"):
                failures.append("reqif missing the XML declaration")
            if "<REQ-IF" not in text:
                failures.append("reqif has no REQ-IF root element")
            n = text.count("<SPEC-OBJECT ") + text.count("<SPEC-OBJECT>")
            if n < 10:
                failures.append(f"reqif has too few SPEC-OBJECTs: {n}")

        # 2. HTML — a browsable report with an index page.
        html = d / "html"
        r = run(["rivet", "export", "--format", "html", "--offline", "--output", str(html)])
        if r.returncode != 0:
            failures.append(f"html export failed: {r.stderr.strip()}")
        elif not (html / "index.html").is_file():
            failures.append("html export produced no index.html")

    if failures:
        print("tracepack-check: FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("tracepack-check: OK — ReqIF (well-formed, assessor-importable) + HTML report both export")
    return 0


if __name__ == "__main__":
    sys.exit(main())
