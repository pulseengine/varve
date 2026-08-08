#!/usr/bin/env python3
"""Claim-check (REQ-CLAIM-001): every load-bearing claim in claims.yaml must
point at evidence that still exists. Drift goes red, not stale.

Zero-dependency YAML subset parser on purpose: claims.yaml sticks to the
flat shape this script understands, and CI needs no pip install.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_claims(path: Path):
    """Parse the deliberately-restricted claims.yaml shape."""
    claims, current = [], None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if m := re.match(r'\s*- claim: "(.*)"', line):
            current = {"claim": m.group(1), "evidence": []}
            claims.append(current)
        elif m := re.match(r"\s*- \{ (.*) \}", line):
            fields = dict(
                (k.strip(), v.strip().strip('"'))
                for k, v in (pair.split(":", 1) for pair in m.group(1).split(","))
            )
            current["evidence"].append(fields)
    return claims


def test_exists(name: str) -> bool:
    result = subprocess.run(
        ["grep", "-rn", f"fn {name}(", "crates/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def main() -> int:
    claims = parse_claims(ROOT / "claims.yaml")
    if not claims:
        print("claim-check: no claims parsed — refusing to pass vacuously")
        return 1
    failures = []
    for entry in claims:
        for ev in entry["evidence"]:
            kind, ref = ev["kind"], ev["ref"]
            if kind == "test":
                ok = test_exists(ref)
            elif kind == "file":
                ok = (ROOT / ref).is_file()
            elif kind == "workflow":
                wf = ROOT / ev["file"]
                ok = wf.is_file() and ref in wf.read_text()
            else:
                ok = False
            if not ok:
                failures.append(f"  CLAIM «{entry['claim']}»\n    missing {kind}: {ref}")
    if failures:
        print("claim-check: FAILED — claims whose evidence no longer exists:")
        print("\n".join(failures))
        return 1
    total = sum(len(c["evidence"]) for c in claims)
    print(f"claim-check: OK — {len(claims)} claim(s), {total} evidence item(s) all present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
