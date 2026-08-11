#!/usr/bin/env python3
"""Review-check (REQ-INDEP-001): each release carries a recorded INDEPENDENT
clean-room review verdict, and every recorded verdict is coherent.

The independence mechanism is *recorded, advisory* at v0.x (DD-019): a missing
review is a WARNING, not a failure — the auditable trail is the deliverable,
not a hard gate (the refute-and-block gate lands at v1.0). But a review record
that IS present must be well-formed and must reference real requirements: a
malformed or dangling record is a hard FAILURE, because a broken record is
worse than an honest absence.

Zero-dependency on purpose (CI needs no pip install): `reviews/*.yaml` sticks
to the constrained shape this parser understands.

Exit codes:
  0  all present records are coherent (missing/partial records only warn)
  1  a record is malformed, or references a requirement that does not exist,
     or no records were parsed when some were expected
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VALID_VERDICTS = {"pass", "dissent"}
VALID_KINDS = {"clean-room-agent", "human"}
# The recorded-review mechanism began at this release (DD-019). Earlier
# releases predate it; warning about reviews we will never retroactively
# perform is noise, not signal. Coverage warnings apply from here forward.
MECHANISM_SINCE = (0, 14, 0)


def version_tuple(rel: str):
    """`v0.14.0` -> (0, 14, 0); unparseable -> None (never floored out)."""
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", rel or "")
    return tuple(int(x) for x in m.groups()) if m else None


def parse_review(path: Path) -> dict:
    """Parse the constrained reviews/*.yaml shape: top-level scalars, one
    nested `reviewer` map, a `scope` list, and a free-text `evidence` block."""
    rec: dict = {"reviewer": {}, "scope": [], "path": path}
    section = None
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if m := re.match(r"^reviewer:\s*$", line):
            section = "reviewer"
            continue
        if m := re.match(r"^scope:\s*$", line):
            section = "scope"
            continue
        if (m := re.match(r"^\s+-\s+(\S+)\s*$", line)) and section == "scope":
            rec["scope"].append(m.group(1))
            continue
        if (m := re.match(r"^\s+(\w[\w-]*):\s*(.*)$", line)) and section == "reviewer":
            rec["reviewer"][m.group(1)] = m.group(2).strip().strip('"')
            continue
        if m := re.match(r"^(\w[\w-]*):\s*(.*)$", line):
            key, val = m.group(1), m.group(2).strip()
            # A `>` or `|` opens a block scalar we don't need to keep verbatim.
            rec[key] = "" if val in (">", "|") else val.strip('"')
            section = None
            continue
    return rec


def requirements_by_release() -> dict:
    """Map release -> list of (req_id, status) from artifacts/requirements.yaml.
    A minimal scan of the `- id: / status: / release:` shape."""
    out: dict = {}
    req_id = status = release = None
    for raw in (ROOT / "artifacts" / "requirements.yaml").read_text().splitlines():
        line = raw.split("#", 1)[0]
        if m := re.match(r"\s*-\s+id:\s+(REQ-\S+)", line):
            req_id, status, release = m.group(1), None, None
        elif m := re.match(r"\s*type:\s+(\S+)", line):
            # A new artifact of another type ends the current requirement.
            if m.group(1) != "requirement":
                req_id = None
        elif req_id and (m := re.match(r"\s*status:\s+(\S+)", line)):
            status = m.group(1)
        elif req_id and (m := re.match(r"\s*release:\s+(\S+)", line)):
            release = m.group(1)
            out.setdefault(release, []).append((req_id, status))
            req_id = None
    return out


def known_requirement_ids() -> set:
    ids = set()
    for reqs in requirements_by_release().values():
        ids.update(rid for rid, _ in reqs)
    return ids


def check(reviews_dir: Path, reqs_by_release: dict, known_ids: set) -> int:
    records = sorted(reviews_dir.glob("*.yaml")) if reviews_dir.is_dir() else []
    reviewed_releases = {}
    hard_failures, warnings = [], []

    for path in records:
        rec = parse_review(path)
        rel = rec.get("release")
        who = rec.get("reviewer", {})
        # Coherence — a present record must be well-formed (hard failures).
        if not rel:
            hard_failures.append(f"{path.name}: no `release`")
        elif path.stem != rel:
            hard_failures.append(f"{path.name}: release '{rel}' != filename '{path.stem}'")
        if rec.get("verdict") not in VALID_VERDICTS:
            hard_failures.append(f"{path.name}: verdict must be one of {sorted(VALID_VERDICTS)}")
        if who.get("kind") not in VALID_KINDS:
            hard_failures.append(f"{path.name}: reviewer.kind must be one of {sorted(VALID_KINDS)}")
        if not who.get("id"):
            hard_failures.append(f"{path.name}: reviewer.id is required")
        if not rec.get("date"):
            hard_failures.append(f"{path.name}: date is required")
        if not rec.get("scope"):
            hard_failures.append(f"{path.name}: scope must name the reviewed requirements")
        for rid in rec.get("scope", []):
            if rid not in known_ids:
                hard_failures.append(f"{path.name}: scope references unknown requirement {rid}")
        if rel:
            reviewed_releases[rel] = rec
        if rec.get("verdict") == "dissent":
            warnings.append(f"{path.name}: verdict is DISSENT — {rec.get('summary', 'see record')}")

    # Coverage — advisory: a release with verified reqs but no review only warns.
    for rel, reqs in sorted(reqs_by_release.items()):
        verified = [rid for rid, st in reqs if st == "verified"]
        if not verified:
            continue
        vt = version_tuple(rel)
        if vt is not None and vt < MECHANISM_SINCE:
            continue  # predates the recorded-review mechanism
        rec = reviewed_releases.get(rel)
        if rec is None:
            warnings.append(f"{rel}: {len(verified)} verified requirement(s), no independent-review record")
            continue
        uncovered = [rid for rid in verified if rid not in rec.get("scope", [])]
        if uncovered:
            warnings.append(f"{rel}: review does not cover {', '.join(uncovered)}")

    for w in warnings:
        print(f"review-check: WARN  {w}")
    if hard_failures:
        print("review-check: FAILED — incoherent review record(s):")
        for f in hard_failures:
            print(f"  {f}")
        return 1
    print(
        f"review-check: OK — {len(records)} review record(s), "
        f"{len(reviewed_releases)} release(s) with a recorded independent verdict"
        + (f", {len(warnings)} advisory warning(s)" if warnings else "")
    )
    return 0


def self_test() -> int:
    """Oracle: a broken record FAILS, a good one PASSES. Run with --self-test."""
    import tempfile

    known = {"REQ-A", "REQ-B"}
    reqs = {"v9.9.9": [("REQ-A", "verified"), ("REQ-B", "verified")]}
    good = (
        "release: v9.9.9\n"
        "reviewer:\n  id: smithy-clean-room\n  kind: clean-room-agent\n"
        "date: 2026-08-11\nverdict: pass\n"
        "scope:\n  - REQ-A\n  - REQ-B\n"
    )
    bad_verdict = good.replace("verdict: pass", "verdict: maybe")
    dangling = good.replace("  - REQ-B", "  - REQ-NOPE")
    with tempfile.TemporaryDirectory() as d:
        good_dir = Path(d) / "good"
        good_dir.mkdir()
        (good_dir / "v9.9.9.yaml").write_text(good)
        assert check(good_dir, reqs, known) == 0, "a coherent record must pass"

        for label, body in [("bad-verdict", bad_verdict), ("dangling", dangling)]:
            bd = Path(d) / label
            bd.mkdir()
            (bd / "v9.9.9.yaml").write_text(body)
            assert check(bd, reqs, known) == 1, f"{label} record must fail"

        # A missing record only warns (advisory) — still exit 0.
        empty = Path(d) / "empty"
        empty.mkdir()
        assert check(empty, reqs, known) == 0, "a missing record must not hard-fail at v0.x"
    print("review-check --self-test: OK — broken records fail, coherent pass, missing only warns")
    return 0


def main(argv) -> int:
    if "--self-test" in argv:
        return self_test()
    return check(ROOT / "reviews", requirements_by_release(), known_requirement_ids())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
