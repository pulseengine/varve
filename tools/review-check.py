#!/usr/bin/env python3
"""Review-check (REQ-INDEP-001): each release from v0.14.0 carries a recorded
INDEPENDENT clean-room review — a `method: review` verification artifact whose
`verifies` links cover that release's verified requirements (DD-019).

The review record IS a rivet artifact: rivet validates its coherence, its
links, and its lifecycle status natively — there is no bespoke file format and
no hand-rolled parser here. This script adds only the ADVISORY coverage query
rivet's built-in rules don't express: which released, verified requirements
still lack an independent-review verdict.

Reads `rivet ... --format json` (stdlib json only — no regex, no YAML parsing).
Coverage is advisory at v0.x: a release missing a review only WARNS. A malformed
graph is `rivet validate`'s job, not this script's. Exit non-zero only if the
rivet data cannot be read at all.

`--self-test` runs the coverage logic against injected fixtures (no rivet, no
network) — the oracle that this checker actually flags an uncovered release.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The recorded-review mechanism began here (DD-019). Earlier releases predate
# it; coverage warnings apply from this release forward.
MECHANISM_SINCE = (0, 14, 0)


def version_tuple(rel: str):
    """`v0.14.0` -> (0, 14, 0); unparseable -> None (never floored out)."""
    parts = (rel or "").lstrip("v").split(".")
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return None


def rivet_json(args: list) -> dict:
    """Run a rivet command with --format json and parse it. Raises on failure."""
    out = subprocess.run(
        ["rivet", *args, "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)


def _artifacts(payload) -> list:
    """rivet list returns {artifacts: [...]}; be tolerant of a bare list too."""
    if isinstance(payload, dict):
        return payload.get("artifacts", [])
    return payload if isinstance(payload, list) else []


def load_graph():
    """Return (requirements, reviews) as plain dicts from the rivet graph.

    requirements: [{id, status, release}]
    reviews:      [{id, release, status, covers: [req_id, ...]}]  (method == review)
    """
    requirements = [
        {"id": a["id"], "status": a.get("status"), "release": a.get("release")}
        for a in _artifacts(rivet_json(["list", "--type", "requirement"]))
    ]
    reviews = []
    for a in _artifacts(rivet_json(["list", "--type", "verification"])):
        # `list` omits `fields`; `get` carries fields.method — fetch to confirm
        # this verification is a review, not an automated-test.
        full = rivet_json(["get", a["id"]])
        if full.get("fields", {}).get("method") != "review":
            continue
        covers = [
            link["target"]
            for link in full.get("links", [])
            if link.get("type") == "verifies"
        ]
        reviews.append(
            {
                "id": a["id"],
                "release": a.get("release"),
                "status": a.get("status"),
                "covers": covers,
            }
        )
    return requirements, reviews


def check(requirements: list, reviews: list) -> int:
    """Advisory coverage: every release (>= MECHANISM_SINCE) with verified
    requirements should have a verified `method: review` verification covering
    them. Missing/partial only WARNS. Pure — the self-test feeds it fixtures."""
    verified_by_release = {}
    for r in requirements:
        if r["status"] == "verified" and r["release"]:
            verified_by_release.setdefault(r["release"], []).append(r["id"])

    # Union of what verified reviews cover, per release.
    reviewed = {}
    for v in reviews:
        if v["status"] == "verified" and v["release"]:
            reviewed.setdefault(v["release"], set()).update(v["covers"])

    warnings = []
    for rel, verified in sorted(verified_by_release.items()):
        vt = version_tuple(rel)
        if vt is not None and vt < MECHANISM_SINCE:
            continue  # predates the recorded-review mechanism
        covered = reviewed.get(rel, set())
        if not covered:
            warnings.append(
                f"{rel}: {len(verified)} verified requirement(s), no independent-review verdict"
            )
            continue
        uncovered = [rid for rid in verified if rid not in covered]
        if uncovered:
            warnings.append(f"{rel}: review does not cover {', '.join(sorted(uncovered))}")

    for w in warnings:
        print(f"review-check: WARN  {w}")
    n_reviews = sum(1 for v in reviews if v["status"] == "verified")
    print(
        f"review-check: OK — {n_reviews} recorded independent-review verdict(s)"
        + (f", {len(warnings)} advisory warning(s)" if warnings else "")
    )
    return 0


def self_test() -> int:
    """Oracle: an uncovered release WARNS, a covered one does not. No rivet."""
    reqs = [
        {"id": "REQ-A", "status": "verified", "release": "v9.9.9"},
        {"id": "REQ-B", "status": "verified", "release": "v9.9.9"},
        {"id": "REQ-OLD", "status": "verified", "release": "v0.1.0"},  # pre-mechanism
    ]
    covered = [{"id": "VER-REVIEW-v9.9.9", "release": "v9.9.9", "status": "verified",
                "covers": ["REQ-A", "REQ-B"]}]
    partial = [{"id": "VER-REVIEW-v9.9.9", "release": "v9.9.9", "status": "verified",
                "covers": ["REQ-A"]}]

    import io
    import contextlib

    def warnings_from(reviews):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check(reqs, reviews)
        return [ln for ln in buf.getvalue().splitlines() if "WARN" in ln]

    assert warnings_from(covered) == [], "a fully-covered release must not warn"
    assert any("REQ-B" in w for w in warnings_from(partial)), "partial coverage must warn"
    assert any("no independent-review" in w for w in warnings_from([])), "missing review must warn"
    # A pre-mechanism release (v0.1.0) is never warned about.
    assert not any("v0.1.0" in w for w in warnings_from(covered)), "pre-mechanism release must be silent"
    print("review-check --self-test: OK — uncovered/partial warn, covered is silent, pre-mechanism floored")
    return 0


def main(argv) -> int:
    if "--self-test" in argv:
        return self_test()
    try:
        requirements, reviews = load_graph()
    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"review-check: cannot read the rivet graph: {e}")
        return 1
    return check(requirements, reviews)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
