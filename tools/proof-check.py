#!/usr/bin/env python3
"""Run every SMT obligation in proofs/ through ordeal and enforce its declared
verdict (REQ-PROOF-001).

Each `.smt2` declares `; expect: unsat` (an obligation — no counterexample
exists) or `; expect: sat` (a NEGATIVE CONTROL, or a witness generator). The
negative controls are the point: they prove this gate can go red. A proof suite
where every file is expected-unsat cannot distinguish "proved" from "the solver
silently stopped deciding anything".

ordeal returns unsat only after its checker has validated an LRAT certificate,
so an unsat here is evidence a third party can re-check, not an exit code.
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROOFS = sorted((ROOT / "proofs").glob("*.smt2"))


def expected(path: pathlib.Path) -> str:
    for line in path.read_text().splitlines():
        if line.startswith("; expect:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit(f"proof-check: {path.name} declares no `; expect:` verdict")


def main() -> int:
    if not PROOFS:
        print("proof-check: no obligations in proofs/ — nothing is being proved")
        return 1
    failures, controls = [], 0
    for p in PROOFS:
        want = expected(p)
        if want == "sat":
            controls += 1
        try:
            out = subprocess.run(
                ["ordeal", "check", str(p)],
                capture_output=True, text=True, timeout=600,
            )
        except FileNotFoundError:
            print("proof-check: `ordeal` not on PATH — install it from the pinned layer")
            return 1
        got = (out.stdout.strip().splitlines() or [""])[0].strip()
        mark = "ok " if got == want else "FAIL"
        print(f"  {mark} {p.name}: expected {want}, got {got or out.stderr.strip()[:60]!r}")
        if got != want:
            failures.append(p.name)
    if controls == 0:
        print("proof-check: FAIL — no negative control; a gate nobody has seen go red is not a gate")
        return 1
    if failures:
        print(f"proof-check: FAIL — {len(failures)} obligation(s) off: {', '.join(failures)}")
        return 1
    print(f"proof-check: OK — {len(PROOFS)} obligation(s), {controls} negative control(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
