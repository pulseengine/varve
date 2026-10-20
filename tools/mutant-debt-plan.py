#!/usr/bin/env python3
"""Shard the declared mutation debt, and report only what completed (REQ-MUTANTDEBT-001).

varve#181: the nightly advisory run was ONE job over the whole workspace,
cancelled at its 90-minute cap every night after ~32% of 2,675 mutants, so 11 of
the 22 `[not-yet]` files in mutation-scope.toml were never reached. The
instrument that makes declared debt counted rather than hidden counted half of
it, and `|| true` made the cancellation look like a run.

Three modes, stdlib only:

  files   print the `[not-yet]` files of mutation-scope.toml, one per line.
  plan    pack them into shards and print a GitHub Actions matrix as JSON.
  report  read each shard's mutants.log and print a markdown table in which a
          shard is MEASURED (cargo-mutants printed its summary) or INCOMPLETE
          (it did not). Exits 1 if ANY shard is INCOMPLETE.

THE LIST IS DERIVED, NEVER COPIED. REQ-MUTATE-003 exists because a hand-kept
file list drifted (`linestatus.rs` fell outside the gate and nothing noticed).
The workflow therefore never names a debt file: `plan` reads the TOML on every
run, so a file added to `[not-yet]` is sharded tomorrow night without anyone
editing a workflow, and a file promoted into the gate leaves the debt run.

SHARD SIZE. MEASURED on hosted ubuntu-latest: about 7 mutants per minute at
`-j 4`, and the job cap is 90 minutes, so a shard that must finish inside the
cap holds at most ~630 mutants with zero headroom. The default target is 300
(~43 minutes), which leaves room for a slow-test file and the baseline build. A
single file larger than the target gets its own shard rather than being split:
cargo-mutants selects by file, and a file that alone exceeds the cap is a fact
to be shown as INCOMPLETE, not hidden by packing.

Packing is first-fit-decreasing: sort by count, put each file in the first shard
it fits. Deterministic (ties broken by path) so a re-run shards identically.

INCOMPLETE IS NOT ZERO. A cancelled or OOM-killed job prints no summary, and
"0 missed" read off an empty log is the exact lie this tool exists to refuse. So
`report` takes the EXPECTED shards from the plan's matrix, not from whatever
logs happen to exist: a shard whose job was cancelled before it uploaded
anything has no log at all, and is INCOMPLETE too.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tomllib

DEFAULT_TARGET = 300
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SUMMARY = re.compile(r"(\d+) mutants? tested in\b")
FIELD = re.compile(r"(\d+) (caught|missed|unviable|timeouts?)\b")


def debt_files(scope_path):
    with open(scope_path, "rb") as f:
        doc = tomllib.load(f)
    files = sorted(doc.get("not-yet") or {})
    if not files:
        raise SystemExit(
            f"{scope_path} has no [not-yet] files — an empty plan must not read "
            "as 'no debt to measure'; the table is being read wrongly"
        )
    return files


def count_lines(text):
    return sum(1 for line in text.splitlines() if line.strip())


def count_with_cargo(files):
    """Mutants per file via `cargo mutants --list` (cheap: no builds)."""
    counts = {}
    for f in files:
        r = subprocess.run(
            ["cargo", "mutants", "--list", "--no-shuffle", "-f", f],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise SystemExit(f"cargo mutants --list -f {f} failed:\n{r.stderr}")
        counts[f] = count_lines(r.stdout)
    return counts


def pack(counts, target):
    """First-fit-decreasing into shards of at most `target` mutants."""
    shards = []  # each: [total, [files]]
    for f in sorted(counts, key=lambda p: (-counts[p], p)):
        n = counts[f]
        for s in shards:
            if s[0] + n <= target:
                s[0] += n
                s[1].append(f)
                break
        else:
            shards.append([n, [f]])
    return shards


def cmd_files(a):
    print("\n".join(debt_files(a.scope)))
    return 0


def cmd_plan(a):
    files = debt_files(a.scope)
    if a.counts:
        with open(a.counts) as fh:
            counts = json.load(fh)
    else:
        counts = count_with_cargo(files)
    missing = [f for f in files if f not in counts]
    if missing:
        print("::error::no mutant count for: " + ", ".join(missing)
              + " — a file that cannot be placed would silently leave the debt "
                "unmeasured", file=sys.stderr)
        return 1
    shards = pack({f: counts[f] for f in files}, a.target)
    include = []
    for i, (total, fs) in enumerate(shards, 1):
        fs = sorted(fs)
        include.append({
            "shard": f"debt-{i:02d}",
            "count": total,
            "files": fs,
            "flags": " ".join(f"-f {f}" for f in fs),
        })
    placed = sorted(f for s in include for f in s["files"])
    if placed != files:  # defence: the invariant the requirement states
        print("::error::plan did not place every not-yet file exactly once",
              file=sys.stderr)
        return 1
    print(json.dumps({"include": include}))
    return 0


def parse_summary(text):
    """Counts from cargo-mutants' final summary line, or None if it never came."""
    line = None
    for raw in text.splitlines():
        raw = ANSI.sub("", raw)
        if SUMMARY.search(raw):
            line = raw
    if line is None:
        return None
    res = {"tested": int(SUMMARY.search(line).group(1)),
           "caught": 0, "missed": 0, "unviable": 0, "timeouts": 0}
    for n, k in FIELD.findall(line):
        res["timeouts" if k.startswith("timeout") else k] = int(n)
    return res


def cmd_report(a):
    with open(a.matrix) as fh:
        shards = json.load(fh)["include"]
    rows, incomplete = [], 0
    tot = {"tested": 0, "caught": 0, "missed": 0, "unviable": 0, "timeouts": 0}
    for s in shards:
        path = os.path.join(a.logs, f"mutants-{s['shard']}", "mutants.log")
        try:
            with open(path, errors="replace") as fh:
                res = parse_summary(fh.read())
        except OSError:
            res = None
        nfiles = len(s["files"])
        if res is None:
            incomplete += 1
            rows.append(f"| {s['shard']} | {nfiles} | {s['count']} | INCOMPLETE | - | - | - | - |")
            continue
        for k in tot:
            tot[k] += res[k]
        rows.append(
            f"| {s['shard']} | {nfiles} | {s['count']} | MEASURED | {res['tested']} "
            f"| {res['missed']} | {res['timeouts']} | {res['unviable']} |"
        )
    print("## Mutation debt (advisory)\n")
    print("| shard | files | planned | status | tested | missed | timeouts | unviable |")
    print("|---|---|---|---|---|---|---|---|")
    print("\n".join(rows))
    print()
    measured = len(shards) - incomplete
    if measured:
        print(f"{measured} of {len(shards)} shards have a summary; across those "
              f"{tot['tested']} mutants were tested, {tot['missed']} missed, "
              f"{tot['timeouts']} timed out.")
    else:
        print(f"No shard produced a summary: nothing was measured.")
    if incomplete:
        print(f"\n**{incomplete} shard(s) INCOMPLETE — no cargo-mutants summary. "
              "Those files were NOT measured; this is not a zero-missed result.**")
        return 1
    if tot["timeouts"]:
        print("\nTimed-out mutants are ones the suite never finished under "
              "(detection, not silence); named in each shard's mutants.log.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("files")
    f.add_argument("--scope", default="mutation-scope.toml")
    f.set_defaults(fn=cmd_files)
    pl = sub.add_parser("plan")
    pl.add_argument("--scope", default="mutation-scope.toml")
    pl.add_argument("--counts", help="JSON {file: mutants}; default: ask cargo mutants --list")
    pl.add_argument("--target", type=int, default=DEFAULT_TARGET)
    pl.set_defaults(fn=cmd_plan)
    r = sub.add_parser("report")
    r.add_argument("--matrix", required=True)
    r.add_argument("--logs", required=True, help="dir holding mutants-<shard>/mutants.log")
    r.set_defaults(fn=cmd_report)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
