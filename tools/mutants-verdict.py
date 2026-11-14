#!/usr/bin/env python3
"""The verdict of one trust-critical mutation shard, read from its mutants.log.

Usage: mutants-verdict.py [mutants.log]    exit 0 = pass, 1 = fail

REQ-MUTATE-001. A shard passes only on evidence that it TESTED something:

  * the log carries a cargo-mutants summary ("N mutant(s) tested in ..."),
    and only the LAST one counts;
  * every count in it is one this tool understands. An unknown word or a
    changed format fails closed rather than reading as "0 missed";
  * nothing was missed: neither in the summary nor as a `MISSED` line, which
    cargo-mutants writes per survivor (#352: a log naming a survivor beside a
    clean summary used to pass);
  * at least one mutant was tested; and
  * at least one was caught or timed out. A timeout is a mutant the suite never
    finished under, which is detection, not silence.

The last two were added for #319. The previous inline check in ci.yml looked
only for "N missed", so `5 mutants tested in 1s: 5 unviable` (every mutant
failed to build) and `0 mutants tested in 0s` (the file list matched nothing)
both passed with nothing caught.

Output lines are GitHub workflow commands (::notice:: / ::warning:: /
::error::). Python 3.9 floor: no `X | None`, no match statements.
"""
import re
import sys

SUMMARY = re.compile(r"([0-9]+) mutants? tested in [^:\n]*(?::(.*))?$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
MISSED_LINE = re.compile(r"^MISSED\s+(\S.*)$")
COUNT = re.compile(r"^([0-9]+) (missed|caught|unviable|timeouts?|failed|success)$")


def verdict(path):
    """(exit code, list of workflow-command lines) for the log at `path`."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return 1, ["::error::cannot read %s: %s — the gate did not run" % (path, e)]

    lines = [l.strip() for l in ANSI.sub("", text).splitlines()]
    survivors = [m.group(1) for m in (MISSED_LINE.match(l) for l in lines) if m]
    found = [m for m in (SUMMARY.search(l) for l in lines) if m]
    if not found:
        return 1, ["::error::cargo-mutants produced no summary — the gate did not run"]
    last = found[-1]
    summary = last.group(0)
    msgs = ["::notice::" + summary]

    tested = int(last.group(1))
    counts = {}
    tail = (last.group(2) or "").strip()
    for part in [p.strip() for p in tail.split(",")] if tail else []:
        m = COUNT.match(part)
        if not m:
            return 1, msgs + [
                "::error::cannot read '%s' in the summary — a format this gate "
                "does not understand fails, it does not pass" % part
            ]
        word = "timeouts" if m.group(2).startswith("timeout") else m.group(2)
        counts[word] = counts.get(word, 0) + int(m.group(1))

    if survivors:
        return 1, msgs + ["::error::SURVIVED: %s" % s for s in survivors]
    missed = counts.get("missed", 0)
    if missed:
        return 1, msgs + ["::error::%d mutant(s) SURVIVED — a change nothing noticed" % missed]
    if tested == 0:
        return 1, msgs + [
            "::error::the shard tested no mutants — its file list matched nothing, "
            "so it is evidence of nothing"
        ]
    detected = counts.get("caught", 0) + counts.get("timeouts", 0)
    if detected == 0:
        return 1, msgs + [
            "::error::the shard caught nothing: %d mutant(s) tested, none caught "
            "or timed out (all unviable?) — a shard that cannot kill a mutant "
            "proves nothing about its tests" % tested
        ]
    if counts.get("timeouts", 0):
        msgs.append(
            "::warning::%s — timed-out mutants are ones the suite never finished "
            "under, which is detection, not silence. Named in the log." % summary
        )
    return 0, msgs


def main(argv):
    code, msgs = verdict(argv[1] if len(argv) > 1 else "mutants.log")
    print("\n".join(msgs))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
