#!/usr/bin/env python3
"""Tests for tools/mutant-debt-plan.py (REQ-MUTANTDEBT-001).

Run: python3 -m unittest discover -s tools -p 'test_*.py'

Python tests are not scanned by tools/trace-gate.py (it reads `.rs` only), so
the marker below is documentation for a reader; the edge that trace-gate counts
is VER-MUTANTDEBT-001's `verifies` link.
"""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "mutant_debt_plan", os.path.join(HERE, "mutant-debt-plan.py")
)
mdp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mdp)

SCOPE = """
[bin-target]
"crates/x/src/main.rs" = "cli"

[not-yet]
"crates/a/src/one.rs" = "r"
"crates/a/src/two.rs" = "r"
"crates/a/src/three.rs" = "r"
"crates/a/src/big.rs" = "r"
"""

COUNTS = {
    "crates/a/src/one.rs": 100,
    "crates/a/src/two.rs": 120,
    "crates/a/src/three.rs": 90,
    "crates/a/src/big.rs": 800,
}

def full_log(n, missed=12, unviable=18):
    """A finished shard log that tested exactly `n` mutants."""
    caught = n - missed - unviable
    return (
        f"Found {n} mutants to test\n"
        f"{n} mutants tested in 41m: {missed} missed, {caught} caught, {unviable} unviable\n"
    )


FULL_LOG = full_log(300)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = mdp.main(argv)
        except SystemExit as e:  # argparse
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scope = self.write("scope.toml", SCOPE)
        self.counts = self.write("counts.json", json.dumps(COUNTS))

    def write(self, name, text):
        p = os.path.join(self.tmp.name, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def plan(self, scope=None, counts=None, target=300):
        code, out, err = run(
            ["plan", "--scope", scope or self.scope,
             "--counts", counts or self.counts, "--target", str(target)]
        )
        return code, out, err


# rivet: verifies REQ-MUTANTDEBT-001
class PlanTests(Fixture):
    def test_every_not_yet_file_placed_exactly_once(self):
        code, out, _ = self.plan()
        self.assertEqual(code, 0)
        matrix = json.loads(out)
        placed = [f for s in matrix["include"] for f in s["files"]]
        self.assertEqual(sorted(placed), sorted(COUNTS))
        self.assertEqual(len(placed), len(set(placed)))

    def test_file_over_target_gets_its_own_shard(self):
        _, out, _ = self.plan()
        shards = json.loads(out)["include"]
        big = [s for s in shards if "crates/a/src/big.rs" in s["files"]]
        self.assertEqual(len(big), 1)
        self.assertEqual(big[0]["files"], ["crates/a/src/big.rs"])

    def test_small_files_pack_up_to_target(self):
        _, out, _ = self.plan()
        for s in json.loads(out)["include"]:
            if s["files"] != ["crates/a/src/big.rs"]:
                self.assertLessEqual(s["count"], 300)
        small = [s for s in json.loads(out)["include"] if s["count"] != 800]
        self.assertEqual(len(small), 2)  # 120+100 / 90 is not forced into 3

    def test_flags_string_is_cargo_mutants_flags(self):
        _, out, _ = self.plan()
        for s in json.loads(out)["include"]:
            self.assertEqual(
                s["flags"], " ".join(f"-f {f}" for f in s["files"])
            )

    def test_derived_from_toml_not_hand_copied(self):
        extra = SCOPE + '"crates/a/src/new.rs" = "r"\n'
        scope2 = self.write("scope2.toml", extra)
        counts2 = self.write("counts2.json", json.dumps({**COUNTS, "crates/a/src/new.rs": 5}))
        _, out, _ = self.plan(scope=scope2, counts=counts2)
        placed = [f for s in json.loads(out)["include"] for f in s["files"]]
        self.assertIn("crates/a/src/new.rs", placed)

    def test_other_sections_are_not_debt(self):
        _, out, _ = self.plan()
        self.assertNotIn("main.rs", out)

    def test_file_without_a_count_fails(self):
        c = dict(COUNTS)
        del c["crates/a/src/two.rs"]
        code, _, err = self.plan(counts=self.write("c.json", json.dumps(c)))
        self.assertNotEqual(code, 0)
        self.assertIn("two.rs", err)

    def test_empty_not_yet_fails_rather_than_emitting_an_empty_matrix(self):
        scope = self.write("e.toml", "[not-yet]\n")
        code, _, _ = self.plan(scope=scope)
        self.assertNotEqual(code, 0)

    def test_shard_names_unique(self):
        _, out, _ = self.plan()
        names = [s["shard"] for s in json.loads(out)["include"]]
        self.assertEqual(len(names), len(set(names)))

    def test_files_mode_lists_the_debt(self):
        code, out, _ = run(["files", "--scope", self.scope])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(out.split()), sorted(COUNTS))

    def test_count_lines_ignores_blanks(self):
        self.assertEqual(mdp.count_lines("a\n\nb\n  \nc\n"), 3)


# rivet: verifies REQ-MUTANTDEBT-001
class ReportTests(Fixture):
    def setUp(self):
        super().setUp()
        _, out, _ = self.plan()
        self.matrix_text = out
        self.matrix = self.write("matrix.json", out)
        self.shards = [s["shard"] for s in json.loads(out)["include"]]
        # What the plan said each shard holds: a finished log must agree.
        self.planned = {s["shard"]: s["count"] for s in json.loads(out)["include"]}

    def log(self, shard, text):
        self.write(f"logs/mutants-{shard}/mutants.log", text)

    def report(self):
        return run(["report", "--matrix", self.matrix,
                    "--logs", os.path.join(self.tmp.name, "logs")])

    def all_full(self):
        for s in self.shards:
            self.log(s, full_log(self.planned[s]))

    def test_all_summaries_measured_exit_zero(self):
        self.all_full()
        code, out, _ = self.report()
        self.assertEqual(code, 0)
        self.assertNotIn("INCOMPLETE", out)
        self.assertIn("MEASURED", out)
        self.assertIn("12", out)  # the missed count is shown
        self.assertIn("missed", out)

    def test_log_truncated_before_summary_is_incomplete_and_fails(self):
        self.all_full()
        self.log(self.shards[0], "Found 300 mutants to test\nok src/x.rs:1: replace a\n")
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        self.assertIn("INCOMPLETE", out)
        row = [l for l in out.splitlines() if self.shards[0] in l][0]
        self.assertNotIn("MEASURED", row)
        self.assertNotIn("| 0 |", row)  # never zero missed

    def test_empty_log_is_incomplete(self):
        self.all_full()
        self.log(self.shards[0], "")
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        self.assertIn("INCOMPLETE", out)

    def test_missing_artifact_is_incomplete(self):
        for s in self.shards[1:]:
            self.log(s, full_log(self.planned[s]))
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        row = [l for l in out.splitlines() if self.shards[0] in l][0]
        self.assertIn("INCOMPLETE", row)

    def test_no_logs_dir_at_all_is_all_incomplete(self):
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        rows = [l for l in out.splitlines() if l.startswith("| debt-")]
        self.assertEqual(len(rows), len(self.shards))
        self.assertTrue(all("INCOMPLETE" in r for r in rows))
        self.assertNotIn("MEASURED", out)

    def test_timeouts_are_reported_but_still_measured(self):
        self.all_full()
        n = self.planned[self.shards[0]]
        self.log(
            self.shards[0],
            f"{n} mutants tested in 50m: 0 missed, {n - 20} caught, 10 unviable, 10 timeouts\n",
        )
        code, out, _ = self.report()
        self.assertEqual(code, 0)
        row = [l for l in out.splitlines() if self.shards[0] in l][0]
        self.assertIn("MEASURED", row)
        self.assertIn("10", row)
        self.assertIn("timeout", out)

    def test_singular_timeout_and_ansi_are_parsed(self):
        self.all_full()
        n = self.planned[self.shards[0]]
        self.log(
            self.shards[0],
            f"\x1b[1m{n} mutants tested in 5m\x1b[0m: 1 missed, {n - 2} caught, 1 timeout\n",
        )
        code, out, _ = self.report()
        self.assertEqual(code, 0)
        self.assertIn("MEASURED", [l for l in out.splitlines() if self.shards[0] in l][0])

    # THE GAP THIS CLOSES: a summary line proves cargo-mutants FINISHED
    # something, not that it finished THE SHARD. A log reading "12 mutants
    # tested" for a shard planned at 314 was MEASURED and exited 0.
    def test_a_summary_for_fewer_mutants_than_planned_is_incomplete(self):
        self.all_full()
        shard = self.shards[0]
        planned = self.planned[shard]
        self.log(shard, full_log(12, missed=1, unviable=1))
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        row = [l for l in out.splitlines() if l.startswith(f"| {shard} ")][0]
        self.assertIn("INCOMPLETE", row)
        self.assertNotIn("MEASURED", row)
        # The numbers are shown, so a reader sees how far it got.
        self.assertIn(f"tested 12 of {planned} planned", row)
        self.assertNotIn("| 0 |", row)

    def test_a_summary_for_more_mutants_than_planned_is_incomplete_too(self):
        self.all_full()
        shard = self.shards[0]
        planned = self.planned[shard]
        self.log(shard, full_log(planned + 30))
        code, out, _ = self.report()
        self.assertNotEqual(code, 0)
        row = [l for l in out.splitlines() if l.startswith(f"| {shard} ")][0]
        self.assertIn("INCOMPLETE", row)
        self.assertIn("plan and run disagree", row)
        self.assertIn(f"tested {planned + 30}, planned {planned}", row)

    def test_a_shard_that_tested_exactly_what_was_planned_is_measured(self):
        self.all_full()
        code, out, _ = self.report()
        self.assertEqual(code, 0)
        rows = [l for l in out.splitlines() if l.startswith("| debt-")]
        self.assertTrue(all("MEASURED" in r for r in rows), rows)

    def test_an_incomplete_shard_adds_nothing_to_the_measured_totals(self):
        self.all_full()
        shard = self.shards[0]
        self.log(shard, full_log(12, missed=11, unviable=0))
        _, out, _ = self.report()
        others = sum(self.planned[s] for s in self.shards[1:])
        self.assertIn(f"{others} mutants were tested", out)
        self.assertIn(f"{len(self.shards) - 1} of {len(self.shards)} shards have a summary", out)

    def test_the_closing_line_names_both_kinds_of_incomplete(self):
        self.all_full()
        self.log(self.shards[0], full_log(12, missed=1, unviable=1))
        _, out, _ = self.report()
        self.assertIn("does not match the plan", out)
        self.assertIn("NOT measured", out)

    def test_parse_summary(self):
        self.assertEqual(
            mdp.parse_summary(FULL_LOG),
            {"tested": 300, "caught": 270, "missed": 12, "unviable": 18, "timeouts": 0},
        )
        self.assertIsNone(mdp.parse_summary("Found 3 mutants to test\n"))


if __name__ == "__main__":
    unittest.main()
