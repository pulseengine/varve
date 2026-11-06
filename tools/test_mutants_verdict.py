#!/usr/bin/env python3
"""Tests for tools/mutants-verdict.py, the trust-critical mutation shard's verdict.

Run: python3 -m unittest discover -s tools -p 'test_*.py'

REQ-MUTATE-001: a mutation shard passes only on evidence that it tested
something. Before this tool the verdict lived inline in ci.yml and looked for
`N missed` alone, so `5 mutants tested in 1s: 5 unviable` and
`0 mutants tested in 0s` both passed with nothing caught (#319, item 1).
"""
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "mutants_verdict", os.path.join(HERE, "mutants-verdict.py")
)
mv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mv)


def verdict(log):
    """(exit code, messages) for a mutants.log with this content."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(log)
        path = f.name
    try:
        return mv.verdict(path)
    finally:
        os.unlink(path)


class Passes(unittest.TestCase):
    def test_a_shard_that_caught_mutants_and_missed_none_passes(self):
        code, _ = verdict("...\n46 mutants tested in 6m: 35 caught, 11 unviable\n")
        self.assertEqual(code, 0)

    def test_timeouts_are_detection_and_pass_beside_caught(self):
        code, msgs = verdict("40 mutants tested in 9m: 30 caught, 8 unviable, 2 timeouts\n")
        self.assertEqual(code, 0)
        self.assertTrue(any(m.startswith("::warning::") for m in msgs), msgs)

    def test_the_singular_form_cargo_mutants_prints_for_one_mutant_is_read(self):
        code, _ = verdict("1 mutant tested in 3s: 1 caught\n")
        self.assertEqual(code, 0)

    def test_a_summary_coloured_with_ansi_escapes_is_read(self):
        # cargo-mutants colours its summary on a terminal (the same shape is
        # in test_mutant_debt_plan.py); colour must not change the verdict.
        log = "\x1b[1m46 mutants tested in 5m\x1b[0m: \x1b[32m35 caught\x1b[0m, 11 unviable\n"
        self.assertEqual(verdict(log)[0], 0)
        log = "\x1b[1m46 mutants tested in 5m\x1b[0m: \x1b[31m1 missed\x1b[0m, 34 caught\n"
        self.assertEqual(verdict(log)[0], 1)

    def test_only_the_last_summary_counts(self):
        log = "3 mutants tested in 1s: 1 missed, 2 caught\n...\n9 mutants tested in 2m: 9 caught\n"
        self.assertEqual(verdict(log)[0], 0)


class Fails(unittest.TestCase):
    def test_no_summary_fails(self):
        code, msgs = verdict("Found 12 mutants to test\nKilled\n")
        self.assertEqual(code, 1)
        self.assertIn("no summary", " ".join(msgs))

    def test_a_survivor_fails(self):
        code, msgs = verdict("46 mutants tested in 6m: 1 missed, 34 caught, 11 unviable\n")
        self.assertEqual(code, 1)
        self.assertIn("SURVIVED", " ".join(msgs))

    # The two fabricated logs from #319.
    def test_a_shard_whose_every_mutant_was_unviable_fails(self):
        code, msgs = verdict("5 mutants tested in 1s: 5 unviable\n")
        self.assertEqual(code, 1)
        self.assertIn("caught nothing", " ".join(msgs))

    def test_a_shard_that_tested_no_mutants_fails(self):
        code, msgs = verdict("0 mutants tested in 0s\n")
        self.assertEqual(code, 1)
        self.assertIn("tested no mutants", " ".join(msgs))

    def test_a_summary_the_tool_cannot_read_fails_closed(self):
        # A format change must not read as "0 missed".
        code, _ = verdict("46 mutants tested in 6m: thirty-five caught\n")
        self.assertEqual(code, 1)

    def test_a_missing_log_fails(self):
        code, _ = mv.verdict(os.path.join(HERE, "no-such-mutants.log"))
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
