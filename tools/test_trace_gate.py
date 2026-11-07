#!/usr/bin/env python3
"""Tests for tools/trace-gate.py's rule for what counts as `verifies` evidence.

Run: python3 -m unittest discover -s tools -p 'test_*.py'

#333, item 3: a `draft` verification with `steps: []` and a `verifies` edge
satisfied the gate for a `verified` requirement, although nothing in it runs.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "trace_gate", os.path.join(HERE, "trace-gate.py")
)
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)


def ver(status="verified", **fields):
    return {
        "id": "VER-X-001",
        "type": "verification",
        "status": status,
        "fields": fields,
        "links": [{"type": "verifies", "target": "REQ-X-001"}],
    }


def counted(a):
    incoming, ignored = tg.edges({a["id"]: a})
    return "REQ-X-001" in incoming, ignored


class EvidenceRule(unittest.TestCase):
    def test_a_draft_verification_does_not_count_even_with_steps(self):
        ok, ignored = counted(ver("draft", method="test", steps=[{"run": "cargo test"}]))
        self.assertFalse(ok)
        self.assertEqual(ignored, {"REQ-X-001": ["VER-X-001"]})

    def test_an_empty_steps_list_does_not_count(self):
        self.assertFalse(counted(ver(method="test", steps=[]))[0])

    def test_missing_or_blank_steps_do_not_count(self):
        self.assertFalse(counted(ver(method="test"))[0])
        self.assertFalse(counted(ver(method="test", steps="   "))[0])

    def test_steps_as_a_list_count(self):
        self.assertTrue(counted(ver(method="test", steps=[{"run": "cargo test"}]))[0])

    def test_steps_as_a_string_count(self):
        self.assertTrue(counted(ver(method="test", steps="cargo test --workspace"))[0])

    def test_an_inspection_or_review_counts_without_steps(self):
        self.assertTrue(counted(ver("accepted", method="inspection"))[0])
        self.assertTrue(counted(ver(method="review"))[0])

    def test_a_draft_inspection_does_not_count(self):
        self.assertFalse(counted(ver("draft", method="inspection"))[0])

    def test_a_partially_verifies_edge_follows_the_same_rule(self):
        a = ver(method="test", steps=[])
        a["links"] = [{"type": "partially-verifies", "target": "REQ-X-001"}]
        self.assertFalse(counted(a)[0])
        a["fields"]["steps"] = "cargo test"
        self.assertTrue(counted(a)[0])


if __name__ == "__main__":
    unittest.main()
