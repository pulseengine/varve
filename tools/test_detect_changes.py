#!/usr/bin/env python3
"""Tests for tools/ci/detect-changes.sh under temper's gate probe.

Run: python3 -m unittest discover -s tools -p 'test_*.py'

temper's probe (temper docs/gate-probe.md) runs the detector with
GATE_PROBE_FILES naming the changed paths and NO other environment. A detector
that answers "run everything" for an unknown event would pass every probe
without classifying anything, so these tests also need one path that must come
back code=false. Without it, the probe proves nothing.
"""
import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DETECTOR = os.path.join(ROOT, "tools", "ci", "detect-changes.sh")
CONTRACT = os.path.join(ROOT, ".github", "gate-probe.json")

# temper's default controls: each must classify as code.
DEFAULT_CONTROLS = [
    "docs/gate-probe-control.rs",
    "supply-chain/gate-probe-control.toml",
    "gate-probe-new-dir/control.bin",
]

# The negative control: a Markdown file outside crates/ whose basename nothing
# in source, a workflow or tools/ mentions. It must classify as NOT code.
# Built from two pieces ON PURPOSE: the detector greps tools/ for the
# basename, and this file is in tools/, so writing the name whole here would
# make it "referenced" and therefore code.
NOT_CODE = "gate-probe-" + "not-code.md"


def classify(paths, env_extra=None, cwd=ROOT):
    """Run the detector the way the probe does; return its `code` output."""
    with tempfile.TemporaryDirectory() as tmp:
        listing = os.path.join(tmp, "files")
        out = os.path.join(tmp, "output")
        with open(listing, "w") as f:
            f.write("\n".join(paths) + ("\n" if paths else ""))
        open(out, "w").close()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "GATE_PROBE_FILES": listing, "GITHUB_OUTPUT": out}
        if env_extra:
            env.update(env_extra)
        subprocess.run([DETECTOR], cwd=cwd, env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        values = {}
        with open(out) as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                values[k] = v
        return values.get("code")


class GateProbe(unittest.TestCase):
    def test_the_contract_names_the_detector_and_its_output(self):
        with open(CONTRACT) as f:
            c = json.load(f)
        self.assertEqual(c["version"], 1)
        (d,) = c["detectors"]
        self.assertEqual(d["command"], ["tools/ci/detect-changes.sh"])
        self.assertEqual(d["outputs"], ["code"])

    def test_every_default_and_declared_control_runs_everything(self):
        with open(CONTRACT) as f:
            declared = json.load(f)["detectors"][0]["controls"]
        for path in DEFAULT_CONTROLS + declared:
            with self.subTest(path=path):
                self.assertEqual(classify([path]), "true")

    def test_the_negative_control_is_not_code(self):
        # Fails if the probe branch falls through to the event check (no
        # EVENT_NAME runs everything), which is the vacuous-probe shape.
        self.assertEqual(classify([NOT_CODE]), "false")

    def test_the_contract_declares_the_negative_control(self):
        # `negative_controls` is the field spar#612 uses and that has been
        # proposed to temper. Every entry must classify as NOT code; the
        # one this file builds in pieces must be among them.
        with open(CONTRACT) as f:
            negatives = json.load(f)["detectors"][0]["negative_controls"]
        self.assertIn(NOT_CODE, negatives)
        for path in negatives:
            with self.subTest(path=path):
                self.assertEqual(classify([path]), "false")

    def test_the_probe_s_event_variables_do_not_change_the_answer(self):
        # temper#87: the probe also sets EVENT_NAME / GITHUB_EVENT_NAME to
        # pull_request, with no BASE_SHA. GATE_PROBE_FILES must still decide.
        ev = {"EVENT_NAME": "pull_request", "GITHUB_EVENT_NAME": "pull_request"}
        self.assertEqual(classify([NOT_CODE], ev), "false")
        self.assertEqual(classify(["docs/gate-probe-control.rs"], ev), "true")

    def test_one_code_path_among_docs_runs_everything(self):
        self.assertEqual(classify([NOT_CODE, "Cargo.toml"]), "true")

    def test_an_empty_listing_runs_everything(self):
        self.assertEqual(classify([]), "true")

    def test_an_unreadable_listing_runs_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "output")
            open(out, "w").close()
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "GATE_PROBE_FILES": os.path.join(tmp, "missing"),
                   "GITHUB_OUTPUT": out}
            subprocess.run([DETECTOR], cwd=ROOT, env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with open(out) as f:
                self.assertIn("code=true", f.read())

    def test_a_referenced_markdown_file_is_code(self):
        # README.md is include_str!'d by crates/varve/src/docs.rs.
        self.assertEqual(classify(["README.md"]), "true")

    def test_a_failing_git_grep_runs_everything(self):
        # #352 item 2: outside a git repository `git grep` exits 128, which the
        # detector read as "not referenced" and classified docs as not code.
        with tempfile.TemporaryDirectory() as notrepo:
            self.assertEqual(classify([NOT_CODE], cwd=notrepo), "true")


if __name__ == "__main__":
    unittest.main()
