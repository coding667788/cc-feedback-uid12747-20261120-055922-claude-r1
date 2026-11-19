"""Cross-check the engine against the independent read-only reference model."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

import support

from solution.runner import run_case

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_OPS = [
    {"op": "register_objects", "objects": {
        "O1": "alpha-1", "O2": "beta-2", "O9": "rogue-9"}},
    {"op": "register_key", "key_id": "k-root", "secret": "root-secret"},
    {"op": "register_key", "key_id": "k-rel", "secret": "rel-secret"},
]


def make_case(case_id, device_entries, ops):
    return {
        "case_id": case_id,
        "ops": BASE_OPS + [
            {"op": "create_device", "device": "d1", "baseline": {
                "version": 1, "entries": device_entries, "sign_with": "k-root"}},
        ] + ops,
    }


def full_segment(batch, observations):
    return {"op": "submit_segment", "device": "d1", "batch": batch,
            "segment_count": 1, "index": 0, "observations": observations}


class ReferenceCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fim-ref-")
        self.db = os.path.join(self.tmp.name, "ref.db")
        self.addCleanup(self.tmp.cleanup)

    def run_and_check(self, case):
        result = run_case(case, self.db)
        self.assertTrue(
            result["reference"]["match"],
            f"reference mismatch: {result['reference']['mismatches']}",
        )
        return result

    def test_path_case_folding(self):
        case = make_case(
            "ref-case-fold",
            [["C:/App/A.EXE", "O1"], ["C:/App/b.exe", "O2"]],
            [
                full_segment("b1", {"c:/app/a.exe": "O1", "C:/APP/B.EXE": "O2"}),
                {"op": "precheck", "device": "d1", "batch": "b1"},
                {"op": "commit", "precheck": "last"},
            ],
        )
        result = self.run_and_check(case)
        pre = result["ops"][5]["result"]
        self.assertEqual(pre["alerts"], [])
        commit = result["ops"][6]["result"]
        self.assertEqual(commit["receipt"]["alert_count"], 0)

    def test_same_object_multiple_aliases(self):
        case = make_case(
            "ref-alias",
            [["C:/App/a.exe", "O1"], ["C:/App/b.exe", "O1"], ["C:/App/c.dll", "O2"]],
            [
                # Both aliases observed consistently -> clean.
                full_segment("b1", {"C:/App/a.exe": "O1", "C:/App/b.exe": "O1",
                                    "C:/App/c.dll": "O2"}),
                {"op": "precheck", "device": "d1", "batch": "b1"},
                {"op": "commit", "precheck": "last"},
                # One alias retargeted to another trusted object -> alias_change.
                full_segment("b2", {"C:/App/a.exe": "O2", "C:/App/b.exe": "O1",
                                    "C:/App/c.dll": "O2"}),
                {"op": "precheck", "device": "d1", "batch": "b2"},
                {"op": "commit", "precheck": "last"},
            ],
        )
        result = self.run_and_check(case)
        self.assertEqual(result["ops"][5]["result"]["alerts"], [])
        alerts = result["ops"][8]["result"]["alerts"]
        self.assertEqual(
            [(a["kind"], a["path"]) for a in alerts],
            [("alias_change", "C:/app/a.exe")],
        )

    def test_same_name_new_object(self):
        case = make_case(
            "ref-new-object",
            [["C:/App/a.exe", "O1"], ["C:/App/b.exe", "O2"]],
            [
                full_segment("b1", {"C:/App/a.exe": "O9", "C:/App/b.exe": "O2"}),
                {"op": "precheck", "device": "d1", "batch": "b1"},
                {"op": "commit", "precheck": "last"},
            ],
        )
        result = self.run_and_check(case)
        alerts = result["ops"][5]["result"]["alerts"]
        self.assertEqual(
            [(a["kind"], a["path"], a["base_oid"], a["new_oid"]) for a in alerts],
            [("content_change", "C:/app/a.exe", "O1", "O9")],
        )
        # Trust unchanged by attestation.
        self.assertEqual(result["final_views"]["d1"]["trusted_objects"], ["O1", "O2"])

    def test_approved_content_revoked_by_release(self):
        case = make_case(
            "ref-revoked-content",
            [["C:/App/a.exe", "O1"], ["C:/App/b.exe", "O2"]],
            [
                # Release v2 drops b.exe; O2 approval is revoked.
                full_segment("b1", {"C:/App/a.exe": "O1"}),
                {"op": "precheck", "device": "d1", "batch": "b1", "release": {
                    "version": 2,
                    "entries": [["C:/App/a.exe", "O1"]],
                    "sign_with": "k-rel",
                }},
                {"op": "commit", "precheck": "last"},
                # O2 reappears: previously approved, now untrusted.
                full_segment("b2", {"C:/App/a.exe": "O2"}),
                {"op": "precheck", "device": "d1", "batch": "b2"},
                {"op": "commit", "precheck": "last"},
            ],
        )
        result = self.run_and_check(case)
        release = result["ops"][5]["result"]
        self.assertEqual(
            [(a["kind"], a["path"]) for a in release["alerts"]],
            [("legit_release", "C:/app/b.exe")],
        )
        alerts = result["ops"][8]["result"]["alerts"]
        self.assertEqual(
            [(a["kind"], a["path"], a["new_oid"]) for a in alerts],
            [("content_change", "C:/app/a.exe", "O2")],
        )
        self.assertEqual(result["final_views"]["d1"]["trusted_objects"], ["O1"])


class ShippedCaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fim-case-")
        self.db = os.path.join(self.tmp.name, "case.db")
        self.addCleanup(self.tmp.cleanup)

    def test_shipped_cases_json_matches_reference(self):
        with open(os.path.join(REPO_ROOT, "cases.json"), "r", encoding="utf-8") as fh:
            case = json.load(fh)
        result = run_case(case, self.db)
        self.assertTrue(
            result["reference"]["match"],
            f"reference mismatch: {result['reference']['mismatches']}",
        )
        errors = {op["index"]: op["code"] for op in result["ops"]
                  if op["status"] == "error"}
        self.assertEqual(errors, {
            14: "ERR_INCOMPLETE_OBSERVATION",
            16: "ERR_BATCH_CLOSED",
            35: "ERR_BASELINE_SWAPPED",
            39: "ERR_SIGNER_REVOKED",
            41: "ERR_BAD_SIGNATURE",
            45: "ERR_GENERATION_CHANGED",
        })
        view = result["final_views"]["dev-1"]
        self.assertEqual(view["generation"], 2)
        self.assertEqual(view["version"], 10)
        self.assertEqual(view["trusted_objects"], ["O1", "O2"])

    def test_cli_end_to_end(self):
        out = os.path.join(self.tmp.name, "result.json")
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", os.path.join(REPO_ROOT, "cases.json"),
             "--output", out],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out, "r", encoding="utf-8") as fh:
            result = json.load(fh)
        self.assertTrue(result["reference"]["match"])
        self.assertEqual(len(result["ops"]), 47)


if __name__ == "__main__":
    unittest.main()
