"""Single-process engine semantics: alerts, gaps, releases, trust rules."""

import os
import tempfile
import unittest

import support
from support import DEVICE, ENTRIES_V1, make_engine, submit_full

from solution.errors import Err, EngineError


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fim-test-")
        self.db = os.path.join(self.tmp.name, "test.db")
        self.eng = make_engine(self.db)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: self.eng.close())

    def commit(self, precheck):
        return self.eng.commit(precheck["precheck_id"])[0]


class TestAttestation(EngineTestCase):
    def test_clean_observation_case_folded_paths_no_alerts(self):
        obs = {
            "c:/APP/a.exe": "O1",
            "C:/app/B.EXE": "O1",
            "C:/App/c.dll": "O2",
            "d:/DATA/D.Dat": "O3",
        }
        submit_full(self.eng, "b1", obs, count=2)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(pre["alerts"], [])
        receipt = self.commit(pre)
        self.assertEqual(receipt["kind"], "attestation")
        self.assertEqual(receipt["version"], 1)
        self.assertEqual(receipt["alert_count"], 0)

    def test_content_change_and_deletion(self):
        obs = {
            "C:/App/a.exe": "O4",   # new object, never authorized
            "C:/App/b.exe": "O1",
            "C:/App/c.dll": "O2",
            "D:/Data/d.dat": None,  # explicitly missing
        }
        submit_full(self.eng, "b1", obs)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(
            [(a["kind"], a["path"], a["base_oid"], a["new_oid"]) for a in pre["alerts"]],
            [
                ("content_change", "C:/app/a.exe", "O1", "O4"),
                ("content_change", "D:/data/d.dat", "O3", None),
            ],
        )
        receipt = self.commit(pre)
        self.assertEqual(receipt["alert_count"], 2)
        # Attestation never mutates trust.
        self.assertEqual(
            self.eng.device_view(DEVICE)["trusted_objects"], ["O1", "O2", "O3"]
        )

    def test_alias_change_to_trusted_object(self):
        obs = {
            "C:/App/a.exe": "O2",   # O2 is trusted via c.dll
            "C:/App/b.exe": "O1",
            "C:/App/c.dll": "O2",
            "D:/Data/d.dat": "O3",
        }
        submit_full(self.eng, "b1", obs)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(len(pre["alerts"]), 1)
        alert = pre["alerts"][0]
        self.assertEqual(alert["kind"], "alias_change")
        self.assertEqual(alert["path"], "C:/app/a.exe")
        self.assertEqual((alert["base_oid"], alert["new_oid"]), ("O1", "O2"))

    def test_same_name_new_object_is_content_change(self):
        obs = {
            "C:/App/a.exe": "O1",
            "C:/App/b.exe": "O1",
            "C:/App/c.dll": "O5",   # registered object, but not trusted
            "D:/Data/d.dat": "O3",
        }
        submit_full(self.eng, "b1", obs)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(len(pre["alerts"]), 1)
        self.assertEqual(pre["alerts"][0]["kind"], "content_change")
        self.assertEqual(pre["alerts"][0]["path"], "C:/app/c.dll")

    def test_multi_alias_consistent_observation(self):
        submit_full(self.eng, "b1", support.clean_observation(), count=2)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(pre["alerts"], [])

    def test_idempotent_commit_single_alert_set(self):
        obs = dict(support.clean_observation())
        obs["C:/App/a.exe"] = "O4"
        submit_full(self.eng, "b1", obs)
        pre = self.eng.precheck(DEVICE, "b1")
        receipt1, cached1 = self.eng.commit(pre["precheck_id"])
        receipt2, cached2 = self.eng.commit(pre["precheck_id"])
        self.assertFalse(cached1)
        self.assertTrue(cached2)
        self.assertEqual(receipt1, receipt2)
        rows = self.eng.store.q("SELECT COUNT(*) AS n FROM alerts WHERE commit_id=?",
                                (receipt1["commit_id"],))
        self.assertEqual(rows[0]["n"], 1)


class TestObservationGaps(EngineTestCase):
    def test_missing_segment_then_late_arrival(self):
        view = self.eng.device_view(DEVICE)
        self.eng.submit_segment({
            "device": DEVICE, "batch": "b1", "segment_count": 2, "index": 0,
            "generation": view["generation"], "baseline_cas": view["baseline_cas"],
            "observations": {"C:/App/a.exe": "O1", "C:/App/b.exe": "O1"},
        })
        with self.assertRaises(EngineError) as cm:
            self.eng.precheck(DEVICE, "b1")
        self.assertEqual(cm.exception.code, Err.INCOMPLETE_OBSERVATION)

        closed = self.eng.close_batch(DEVICE, "b1")
        alerts = self.eng.alerts_for(closed["commit_id"])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["kind"], "data_gap")
        self.assertIn("missing segments [1]", alerts[0]["detail"])

        # The late segment is refused; nothing was reported as vanished.
        with self.assertRaises(EngineError) as cm:
            self.eng.submit_segment({
                "device": DEVICE, "batch": "b1", "segment_count": 2, "index": 1,
                "generation": view["generation"], "baseline_cas": view["baseline_cas"],
                "observations": {"C:/App/c.dll": "O2", "D:/Data/d.dat": "O3"},
            })
        self.assertEqual(cm.exception.code, Err.BATCH_CLOSED)
        kinds = {r["kind"] for r in self.eng.store.q("SELECT kind FROM alerts")}
        self.assertEqual(kinds, {"data_gap"})

        # A fresh, complete batch still commits cleanly.
        submit_full(self.eng, "b2", support.clean_observation(), count=2)
        receipt = self.commit(self.eng.precheck(DEVICE, "b2"))
        self.assertEqual(receipt["alert_count"], 0)

    def test_duplicate_segment_idempotent_and_conflict(self):
        view = self.eng.device_view(DEVICE)
        seg = {
            "device": DEVICE, "batch": "b1", "segment_count": 1, "index": 0,
            "generation": view["generation"], "baseline_cas": view["baseline_cas"],
            "observations": dict(support.clean_observation()),
        }
        first = self.eng.submit_segment(seg)
        second = self.eng.submit_segment(seg)
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        conflicting = dict(seg, observations={"C:/App/a.exe": "O1"})
        with self.assertRaises(EngineError) as cm:
            self.eng.submit_segment(conflicting)
        self.assertEqual(cm.exception.code, Err.DUPLICATE_SEGMENT)

    def test_unknown_object_rejected(self):
        view = self.eng.device_view(DEVICE)
        with self.assertRaises(EngineError) as cm:
            self.eng.submit_segment({
                "device": DEVICE, "batch": "b1", "segment_count": 1, "index": 0,
                "generation": view["generation"], "baseline_cas": view["baseline_cas"],
                "observations": {"C:/App/a.exe": "O9"},
            })
        self.assertEqual(cm.exception.code, Err.UNKNOWN_OBJECT)

    def test_scope_mismatch_unknown_path(self):
        obs = dict(support.clean_observation())
        obs["C:/App/evil.exe"] = "O1"
        submit_full(self.eng, "b1", obs)
        with self.assertRaises(EngineError) as cm:
            self.eng.precheck(DEVICE, "b1")
        self.assertEqual(cm.exception.code, Err.SCOPE_MISMATCH)


class TestReleases(EngineTestCase):
    RELEASE_V2 = {
        "version": 2,
        "entries": [
            ["C:/App/a.exe", "O5"],
            ["C:/App/b.exe", "O5"],
            ["C:/App/c.dll", "O2"],
            ["C:/App/e.exe", "O6"],
        ],
        "sign_with": "k-rel",
    }
    RELEASE_V2_OBS = {
        "C:/App/a.exe": "O5",
        "C:/App/b.exe": "O5",
        "C:/App/c.dll": "O2",
        "C:/App/e.exe": "O6",
    }

    def test_legit_release_flow(self):
        submit_full(self.eng, "b1", self.RELEASE_V2_OBS)
        pre = self.eng.precheck(DEVICE, "b1", self.RELEASE_V2)
        self.assertEqual(pre["kind"], "release")
        self.assertEqual(
            [(a["kind"], a["path"]) for a in pre["alerts"]],
            [
                ("legit_release", "C:/app/a.exe"),
                ("legit_release", "C:/app/b.exe"),
                ("legit_release", "C:/app/e.exe"),
                ("legit_release", "D:/data/d.dat"),
            ],
        )
        receipt = self.commit(pre)
        self.assertEqual(receipt["version"], 2)
        view = self.eng.device_view(DEVICE)
        self.assertEqual(view["trusted_objects"], ["O2", "O5", "O6"])

        # Old content is no longer trusted after the release.
        obs = dict(self.RELEASE_V2_OBS)
        obs["C:/App/a.exe"] = "O1"
        submit_full(self.eng, "b2", obs)
        pre2 = self.eng.precheck(DEVICE, "b2")
        self.assertEqual(
            [(a["kind"], a["path"]) for a in pre2["alerts"]],
            [("content_change", "C:/app/a.exe")],
        )

    def test_release_requires_confirming_observation(self):
        obs = dict(self.RELEASE_V2_OBS)
        obs["C:/App/a.exe"] = "O1"  # device does not match the release
        submit_full(self.eng, "b1", obs)
        with self.assertRaises(EngineError) as cm:
            self.eng.precheck(DEVICE, "b1", self.RELEASE_V2)
        self.assertEqual(cm.exception.code, Err.OBSERVATION_MISMATCH)

    def test_bad_signature_rejected(self):
        submit_full(self.eng, "b1", self.RELEASE_V2_OBS)
        forged = dict(self.RELEASE_V2, sign_with=None)
        forged = {
            "version": 2,
            "entries": self.RELEASE_V2["entries"],
            "key_id": "k-rel",
            "signature": "00" * 32,
        }
        with self.assertRaises(EngineError) as cm:
            self.eng.precheck(DEVICE, "b1", forged)
        self.assertEqual(cm.exception.code, Err.BAD_SIGNATURE)

    def test_revoked_signer_blocks_commit(self):
        submit_full(self.eng, "b1", self.RELEASE_V2_OBS)
        pre = self.eng.precheck(DEVICE, "b1", self.RELEASE_V2)
        self.eng.revoke_key("k-rel")
        with self.assertRaises(EngineError) as cm:
            self.eng.commit(pre["precheck_id"])
        self.assertEqual(cm.exception.code, Err.SIGNER_REVOKED)
        # Trusted view untouched.
        self.assertEqual(self.eng.device_view(DEVICE)["version"], 1)

    def test_trust_not_laundered_by_rename_or_rollback(self):
        # 1. Rogue content observed; it is alerted, never trusted.
        obs = dict(support.clean_observation())
        obs["C:/App/a.exe"] = "OX"
        submit_full(self.eng, "b1", obs)
        self.commit(self.eng.precheck(DEVICE, "b1"))
        self.assertNotIn("OX", self.eng.device_view(DEVICE)["trusted_objects"])

        # 2. Authorized release renames a.exe -> z.exe (same object O1).
        rename = {
            "version": 2,
            "entries": [
                ["C:/App/z.exe", "O1"],
                ["C:/App/b.exe", "O1"],
                ["C:/App/c.dll", "O2"],
                ["D:/Data/d.dat", "O3"],
            ],
            "sign_with": "k-root",
        }
        rename_obs = {
            "C:/App/z.exe": "O1",
            "C:/App/b.exe": "O1",
            "C:/App/c.dll": "O2",
            "D:/Data/d.dat": "O3",
        }
        submit_full(self.eng, "b2", rename_obs)
        self.commit(self.eng.precheck(DEVICE, "b2", rename))
        self.assertNotIn("OX", self.eng.device_view(DEVICE)["trusted_objects"])

        # 3. Authorized rollback to the v1 manifest.
        rollback = {"version": 3, "entries": ENTRIES_V1, "sign_with": "k-root"}
        submit_full(self.eng, "b3", support.clean_observation())
        self.commit(self.eng.precheck(DEVICE, "b3", rollback))
        self.assertNotIn("OX", self.eng.device_view(DEVICE)["trusted_objects"])

        # 4. The rogue content is still untrusted afterwards.
        obs = dict(support.clean_observation())
        obs["C:/App/a.exe"] = "OX"
        submit_full(self.eng, "b4", obs)
        pre = self.eng.precheck(DEVICE, "b4")
        self.assertEqual(
            [(a["kind"], a["path"], a["new_oid"]) for a in pre["alerts"]],
            [("content_change", "C:/app/a.exe", "OX")],
        )


class TestCommitGuards(EngineTestCase):
    def test_baseline_swap_between_precheck_and_commit(self):
        submit_full(self.eng, "b1", support.clean_observation())
        stale = self.eng.precheck(DEVICE, "b1")
        # Another release moves the baseline forward.
        release = {
            "version": 2,
            "entries": [
                ["C:/App/a.exe", "O1"],
                ["C:/App/b.exe", "O1"],
                ["C:/App/c.dll", "O6"],
                ["D:/Data/d.dat", "O3"],
            ],
            "sign_with": "k-root",
        }
        obs = dict(support.clean_observation())
        obs["C:/App/c.dll"] = "O6"
        submit_full(self.eng, "b2", obs)
        self.commit(self.eng.precheck(DEVICE, "b2", release))
        with self.assertRaises(EngineError) as cm:
            self.eng.commit(stale["precheck_id"])
        self.assertEqual(cm.exception.code, Err.BASELINE_SWAPPED)

    def test_generation_change_between_precheck_and_commit(self):
        submit_full(self.eng, "b1", support.clean_observation())
        stale = self.eng.precheck(DEVICE, "b1")
        self.eng.rebuild_device(DEVICE, {
            "version": 10,
            "entries": [["C:/App/a.exe", "O1"], ["C:/App/c.dll", "O2"]],
            "sign_with": "k-root",
        })
        with self.assertRaises(EngineError) as cm:
            self.eng.commit(stale["precheck_id"])
        self.assertEqual(cm.exception.code, Err.GENERATION_CHANGED)

    def test_precheck_unknown(self):
        with self.assertRaises(EngineError) as cm:
            self.eng.commit("f" * 64)
        self.assertEqual(cm.exception.code, Err.PRECHECK_NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
