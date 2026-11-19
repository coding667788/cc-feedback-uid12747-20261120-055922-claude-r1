"""Multi-process scenarios pinned by independent worker processes (spawn)."""

import json
import multiprocessing
import os
import tempfile
import unittest

import support
from support import DEVICE, make_engine, run_op_process

from solution.errors import Err, EngineError
from solution import workers


def read_result(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class ConcurrencyTestCase(unittest.TestCase):
    def setUp(self):
        self.ctx = multiprocessing.get_context("spawn")
        self.tmp = tempfile.TemporaryDirectory(prefix="fim-mp-")
        self.db = os.path.join(self.tmp.name, "shared.db")
        self.eng = make_engine(self.db)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: self.eng.close())
        self._n = 0

    def result_path(self):
        self._n += 1
        return os.path.join(self.tmp.name, f"result-{self._n}.json")

    def run_worker(self, target, *args):
        rp = self.result_path()
        run_op_process(self.ctx, target, (self.db, rp) + args)
        return read_result(rp)

    def segment(self, batch, index, count, observations, view=None):
        view = view or self.eng.device_view(DEVICE)
        return {
            "device": DEVICE,
            "batch": batch,
            "segment_count": count,
            "index": index,
            "generation": view["generation"],
            "baseline_cas": view["baseline_cas"],
            "observations": observations,
        }


class TestCrossProcessIngest(ConcurrencyTestCase):
    def test_concurrent_out_of_order_segments_from_two_processes(self):
        obs = support.clean_observation()
        items = sorted(obs.items())
        seg_a = self.segment("b1", 1, 2, dict(items[2:]))   # submitted first
        seg_b = self.segment("b1", 0, 2, dict(items[:2]))
        procs = [
            self.ctx.Process(target=workers.worker_submit_segment,
                             args=(self.db, self.result_path(), seg_a)),
            self.ctx.Process(target=workers.worker_submit_segment,
                             args=(self.db, self.result_path(), seg_b)),
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
            self.assertEqual(p.exitcode, 0)
        pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(pre["alerts"], [])
        receipt, _ = self.eng.commit(pre["precheck_id"])
        self.assertEqual(receipt["alert_count"], 0)


class TestGenerationChange(ConcurrencyTestCase):
    def test_commit_fails_after_device_rebuild_in_other_process(self):
        view = self.eng.device_view(DEVICE)
        seg = self.segment("b1", 0, 1, support.clean_observation(), view)
        res = self.run_worker(workers.worker_submit_segment, seg)
        self.assertEqual(res["status"], "ok")
        pre = self.eng.precheck(DEVICE, "b1")

        rebuild = self.run_worker(workers.worker_rebuild, DEVICE, {
            "version": 10,
            "entries": [["C:/App/a.exe", "O1"], ["C:/App/c.dll", "O2"]],
            "sign_with": "k-root",
        })
        self.assertEqual(rebuild["status"], "ok")
        self.assertEqual(rebuild["result"]["generation"], 2)

        res = self.run_worker(workers.worker_commit, pre["precheck_id"])
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["code"], Err.GENERATION_CHANGED)


class TestBaselineSwap(ConcurrencyTestCase):
    def test_commit_fails_after_other_process_replaces_baseline(self):
        support.submit_full(self.eng, "b1", support.clean_observation())
        stale = self.eng.precheck(DEVICE, "b1")

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
        obs = support.clean_observation()
        obs["C:/App/c.dll"] = "O6"
        res = self.run_worker(workers.worker_submit_segment, self.segment("b2", 0, 1, obs))
        self.assertEqual(res["status"], "ok")
        res = self.run_worker(workers.worker_precheck, DEVICE, "b2", release)
        self.assertEqual(res["status"], "ok")
        res = self.run_worker(workers.worker_commit, res["result"]["precheck_id"])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["result"]["version"], 2)

        res = self.run_worker(workers.worker_commit, stale["precheck_id"])
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["code"], Err.BASELINE_SWAPPED)


class TestLateSegment(ConcurrencyTestCase):
    def test_missing_segment_gap_then_late_segment_from_other_process(self):
        seg0 = self.segment("b1", 0, 2, {
            "C:/App/a.exe": "O1",
            "C:/App/b.exe": "O1",
        })
        res = self.run_worker(workers.worker_submit_segment, seg0)
        self.assertEqual(res["status"], "ok")

        with self.assertRaises(EngineError) as cm:
            self.eng.precheck(DEVICE, "b1")
        self.assertEqual(cm.exception.code, Err.INCOMPLETE_OBSERVATION)

        res = self.run_worker(workers.worker_close_batch, DEVICE, "b1")
        self.assertEqual(res["status"], "ok")
        alerts = self.eng.alerts_for(res["result"]["commit_id"])
        self.assertEqual([a["kind"] for a in alerts], ["data_gap"])

        late = self.segment("b1", 1, 2, {
            "C:/App/c.dll": "O2",
            "D:/Data/d.dat": "O3",
        })
        res = self.run_worker(workers.worker_submit_segment, late)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["code"], Err.BATCH_CLOSED)

        # No file was ever reported deleted.
        kinds = {r["kind"] for r in self.eng.store.q("SELECT kind FROM alerts")}
        self.assertEqual(kinds, {"data_gap"})


class TestSignerRevocation(ConcurrencyTestCase):
    def test_commit_fails_after_revocation_in_other_process(self):
        release = {
            "version": 2,
            "entries": [
                ["C:/App/a.exe", "O5"],
                ["C:/App/b.exe", "O5"],
                ["C:/App/c.dll", "O2"],
                ["D:/Data/d.dat", "O3"],
            ],
            "sign_with": "k-rel",
        }
        obs = support.clean_observation()
        obs["C:/App/a.exe"] = "O5"
        obs["C:/App/b.exe"] = "O5"
        support.submit_full(self.eng, "b1", obs)
        pre = self.eng.precheck(DEVICE, "b1", release)

        res = self.run_worker(workers.worker_revoke_key, "k-rel")
        self.assertEqual(res["status"], "ok")

        res = self.run_worker(workers.worker_commit, pre["precheck_id"])
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["code"], Err.SIGNER_REVOKED)
        self.assertEqual(self.eng.device_view(DEVICE)["version"], 1)


if __name__ == "__main__":
    unittest.main()
