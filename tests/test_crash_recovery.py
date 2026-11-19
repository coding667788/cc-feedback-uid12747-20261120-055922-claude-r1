"""Crash-recovery: workers really die at the two commit kill points."""

import multiprocessing
import os
import tempfile
import unittest

import support
from support import DEVICE, make_engine, run_op_process

from solution.engine import Engine
from solution import workers


class CrashRecoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.ctx = multiprocessing.get_context("spawn")
        self.tmp = tempfile.TemporaryDirectory(prefix="fim-crash-")
        self.db = os.path.join(self.tmp.name, "crash.db")
        self.eng = make_engine(self.db)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: self.eng.close())
        # One content change + one deletion -> two alerts in the commit.
        obs = support.clean_observation()
        obs["C:/App/a.exe"] = "O4"
        obs["D:/Data/d.dat"] = None
        support.submit_full(self.eng, "b1", obs)
        self.pre = self.eng.precheck(DEVICE, "b1")
        self.assertEqual(len(self.pre["alerts"]), 2)

    def reopen(self):
        self.eng.close()
        self.eng = Engine(self.db)

    def assert_single_version_pinned_alert_set(self, commit_id, expect_alerts=2):
        rows = self.eng.store.q(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT version) AS v FROM alerts "
            "WHERE commit_id=?",
            (commit_id,),
        )[0]
        self.assertEqual(rows["n"], expect_alerts)
        self.assertEqual(rows["v"], 1)
        receipts = self.eng.store.q(
            "SELECT COUNT(*) AS n FROM receipts WHERE commit_id=?", (commit_id,)
        )[0]
        self.assertEqual(receipts["n"], 1)

    def test_kill_after_alerts_written_before_view_flip(self):
        proc = self.ctx.Process(
            target=workers.crash_worker,
            args=(self.db, self.pre["precheck_id"], "after_alerts"),
        )
        proc.start()
        proc.join(60)
        self.assertEqual(proc.exitcode, 42)

        # Mid-crash state is visible: alerts persisted, view not flipped.
        import sqlite3
        conn = sqlite3.connect(self.db)
        try:
            row = conn.execute("SELECT status FROM commits").fetchone()
            self.assertEqual(row[0], "alerts_pending")
            n_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            self.assertEqual(n_alerts, 2)
            n_receipts = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            self.assertEqual(n_receipts, 0)
        finally:
            conn.close()

        self.reopen()  # recovery runs at open
        commits = self.eng.store.q("SELECT commit_id, status FROM commits")
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0]["status"], "receipted")
        cid = commits[0]["commit_id"]
        self.assert_single_version_pinned_alert_set(cid)
        self.assertEqual(self.eng.device_view(DEVICE)["version"], 1)

        # Re-committing is idempotent: same receipt, still one alert set.
        receipt, cached = self.eng.commit(self.pre["precheck_id"])
        self.assertTrue(cached)
        self.assertEqual(receipt["commit_id"], cid)
        self.assert_single_version_pinned_alert_set(cid)

    def test_kill_after_commit_before_receipt(self):
        proc = self.ctx.Process(
            target=workers.crash_worker,
            args=(self.db, self.pre["precheck_id"], "after_commit"),
        )
        proc.start()
        proc.join(60)
        self.assertEqual(proc.exitcode, 43)

        self.reopen()  # recovery writes the missing receipt
        commits = self.eng.store.q("SELECT commit_id, status FROM commits")
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0]["status"], "receipted")
        cid = commits[0]["commit_id"]
        self.assert_single_version_pinned_alert_set(cid)

        receipt1 = self.eng.receipt(cid)
        receipt2, cached = self.eng.commit(self.pre["precheck_id"])
        self.assertTrue(cached)
        self.assertEqual(receipt1, receipt2)
        self.assert_single_version_pinned_alert_set(cid)


if __name__ == "__main__":
    unittest.main()
