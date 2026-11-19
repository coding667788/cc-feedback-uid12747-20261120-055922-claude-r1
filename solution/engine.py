"""Monitoring engine: acquisition ingest, precheck, atomic commit, recovery.

Rules implemented here (see README for the full specification):

* A device manifest pins generation, baseline version, protected paths and
  object ids with SHA-256.  Hard-link aliases fall out of the object table:
  several protected paths may reference the same object.
* Observations arrive in segments bound to (device, generation, baseline CAS,
  batch).  Segments may arrive out of order and from concurrent processes.
  A batch is complete only when every declared segment is present and the
  union of their scopes covers the protected paths exactly once.  A missing
  segment never turns into "all files vanished".
* A completed observation first yields a *precheck* — a staged, non-executable
  plan.  ``commit`` re-validates device generation, current signer
  authorization, the complete segment set and the baseline CAS, then records
  the new trusted view, the diff alerts and an idempotent receipt in SQLite.
* Trust is object-level and only ever granted by an authorized, committed
  release.  Content that was never authorized does not become trusted because
  a path is later renamed or an old baseline is rolled back.
* ``commit`` writes in three phases (alerts -> view flip -> receipt) with real
  kill points between them; ``_recover`` runs at open and guarantees exactly
  one version-pinned alert set and one receipt per commit.
"""

from __future__ import annotations

import json
import os

from . import model
from .errors import Err, EngineError
from .paths import canon_path
from .store import Store

# Alert kinds
LEGIT_RELEASE = "legit_release"
CONTENT_CHANGE = "content_change"
ALIAS_CHANGE = "alias_change"
DATA_GAP = "data_gap"


def _alert(kind, path, base_oid, new_oid, detail):
    return {
        "kind": kind,
        "path": path,
        "base_oid": base_oid,
        "new_oid": new_oid,
        "detail": detail,
    }


def diff_attestation(base_entries, observed, trusted_oids):
    """Diff the trusted baseline against a complete observation."""
    alerts = []
    for path in sorted(base_entries):
        base_oid = base_entries[path][0]
        obs = observed[path]
        if obs is None:
            alerts.append(_alert(CONTENT_CHANGE, path, base_oid, None, "file deleted"))
        elif obs == base_oid:
            continue
        elif obs in trusted_oids:
            alerts.append(
                _alert(ALIAS_CHANGE, path, base_oid, obs,
                       "path retargeted to another trusted object")
            )
        else:
            alerts.append(
                _alert(CONTENT_CHANGE, path, base_oid, obs, "untrusted object content")
            )
    return alerts


def diff_release(base_entries, new_entries):
    """Diff the current baseline against an authorized release manifest."""
    new_map = {p: (o, s) for p, o, s in new_entries}
    alerts = []
    for path in sorted(set(base_entries) | set(new_map)):
        old = base_entries.get(path)
        new = new_map.get(path)
        if old and not new:
            alerts.append(_alert(LEGIT_RELEASE, path, old[0], None, "removed by release"))
        elif new and not old:
            alerts.append(_alert(LEGIT_RELEASE, path, None, new[0], "added by release"))
        elif old[0] != new[0]:
            alerts.append(
                _alert(LEGIT_RELEASE, path, old[0], new[0], "changed by release")
            )
    return alerts


class Engine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.store = Store(db_path)
        self._recover()

    def close(self):
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ keys
    def register_key(self, key_id, secret):
        with self.store.txn() as c:
            c.execute(
                "INSERT INTO keys(key_id, secret, revoked) VALUES(?,?,0) "
                "ON CONFLICT(key_id) DO UPDATE SET secret=excluded.secret",
                (key_id, secret),
            )
        return {"key_id": key_id}

    def revoke_key(self, key_id):
        with self.store.txn() as c:
            cur = c.execute("UPDATE keys SET revoked=1 WHERE key_id=?", (key_id,))
            if cur.rowcount == 0:
                raise EngineError(Err.KEY_NOT_FOUND, key_id)
        return {"key_id": key_id, "revoked": True}

    # --------------------------------------------------------------- objects
    def register_objects(self, objects):
        with self.store.txn() as c:
            for oid, content in objects.items():
                fp = model.object_fingerprint(content)
                row = c.execute(
                    "SELECT sha256 FROM objects WHERE oid=?", (oid,)
                ).fetchone()
                if row and row["sha256"] != fp["sha256"]:
                    raise EngineError(Err.OBJECT_CONFLICT, oid)
                c.execute(
                    "INSERT OR REPLACE INTO objects(oid, sha256, size) VALUES(?,?,?)",
                    (oid, fp["sha256"], fp["size"]),
                )
        return {"count": len(objects)}

    # --------------------------------------------------------------- devices
    def _device_row(self, device_id):
        row = self.store.q1(
            "SELECT device_id, generation, current_baseline_cas FROM devices "
            "WHERE device_id=?",
            (device_id,),
        )
        if not row:
            raise EngineError(Err.DEVICE_NOT_FOUND, device_id)
        return row

    def _baseline_entries(self, cas):
        row = self.store.q1(
            "SELECT entries_json, version FROM baselines WHERE cas=?", (cas,)
        )
        if not row:
            raise EngineError(Err.BASELINE_NOT_FOUND, cas)
        entries = {
            e["path"]: (e["oid"], e["sha256"]) for e in json.loads(row["entries_json"])
        }
        return entries, row["version"]

    def _build_baseline(self, device_id, spec):
        version = int(spec["version"])
        seen = {}
        entries = []
        for path, oid in spec["entries"]:
            cp = canon_path(path)
            if cp in seen:
                raise EngineError(Err.DUPLICATE_PATH, cp)
            obj = self.store.q1("SELECT sha256 FROM objects WHERE oid=?", (oid,))
            if not obj:
                raise EngineError(Err.UNKNOWN_OBJECT, oid)
            seen[cp] = True
            entries.append((cp, oid, obj["sha256"]))
        entries.sort()
        cas = model.baseline_cas(device_id, version, entries)
        if "sign_with" in spec:
            key_id = spec["sign_with"]
            key = self.store.q1("SELECT secret FROM keys WHERE key_id=?", (key_id,))
            if not key:
                raise EngineError(Err.KEY_NOT_FOUND, key_id)
            signature = model.sign(key["secret"], cas)
        else:
            key_id = spec.get("key_id")
            signature = spec.get("signature", "")
        return cas, entries, signature, key_id, version

    def _check_signature(self, key_id, cas, signature):
        key = self.store.q1(
            "SELECT secret, revoked FROM keys WHERE key_id=?", (key_id,)
        )
        if not key:
            raise EngineError(Err.KEY_NOT_FOUND, key_id)
        if key["revoked"]:
            raise EngineError(Err.SIGNER_REVOKED, key_id)
        if not model.verify(key["secret"], cas, signature or ""):
            raise EngineError(Err.BAD_SIGNATURE, key_id)

    @staticmethod
    def _entries_json(entries):
        return json.dumps(
            [{"path": p, "oid": o, "sha256": s} for p, o, s in entries],
            sort_keys=True,
        )

    def create_device(self, device_id, spec):
        if self.store.q1("SELECT 1 FROM devices WHERE device_id=?", (device_id,)):
            raise EngineError(Err.DEVICE_EXISTS, device_id)
        cas, entries, signature, key_id, version = self._build_baseline(device_id, spec)
        self._check_signature(key_id, cas, signature)
        with self.store.txn() as c:
            c.execute(
                "INSERT INTO baselines(cas, device_id, version, entries_json, "
                "signature, key_id) VALUES(?,?,?,?,?,?)",
                (cas, device_id, version, self._entries_json(entries), signature, key_id),
            )
            c.execute(
                "INSERT INTO devices(device_id, generation, current_baseline_cas, seq) "
                "VALUES(?,?,?,0)",
                (device_id, 1, cas),
            )
        return {
            "device": device_id,
            "generation": 1,
            "baseline_cas": cas,
            "version": version,
        }

    def rebuild_device(self, device_id, spec):
        dev = self._device_row(device_id)
        cas, entries, signature, key_id, version = self._build_baseline(device_id, spec)
        self._check_signature(key_id, cas, signature)
        generation = dev["generation"] + 1
        with self.store.txn() as c:
            c.execute(
                "INSERT OR IGNORE INTO baselines(cas, device_id, version, entries_json, "
                "signature, key_id) VALUES(?,?,?,?,?,?)",
                (cas, device_id, version, self._entries_json(entries), signature, key_id),
            )
            c.execute(
                "UPDATE devices SET generation=?, current_baseline_cas=?, seq=seq+1 "
                "WHERE device_id=?",
                (generation, cas, device_id),
            )
        return {
            "device": device_id,
            "generation": generation,
            "baseline_cas": cas,
            "version": version,
        }

    def device_view(self, device_id):
        dev = self._device_row(device_id)
        entries, version = self._baseline_entries(dev["current_baseline_cas"])
        return {
            "device": device_id,
            "generation": dev["generation"],
            "baseline_cas": dev["current_baseline_cas"],
            "version": version,
            "entries": [
                {"path": p, "oid": o, "sha256": s}
                for p, (o, s) in sorted(entries.items())
            ],
            "trusted_objects": sorted({o for o, _ in entries.values()}),
        }

    # -------------------------------------------------------------- segments
    def submit_segment(self, seg):
        device_id = seg["device"]
        batch_id = seg["batch"]
        self._device_row(device_id)
        count = int(seg["segment_count"])
        index = int(seg["index"])
        if not 0 <= index < count:
            raise EngineError(
                Err.SCOPE_MISMATCH, f"segment index {index} outside 0..{count - 1}"
            )
        generation = int(seg["generation"])
        cas = seg["baseline_cas"]
        self._baseline_entries(cas)  # pinned baseline must be known
        obs = {}
        for path, oid in seg["observations"].items():
            cp = canon_path(path)
            if cp in obs:
                raise EngineError(Err.DUPLICATE_PATH, cp)
            if oid is not None and not self.store.q1(
                "SELECT 1 FROM objects WHERE oid=?", (oid,)
            ):
                raise EngineError(Err.UNKNOWN_OBJECT, oid)
            obs[cp] = oid
        payload = json.dumps(obs, sort_keys=True)
        with self.store.txn() as c:
            c.execute(
                "INSERT OR IGNORE INTO batches(device_id, batch_id, generation, "
                "baseline_cas, segment_count, state) VALUES(?,?,?,?,?,'open')",
                (device_id, batch_id, generation, cas, count),
            )
            batch = c.execute(
                "SELECT generation, baseline_cas, segment_count, state FROM batches "
                "WHERE device_id=? AND batch_id=?",
                (device_id, batch_id),
            ).fetchone()
            if batch["state"] != "open":
                raise EngineError(Err.BATCH_CLOSED, batch_id)
            if (batch["generation"], batch["baseline_cas"], batch["segment_count"]) != (
                generation,
                cas,
                count,
            ):
                raise EngineError(
                    Err.SCOPE_MISMATCH, "segment header disagrees with batch"
                )
            existing = c.execute(
                "SELECT obs_json FROM segments WHERE device_id=? AND batch_id=? "
                "AND seg_index=?",
                (device_id, batch_id, index),
            ).fetchone()
            if existing is None:
                c.execute(
                    "INSERT INTO segments(device_id, batch_id, seg_index, "
                    "generation, baseline_cas, obs_json) VALUES(?,?,?,?,?,?)",
                    (device_id, batch_id, index, generation, cas, payload),
                )
                duplicate = False
            else:
                if existing["obs_json"] != payload:
                    raise EngineError(Err.DUPLICATE_SEGMENT, f"{batch_id}#{index}")
                duplicate = True
        return {"batch": batch_id, "index": index, "duplicate": duplicate}

    # -------------------------------------------------------------- precheck
    def precheck(self, device_id, batch_id, release_spec=None):
        self._device_row(device_id)
        batch = self.store.q1(
            "SELECT * FROM batches WHERE device_id=? AND batch_id=?",
            (device_id, batch_id),
        )
        if not batch:
            raise EngineError(Err.BATCH_NOT_FOUND, batch_id)
        if batch["state"] != "open":
            raise EngineError(Err.BATCH_CLOSED, batch_id)
        rows = self.store.q(
            "SELECT seg_index, obs_json FROM segments WHERE device_id=? AND batch_id=? "
            "ORDER BY seg_index",
            (device_id, batch_id),
        )
        if len(rows) != batch["segment_count"]:
            missing = sorted(
                set(range(batch["segment_count"])) - {r["seg_index"] for r in rows}
            )
            raise EngineError(
                Err.INCOMPLETE_OBSERVATION, f"missing segments: {missing}"
            )
        base_entries, base_version = self._baseline_entries(batch["baseline_cas"])
        observed = {}
        for row in rows:
            for cp, oid in json.loads(row["obs_json"]).items():
                if cp in observed:
                    raise EngineError(
                        Err.SCOPE_MISMATCH, f"overlapping segment path: {cp}"
                    )
                observed[cp] = oid
        if release_spec is not None:
            kind = "release"
            new_cas, new_entries, signature, key_id, version = self._build_baseline(
                device_id, release_spec
            )
            key = self.store.q1("SELECT secret FROM keys WHERE key_id=?", (key_id,))
            if not key:
                raise EngineError(Err.KEY_NOT_FOUND, key_id)
            if not model.verify(key["secret"], new_cas, signature or ""):
                raise EngineError(Err.BAD_SIGNATURE, key_id)
            release_view = {p: o for p, o, _ in new_entries}
            if set(observed) != set(release_view):
                raise EngineError(
                    Err.SCOPE_MISMATCH,
                    "observation scope does not match release scope",
                )
            if observed != release_view:
                raise EngineError(
                    Err.OBSERVATION_MISMATCH, "observation does not confirm release"
                )
            alerts = diff_release(base_entries, new_entries)
            release_json = {
                "cas": new_cas,
                "version": version,
                "signature": signature,
                "key_id": key_id,
                "entries": [
                    {"path": p, "oid": o, "sha256": s} for p, o, s in new_entries
                ],
            }
        else:
            kind = "attestation"
            new_cas = batch["baseline_cas"]
            version = base_version
            if set(observed) != set(base_entries):
                raise EngineError(
                    Err.SCOPE_MISMATCH,
                    "observation scope does not cover protected paths",
                )
            trusted = {o for o, _ in base_entries.values()}
            alerts = diff_attestation(base_entries, observed, trusted)
            release_json = None
        pid = model.precheck_id(device_id, batch_id, kind, new_cas)
        with self.store.txn() as c:
            c.execute(
                "INSERT OR IGNORE INTO prechecks(precheck_id, device_id, batch_id, "
                "generation, baseline_cas, kind, release_json, diff_json, state) "
                "VALUES(?,?,?,?,?,?,?,?, 'staged')",
                (
                    pid,
                    device_id,
                    batch_id,
                    batch["generation"],
                    batch["baseline_cas"],
                    kind,
                    json.dumps(release_json, sort_keys=True) if release_json else None,
                    json.dumps(alerts, sort_keys=True),
                ),
            )
        return {
            "precheck_id": pid,
            "kind": kind,
            "version": version,
            "new_cas": new_cas,
            "alerts": alerts,
        }

    # ---------------------------------------------------------------- commit
    def commit(self, precheck_id, kill_point=None):
        pre = self.store.q1(
            "SELECT * FROM prechecks WHERE precheck_id=?", (precheck_id,)
        )
        if not pre:
            raise EngineError(Err.PRECHECK_NOT_FOUND, precheck_id)
        existing = self.store.q1(
            "SELECT commit_id, status FROM commits WHERE precheck_id=?", (precheck_id,)
        )
        if existing and existing["status"] in ("committed", "receipted"):
            return self._receipt(existing["commit_id"]), True
        if existing and existing["status"] == "alerts_pending":
            self._finalize_or_abort(existing["commit_id"])
            row = self.store.q1(
                "SELECT status FROM commits WHERE commit_id=?",
                (existing["commit_id"],),
            )
            if row["status"] in ("committed", "receipted"):
                return self._receipt(existing["commit_id"]), True
            raise EngineError(
                Err.GENERATION_CHANGED, "staged commit aborted: device moved on"
            )
        dev = self._device_row(pre["device_id"])
        if dev["generation"] != pre["generation"]:
            raise EngineError(
                Err.GENERATION_CHANGED,
                f"device at generation {dev['generation']}, "
                f"precheck pinned to {pre['generation']}",
            )
        if dev["current_baseline_cas"] != pre["baseline_cas"]:
            raise EngineError(
                Err.BASELINE_SWAPPED,
                "current baseline CAS differs from precheck baseline",
            )
        batch = self.store.q1(
            "SELECT segment_count, state FROM batches WHERE device_id=? AND batch_id=?",
            (pre["device_id"], pre["batch_id"]),
        )
        nseg = self.store.q1(
            "SELECT COUNT(*) AS n FROM segments WHERE device_id=? AND batch_id=?",
            (pre["device_id"], pre["batch_id"]),
        )["n"]
        if not batch or batch["state"] != "open" or nseg != batch["segment_count"]:
            raise EngineError(Err.INCOMPLETE_OBSERVATION, pre["batch_id"])
        release = json.loads(pre["release_json"]) if pre["release_json"] else None
        if release:
            # Authorization is re-checked at commit time: a key revoked after
            # the precheck invalidates the release.
            self._check_signature(release["key_id"], release["cas"], release["signature"])
            new_cas, version = release["cas"], release["version"]
        else:
            new_cas = pre["baseline_cas"]
            _, version = self._baseline_entries(pre["baseline_cas"])
        alerts = json.loads(pre["diff_json"])
        cid = model.commit_id(precheck_id)

        # Phase 1: commit row + version-pinned alerts.
        with self.store.txn() as c:
            c.execute(
                "INSERT INTO commits(commit_id, precheck_id, device_id, batch_id, "
                "generation, base_cas, new_cas, version, kind, status) "
                "VALUES(?,?,?,?,?,?,?,?,?,'alerts_pending')",
                (
                    cid,
                    precheck_id,
                    pre["device_id"],
                    pre["batch_id"],
                    pre["generation"],
                    pre["baseline_cas"],
                    new_cas,
                    version,
                    pre["kind"],
                ),
            )
            if release:
                c.execute(
                    "INSERT OR IGNORE INTO baselines(cas, device_id, version, "
                    "entries_json, signature, key_id) VALUES(?,?,?,?,?,?)",
                    (
                        new_cas,
                        pre["device_id"],
                        version,
                        json.dumps(release["entries"], sort_keys=True),
                        release["signature"],
                        release["key_id"],
                    ),
                )
            for a in alerts:
                c.execute(
                    "INSERT INTO alerts(commit_id, version, kind, path, detail_json) "
                    "VALUES(?,?,?,?,?)",
                    (cid, version, a["kind"], a["path"], json.dumps(a, sort_keys=True)),
                )
        if kill_point == "after_alerts":  # real kill point 1 (alert written, view not flipped)
            os._exit(42)

        # Phase 2: flip the trusted view atomically (or abort if it moved).
        self._finalize_or_abort(cid)
        if kill_point == "after_commit":  # real kill point 2 (committed, no receipt yet)
            os._exit(43)

        # Phase 3: idempotent receipt.
        return self._receipt(cid), False

    def _finalize_or_abort(self, cid):
        with self.store.txn() as c:
            cm = c.execute(
                "SELECT * FROM commits WHERE commit_id=?", (cid,)
            ).fetchone()
            if not cm or cm["status"] != "alerts_pending":
                return
            flipped = c.execute(
                "UPDATE devices SET current_baseline_cas=?, seq=seq+1 "
                "WHERE device_id=? AND generation=? AND current_baseline_cas=?",
                (cm["new_cas"], cm["device_id"], cm["generation"], cm["base_cas"]),
            ).rowcount
            if flipped == 0:
                c.execute("DELETE FROM alerts WHERE commit_id=?", (cid,))
                c.execute("UPDATE commits SET status='aborted' WHERE commit_id=?", (cid,))
                return
            c.execute(
                "UPDATE prechecks SET state='committed' WHERE precheck_id=?",
                (cm["precheck_id"],),
            )
            c.execute(
                "UPDATE batches SET state='committed' WHERE device_id=? AND batch_id=?",
                (cm["device_id"], cm["batch_id"]),
            )
            c.execute(
                "UPDATE commits SET status='committed' WHERE commit_id=?", (cid,)
            )

    def _receipt(self, cid):
        row = self.store.q1(
            "SELECT receipt_json FROM receipts WHERE commit_id=?", (cid,)
        )
        if row:
            return json.loads(row["receipt_json"])
        with self.store.txn() as c:
            row = c.execute(
                "SELECT receipt_json FROM receipts WHERE commit_id=?", (cid,)
            ).fetchone()
            if row:
                return json.loads(row["receipt_json"])
            cm = c.execute(
                "SELECT * FROM commits WHERE commit_id=?", (cid,)
            ).fetchone()
            alerts = [
                json.loads(r["detail_json"])
                for r in c.execute(
                    "SELECT detail_json FROM alerts WHERE commit_id=? "
                    "ORDER BY path, kind",
                    (cid,),
                )
            ]
            body = model.receipt_body(
                cid,
                cm["device_id"],
                cm["batch_id"],
                cm["kind"],
                cm["generation"],
                cm["base_cas"],
                cm["new_cas"],
                cm["version"],
                alerts,
            )
            c.execute(
                "INSERT INTO receipts(commit_id, receipt_json) VALUES(?,?)",
                (cid, json.dumps(body, sort_keys=True)),
            )
            c.execute(
                "UPDATE commits SET status='receipted' WHERE commit_id=?", (cid,)
            )
            return body

    def _recover(self):
        """Finish or abort interrupted commits; exactly one alert set + receipt."""
        for row in self.store.q("SELECT commit_id FROM commits WHERE status='alerts_pending'"):
            self._finalize_or_abort(row["commit_id"])
        for row in self.store.q("SELECT commit_id FROM commits WHERE status='committed'"):
            self._receipt(row["commit_id"])

    # -------------------------------------------------------------- gap close
    def close_batch(self, device_id, batch_id):
        dev = self._device_row(device_id)
        batch = self.store.q1(
            "SELECT * FROM batches WHERE device_id=? AND batch_id=?",
            (device_id, batch_id),
        )
        if not batch:
            raise EngineError(Err.BATCH_NOT_FOUND, batch_id)
        if batch["state"] != "open":
            raise EngineError(Err.BATCH_CLOSED, batch_id)
        present = {
            r["seg_index"]
            for r in self.store.q(
                "SELECT seg_index FROM segments WHERE device_id=? AND batch_id=?",
                (device_id, batch_id),
            )
        }
        if len(present) >= batch["segment_count"]:
            raise EngineError(Err.BATCH_COMPLETE, batch_id)
        missing = sorted(set(range(batch["segment_count"])) - present)
        _, version = self._baseline_entries(dev["current_baseline_cas"])
        cid = model.gap_commit_id(device_id, batch_id)
        alert = _alert(
            DATA_GAP,
            "*",
            None,
            None,
            f"observation incomplete; missing segments {missing}; "
            "no protected file is treated as vanished",
        )
        with self.store.txn() as c:
            if not c.execute(
                "SELECT 1 FROM commits WHERE commit_id=?", (cid,)
            ).fetchone():
                c.execute(
                    "INSERT INTO commits(commit_id, precheck_id, device_id, batch_id, "
                    "generation, base_cas, new_cas, version, kind, status) "
                    "VALUES(?,NULL,?,?,?,?,?,?,?,'committed')",
                    (
                        cid,
                        device_id,
                        batch_id,
                        dev["generation"],
                        dev["current_baseline_cas"],
                        dev["current_baseline_cas"],
                        version,
                        "gap",
                    ),
                )
                c.execute(
                    "INSERT INTO alerts(commit_id, version, kind, path, detail_json) "
                    "VALUES(?,?,?,?,?)",
                    (cid, version, DATA_GAP, "*", json.dumps(alert, sort_keys=True)),
                )
            c.execute(
                "UPDATE batches SET state='closed_gap' WHERE device_id=? AND batch_id=?",
                (device_id, batch_id),
            )
        receipt = self._receipt(cid)
        return {"commit_id": cid, "cached": False, "receipt": receipt}

    # ---------------------------------------------------------------- queries
    def receipt(self, commit_id):
        row = self.store.q1(
            "SELECT receipt_json FROM receipts WHERE commit_id=?", (commit_id,)
        )
        if not row:
            raise EngineError(Err.RECEIPT_NOT_FOUND, commit_id)
        return json.loads(row["receipt_json"])

    def alerts_for(self, commit_id):
        out = []
        for r in self.store.q(
            "SELECT version, detail_json FROM alerts WHERE commit_id=? "
            "ORDER BY path, kind",
            (commit_id,),
        ):
            detail = json.loads(r["detail_json"])
            detail["version"] = r["version"]
            out.append(detail)
        return out

    def commit_row(self, commit_id):
        row = self.store.q1("SELECT * FROM commits WHERE commit_id=?", (commit_id,))
        if not row:
            raise EngineError(Err.RECEIPT_NOT_FOUND, commit_id)
        return dict(row)
