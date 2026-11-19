"""Independent, read-only reference model.

A second, deliberately separate implementation of the monitoring rules.  It
keeps all state in plain Python structures, never touches SQLite or the file
system, and replays a case to produce the expected per-op results and final
trusted views.  Tests cross-check the engine against this model on:

* path case folding (``C:\\App\\A.EXE`` == ``c:/app/a.exe``),
* one object reachable through several aliases,
* a new object appearing under an unchanged name,
* previously approved content being revoked by a later release.

Only the hash/signature primitives of :mod:`solution.model` are shared (they
define the wire format); every rule decision below is re-derived here.
"""

from __future__ import annotations

from . import model
from .errors import Err
from .paths import canon_path


class RefError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _mk_alert(kind, path, base_oid, new_oid, detail):
    return {
        "kind": kind,
        "path": path,
        "base_oid": base_oid,
        "new_oid": new_oid,
        "detail": detail,
    }


class ReferenceModel:
    def __init__(self):
        self.objects = {}     # oid -> {"sha256":..., "size":...}
        self.keys = {}        # key_id -> {"secret":..., "revoked": bool}
        self.devices = {}     # device -> {"generation": int, "cas": str}
        self.baselines = {}   # cas -> {"version": int, "entries": {path: (oid, sha)}}
        self.batches = {}     # (device, batch) -> dict
        self.prechecks = {}   # pid -> dict
        self.commit_by_precheck = {}  # pid -> receipt
        self.receipts = {}    # commit_id -> receipt
        self.ctx = {}

    # ------------------------------------------------------------------ util
    def _device(self, device):
        if device not in self.devices:
            raise RefError(Err.DEVICE_NOT_FOUND, device)
        return self.devices[device]

    def _baseline(self, cas):
        if cas not in self.baselines:
            raise RefError(Err.BASELINE_NOT_FOUND, cas)
        return self.baselines[cas]

    def _build_manifest(self, device, spec):
        version = int(spec["version"])
        entries = {}
        for path, oid in spec["entries"]:
            cp = canon_path(path)
            if cp in entries:
                raise RefError(Err.DUPLICATE_PATH, cp)
            if oid not in self.objects:
                raise RefError(Err.UNKNOWN_OBJECT, oid)
            entries[cp] = (oid, self.objects[oid]["sha256"])
        cas = model.baseline_cas(
            device, version, [(p, o, s) for p, (o, s) in entries.items()]
        )
        if "sign_with" in spec:
            key_id = spec["sign_with"]
            if key_id not in self.keys:
                raise RefError(Err.KEY_NOT_FOUND, key_id)
            signature = model.sign(self.keys[key_id]["secret"], cas)
        else:
            key_id = spec.get("key_id")
            signature = spec.get("signature", "")
        return cas, entries, signature, key_id, version

    def _check_signature(self, key_id, cas, signature):
        key = self.keys.get(key_id)
        if key is None:
            raise RefError(Err.KEY_NOT_FOUND, key_id)
        if key["revoked"]:
            raise RefError(Err.SIGNER_REVOKED, key_id)
        if not model.verify(key["secret"], cas, signature or ""):
            raise RefError(Err.BAD_SIGNATURE, key_id)

    def _view(self, device):
        dev = self._device(device)
        base = self._baseline(dev["cas"])
        return {
            "device": device,
            "generation": dev["generation"],
            "baseline_cas": dev["cas"],
            "version": base["version"],
            "entries": [
                {"path": p, "oid": o, "sha256": s}
                for p, (o, s) in sorted(base["entries"].items())
            ],
            "trusted_objects": sorted({o for o, _ in base["entries"].values()}),
        }

    # ------------------------------------------------------------------- ops
    def op_register_objects(self, op):
        for oid, content in op["objects"].items():
            fp = model.object_fingerprint(content)
            if oid in self.objects and self.objects[oid]["sha256"] != fp["sha256"]:
                raise RefError(Err.OBJECT_CONFLICT, oid)
            self.objects[oid] = fp
        return {"count": len(op["objects"])}

    def op_register_key(self, op):
        self.keys[op["key_id"]] = {"secret": op["secret"], "revoked": False}
        return {"key_id": op["key_id"]}

    def op_revoke_key(self, op):
        if op["key_id"] not in self.keys:
            raise RefError(Err.KEY_NOT_FOUND, op["key_id"])
        self.keys[op["key_id"]]["revoked"] = True
        return {"key_id": op["key_id"], "revoked": True}

    def op_create_device(self, op):
        device = op["device"]
        if device in self.devices:
            raise RefError(Err.DEVICE_EXISTS, device)
        cas, entries, signature, key_id, version = self._build_manifest(
            device, op["baseline"]
        )
        self._check_signature(key_id, cas, signature)
        self.baselines[cas] = {"version": version, "entries": entries}
        self.devices[device] = {"generation": 1, "cas": cas}
        return {
            "device": device,
            "generation": 1,
            "baseline_cas": cas,
            "version": version,
        }

    def op_rebuild(self, op):
        device = op["device"]
        dev = self._device(device)
        cas, entries, signature, key_id, version = self._build_manifest(
            device, op["baseline"]
        )
        self._check_signature(key_id, cas, signature)
        self.baselines.setdefault(cas, {"version": version, "entries": entries})
        dev["generation"] += 1
        dev["cas"] = cas
        return {
            "device": device,
            "generation": dev["generation"],
            "baseline_cas": cas,
            "version": version,
        }

    def op_submit_segment(self, op):
        device = op["device"]
        self._device(device)
        generation, cas = self._resolve_pins(op)
        count = int(op["segment_count"])
        index = int(op["index"])
        if not 0 <= index < count:
            raise RefError(Err.SCOPE_MISMATCH, f"segment index {index} outside 0..{count-1}")
        self._baseline(cas)
        obs = {}
        for path, oid in op["observations"].items():
            cp = canon_path(path)
            if cp in obs:
                raise RefError(Err.DUPLICATE_PATH, cp)
            if oid is not None and oid not in self.objects:
                raise RefError(Err.UNKNOWN_OBJECT, oid)
            obs[cp] = oid
        key = (device, op["batch"])
        batch = self.batches.get(key)
        if batch is None:
            batch = {
                "generation": generation,
                "cas": cas,
                "count": count,
                "state": "open",
                "segments": {},
            }
            self.batches[key] = batch
        if batch["state"] != "open":
            raise RefError(Err.BATCH_CLOSED, op["batch"])
        if (batch["generation"], batch["cas"], batch["count"]) != (generation, cas, count):
            raise RefError(Err.SCOPE_MISMATCH, "segment header disagrees with batch")
        if index in batch["segments"]:
            if batch["segments"][index] != obs:
                raise RefError(Err.DUPLICATE_SEGMENT, f"{op['batch']}#{index}")
            duplicate = True
        else:
            batch["segments"][index] = obs
            duplicate = False
        return {"batch": op["batch"], "index": index, "duplicate": duplicate}

    def op_precheck(self, op):
        device = op["device"]
        self._device(device)
        key = (device, op["batch"])
        batch = self.batches.get(key)
        if batch is None:
            raise RefError(Err.BATCH_NOT_FOUND, op["batch"])
        if batch["state"] != "open":
            raise RefError(Err.BATCH_CLOSED, op["batch"])
        if len(batch["segments"]) != batch["count"]:
            missing = sorted(set(range(batch["count"])) - set(batch["segments"]))
            raise RefError(Err.INCOMPLETE_OBSERVATION, f"missing segments: {missing}")
        base = self._baseline(batch["cas"])
        observed = {}
        for index in sorted(batch["segments"]):
            for cp, oid in batch["segments"][index].items():
                if cp in observed:
                    raise RefError(Err.SCOPE_MISMATCH, f"overlapping segment path: {cp}")
                observed[cp] = oid
        release_spec = op.get("release")
        if release_spec is not None:
            kind = "release"
            new_cas, new_entries, signature, key_id, version = self._build_manifest(
                device, release_spec
            )
            key_obj = self.keys.get(key_id)
            if key_obj is None:
                raise RefError(Err.KEY_NOT_FOUND, key_id)
            if not model.verify(key_obj["secret"], new_cas, signature or ""):
                raise RefError(Err.BAD_SIGNATURE, key_id)
            release_view = {p: o for p, (o, _) in new_entries.items()}
            if set(observed) != set(release_view):
                raise RefError(Err.SCOPE_MISMATCH, "observation scope does not match release scope")
            if observed != release_view:
                raise RefError(Err.OBSERVATION_MISMATCH, "observation does not confirm release")
            alerts = []
            for path in sorted(set(base["entries"]) | set(new_entries)):
                old = base["entries"].get(path)
                new = new_entries.get(path)
                if old and not new:
                    alerts.append(_mk_alert("legit_release", path, old[0], None, "removed by release"))
                elif new and not old:
                    alerts.append(_mk_alert("legit_release", path, None, new[0], "added by release"))
                elif old[0] != new[0]:
                    alerts.append(_mk_alert("legit_release", path, old[0], new[0], "changed by release"))
            release = {
                "cas": new_cas,
                "version": version,
                "signature": signature,
                "key_id": key_id,
                "entries": new_entries,
            }
        else:
            kind = "attestation"
            new_cas = batch["cas"]
            version = base["version"]
            release = None
            if set(observed) != set(base["entries"]):
                raise RefError(Err.SCOPE_MISMATCH, "observation scope does not cover protected paths")
            trusted = {o for o, _ in base["entries"].values()}
            alerts = []
            for path in sorted(base["entries"]):
                base_oid = base["entries"][path][0]
                obs = observed[path]
                if obs is None:
                    alerts.append(_mk_alert("content_change", path, base_oid, None, "file deleted"))
                elif obs == base_oid:
                    continue
                elif obs in trusted:
                    alerts.append(_mk_alert("alias_change", path, base_oid, obs,
                                            "path retargeted to another trusted object"))
                else:
                    alerts.append(_mk_alert("content_change", path, base_oid, obs,
                                            "untrusted object content"))
        pid = model.precheck_id(device, op["batch"], kind, new_cas)
        self.prechecks[pid] = {
            "device": device,
            "batch": op["batch"],
            "generation": batch["generation"],
            "cas": batch["cas"],
            "kind": kind,
            "new_cas": new_cas,
            "version": version,
            "alerts": alerts,
            "release": release,
        }
        self.ctx["last_precheck"] = pid
        if op.get("as"):
            self.ctx[op["as"]] = pid
        return {
            "precheck_id": pid,
            "kind": kind,
            "version": version,
            "new_cas": new_cas,
            "alerts": alerts,
        }

    def op_commit(self, op):
        pid = self.ctx["last_precheck"] if op.get("precheck") == "last" else self.ctx[op["precheck"]] if op["precheck"] in self.ctx else op["precheck"]
        if pid not in self.prechecks:
            raise RefError(Err.PRECHECK_NOT_FOUND, pid)
        if pid in self.commit_by_precheck:
            receipt = self.commit_by_precheck[pid]
            self.ctx["last_commit"] = receipt["commit_id"]
            return {"commit_id": receipt["commit_id"], "cached": True, "receipt": receipt}
        pre = self.prechecks[pid]
        dev = self._device(pre["device"])
        if dev["generation"] != pre["generation"]:
            raise RefError(Err.GENERATION_CHANGED, "device generation moved on")
        if dev["cas"] != pre["cas"]:
            raise RefError(Err.BASELINE_SWAPPED, "current baseline differs from precheck")
        batch = self.batches[(pre["device"], pre["batch"])]
        if batch["state"] != "open" or len(batch["segments"]) != batch["count"]:
            raise RefError(Err.INCOMPLETE_OBSERVATION, pre["batch"])
        release = pre["release"]
        if release is not None:
            self._check_signature(release["key_id"], release["cas"], release["signature"])
            self.baselines.setdefault(
                release["cas"], {"version": release["version"], "entries": release["entries"]}
            )
        cid = model.commit_id(pid)
        dev["cas"] = pre["new_cas"]
        batch["state"] = "committed"
        receipt = model.receipt_body(
            cid, pre["device"], pre["batch"], pre["kind"], pre["generation"],
            pre["cas"], pre["new_cas"], pre["version"], pre["alerts"],
        )
        self.commit_by_precheck[pid] = receipt
        self.receipts[cid] = receipt
        self.ctx["last_commit"] = cid
        return {"commit_id": cid, "cached": False, "receipt": receipt}

    def op_close_batch(self, op):
        device = op["device"]
        dev = self._device(device)
        key = (device, op["batch"])
        batch = self.batches.get(key)
        if batch is None:
            raise RefError(Err.BATCH_NOT_FOUND, op["batch"])
        if batch["state"] != "open":
            raise RefError(Err.BATCH_CLOSED, op["batch"])
        if len(batch["segments"]) >= batch["count"]:
            raise RefError(Err.BATCH_COMPLETE, op["batch"])
        missing = sorted(set(range(batch["count"])) - set(batch["segments"]))
        version = self._baseline(dev["cas"])["version"]
        cid = model.gap_commit_id(device, op["batch"])
        alert = _mk_alert(
            "data_gap", "*", None, None,
            f"observation incomplete; missing segments {missing}; "
            "no protected file is treated as vanished",
        )
        batch["state"] = "closed_gap"
        receipt = self.receipts.get(cid)
        if receipt is None:
            receipt = model.receipt_body(
                cid, device, op["batch"], "gap", dev["generation"],
                dev["cas"], dev["cas"], version, [alert],
            )
            self.receipts[cid] = receipt
        self.ctx["last_commit"] = cid
        return {"commit_id": cid, "cached": False, "receipt": receipt}

    def op_receipt(self, op):
        cid = self.ctx["last_commit"] if op.get("commit") == "last" else op["commit"]
        if cid not in self.receipts:
            raise RefError(Err.RECEIPT_NOT_FOUND, cid)
        return {"receipt": self.receipts[cid]}

    def op_view(self, op):
        return {"view": self._view(op["device"])}

    # -------------------------------------------------------------- dispatch
    def _resolve_pins(self, op):
        generation = op.get("generation", "current")
        cas = op.get("baseline_cas", "current")
        if generation == "current" or cas == "current":
            dev = self._device(op["device"])
            if generation == "current":
                generation = dev["generation"]
            if cas == "current":
                cas = dev["cas"]
        return generation, cas

    def _dispatch(self, op):
        kind = op["op"]
        handler = getattr(self, f"op_{kind}", None)
        if handler is None:
            raise RefError(Err.UNKNOWN_OP, kind)
        return handler(op)

    def run_case(self, case):
        results = []
        for i, op in enumerate(case.get("ops", [])):
            try:
                result = self._dispatch(op)
                results.append({"index": i, "op": op["op"], "status": "ok", "result": result})
            except RefError as exc:
                results.append({
                    "index": i,
                    "op": op["op"],
                    "status": "error",
                    "code": exc.code,
                    "detail": exc.detail,
                })
        return results

    def final_views(self, device_ids):
        return {d: self._view(d) for d in device_ids if d in self.devices}
