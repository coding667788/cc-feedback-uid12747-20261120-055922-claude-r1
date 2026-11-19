"""Replay a synthetic case (cases.json) against the engine and the reference.

The runner executes every op against a fresh SQLite database, then replays the
same ops through the independent read-only reference model and reports whether
the two agree.  Output is fully deterministic (no clocks, no randomness).
"""

from __future__ import annotations

from .engine import Engine
from .errors import EngineError
from .reference import ReferenceModel


def _resolve_segment(eng, op):
    generation = op.get("generation", "current")
    cas = op.get("baseline_cas", "current")
    if generation == "current" or cas == "current":
        view = eng.device_view(op["device"])
        if generation == "current":
            generation = view["generation"]
        if cas == "current":
            cas = view["baseline_cas"]
    return {
        "device": op["device"],
        "batch": op["batch"],
        "segment_count": op["segment_count"],
        "index": op["index"],
        "generation": generation,
        "baseline_cas": cas,
        "observations": op["observations"],
    }


def _run_op(eng, op, ctx):
    kind = op["op"]
    if kind == "register_objects":
        return eng.register_objects(op["objects"])
    if kind == "register_key":
        return eng.register_key(op["key_id"], op["secret"])
    if kind == "revoke_key":
        return eng.revoke_key(op["key_id"])
    if kind == "create_device":
        return eng.create_device(op["device"], op["baseline"])
    if kind == "rebuild":
        return eng.rebuild_device(op["device"], op["baseline"])
    if kind == "submit_segment":
        return eng.submit_segment(_resolve_segment(eng, op))
    if kind == "precheck":
        out = eng.precheck(op["device"], op["batch"], op.get("release"))
        ctx["last_precheck"] = out["precheck_id"]
        if op.get("as"):
            ctx[op["as"]] = out["precheck_id"]
        return out
    if kind == "commit":
        pid = _resolve_ref(ctx, op.get("precheck"), "last_precheck")
        receipt, cached = eng.commit(pid)
        ctx["last_commit"] = receipt["commit_id"]
        return {"commit_id": receipt["commit_id"], "cached": cached, "receipt": receipt}
    if kind == "close_batch":
        out = eng.close_batch(op["device"], op["batch"])
        ctx["last_commit"] = out["commit_id"]
        return out
    if kind == "receipt":
        cid = _resolve_ref(ctx, op.get("commit"), "last_commit")
        return {"receipt": eng.receipt(cid)}
    if kind == "view":
        return {"view": eng.device_view(op["device"])}
    raise EngineError("ERR_UNKNOWN_OP", kind)


def _resolve_ref(ctx, value, default_key):
    if value is None or value == "last":
        return ctx[default_key]
    return ctx.get(value, value)


def _device_ids(case):
    seen = []
    for op in case.get("ops", []):
        if op["op"] == "create_device" and op["device"] not in seen:
            seen.append(op["device"])
    return seen


def _norm(result):
    result = dict(result)
    result.pop("detail", None)
    return result


def compare(engine_results, ref_results):
    mismatches = []
    if len(engine_results) != len(ref_results):
        mismatches.append(
            {"error": "result length mismatch",
             "engine": len(engine_results), "reference": len(ref_results)}
        )
    for eng_res, ref_res in zip(engine_results, ref_results):
        if _norm(eng_res) != _norm(ref_res):
            mismatches.append(
                {"index": eng_res["index"], "op": eng_res["op"],
                 "engine": eng_res, "reference": ref_res}
            )
        if len(mismatches) >= 5:
            break
    return mismatches


def run_case(case, db_path):
    eng = Engine(db_path)
    results = []
    ctx = {}
    try:
        for i, op in enumerate(case.get("ops", [])):
            try:
                out = _run_op(eng, op, ctx)
                results.append({"index": i, "op": op["op"], "status": "ok", "result": out})
            except EngineError as exc:
                results.append({
                    "index": i,
                    "op": op["op"],
                    "status": "error",
                    "code": exc.code,
                    "detail": exc.detail,
                })
        views = {}
        for device in _device_ids(case):
            try:
                views[device] = eng.device_view(device)
            except EngineError:
                pass
    finally:
        eng.close()

    ref = ReferenceModel()
    ref_results = ref.run_case(case)
    mismatches = compare(results, ref_results)
    ref_views = ref.final_views(_device_ids(case))
    if ref_views != views:
        mismatches.append({"error": "final view mismatch",
                           "engine": views, "reference": ref_views})
    return {
        "case_id": case.get("case_id", "case"),
        "ops": results,
        "final_views": views,
        "reference": {"match": not mismatches, "mismatches": mismatches},
    }
