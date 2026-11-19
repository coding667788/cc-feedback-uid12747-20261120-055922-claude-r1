"""Worker entry points for the multi-process tests.

Each worker opens its own :class:`~solution.engine.Engine` on the shared
SQLite database, performs exactly one action and (except the crash worker)
writes a small JSON result file the parent process asserts on.  The crash
worker really terminates itself (``os._exit``) at a commit kill point so the
restart/recovery path can be verified from a fresh process.
"""

from __future__ import annotations

import json

from .engine import Engine
from .errors import EngineError


def _write(result_path, payload):
    with open(result_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True)


def _guard(result_path, fn):
    try:
        out = fn()
    except EngineError as exc:
        _write(result_path, {"status": "error", "code": exc.code, "detail": exc.detail})
    else:
        _write(result_path, {"status": "ok", "result": out})


def worker_submit_segment(db_path, result_path, seg):
    _guard(result_path, lambda: Engine(db_path).submit_segment(seg))


def worker_precheck(db_path, result_path, device, batch, release=None):
    _guard(result_path, lambda: Engine(db_path).precheck(device, batch, release))


def worker_commit(db_path, result_path, precheck_id):
    eng = Engine(db_path)
    _guard(result_path, lambda: eng.commit(precheck_id)[0])


def worker_rebuild(db_path, result_path, device, spec):
    _guard(result_path, lambda: Engine(db_path).rebuild_device(device, spec))


def worker_revoke_key(db_path, result_path, key_id):
    _guard(result_path, lambda: Engine(db_path).revoke_key(key_id))


def worker_close_batch(db_path, result_path, device, batch):
    _guard(result_path, lambda: Engine(db_path).close_batch(device, batch))


def crash_worker(db_path, precheck_id, kill_point):
    """Commit and really die at ``kill_point`` (no result file is written)."""
    Engine(db_path).commit(precheck_id, kill_point=kill_point)
