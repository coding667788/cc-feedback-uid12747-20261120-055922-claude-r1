"""Shared fixtures for the test suite."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.engine import Engine  # noqa: E402
from solution.paths import canon_path  # noqa: E402

OBJECTS = {
    "O1": "alpha-1",
    "O2": "beta-2",
    "O3": "gamma-3",
    "O4": "delta-4",
    "O5": "epsilon-5",
    "O6": "zeta-6",
    "OX": "rogue-x",
}

KEYS = {"k-root": "root-secret", "k-rel": "rel-secret"}

ENTRIES_V1 = [
    ["C:/App/a.exe", "O1"],
    ["C:/App/b.exe", "O1"],   # hard-link alias of a.exe
    ["C:/App/c.dll", "O2"],
    ["D:/Data/d.dat", "O3"],
]

DEVICE = "dev-1"


def make_engine(db_path):
    eng = Engine(db_path)
    eng.register_objects(OBJECTS)
    for key_id, secret in KEYS.items():
        eng.register_key(key_id, secret)
    eng.create_device(DEVICE, {"version": 1, "entries": ENTRIES_V1, "sign_with": "k-root"})
    return eng


def clean_observation():
    return {path: oid for path, oid in ENTRIES_V1}


def submit_full(eng, batch, obs, count=1, device=DEVICE):
    """Submit a complete observation split into ``count`` segments."""
    items = sorted(((canon_path(p), o) for p, o in obs.items()), key=lambda t: t[0])
    view = eng.device_view(device)
    chunks = [items[i::count] for i in range(count)]
    for index, chunk in enumerate(chunks):
        eng.submit_segment({
            "device": device,
            "batch": batch,
            "segment_count": count,
            "index": index,
            "generation": view["generation"],
            "baseline_cas": view["baseline_cas"],
            "observations": dict(chunk),
        })


def run_op_process(ctx, target, args, expect_exit=0):
    proc = ctx.Process(target=target, args=args)
    proc.start()
    proc.join(60)
    assert proc.exitcode == expect_exit, f"worker exitcode={proc.exitcode}"
