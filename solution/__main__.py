"""CLI: ``python -m solution --input cases.json --output result.json``.

Exit codes: 0 = replay succeeded and engine matches the reference model;
2 = harness/IO failure; 3 = replay finished but engine and reference disagree.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from .runner import run_case


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Offline file-integrity monitoring simulator (synthetic inputs only)",
    )
    parser.add_argument("--input", required=True, help="path to cases.json")
    parser.add_argument("--output", required=True, help="path to write result.json")
    parser.add_argument("--db", default=None,
                        help="optional SQLite path (default: a fresh temporary DB)")
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            case = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read input {args.input}: {exc}", file=sys.stderr)
        return 2

    tmp = None
    db_path = args.db
    if db_path is None:
        tmp = tempfile.TemporaryDirectory(prefix="fim-sim-")
        db_path = os.path.join(tmp.name, "case.db")

    try:
        result = run_case(case, db_path)
    except Exception as exc:  # harness failure, not a domain error
        print(f"error: case execution failed: {exc}", file=sys.stderr)
        if tmp is not None:
            tmp.cleanup()
        return 2

    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except OSError as exc:
        print(f"error: cannot write output {args.output}: {exc}", file=sys.stderr)
        if tmp is not None:
            tmp.cleanup()
        return 2

    ok = result["reference"]["match"]
    errors = sum(1 for r in result["ops"] if r["status"] == "error")
    print(
        f"case={result['case_id']} ops={len(result['ops'])} "
        f"domain_errors={errors} reference_match={ok}"
    )
    if tmp is not None:
        tmp.cleanup()
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
