"""Content addressing, synthetic signatures and deterministic identifiers.

Only the standard library is used.  "Signatures" are HMAC-SHA256 over the
baseline CAS with a synthetic secret; the key registry lives in the store so
revocation is visible to every process.
"""

from __future__ import annotations

import hashlib
import hmac
import json


def canonical(obj) -> str:
    """Deterministic JSON encoding used for every hash input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def object_fingerprint(content: str) -> dict:
    """Synthetic object table entry: SHA-256 + size of the synthetic content."""
    return {
        "sha256": sha256_text("object:" + content),
        "size": len(content.encode("utf-8")),
    }


def baseline_cas(device_id: str, version: int, entries) -> str:
    """Content address of a baseline manifest.

    ``entries`` is an iterable of ``(canonical_path, oid, sha256)`` tuples.
    """
    doc = {
        "device": device_id,
        "version": int(version),
        "entries": [
            {"path": p, "oid": o, "sha256": s} for p, o, s in sorted(entries)
        ],
    }
    return sha256_text("baseline:" + canonical(doc))


def sign(secret: str, cas: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), ("baseline:" + cas).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify(secret: str, cas: str, signature: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(secret, cas), signature)


def precheck_id(device_id: str, batch_id: str, kind: str, new_cas: str) -> str:
    return sha256_text("precheck:" + canonical([device_id, batch_id, kind, new_cas]))


def commit_id(precheck: str) -> str:
    return sha256_text("commit:" + precheck)


def gap_commit_id(device_id: str, batch_id: str) -> str:
    return sha256_text("commit:gap:" + canonical([device_id, batch_id]))


def receipt_body(
    commit: str,
    device: str,
    batch_id: str,
    kind: str,
    generation: int,
    base_cas: str,
    new_cas: str,
    version: int,
    alerts,
) -> dict:
    """Deterministic, idempotent receipt.

    Every alert is pinned to the baseline ``version`` it was raised against.
    """
    pinned = [dict(a, version=version) for a in alerts]
    body = {
        "commit_id": commit,
        "device": device,
        "batch_id": batch_id,
        "kind": kind,
        "generation": int(generation),
        "base_cas": base_cas,
        "new_cas": new_cas,
        "version": int(version),
        "alert_count": len(alerts),
        "alerts_digest": sha256_text("alerts:" + canonical(pinned)),
    }
    body["receipt_digest"] = sha256_text("receipt:" + canonical(body))
    return body
