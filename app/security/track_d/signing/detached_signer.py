"""
TRACK D — Detached Signature Generator (Hardened)
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .signer_interface import ISigner


def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def generate_detached_signature(
    *,
    payload: Dict[str, Any],
    signer: ISigner,
    signed_at_utc: str,
    expires_at_utc: Optional[str] = None,
) -> Dict[str, Any]:

    signed_at = _parse_utc(signed_at_utc)
    expires_at = _parse_utc(expires_at_utc) if expires_at_utc else None

    if expires_at and expires_at <= signed_at:
        raise ValueError("expires_at must be after signed_at")

    canonical = _canonical(payload)
    payload_hash = hashlib.sha256(canonical).hexdigest()

    # ✅ FIX: unpack tuple correctly
    signature_hex, key_id = signer.sign(payload_hash.encode("utf-8"))

    return {
        "type": "DETACHED",
        "key_id": key_id,
        "algorithm": signer.algorithm(),
        "signed_at": signed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (
            expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            if expires_at
            else None
        ),
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "signature": signature_hex,  # now string
    }
