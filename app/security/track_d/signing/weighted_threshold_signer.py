"""
TRACK D — Weighted Threshold Signer (Hardened)
"""

from __future__ import annotations

import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .signer_interface import ISigner
from .trust_store import TrustStore


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


def generate_weighted_threshold_signature(
    *,
    payload: Dict[str, Any],
    signers: List[ISigner],
    required_weight: int,
    signed_at_utc: str,
    trust_store: Optional[TrustStore] = None,
) -> Dict[str, Any]:

    if required_weight <= 0:
        raise ValueError("required_weight must be positive")

    if not signers:
        raise ValueError("At least one signer required")

    signed_at = _parse_utc(signed_at_utc)

    canonical = _canonical(payload)
    payload_hash = hashlib.sha256(canonical).hexdigest()

    seen_keys = set()
    signatures = []
    accumulated_weight = 0

    for signer in signers:

        key_id = signer.key_id()

        if key_id in seen_keys:
            raise ValueError("Duplicate signer key detected")

        seen_keys.add(key_id)

        # ✅ FIX: unpack tuple
        sig_hex, returned_key_id = signer.sign(payload_hash.encode("utf-8"))

        if returned_key_id != key_id:
            raise ValueError("Signer returned mismatched key_id")

        if trust_store:
            accumulated_weight += trust_store.get_weight(key_id)

        signatures.append({
            "key_id": key_id,
            "signature": sig_hex,
            "signed_at": signed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    if trust_store and accumulated_weight < required_weight:
        raise ValueError("Insufficient accumulated weight at signing time")

    signatures.sort(key=lambda x: x["key_id"])

    return {
        "type": "WEIGHTED_THRESHOLD",
        "required_weight": required_weight,
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "signatures": signatures,
    }
