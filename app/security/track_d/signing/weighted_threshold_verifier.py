"""
TRACK D — Weighted Threshold Verifier (Hardened)

Security Guarantees:
- Payload integrity enforcement
- Duplicate signer prevention
- Strict UTC enforcement
- Lifecycle validation
- Deterministic weight accumulation
- Algorithm enforcement
- Hash algorithm binding
- Quorum enforcement
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, Any, Set
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .trust_store import TrustStore


# ---------------------------------------------------------
# Strict UTC
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Weighted Threshold Verifier
# ---------------------------------------------------------

class WeightedThresholdVerifier:

    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store

    def verify(
        self,
        *,
        payload: Dict[str, Any],
        signature_object: Dict[str, Any],
        now_utc: str,
    ) -> bool:

        now = _parse_utc(now_utc)

        # ---------------------------------------------------------
        # Structure Validation
        # ---------------------------------------------------------

        if signature_object.get("type") != "WEIGHTED_THRESHOLD":
            raise ValueError("Invalid signature type")

        if signature_object.get("hash_algorithm") != "SHA-256":
            raise ValueError("Unsupported hash algorithm")

        required_weight = signature_object.get("required_weight")
        if not isinstance(required_weight, int) or required_weight <= 0:
            raise ValueError("Invalid required_weight")

        payload_hash = signature_object.get("payload_hash")
        signatures = signature_object.get("signatures", [])

        if not signatures:
            raise ValueError("No signatures provided")

        # ---------------------------------------------------------
        # Payload Integrity
        # ---------------------------------------------------------

        canonical = _canonical(payload)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        if expected_hash != payload_hash:
            raise ValueError("Payload hash mismatch")

        total_weight = 0
        seen_keys: Set[str] = set()

        # ---------------------------------------------------------
        # Signature Verification
        # ---------------------------------------------------------

        for entry in signatures:

            if "key_id" not in entry or "signature" not in entry or "signed_at" not in entry:
                raise ValueError("Malformed signature entry")

            key_id = entry["key_id"]

            if key_id in seen_keys:
                raise ValueError("Duplicate signer detected")

            seen_keys.add(key_id)

            signed_at = _parse_utc(entry["signed_at"])

            if signed_at > now:
                raise ValueError("Future-dated signature")

            # Lifecycle validation
            self.trust_store.validate_lifecycle(key_id, now_utc)

            # Algorithm enforcement
            if self.trust_store.get_algorithm(key_id) != "Ed25519":
                raise ValueError("Unsupported algorithm")

            weight = self.trust_store.get_weight(key_id)

            if weight <= 0:
                raise ValueError("Invalid weight")

            public_key_bytes = self.trust_store.get_public_key(key_id)
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            try:
                signature_bytes = bytes.fromhex(entry["signature"])
            except Exception:
                raise ValueError("Invalid signature encoding")

            public_key.verify(
                signature_bytes,
                payload_hash.encode("utf-8"),
            )

            total_weight += weight

        # ---------------------------------------------------------
        # Quorum Enforcement
        # ---------------------------------------------------------

        if total_weight < required_weight:
            raise ValueError("Insufficient quorum weight")

        return True
