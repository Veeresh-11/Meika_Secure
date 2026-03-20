"""
TRACK D — Detached Signature Verifier (Hardened)

Security Guarantees:
- Type enforcement
- Hash algorithm binding
- Strict UTC enforcement
- Future-dated rejection
- Key activation enforcement
- Lifecycle validation
- Expiration enforcement
- Replay detection (per instance)
- Algorithm enforcement
- Payload integrity binding
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, Any
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .trust_store import TrustStore


# ---------------------------------------------------------
# Strict UTC Parsing
# ---------------------------------------------------------

def _parse_utc(ts: str) -> datetime:
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise ValueError("Timestamp must be RFC3339 UTC (Z suffix required)")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------

def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------
# Detached Verifier
# ---------------------------------------------------------

class DetachedVerifier:

    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store
        self._seen_hashes = set()

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

        if signature_object.get("type") != "DETACHED":
            raise ValueError("Invalid signature type")

        if signature_object.get("hash_algorithm") != "SHA-256":
            raise ValueError("Unsupported hash algorithm")

        required_fields = [
            "key_id",
            "signature",
            "signed_at",
            "payload_hash",
            "algorithm",
        ]

        for field in required_fields:
            if field not in signature_object:
                raise ValueError(f"Missing required field: {field}")

        key_id = signature_object["key_id"]

        signed_at = _parse_utc(signature_object["signed_at"])

        # ---------------------------------------------------------
        # Future-dated signature protection
        # ---------------------------------------------------------

        if signed_at > now:
            raise ValueError("Signature is from the future")

        # ---------------------------------------------------------
        # Key activation enforcement
        # ---------------------------------------------------------

        key_meta = self.trust_store.get_metadata(key_id)
        key_created_at = key_meta["created_at"]

        if signed_at < key_created_at:
            raise ValueError("Signature created before key activation")

        # ---------------------------------------------------------
        # Expiration enforcement
        # ---------------------------------------------------------

        if signature_object.get("expires_at"):
            expires_at = _parse_utc(signature_object["expires_at"])
            if now > expires_at:
                raise ValueError("Signature expired")

        # ---------------------------------------------------------
        # Key lifecycle validation
        # ---------------------------------------------------------

        self.trust_store.validate_lifecycle(key_id, now_utc)

        # ---------------------------------------------------------
        # Algorithm enforcement
        # ---------------------------------------------------------

        if self.trust_store.get_algorithm(key_id) != "Ed25519":
            raise ValueError("Unsupported algorithm")

        if signature_object["algorithm"] != "Ed25519":
            raise ValueError("Algorithm mismatch")

        # ---------------------------------------------------------
        # Payload integrity
        # ---------------------------------------------------------

        canonical = _canonical(payload)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        if expected_hash != signature_object["payload_hash"]:
            raise ValueError("Payload hash mismatch")

        # ---------------------------------------------------------
        # Replay detection
        # ---------------------------------------------------------

        if expected_hash in self._seen_hashes:
            raise ValueError("Replay detected")

        # ---------------------------------------------------------
        # Signature verification
        # ---------------------------------------------------------

        public_key_bytes = self.trust_store.get_public_key(key_id)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        try:
            signature_bytes = bytes.fromhex(signature_object["signature"])
        except Exception:
            raise ValueError("Invalid signature encoding")

        public_key.verify(
            signature_bytes,
            signature_object["payload_hash"].encode("utf-8"),
        )

        # Mark seen AFTER success
        self._seen_hashes.add(expected_hash)

        return True
