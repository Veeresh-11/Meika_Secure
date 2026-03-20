"""
TRACK D — Enterprise Export Verifier (Hardened)

Security Guarantees:
- Strict structure validation
- Hash algorithm binding
- Algorithm enforcement
- Lifecycle validation
- Canonical integrity enforcement
- Bundle hash binding
- Deterministic verification
"""

from __future__ import annotations

import json
import hashlib
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .trust_store import TrustStore


# ---------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------

def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------
# Export Verifier
# ---------------------------------------------------------

class ExportVerifier:

    def __init__(self, trust_store: TrustStore):
        self.trust_store = trust_store

    def verify(self, bundle: Dict[str, Any], now_utc: str) -> bool:

        # ---------------------------------------------------------
        # Structure Validation
        # ---------------------------------------------------------

        required_fields = [
            "key_id",
            "signature",
            "bundle_hash",
            "hash_algorithm",
            "signing_algorithm",
        ]

        for field in required_fields:
            if field not in bundle:
                raise ValueError(f"Missing required field: {field}")

        if bundle.get("hash_algorithm") != "SHA-256":
            raise ValueError("Unsupported hash algorithm")

        if bundle.get("signing_algorithm") != "Ed25519":
            raise ValueError("Unsupported signing algorithm")

        key_id = bundle["key_id"]

        # ---------------------------------------------------------
        # Lifecycle Validation
        # ---------------------------------------------------------

        self.trust_store.validate_lifecycle(key_id, now_utc)

        if self.trust_store.get_algorithm(key_id) != "Ed25519":
            raise ValueError("TrustStore algorithm mismatch")

        # ---------------------------------------------------------
        # Canonical Payload Reconstruction
        # ---------------------------------------------------------

        # Remove signature-bound fields only
        payload = {
            k: v for k, v in bundle.items()
            if k not in (
                "signature",
                "bundle_hash",
                "key_id",
                "hash_algorithm",
                "signing_algorithm",
            )
        }

        canonical = _canonical(payload)

        # ---------------------------------------------------------
        # Verify Bundle Hash
        # ---------------------------------------------------------

        expected_hash = hashlib.sha256(canonical).hexdigest()

        if expected_hash != bundle["bundle_hash"]:
            raise ValueError("Bundle hash mismatch")

        # ---------------------------------------------------------
        # Signature Verification
        # ---------------------------------------------------------

        public_key_bytes = self.trust_store.get_public_key(key_id)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        try:
            signature_bytes = bytes.fromhex(bundle["signature"])
        except Exception:
            raise ValueError("Invalid signature encoding")

        public_key.verify(signature_bytes, canonical)

        return True
