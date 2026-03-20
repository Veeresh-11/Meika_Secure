"""
TRACK D — Node Manifest

Security Guarantees:
- Canonical JSON signing
- Ed25519 signature enforcement
- Tamper detection
"""

from __future__ import annotations

import json
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class NodeManifest:

    def __init__(
        self,
        *,
        node_id: str,
        public_key_hex: str,
        capabilities: list[str],
        weight: int,
        created_at: str,
    ):
        self.node_id = node_id
        self.public_key_hex = public_key_hex
        self.capabilities = list(capabilities)
        self.weight = weight
        self.created_at = created_at

    def _payload(self) -> dict:
        return {
            "node_id": self.node_id,
            "public_key_hex": self.public_key_hex,
            "capabilities": sorted(self.capabilities),
            "weight": self.weight,
            "created_at": self.created_at,
        }

    def sign(self, signer) -> str:
        payload_hash = hashlib.sha256(_canonical(self._payload())).hexdigest()
        sig_hex, _ = signer.sign(payload_hash.encode("utf-8"))
        return sig_hex

    def verify(self, signature_hex: str) -> bool:
        payload_hash = hashlib.sha256(_canonical(self._payload())).hexdigest()

        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(self.public_key_hex)
        )

        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                payload_hash.encode("utf-8"),
            )
        except Exception:
            raise ValueError("Manifest verification failed")

        return True
