"""
TRACK D — Consensus Vote
Signed vote from node.
"""

from __future__ import annotations
import json
import hashlib
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class Vote:

    def __init__(
        self,
        *,
        node_id: str,
        proposal_hash: str,
        signed_at: str,
        signature: str,
    ):
        self.node_id = node_id
        self.proposal_hash = proposal_hash
        self.signed_at = signed_at
        self.signature = signature

    def verify(self, public_key_bytes: bytes) -> bool:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        payload = {
            "node_id": self.node_id,
            "proposal_hash": self.proposal_hash,
            "signed_at": self.signed_at,
        }

        try:
            public_key.verify(
                bytes.fromhex(self.signature),
                _canonical(payload),
            )
            return True
        except Exception:
            return False
