"""
TRACK D — Bootstrap Manifest

Security Guarantees:
- Genesis node uniqueness
- Canonical signing
- Tamper detection
"""

from __future__ import annotations

import json
import hashlib
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .node_identity import NodeIdentity


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class BootstrapManifest:

    def __init__(
        self,
        *,
        genesis_nodes: List[NodeIdentity],
        created_at: str,
    ):

        node_ids = [n.node_id for n in genesis_nodes]

        if len(node_ids) != len(set(node_ids)):
            raise ValueError("Duplicate genesis node")

        self.genesis_nodes = list(genesis_nodes)
        self.created_at = created_at

    def _payload(self) -> dict:
        return {
            "genesis_nodes": sorted(n.node_id for n in self.genesis_nodes),
            "created_at": self.created_at,
        }

    def sign(self, signer) -> str:
        payload_hash = hashlib.sha256(_canonical(self._payload())).hexdigest()
        sig_hex, _ = signer.sign(payload_hash.encode("utf-8"))
        return sig_hex

    def verify(self, signature_hex: str, public_key_hex: str) -> bool:
        payload_hash = hashlib.sha256(_canonical(self._payload())).hexdigest()

        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex)
        )

        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                payload_hash.encode("utf-8"),
            )
        except Exception:
            raise ValueError("Bootstrap verification failed")

        return True
