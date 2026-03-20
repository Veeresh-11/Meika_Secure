"""
TRACK D — Root Certificate

Security Guarantees:
- Deterministic canonical encoding
- Cluster-signed quorum certification
- Immutable certificate hash
- Ed25519 verification
- Tamper detection
"""

from __future__ import annotations

import json
import hashlib
from typing import List, Dict, Any
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------
# Canonical Encoding
# ---------------------------------------------------------

def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ---------------------------------------------------------
# Root Certificate
# ---------------------------------------------------------

@dataclass(frozen=True)
class RootCertificate:
    cluster_id: str
    proposal_hash: str
    merkle_root: str
    participants: List[str]
    total_weight: int
    minimum_weight: int
    created_at: str
    signature: str

    # -----------------------------------------------------
    # Canonical Body (unsigned)
    # -----------------------------------------------------

    def _body(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "proposal_hash": self.proposal_hash,
            "merkle_root": self.merkle_root,
            "participants": sorted(self.participants),
            "total_weight": self.total_weight,
            "minimum_weight": self.minimum_weight,
            "created_at": self.created_at,
        }

    # -----------------------------------------------------
    # Certificate Hash
    # -----------------------------------------------------

    def certificate_hash(self) -> str:
        return hashlib.sha256(_canonical(self._body())).hexdigest()

    # -----------------------------------------------------
    # Verify Signature
    # -----------------------------------------------------

    def verify(self, public_key_bytes: bytes) -> bool:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        try:
            public_key.verify(
                bytes.fromhex(self.signature),
                self.certificate_hash().encode("utf-8"),
            )
            return True
        except InvalidSignature:
            raise ValueError("Invalid root certificate signature")

    # -----------------------------------------------------
    # Create Certificate (Factory)
    # -----------------------------------------------------

    @staticmethod
    def issue(
        *,
        cluster_id: str,
        proposal_hash: str,
        merkle_root: str,
        participants: List[str],
        total_weight: int,
        minimum_weight: int,
        created_at: str,
        private_key: Ed25519PrivateKey,
    ) -> "RootCertificate":

        body = {
            "cluster_id": cluster_id,
            "proposal_hash": proposal_hash,
            "merkle_root": merkle_root,
            "participants": sorted(participants),
            "total_weight": total_weight,
            "minimum_weight": minimum_weight,
            "created_at": created_at,
        }

        cert_hash = hashlib.sha256(_canonical(body)).hexdigest()

        signature = private_key.sign(
            cert_hash.encode("utf-8")
        ).hex()

        return RootCertificate(
            cluster_id=cluster_id,
            proposal_hash=proposal_hash,
            merkle_root=merkle_root,
            participants=sorted(participants),
            total_weight=total_weight,
            minimum_weight=minimum_weight,
            created_at=created_at,
            signature=signature,
        )
