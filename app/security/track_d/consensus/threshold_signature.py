from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# =========================================================
# Threshold Signature Object
# =========================================================

@dataclass(frozen=True)
class ThresholdSignature:
    message_hash: str
    aggregate_signature: str
    threshold: int
    total: int
    signer_id: str

    def verify(self, expected_message_hash: str) -> bool:

        if expected_message_hash != self.message_hash:
            return False

        expected = _hash(
            (
                self.message_hash
                + str(self.threshold)
                + str(self.total)
                + self.signer_id
            ).encode()
        )

        return expected == self.aggregate_signature


# =========================================================
# Threshold Signer
# =========================================================

class ThresholdSigner:

    # Class-level governance authority
    _governance_signer_id: str | None = None

    def __init__(self, *, total: int, threshold: int):

        if threshold > total:
            raise ValueError("Threshold cannot exceed total")

        self.total = total
        self.threshold = threshold
        self._id = secrets.token_hex(8)

        # First signer created becomes governance signer
        if ThresholdSigner._governance_signer_id is None:
            ThresholdSigner._governance_signer_id = self._id

    @classmethod
    def generate(cls, *, total: int, threshold: int):
        return cls(total=total, threshold=threshold)

    @classmethod
    def governance_signer_id(cls) -> str | None:
        return cls._governance_signer_id

    def sign(self, message_hash: str) -> ThresholdSignature:

        aggregate = _hash(
            (
                message_hash
                + str(self.threshold)
                + str(self.total)
                + self._id
            ).encode()
        )

        return ThresholdSignature(
            message_hash=message_hash,
            aggregate_signature=aggregate,
            threshold=self.threshold,
            total=self.total,
            signer_id=self._id,
        )
