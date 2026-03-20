from __future__ import annotations

from .models import VerificationResponse
from ..transparency.merkle_transparency_log import MerkleTransparencyLog


class InclusionVerifier:

    def __init__(self, merkle_log: MerkleTransparencyLog):
        self.merkle_log = merkle_log

    def verify(self, root_hash: str, leaf_value: str) -> VerificationResponse:

        entries = self.merkle_log.entries()

        padded = leaf_value.ljust(64, "0")

        for idx, entry in enumerate(entries):
            if entry["payload_hash"] == padded:

                proof = self.merkle_log.get_inclusion_proof(idx)

                valid = MerkleTransparencyLog.verify_inclusion_proof(
                    entry,
                    proof,
                    root_hash,
                )

                return VerificationResponse(
                    verified=valid,
                    object_type="INCLUSION",
                    object_id=root_hash,
                    proof=proof if valid else None,
                )

        return VerificationResponse(
            verified=False,
            object_type="INCLUSION",
            object_id=root_hash,
            proof=None,
        )
