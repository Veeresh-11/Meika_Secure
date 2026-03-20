from __future__ import annotations

from ..anchoring.anchor_client import AnchorClient
from .models import VerificationResponse


class AnchorVerifier:

    def __init__(self, anchor_client: AnchorClient):
        self.anchor_client = anchor_client

    def verify(self, root_hash: str) -> VerificationResponse:

        # Attempt to retrieve receipt from client
        if not hasattr(self.anchor_client, "get_receipt"):
            return VerificationResponse(
                verified=False,
                object_type="ANCHOR",
                object_id=root_hash,
                proof=None,
            )

        receipt = self.anchor_client.get_receipt(root_hash)

        if receipt is None:
            return VerificationResponse(
                verified=False,
                object_type="ANCHOR",
                object_id=root_hash,
                proof=None,
            )

        valid = self.anchor_client.verify(receipt)

        proof = receipt.to_dict() if valid else None

        return VerificationResponse(
            verified=valid,
            object_type="ANCHOR",
            object_id=root_hash,
            proof=proof,
        )
