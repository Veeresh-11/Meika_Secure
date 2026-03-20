from __future__ import annotations
from typing import Dict, Any

from ..transparency.transparency_log import TransparencyLog
from .models import VerificationResponse


class RootVerifier:

    def __init__(self, transparency_log: TransparencyLog):
        self.transparency_log = transparency_log

    def verify(self, root_hash: str) -> VerificationResponse:

        exists = self.transparency_log.contains(root_hash)

        proof: Dict[str, Any] | None = None

        if exists:
            proof = {
                "payload_hash": root_hash,
                "log_size": self.transparency_log.size(),
            }

        return VerificationResponse(
            verified=exists,
            object_type="ROOT",
            object_id=root_hash,
            proof=proof,
        )
