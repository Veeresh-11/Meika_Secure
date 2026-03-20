from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime, timezone


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class VerificationResponse:
    verified: bool
    object_type: str
    object_id: str
    proof: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "proof": self.proof,
            "timestamp": _utc_now(),
        }
