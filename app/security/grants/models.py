
# app/security/grants/models.py

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4


@dataclass  # ❗ NOT frozen in Sprint A3
class Grant:
    grant_id: str
    principal_id: str
    issued_at: datetime
    expires_at: datetime
    issued_by_policy: str
    intent: str
    justification: str

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "principal_id": self.principal_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issued_by_policy": self.issued_by_policy,
            "intent": self.intent,
            "justification": self.justification,
        }


def create_grant(
    *,
    principal_id: str,
    intent: str,
    lifetime_seconds: int,
    issued_by_policy: str,
    justification: str,
) -> Grant:
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(seconds=lifetime_seconds)

    return Grant(
        grant_id=str(uuid4()),
        principal_id=principal_id,
        intent=intent,
        issued_at=issued_at,
        expires_at=expires_at,
        issued_by_policy=issued_by_policy,
        justification=justification,
    )
