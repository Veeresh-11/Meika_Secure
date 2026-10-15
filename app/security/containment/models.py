# app/security/containment/models.py

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class ContainmentState:
    """
    Represents an active containment.
    While active, all authority is suppressed.
    """
    principal_id: str
    reason: str
    activated_at: datetime
    expires_at: Optional[datetime] = None

    def is_active(self, now: Optional[datetime] = None) -> bool:
        if now is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
        if self.expires_at is None:
            return True
        return now < self.expires_at
