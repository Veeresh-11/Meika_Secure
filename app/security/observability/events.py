import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict
from enum import Enum


class SecurityEventType(str, Enum):
    AUTH_ATTEMPT = "auth.attempt"
    AUTH_DECISION = "auth.decision"
    GRANT_ISSUED = "grant.issued"
    GRANT_EXPIRED = "grant.expired"
    CONTAINMENT_TRIGGERED = "containment.triggered"
    POLICY_DENY = "policy.deny"


@dataclass(frozen=True)
class SecurityEvent:
    event_type: SecurityEventType
    timestamp: datetime
    principal_id: Optional[str]
    decision: Optional[str]
    policy_version: Optional[str]
    metadata: Dict

class GovernanceEventStream:
    """
    Ring-buffer event stream for governance operations.
    """

    def __init__(self, max_size=1000):
        self._lock = threading.Lock()
        self._events = deque(maxlen=max_size)

    def emit(self, event_type: str, payload: dict):
        with self._lock:
            self._events.append({
                "type": event_type,
                "payload": payload,
            })

    def snapshot(self):
        with self._lock:
            return list(self._events)


event_stream = GovernanceEventStream()
