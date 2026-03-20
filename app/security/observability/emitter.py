from typing import List
from app.security.observability.events import SecurityEvent


class EventSink:
    def emit(self, event: SecurityEvent) -> None:
        raise NotImplementedError


class SecurityEventEmitter:
    """
    Non-authoritative, best-effort event emitter.
    Failure here must never affect execution.
    """

    def __init__(self, sinks: List[EventSink]):
        self._sinks = sinks

    def emit(self, event: SecurityEvent) -> None:
        for sink in self._sinks:
            try:
                sink.emit(event)
            except Exception:
                # Explicitly swallow errors
                # Observability must NEVER affect security
                pass
