from app.security.observability.events import SecurityEvent
from app.security.observability.emitter import EventSink


class SOARSink(EventSink):
    def emit(self, event: SecurityEvent) -> None:
        # Stub: trigger workflows / playbooks
        # Never affects decisions
        pass
