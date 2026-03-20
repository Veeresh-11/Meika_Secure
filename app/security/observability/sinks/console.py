from app.security.observability.events import SecurityEvent
from app.security.observability.emitter import EventSink


class ConsoleSink(EventSink):
    def emit(self, event: SecurityEvent) -> None:
        print(f"[SECURITY EVENT] {event}")
