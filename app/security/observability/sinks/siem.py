from app.security.observability.events import SecurityEvent
from app.security.observability.emitter import EventSink


class SIEMSink(EventSink):
    def emit(self, event: SecurityEvent) -> None:
        # Stub: forward to Splunk / Sentinel / Elastic
        # Must be async / fire-and-forget in real deployment
        pass
