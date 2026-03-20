from app.security.pipeline import SecureIDKernel
from app.security.errors import SecurityInvariantViolation
from app.security.runtime_state import KernelState


class CollectSink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def test_tamper_emits_event():
    sink = CollectSink()
    kernel = SecureIDKernel(event_emitter=sink)

    # Force version mismatch
    kernel._enter_safe_mode("TEST_TAMPER")

    assert kernel._state == KernelState.SAFE_MODE
    assert len(sink.events) == 1
    assert sink.events[0].event_type == "KERNEL_TAMPER_DETECTED"

