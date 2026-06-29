from app.security.tamper_event import TamperEvent
from app.security.version import (
    KERNEL_VERSION,
    KERNEL_BUILD_HASH,
)


def test_create_tamper_event():

    event = TamperEvent.create(
        "TEST_REASON"
    )

    assert event.event_type == "KERNEL_TAMPER_DETECTED"
    assert event.kernel_version == KERNEL_VERSION
    assert event.kernel_build_hash == KERNEL_BUILD_HASH
    assert event.reason == "TEST_REASON"
    assert event.timestamp is not None