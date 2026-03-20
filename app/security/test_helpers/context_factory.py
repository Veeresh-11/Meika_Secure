from datetime import datetime

from app.security.context import SecurityContext


def a1_test_context() -> SecurityContext:
    """
    Deterministic baseline context for Sprint A1/A2 tests.
    """
    return SecurityContext(
        request_id="req-1",
        principal_id="test-user",
        intent="test",
        authenticated=True,
        device_id="dev-1",
        device=None,
        risk_signals={},
        request_time=datetime(2024, 1, 1),
        metadata={},
    )
