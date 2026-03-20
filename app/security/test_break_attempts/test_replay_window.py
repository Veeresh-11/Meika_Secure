import pytest

pytestmark = pytest.mark.break_attempt
from app.security.decision import SecurityDecision
from app.security.time.clock import SecurityClock
from app.security.decision import DecisionOutcome

class FakeSnapshot:
    def __init__(self, timestamp, snapshot_id):
        self.timestamp = timestamp
        self.snapshot_id = snapshot_id


def test_snapshot_replay_is_denied():
    clock = SecurityClock(
        now_monotonic=lambda: 1000.0,
        replay_window_seconds=30,
        max_skew_seconds=5,
    )

    snapshot = FakeSnapshot(timestamp=995.0, snapshot_id="abc")

    first = clock.evaluate_snapshot(snapshot)
    second = clock.evaluate_snapshot(snapshot)

    assert first.outcome is DecisionOutcome.ALLOW
    assert second.outcome is DecisionOutcome.DENY
