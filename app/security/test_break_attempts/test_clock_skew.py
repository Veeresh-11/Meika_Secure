import pytest

pytestmark = pytest.mark.break_attempt
from app.security.time.clock import SecurityClock
from app.security.decision import SecurityDecision
from app.security.decision import DecisionOutcome

class FakeSnapshot:
    def __init__(self, timestamp, snapshot_id="snap-1"):
        self.timestamp = timestamp
        self.snapshot_id = snapshot_id


def test_future_snapshot_is_denied():
    clock = SecurityClock(
        now_monotonic=lambda: 1000.0,
        replay_window_seconds=30,
        max_skew_seconds=5,
    )

    snapshot = FakeSnapshot(timestamp=1010.0)

    decision = clock.evaluate_snapshot(snapshot)
    assert decision.outcome is DecisionOutcome.DENY


def test_stale_snapshot_is_denied():
    clock = SecurityClock(
        now_monotonic=lambda: 1000.0,
        replay_window_seconds=30,
        max_skew_seconds=5,
    )

    snapshot = FakeSnapshot(timestamp=900.0)

    decision = clock.evaluate_snapshot(snapshot)
    assert decision.outcome is DecisionOutcome.DENY


def test_small_clock_skew_is_allowed():
    clock = SecurityClock(
        now_monotonic=lambda: 1000.0,
        replay_window_seconds=30,
        max_skew_seconds=5,
    )

    snapshot = FakeSnapshot(timestamp=997.0)

    decision = clock.evaluate_snapshot(snapshot)
    assert decision.outcome is DecisionOutcome.ALLOW
