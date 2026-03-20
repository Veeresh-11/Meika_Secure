from app.security.results import PolicyResult, ResultKind
from app.security.decision import DecisionOutcome
from datetime import datetime


CLOCK_POLICY_VERSION = "security-clock-v1"


class SecurityClock:
    def __init__(
        self,
        now_monotonic,
        replay_window_seconds: float,
        max_skew_seconds: float,
    ):
        self._now = now_monotonic
        self._replay_window = replay_window_seconds
        self._max_skew = max_skew_seconds
        self._seen_snapshots = set()

    def _result(self, *, outcome: DecisionOutcome, reason: str):
        return PolicyResult(
            outcome=outcome,
            policy_version=CLOCK_POLICY_VERSION,
            evaluated_at=self._now(),
            kind=ResultKind.RISK,
            reason=reason,
        )

    def evaluate_snapshot(self, snapshot):
        now = self._now()
        ts = snapshot.timestamp

        # 1️⃣ Future snapshot
        if ts > now + self._max_skew:
            return self._result(
                outcome=DecisionOutcome.DENY,
                reason="snapshot_from_future",
            )

        # 2️⃣ Stale snapshot
        if now - ts > self._replay_window:
            return self._result(
                outcome=DecisionOutcome.DENY,
                reason="snapshot_stale",
            )

        # 3️⃣ Replay detection
        snapshot_id = getattr(snapshot, "snapshot_id", None)
        if snapshot_id in self._seen_snapshots:
            return self._result(
                outcome=DecisionOutcome.DENY,
                reason="snapshot_replay",
            )

        self._seen_snapshots.add(snapshot_id)

        return self._result(
            outcome=DecisionOutcome.ALLOW,
            reason="snapshot_fresh",
        )
