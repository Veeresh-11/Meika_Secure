from datetime import datetime, timedelta


class AnchorPolicy:
    """
    Record-count based anchoring.
    """

    def __init__(self, threshold: int):
        self.threshold = threshold

    def should_anchor(self, record_count: int) -> bool:
        return record_count > 0 and record_count % self.threshold == 0


class TimeAnchorPolicy:
    """
    Time-based anchoring.
    Caller controls scheduling.
    """

    def __init__(self, interval_seconds: int):
        self.interval = timedelta(seconds=interval_seconds)
        self.last_anchor_time = None

    def should_anchor(self) -> bool:
        if self.last_anchor_time is None:
            return True

        return datetime.utcnow() - self.last_anchor_time >= self.interval

    def mark_anchored(self):
        self.last_anchor_time = datetime.utcnow()
