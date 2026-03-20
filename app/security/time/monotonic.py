import time
from datetime import datetime, timezone, timedelta


class MonotonicClock:
    """
    Monotonic wall clock.

    Protects against NTP rollback and system clock manipulation.
    """

    def __init__(self):
        self._start_wall = datetime.now(timezone.utc)
        self._start_mono = time.monotonic()

    def now(self):
        delta = time.monotonic() - self._start_mono
        return self._start_wall + timedelta(seconds=delta)