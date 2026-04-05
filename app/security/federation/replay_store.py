import threading
import time


class ReplayAttackDetected(Exception):
    pass


class InMemoryReplayStore:
    """
    Thread-safe replay protection store.
    Stores JTI with expiry.
    """

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def check_and_store(self, jti: str, exp: int):
        now = int(time.time())

        with self._lock:
            # Cleanup expired JTIs
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]

            # Replay detection
            if jti in self._store:
                raise ReplayAttackDetected("Token replay detected")

            # Store with expiry
            self._store[jti] = exp