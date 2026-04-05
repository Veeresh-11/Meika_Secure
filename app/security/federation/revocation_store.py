import threading
import time


class InMemoryRevocationStore:
    """
    Thread-safe token revocation store.
    Stores revoked JTIs until expiration.
    """

    def __init__(self):
        self._revoked = {}
        self._lock = threading.Lock()

    def revoke(self, jti: str, exp: int):
        """
        Mark token as revoked until expiry.
        """
        with self._lock:
            self._revoked[jti] = exp

    def is_revoked(self, jti: str) -> bool:
        """
        Check if token is revoked.
        Also cleans up expired entries.
        """
        now = int(time.time())

        with self._lock:
            # Cleanup expired JTIs
            expired = [k for k, v in self._revoked.items() if v < now]
            for k in expired:
                del self._revoked[k]

            return jti in self._revoked