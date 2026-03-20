import time
from collections import OrderedDict


class ReplayCache:

    def __init__(self, ttl_seconds):
        self.ttl = ttl_seconds
        self._store = OrderedDict()

    def seen(self, key):

        now = time.monotonic()

        # remove expired entries
        while self._store:
            k, ts = next(iter(self._store.items()))

            if now - ts > self.ttl:
                self._store.popitem(last=False)
            else:
                break

        if key in self._store:
            return True

        self._store[key] = now
        return False
