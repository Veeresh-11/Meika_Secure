import time


class TupleCache:

    def __init__(self, backend, ttl_seconds=30):

        self.backend = backend
        self.ttl = ttl_seconds

        self._cache = {}

    def _key(self, subject, relation, obj):

        return f"{subject}|{relation}|{obj}"

    def has(self, subject, relation, obj):

        key = self._key(subject, relation, obj)

        entry = self._cache.get(key)

        now = time.monotonic()

        if entry and now - entry[1] < self.ttl:
            return entry[0]

        result = self.backend.has(subject, relation, obj)

        self._cache[key] = (result, now)

        return result

    def find_objects(self, subject, relation):

        return self.backend.find_objects(subject, relation)

    def find_subjects(self, relation, obj):

        return self.backend.find_subjects(relation, obj)

    def add(self, subject, relation, obj):

        self.backend.add(subject, relation, obj)
