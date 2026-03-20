from collections import defaultdict
from .base_store import TupleStoreBackend


class MemoryTupleStore(TupleStoreBackend):

    def __init__(self):

        self._subject_index = defaultdict(set)
        self._object_index = defaultdict(set)

    def add(self, subject, relation, obj):

        self._subject_index[(subject, relation)].add(obj)
        self._object_index[(obj, relation)].add(subject)

    def has(self, subject, relation, obj):

        return obj in self._subject_index.get((subject, relation), set())

    def find_subjects(self, relation, obj):

        return sorted(self._object_index.get((obj, relation), []))

    def find_objects(self, subject, relation):

        return sorted(self._subject_index.get((subject, relation), []))
