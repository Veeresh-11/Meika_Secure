from collections import defaultdict


class TupleStore:
    """
    Deterministic indexed tuple store.

    Stores tuples in canonical form:
        subject, relation, object

    Provides O(1) lookups for graph traversal.
    """

    def __init__(self):

        # canonical storage
        self._tuples = set()

        # (subject, relation) -> objects
        self._subject_index = defaultdict(set)

        # (object, relation) -> subjects
        self._object_index = defaultdict(set)

    def add(self, subject: str, relation: str, obj: str):

        key = (subject, relation, obj)

        if key in self._tuples:
            return

        self._tuples.add(key)

        self._subject_index[(subject, relation)].add(obj)
        self._object_index[(obj, relation)].add(subject)

    def has(self, subject: str, relation: str, obj: str) -> bool:

        return obj in self._subject_index.get((subject, relation), set())

    def find_subjects(self, relation: str, obj: str):

        # deterministic order
        return sorted(
            self._object_index.get((obj, relation), [])
        )

    def find_objects(self, subject: str, relation: str):

        # deterministic order
        return sorted(
            self._subject_index.get((subject, relation), [])
        )