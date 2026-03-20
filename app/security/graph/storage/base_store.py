class TupleStoreBackend:
    """
    Base interface for tuple storage backends.

    Allows swapping implementations:
        - memory
        - redis
        - postgres
        - evidence ledger
    """

    def add(self, subject, relation, obj):
        raise NotImplementedError

    def has(self, subject, relation, obj):
        raise NotImplementedError

    def find_subjects(self, relation, obj):
        raise NotImplementedError

    def find_objects(self, subject, relation):
        raise NotImplementedError
