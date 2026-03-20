class TupleStoreBackend:
    """
    Backend interface for tuple storage.
    """

    def add(self, subject, relation, obj):
        raise NotImplementedError

    def has(self, subject, relation, obj):
        raise NotImplementedError

    def find_subjects(self, relation, obj):
        raise NotImplementedError

    def find_objects(self, subject, relation):
        raise NotImplementedError
