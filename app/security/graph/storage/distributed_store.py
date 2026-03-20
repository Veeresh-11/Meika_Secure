class DistributedTupleStore:

    def __init__(self, backend, replica_clients):

        self.backend = backend
        self.replicas = replica_clients

    def add(self, subject, relation, obj):

        self.backend.add(subject, relation, obj)

        for replica in self.replicas:
            replica.replicate(subject, relation, obj)

    def has(self, subject, relation, obj):

        return self.backend.has(subject, relation, obj)

    def find_objects(self, subject, relation):

        return self.backend.find_objects(subject, relation)

    def find_subjects(self, relation, obj):

        return self.backend.find_subjects(relation, obj)
