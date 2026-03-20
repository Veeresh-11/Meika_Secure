class RelationshipGraph:
    """
    Deterministic and safe relationship graph resolver.

    Protects against graph traversal attacks.
    """

    MAX_DEPTH = 10
    MAX_TRAVERSALS = 100

    def __init__(self, store):
        self.store = store

    def check(self, subject, relation, obj, depth=0, visited=None, budget=None):

        if visited is None:
            visited = set()

        if budget is None:
            budget = {"remaining": self.MAX_TRAVERSALS}

        # ----------------------------------------
        # Traversal budget protection
        # ----------------------------------------

        if budget["remaining"] <= 0:
            return False

        budget["remaining"] -= 1

        # ----------------------------------------
        # Depth limit
        # ----------------------------------------

        if depth > self.MAX_DEPTH:
            return False

        key = (subject, relation, obj)

        # ----------------------------------------
        # Cycle protection
        # ----------------------------------------

        if key in visited:
            return False

        visited.add(key)

        # ----------------------------------------
        # Direct relationship
        # ----------------------------------------

        if self.store.has(subject, relation, obj):
            return True

        # ----------------------------------------
        # Parent traversal
        # ----------------------------------------

        parents = self.store.find_objects(obj, "parent")

        for parent in parents:

            if self.check(
                subject,
                relation,
                parent,
                depth + 1,
                visited,
                budget
            ):
                return True

        return False