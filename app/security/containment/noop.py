class NoOpContainmentEngine:
    """
    Null-object containment engine.
    Used for sprints/tests where containment is not enforced.
    """

    def is_contained(self, ctx):
        return False

    def evaluate(self, ctx, decision):
        return decision

