# app/security/containment/engine.py

from app.security.context import SecurityContext


class ContainmentEngine:
    """
    Determines whether a principal is under containment.

    Containment is a hard override:
    - If contained → DENY
    - If not contained → normal evaluation continues

    Default behavior is safe: no containment unless explicitly activated.
    """

    def __init__(self):
        # In-memory containment set (can be replaced with DB / signals later)
        self._contained_principals = set()

    def is_contained(self, context: SecurityContext) -> bool:
        """
        Return True if the principal is currently under containment.
        """
        if not context or not context.principal_id:
            return False

        return context.principal_id in self._contained_principals

    # --- Optional helpers (not used yet, safe to keep) ---

    def contain(self, principal_id: str) -> None:
        """
        Place a principal under containment.
        """
        self._contained_principals.add(principal_id)

    def release(self, principal_id: str) -> None:
        """
        Release a principal from containment.
        """
        self._contained_principals.discard(principal_id)

