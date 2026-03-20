# app/security/grants/validator.py

from datetime import datetime
from app.security.errors import SecurityPipelineError
from app.security.context import SecurityContext
from app.security.grants.store import GrantStore


class GrantValidator:
    """
    Validates the use of a JIT grant at execution time.

    Grants are:
    - explicit
    - time-bound
    - scoped
    - never implicit
    """

    def __init__(self, store: GrantStore):
        self._store = store

    def validate(self, grant_id: str, context: SecurityContext) -> None:
        if not grant_id:
            raise SecurityPipelineError("Missing grant_id")

        grant = self._store.get(grant_id)

        if not grant:
            raise SecurityPipelineError("Grant not found")

        # Principal binding
        if grant.principal_id != context.principal_id:
            raise SecurityPipelineError("Grant does not belong to principal")

        # Expiry enforcement
        if grant.expires_at <= datetime.utcnow():
            raise SecurityPipelineError("Grant has expired")

        # Intent / scope enforcement (basic form)
        if context.intent not in [s.intent for s in grant.scopes]:
            raise SecurityPipelineError("Grant scope does not allow this intent")

        # If all checks pass → grant is valid
        return None

