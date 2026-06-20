# app/security/grants/validator.py

from datetime import datetime

from app.security.context import SecurityContext
from app.security.errors import (
    SecurityPipelineError,
    FailureClass,
)
from app.security.results import DenyReason
from app.security.grants.store import (
    GrantStore,
    GrantNotFoundError,
)


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

    def validate(
        self,
        grant_id: str,
        context: SecurityContext,
    ) -> None:

        # Grant ID required
        if not grant_id:
            raise SecurityPipelineError(
                DenyReason.DEFAULT_DENY,
                FailureClass.GRANT,
            )

        # Grant must exist
        try:
            grant = self._store.get(grant_id)
        except GrantNotFoundError:
            raise SecurityPipelineError(
                DenyReason.DEFAULT_DENY,
                FailureClass.GRANT,
            )

        # Principal binding
        if grant.principal_id != context.principal_id:
            raise SecurityPipelineError(
                DenyReason.GRANT_SCOPE_MISMATCH,
                FailureClass.GRANT,
            )

        # Expiry enforcement
        if grant.expires_at <= datetime.utcnow():
            raise SecurityPipelineError(
                DenyReason.EXPIRED_GRANT,
                FailureClass.GRANT,
            )

        # Intent enforcement
        if context.intent != grant.intent:
            raise SecurityPipelineError(
                DenyReason.GRANT_SCOPE_MISMATCH,
                FailureClass.GRANT,
            )

        return None