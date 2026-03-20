# app/security/evidence/factory.py

import os


def get_evidence_store():
    """
    Backend selection mechanism for Evidence Store.

    Defaults to in-memory store for test determinism.

    Set:
        EVIDENCE_BACKEND=postgres
        EVIDENCE_DSN=postgresql://user:pass@host/db
    """

    backend = os.getenv("EVIDENCE_BACKEND", "inmemory").lower()

    if backend == "postgres":
        from app.security.evidence.postgres_store import PostgresEvidenceStore

        dsn = os.getenv("EVIDENCE_DSN")
        if not dsn:
            raise RuntimeError(
                "EVIDENCE_DSN must be set when EVIDENCE_BACKEND=postgres"
            )
        return PostgresEvidenceStore(dsn)

    # Default: in-memory
    from app.security.evidence.store import InMemoryEvidenceStore

    return InMemoryEvidenceStore()
