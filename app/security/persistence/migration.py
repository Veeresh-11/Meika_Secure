# app/security/persistence/migration.py

from app.security.persistence.db import get_connection


def migrate():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence_records (
            evidence_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            principal_id TEXT,
            intent TEXT NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL,
            details JSONB NOT NULL,
            previous_hash TEXT,
            hash TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_timestamp
        ON evidence_records (timestamp);
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            grant_id TEXT PRIMARY KEY,
            principal_id TEXT NOT NULL,
            scopes JSONB NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            issued_by_policy TEXT NOT NULL,
            justification TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_grants_principal
        ON grants (principal_id);
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_grants_expires
        ON grants (expires_at);
    """)


    conn.commit()
    cur.close()
    conn.close()
