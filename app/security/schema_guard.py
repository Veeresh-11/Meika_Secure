# app/security/schema_guard.py

import hashlib
from app.security.version import SCHEMA_VERSION

def _normalize_dsn(dsn: str) -> str:
    """
    Convert a SQLAlchemy PostgreSQL URL into a psycopg2-compatible DSN.
    """

    if dsn.startswith("postgresql+psycopg://"):
        return dsn.replace(
            "postgresql+psycopg://",
            "postgresql://",
            1,
        )

    return dsn

def compute_schema_checksum(path: str) -> str:
    with open(path, "rb") as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()


def validate_schema(dsn: str, schema_path: str) -> None:
    # ✅ Lazy import (CI-safe)
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError("psycopg2 is required for schema validation")

    expected_checksum = compute_schema_checksum(schema_path)
    

    conn = psycopg2.connect(_normalize_dsn(dsn))
    cur = conn.cursor()

    cur.execute(
        "SELECT schema_version, schema_checksum FROM identity.schema_metadata WHERE id = 1"
    )
    row = cur.fetchone()

    if not row:
        raise RuntimeError("Schema metadata missing")

    db_version, db_checksum = row

    if db_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"Schema version mismatch: expected {SCHEMA_VERSION}, got {db_version}"
        )

    if db_checksum != expected_checksum:
        raise RuntimeError(
            "Schema checksum mismatch — possible unauthorized modification"
        )

    conn.close()