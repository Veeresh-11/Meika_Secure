# app/security/schema_guard.py

import hashlib
import psycopg2
from app.security.version import SCHEMA_VERSION


def compute_schema_checksum(path: str) -> str:
    with open(path, "rb") as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()


def validate_schema(dsn: str, schema_path: str) -> None:
    expected_checksum = compute_schema_checksum(schema_path)

    conn = psycopg2.connect(dsn)
    cur = conn.cursor()

    cur.execute(
        "SELECT schema_version, schema_checksum FROM schema_metadata WHERE id = 1"
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
