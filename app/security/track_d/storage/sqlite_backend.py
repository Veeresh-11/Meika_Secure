"""
TRACK D — Enterprise SQLite Backend (Hardened)

Security Guarantees:
- WAL durability
- FULL synchronous mode
- Foreign key enforcement
- Schema version freeze
- Append-only immutability
- Entry hash uniqueness
- Startup integrity validation
- Fail-closed behavior
"""

from __future__ import annotations

import sqlite3
import json
import hashlib
from pathlib import Path
from typing import Dict, Any


SCHEMA_VERSION = 1


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash_entry(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


# ---------------------------------------------------------
# SQLite Backend
# ---------------------------------------------------------

class SQLiteBackend:

    def __init__(self, path: str):
        self.path = Path(path)

        self.conn = sqlite3.connect(
            str(self.path),
            isolation_level="DEFERRED",
        )

        self.conn.row_factory = sqlite3.Row

        self._configure_pragmas()
        self._initialize_schema()
        self._validate_integrity_on_startup()

    # -----------------------------------------------------
    # PRAGMA Configuration (Strict)
    # -----------------------------------------------------

    def _configure_pragmas(self):

        cur = self.conn.cursor()

        cur.execute("PRAGMA journal_mode=WAL;")
        mode = cur.fetchone()
        if mode and mode[0].lower() != "wal":
            raise RuntimeError("WAL mode not enforced")

        cur.execute("PRAGMA synchronous=FULL;")
        cur.execute("PRAGMA foreign_keys=ON;")

        # Verify foreign keys active
        fk = cur.execute("PRAGMA foreign_keys;").fetchone()
        if fk and fk[0] != 1:
            raise RuntimeError("Foreign keys not enforced")

        self.conn.commit()

    # -----------------------------------------------------
    # Schema Initialization
    # -----------------------------------------------------

    def _initialize_schema(self):

        cur = self.conn.cursor()

        # Schema version
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
        """)

        version = cur.execute("SELECT version FROM schema_version").fetchone()

        if version is None:
            cur.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        elif version["version"] != SCHEMA_VERSION:
            raise RuntimeError("Schema version mismatch — migration required")

        # Ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS verification_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_json TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            );
        """)

        # Transparency
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transparency_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_json TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            );
        """)

        # Governance
        cur.execute("""
            CREATE TABLE IF NOT EXISTS governance_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                family TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            );
        """)

        # Immutable triggers
        for table in [
            "verification_ledger",
            "transparency_log",
            "governance_policies",
        ]:
            cur.execute(f"""
                CREATE TRIGGER IF NOT EXISTS prevent_update_{table}
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'Immutable table');
                END;
            """)
            cur.execute(f"""
                CREATE TRIGGER IF NOT EXISTS prevent_delete_{table}
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'Immutable table');
                END;
            """)

        self.conn.commit()

    # -----------------------------------------------------
    # Append Operations (Atomic)
    # -----------------------------------------------------

    def append(self, table: str, entry: Dict[str, Any]):

        if table not in (
            "verification_ledger",
            "transparency_log",
            "governance_policies",
        ):
            raise ValueError("Invalid table")

        entry_hash = _hash_entry(entry)

        with self.conn:
            self.conn.execute(
                f"INSERT INTO {table} (entry_json, entry_hash) VALUES (?, ?)",
                (json.dumps(entry), entry_hash),
            )

    # -----------------------------------------------------
    # Startup Integrity Validation
    # -----------------------------------------------------

    def _validate_integrity_on_startup(self):

        for table in (
            "verification_ledger",
            "transparency_log",
            "governance_policies",
        ):
            self._validate_table(table)

    def _validate_table(self, table: str):

        rows = self.conn.execute(
            f"SELECT id, entry_json, entry_hash FROM {table} ORDER BY id ASC"
        ).fetchall()

        for row in rows:
            entry = json.loads(row["entry_json"])
            if _hash_entry(entry) != row["entry_hash"]:
                raise RuntimeError(f"Integrity failure in table: {table}")

    # -----------------------------------------------------
    # Close
    # -----------------------------------------------------

    def close(self):
        self.conn.close()
