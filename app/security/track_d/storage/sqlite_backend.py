"""
TRACK D — Sovereign Cryptographic Ledger (Elite Tier)

Includes:
- Hash chain integrity
- Multi-signer quorum
- Key rotation + registry
- Remote distributed signers
- Policy-bound signing
- Root anchoring (local + external)
"""

from __future__ import annotations

import sqlite3
import json
import hashlib
from pathlib import Path
<<<<<<< HEAD
from typing import Dict, Any
from enum import Enum
=======
from typing import Dict, Any, List, Protocol
from enum import Enum
from datetime import datetime

import requests

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
import os
ANCHOR_FILE = os.getenv("ANCHOR_FILE", "ledger.anchor")
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)


class Signer:
    def __init__(self, private_key_hex: str):
        self.sk = SigningKey(private_key_hex, encoder=HexEncoder)
        self.vk = self.sk.verify_key

    def sign(self, msg: str) -> str:
        return self.sk.sign(msg.encode()).signature.hex()

    def get_public_key(self) -> str:
        return self.vk.encode(encoder=HexEncoder).decode()

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

SCHEMA_VERSION = 3
os.environ["ANCHOR_FILE"]
REQUIRED_SIGNATURES = 2


# ---------------------------------------------------------
<<<<<<< HEAD
# Table Enum (Type-safe, injection-proof)
=======
# TABLE ENUM
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
# ---------------------------------------------------------

class Table(str, Enum):
    VERIFICATION = "verification_ledger"
    TRANSPARENCY = "transparency_log"
    GOVERNANCE = "governance_policies"


# ---------------------------------------------------------
<<<<<<< HEAD
# Helpers
=======
# CRYPTO HELPERS
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
# ---------------------------------------------------------

def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _hash_entry(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


def _chain_hash(entry_hash: str, prev_hash: str | None) -> str:
    return hashlib.sha256(((prev_hash or "") + entry_hash).encode()).hexdigest()


def _verify_signature(public_key: str, signature: str, message: str):
    vk = VerifyKey(public_key, encoder=HexEncoder)
    vk.verify(message.encode(), bytes.fromhex(signature))


# ---------------------------------------------------------
# SIGNER INTERFACES
# ---------------------------------------------------------

class SignerInterface(Protocol):
    def sign(self, message: str) -> str: ...
    def get_public_key(self) -> str: ...


# ---------------------------------------------------------
# LOCAL SIGNER
# ---------------------------------------------------------

class LocalSigner:

    def __init__(self, private_key_hex: str):
        self.signing_key = SigningKey(private_key_hex, encoder=HexEncoder)
        self.verify_key = self.signing_key.verify_key

    def sign(self, message: str) -> str:
        return self.signing_key.sign(message.encode()).signature.hex()

    def get_public_key(self) -> str:
        return self.verify_key.encode(encoder=HexEncoder).decode()


# ---------------------------------------------------------
# REMOTE SIGNER (Distributed)
# ---------------------------------------------------------

class RemoteSigner:

    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def sign(self, message: str) -> str:
        response = requests.post(
            f"{self.endpoint}/sign",
            json={"message": message},
            timeout=5,
        )
        response.raise_for_status()
        return response.json()["signature"]

    def get_public_key(self) -> str:
        response = requests.get(f"{self.endpoint}/public_key", timeout=5)
        response.raise_for_status()
        return response.json()["public_key"]


# ---------------------------------------------------------
# POLICY ENGINE (Policy-bound signing)
# ---------------------------------------------------------

class PolicyEngine:

    def validate(self, entry: Dict[str, Any]) -> bool:
        # Example policy (extendable)
        if "timestamp" not in entry:
            return False
        return True


# ---------------------------------------------------------
# EXTERNAL ANCHOR (Pluggable)
# ---------------------------------------------------------

class ExternalAnchor:

    def publish(self, chain_hash: str, signatures: List[dict]):
        # Example: override with blockchain/API
        pass

    def verify(self, chain_hash: str) -> bool:
        return True


# ---------------------------------------------------------
# SQLITE BACKEND
# ---------------------------------------------------------

class SQLiteBackend:

    def __init__(self, path: str):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row

        self.policy = PolicyEngine()
        self.external_anchor = ExternalAnchor()

        self._init_schema()
        self._validate_startup()

    # -----------------------------------------------------

    def _init_schema(self):
        cur = self.conn.cursor()

<<<<<<< HEAD
        cur.execute("PRAGMA journal_mode=WAL;")
        mode = cur.fetchone()
        if mode and mode[0].lower() != "wal":
            raise RuntimeError("WAL mode not enforced")

        cur.execute("PRAGMA synchronous=FULL;")
        cur.execute("PRAGMA foreign_keys=ON;")

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
=======
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS signer_registry (
                public_key TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

<<<<<<< HEAD
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
            Table.VERIFICATION.value,
            Table.TRANSPARENCY.value,
            Table.GOVERNANCE.value,
        ]:
=======
        for table in Table:
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {table.value} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_json TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    prev_chain_hash TEXT,
                    chain_hash TEXT NOT NULL,
                    signatures TEXT NOT NULL
                );
            """)

        self.conn.commit()

    # -----------------------------------------------------
<<<<<<< HEAD
    # Append Operations (Atomic, Safe)
    # -----------------------------------------------------

    def append(self, table: Table, entry: Dict[str, Any]):

        if not isinstance(table, Table):
            raise ValueError("Invalid table")

        entry_hash = _hash_entry(entry)

=======
    # KEY MANAGEMENT
    # -----------------------------------------------------

    def register_signer(self, public_key: str):
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
        with self.conn:
            # nosec B608: table name is Enum-restricted and not user-controlled
            self.conn.execute(
<<<<<<< HEAD
                f"INSERT INTO {table.value} (entry_json, entry_hash) VALUES (?, ?)",
                (json.dumps(entry), entry_hash),
=======
                "INSERT OR REPLACE INTO signer_registry VALUES (?, 'active', ?)",
                (public_key, datetime.utcnow().isoformat()),
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)
            )

    def revoke_signer(self, public_key: str):
        with self.conn:
            self.conn.execute(
                "UPDATE signer_registry SET status='revoked' WHERE public_key=?",
                (public_key,),
            )

<<<<<<< HEAD
    def _validate_integrity_on_startup(self):

        for table in (
            Table.VERIFICATION,
            Table.TRANSPARENCY,
            Table.GOVERNANCE,
        ):
            self._validate_table(table)

    def _validate_table(self, table: Table):

        if not isinstance(table, Table):
            raise ValueError("Invalid table")

        # nosec B608: table name is Enum-restricted and not user-controlled
        rows = self.conn.execute(
            f"SELECT id, entry_json, entry_hash FROM {table.value} ORDER BY id ASC"
        ).fetchall()

        for row in rows:
            entry = json.loads(row["entry_json"])
            if _hash_entry(entry) != row["entry_hash"]:
                raise RuntimeError(f"Integrity failure in table: {table.value}")
=======
    def _is_active(self, public_key: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM signer_registry WHERE public_key=?",
            (public_key,),
        ).fetchone()
        return row and row["status"] == "active"
>>>>>>> 871e562c (feat(security): finalize hardened sqlite ledger with quorum signing, anchor verification, and secure metrics exporter; add integration test)

    # -----------------------------------------------------
    # CHAIN
    # -----------------------------------------------------

    def _last_hash(self, table: Table):
        
        row = self.conn.execute( 
            f"SELECT chain_hash FROM {table.value} ORDER BY id DESC LIMIT 1"# nosec B608
        ).fetchone()
        return row["chain_hash"] if row else None

    # -----------------------------------------------------
    # APPEND
    # -----------------------------------------------------

    def append(
        self,
        table: Table,
        entry: Dict[str, Any],
        signers: List[SignerInterface],
    ):

        if not self.policy.validate(entry):
            raise RuntimeError("Policy validation failed")

        entry_hash = _hash_entry(entry)
        prev = self._last_hash(table)
        chain_hash = _chain_hash(entry_hash, prev)

        signatures = []

        for s in signers:
            pk = s.get_public_key()

            if not self._is_active(pk):
                raise RuntimeError("Inactive signer")

            signatures.append({
                "public_key": pk,
                "signature": s.sign(chain_hash),
            })

        if len(signatures) < REQUIRED_SIGNATURES:
            raise RuntimeError("Quorum not met")

        with self.conn:
           
            self.conn.execute(  
                f""" 
                INSERT INTO {table.value}
                (entry_json, entry_hash, prev_chain_hash, chain_hash, signatures)
                VALUES (?, ?, ?, ?, ?)
                """,# nosec B608
                (
                    json.dumps(entry),
                    entry_hash,
                    prev,
                    chain_hash,
                    json.dumps(signatures),
                ),
            )

        self._anchor(chain_hash, signatures)

    # -----------------------------------------------------
    # ANCHORING
    # -----------------------------------------------------

    def _anchor(self, chain_hash: str, signatures: List[dict]):

        Path(ANCHOR_FILE).write_text(json.dumps({
            "chain_hash": chain_hash,
            "signatures": signatures,
        }))

        self.external_anchor.publish(chain_hash, signatures)

    def _verify_anchor(self, table: Table):

        
        count = self.conn.execute( 
            f"SELECT COUNT(*) as c FROM {table.value}"# nosec B608
        ).fetchone()["c"]

        # ✅ Allow bootstrap if table empty
        if count == 0:
            return

        if not Path(ANCHOR_FILE).exists():
            raise RuntimeError("Missing anchor")

        anchor = json.loads(Path(ANCHOR_FILE).read_text())
        latest = self._last_hash(table)

        if latest != anchor["chain_hash"]:
            raise RuntimeError("Database replacement detected")

        valid = 0
        for sig in anchor["signatures"]:
            try:
                _verify_signature(
                    sig["public_key"],
                    sig["signature"],
                    anchor["chain_hash"],
                )
                valid += 1
            except Exception:
                continue

        if valid < REQUIRED_SIGNATURES:
            raise RuntimeError("Anchor quorum verification failed")
    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    def _validate_startup(self):
        for table in Table:
            
            rows = self.conn.execute( 
                f"SELECT * FROM {table.value} ORDER BY id ASC"# nosec B608
            ).fetchall()

            prev = None

            for r in rows:
                entry = json.loads(r["entry_json"])

                if _hash_entry(entry) != r["entry_hash"]:
                    raise RuntimeError("Hash mismatch")

                expected = _chain_hash(r["entry_hash"], prev)

                if expected != r["chain_hash"]:
                    raise RuntimeError("Chain broken")

                sigs = json.loads(r["signatures"])

                valid = 0
                for sig in sigs:
                    try:
                        _verify_signature(
                            sig["public_key"],
                            sig["signature"],
                            r["chain_hash"],
                        )
                        valid += 1
                    except:
                        pass

                if valid < REQUIRED_SIGNATURES:
                    raise RuntimeError("Quorum failed")

                prev = r["chain_hash"]

            self._verify_anchor(table)

    # -----------------------------------------------------

    def close(self):
        self.conn.close()