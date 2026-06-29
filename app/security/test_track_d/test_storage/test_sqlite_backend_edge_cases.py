import json
import sqlite3
import requests
from unittest.mock import patch, Mock
import pytest 

from pathlib import Path
from unittest.mock import patch
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder
from app.security.track_d.storage.sqlite_backend import (
    SQLiteBackend,
    Table,
    Signer,
    _verify_signature,
    _hash_entry,
    _chain_hash,
    HexEncoder,
    SigningKey,
)
    
@pytest.fixture
def backend(tmp_path):
    db = SQLiteBackend(str(tmp_path / "ledger.db"))
    yield db
    db.close()    
# ---------------------------------------------------------
# Startup validation
# ---------------------------------------------------------


def test_validate_startup_empty_database(
    backend,
):
    backend._validate_startup()


def test_validate_startup_hash_mismatch(
    backend,
):

    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (
            entry_json,
            entry_hash,
            prev_chain_hash,
            chain_hash,
            signatures
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            json.dumps({"timestamp": "2026"}),
            "BADHASH",
            None,
            "CHAIN",
            "[]",
        ),
    )

    backend.conn.commit()

    with pytest.raises(
        RuntimeError,
        match="Hash mismatch",
    ):
        backend._validate_startup()


def test_validate_startup_chain_broken(
    backend,
    monkeypatch,
):

    entry = {
        "timestamp": "2026",
    }

    entry_hash = _hash_entry(entry)

    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (
            entry_json,
            entry_hash,
            prev_chain_hash,
            chain_hash,
            signatures
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            json.dumps(entry),
            entry_hash,
            None,
            "BROKEN_CHAIN",
            json.dumps([]),
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *a, **k: None,
    )

    with pytest.raises(
        RuntimeError,
        match="Chain broken",
    ):
        backend._validate_startup()


def test_validate_startup_quorum_failed(
    backend,
    monkeypatch,
):

    entry = {
        "timestamp": "2026",
    }

    entry_hash = _hash_entry(entry)

    chain_hash = _chain_hash(
        entry_hash,
        None,
    )

    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (
            entry_json,
            entry_hash,
            prev_chain_hash,
            chain_hash,
            signatures
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            json.dumps(entry),
            entry_hash,
            None,
            chain_hash,
            json.dumps([]),
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        SQLiteBackend,
        "_verify_anchor",
        lambda *a, **k: None,
    )

    with pytest.raises(
        RuntimeError,
        match="Quorum failed",
    ):
        backend._validate_startup()


def test_validate_startup_success(
    backend,
    monkeypatch,
):

    entry = {
        "timestamp": "2026",
    }

    entry_hash = _hash_entry(entry)

    chain_hash = _chain_hash(
        entry_hash,
        None,
    )

    signer1 = Signer(
        SigningKey.generate().encode(
            encoder=HexEncoder,
        ).decode()
    )

    signer2 = Signer(
        SigningKey.generate().encode(
            encoder=HexEncoder,
        ).decode()
    )

    signatures = [
        {
            "public_key": signer1.get_public_key(),
            "signature": signer1.sign(chain_hash),
        },
        {
            "public_key": signer2.get_public_key(),
            "signature": signer2.sign(chain_hash),
        },
    ]

    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (
            entry_json,
            entry_hash,
            prev_chain_hash,
            chain_hash,
            signatures
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            json.dumps(entry),
            entry_hash,
            None,
            chain_hash,
            json.dumps(signatures),
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        SQLiteBackend,
        "_verify_anchor",
        lambda *a, **k: None,
    )

    backend._validate_startup()


# ---------------------------------------------------------
# Close
# ---------------------------------------------------------


def test_close(
    backend,
):

    backend.close()

    with pytest.raises(
        sqlite3.ProgrammingError,
    ):
        backend.conn.execute(
            "SELECT 1"
        )
        
def test_validate_startup_bad_signature(
    backend,
    monkeypatch,
):
    entry = {
        "timestamp": "2026",
    }

    entry_hash = _hash_entry(entry)

    chain_hash = _chain_hash(
        entry_hash,
        None,
    )

    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (
            entry_json,
            entry_hash,
            prev_chain_hash,
            chain_hash,
            signatures
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            json.dumps(entry),
            entry_hash,
            None,
            chain_hash,
            json.dumps(
                [
                    {
                        "public_key": "bad",
                        "signature": "bad",
                    }
                ]
            ),
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *a, **k: (_ for _ in ()).throw(Exception()),
    )

    monkeypatch.setattr(
        SQLiteBackend,
        "_verify_anchor",
        lambda *a, **k: None,
    )

    with pytest.raises(
        RuntimeError,
        match="Quorum failed",
    ):
        backend._validate_startup()