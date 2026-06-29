import sqlite3
from pathlib import Path
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from app.security.track_d.storage.sqlite_backend import (
    SQLiteBackend,
    Table,
    Signer,
    _verify_signature,
    HexEncoder,
    SigningKey,
    _chain_hash,
    LocalSigner,
)

import pytest



@pytest.fixture
def signer():
    sk = SigningKey.generate()
    private_hex = sk.encode(encoder=HexEncoder).decode()
    return LocalSigner(private_hex)
# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------


@pytest.fixture
def backend(tmp_path, monkeypatch):

    monkeypatch.setattr(
        SQLiteBackend,
        "_validate_startup",
        lambda self: None,
    )

    monkeypatch.setattr(
        SQLiteBackend,
        "_anchor",
        lambda self, chain_hash, signatures: None,
    )

    db = SQLiteBackend(str(tmp_path / "ledger.db"))

    yield db

    db.close()


# ---------------------------------------------------------
# Constructor / Schema
# ---------------------------------------------------------


def test_backend_creates_database(tmp_path, monkeypatch):

    monkeypatch.setattr(
        SQLiteBackend,
        "_validate_startup",
        lambda self: None,
    )

    monkeypatch.setattr(
        SQLiteBackend,
        "_anchor",
        lambda self, c, s: None,
    )

    dbfile = tmp_path / "ledger.db"

    backend = SQLiteBackend(str(dbfile))

    assert dbfile.exists()

    backend.close()


def test_schema_tables_exist(backend):

    tables = {
        row[0]
        for row in backend.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }

    assert "verification_ledger" in tables
    assert "transparency_log" in tables
    assert "governance_policies" in tables
    assert "signer_registry" in tables


# ---------------------------------------------------------
# Register / Revoke
# ---------------------------------------------------------


def test_register_signer(backend, signer):

    pk = signer.get_public_key()

    backend.register_signer(pk)

    row = backend.conn.execute(
        "SELECT status FROM signer_registry WHERE public_key=?",
        (pk,),
    ).fetchone()

    assert row["status"] == "active"


def test_revoke_signer(backend, signer):

    pk = signer.get_public_key()

    backend.register_signer(pk)
    backend.revoke_signer(pk)

    row = backend.conn.execute(
        "SELECT status FROM signer_registry WHERE public_key=?",
        (pk,),
    ).fetchone()

    assert row["status"] == "revoked"


# ---------------------------------------------------------
# Active Check
# ---------------------------------------------------------


def test_is_active_true(backend, signer):

    pk = signer.get_public_key()

    backend.register_signer(pk)

    assert backend._is_active(pk)


def test_is_active_false_unknown(backend):

    assert backend._is_active("missing") is None


def test_is_active_false_revoked(backend, signer):

    pk = signer.get_public_key()

    backend.register_signer(pk)
    backend.revoke_signer(pk)

    assert backend._is_active(pk) is False


# ---------------------------------------------------------
# Last Hash
# ---------------------------------------------------------


def test_last_hash_empty(backend):

    assert backend._last_hash(Table.VERIFICATION) is None


# ---------------------------------------------------------
# Append
# ---------------------------------------------------------


def test_append_success(backend):

    s1 = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    s2 = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    backend.register_signer(
        s1.get_public_key()
    )

    backend.register_signer(
        s2.get_public_key()
    )

    backend.append(
        Table.VERIFICATION,
        {
            "timestamp": "2026",
            "value": 1,
        },
        [
            s1,
            s2,
        ],
    )

    row = backend.conn.execute(
        "SELECT * FROM verification_ledger"
    ).fetchone()

    assert row is not None


def test_append_policy_failure(backend):

    with pytest.raises(
        RuntimeError,
        match="Policy validation failed",
    ):
        backend.append(
            Table.VERIFICATION,
            {},
            [],
        )


def test_append_inactive_signer(backend):

    s = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    with pytest.raises(
        RuntimeError,
        match="Inactive signer",
    ):
        backend.append(
            Table.VERIFICATION,
            {
                "timestamp": "2026",
            },
            [s],
        )


def test_append_quorum_failure(backend):

    s = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    backend.register_signer(
        s.get_public_key()
    )

    with pytest.raises(
        RuntimeError,
        match="Quorum not met",
    ):
        backend.append(
            Table.VERIFICATION,
            {
                "timestamp": "2026",
            },
            [s],
        )


def test_last_hash_after_append(backend):

    s1 = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    s2 = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    backend.register_signer(
        s1.get_public_key()
    )

    backend.register_signer(
        s2.get_public_key()
    )

    backend.append(
        Table.VERIFICATION,
        {
            "timestamp": "2026",
        },
        [
            s1,
            s2,
        ],
    )

    assert backend._last_hash(
        Table.VERIFICATION
    ) is not None