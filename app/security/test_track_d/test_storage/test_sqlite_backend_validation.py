import json
import os
from pathlib import Path

import pytest
from app.security.track_d.storage.sqlite_backend import (
    SQLiteBackend,
    Table,
    Signer,
    _verify_signature,
    
)


@pytest.fixture
def backend(tmp_path):
    db = SQLiteBackend(str(tmp_path / "ledger.db"))
    yield db
    db.close()

# ---------------------------------------------------------
# Anchoring
# ---------------------------------------------------------


def test_anchor_writes_anchor_file(
    backend,
    tmp_path,
    monkeypatch,
):

    anchor_file = tmp_path / "ledger.anchor"

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(anchor_file),
    )

    called = {}

    def fake_publish(chain_hash, signatures):
        called["chain_hash"] = chain_hash
        called["signatures"] = signatures

    backend.external_anchor.publish = fake_publish

    signatures = [
        {
            "public_key": "pk",
            "signature": "sig",
        }
    ]

    backend._anchor(
        "abc123",
        signatures,
    )

    assert anchor_file.exists()

    data = json.loads(
        anchor_file.read_text()
    )

    assert data["chain_hash"] == "abc123"
    assert data["signatures"] == signatures

    assert called["chain_hash"] == "abc123"


def test_verify_anchor_bootstrap_returns(
    backend,
):
    backend._verify_anchor(
        Table.VERIFICATION,
    )


def test_verify_anchor_missing_file(
    backend,
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(tmp_path / "missing.anchor"),
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
            "{}",
            "a",
            None,
            "b",
            "[]",
        ),
    )

    backend.conn.commit()

    with pytest.raises(
        RuntimeError,
        match="Missing anchor",
    ):
        backend._verify_anchor(
            Table.VERIFICATION,
        )


def test_verify_anchor_database_replacement(
    backend,
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(tmp_path / "ledger.anchor"),
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
            "{}",
            "a",
            None,
            "REALHASH",
            "[]",
        ),
    )

    backend.conn.commit()

    Path(
        os.environ["ANCHOR_FILE"]
    ).write_text(
        json.dumps(
            {
                "chain_hash": "FAKEHASH",
                "signatures": [],
            }
        )
    )

    with pytest.raises(
        RuntimeError,
        match="Database replacement detected",
    ):
        backend._verify_anchor(
            Table.VERIFICATION,
        )


def test_verify_anchor_quorum_failure(
    backend,
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(tmp_path / "ledger.anchor"),
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
            "{}",
            "a",
            None,
            "HASH",
            json.dumps([]),
        ),
    )

    backend.conn.commit()

    Path(
        os.environ["ANCHOR_FILE"]
    ).write_text(
        json.dumps(
            {
                "chain_hash": "HASH",
                "signatures": [],
            }
        )
    )

    with pytest.raises(
        RuntimeError,
        match="Anchor quorum verification failed",
    ):
        backend._verify_anchor(
            Table.VERIFICATION,
        )
        
def test_verify_anchor_invalid_signature(
    backend,
    monkeypatch,
    tmp_path,
):
    anchor = {
        "chain_hash": "abc",
        "signatures": [
            {
                "public_key": "bad",
                "signature": "bad",
            }
        ],
    }

    anchor_file = tmp_path / "ledger.anchor"
    anchor_file.write_text(json.dumps(anchor))

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(anchor_file),
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
            "{}",
            "x",
            None,
            "abc",
            "[]",
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *a, **k: (_ for _ in ()).throw(Exception()),
    )

    with pytest.raises(
        RuntimeError,
        match="Anchor quorum verification failed",
    ):
        backend._verify_anchor(
            Table.VERIFICATION,
        )
        
def test_verify_anchor_success(
    backend,
    monkeypatch,
    tmp_path,
):
    anchor = {
        "chain_hash": "abc",
        "signatures": [
            {},
            {},
        ],
    }

    anchor_file = tmp_path / "ledger.anchor"
    anchor_file.write_text(json.dumps(anchor))

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(anchor_file),
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
            "{}",
            "x",
            None,
            "abc",
            "[]",
        ),
    )

    backend.conn.commit()

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *a, **k: None,
    )

    backend._verify_anchor(
        Table.VERIFICATION,
    )
    
def test_verify_anchor_invalid_signature(
    backend,
    monkeypatch,
    tmp_path,
):
    backend.conn.execute(
        """
        INSERT INTO verification_ledger
        (entry_json, entry_hash, prev_chain_hash, chain_hash, signatures)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "{}",
            "abc",
            None,
            "CHAIN",
            "[]",
        ),
    )
    backend.conn.commit()

    anchor = {
        "chain_hash": "CHAIN",
        "signatures": [
            {
                "public_key": "bad",
                "signature": "bad",
            }
        ],
    }

    anchor_file = tmp_path / "ledger.anchor"
    anchor_file.write_text(json.dumps(anchor))

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(anchor_file),
    )

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *a, **k: (_ for _ in ()).throw(Exception("bad sig")),
    )

    with pytest.raises(
        RuntimeError,
        match="Anchor quorum verification failed",
    ):
        backend._verify_anchor(Table.VERIFICATION)
        
def test_verify_anchor_success(
    backend,
    monkeypatch,
    tmp_path,
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
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "{}",
            "abc",
            None,
            "CHAIN",
            "[]",
        ),
    )
    backend.conn.commit()

    anchor = {
        "chain_hash": "CHAIN",
        "signatures": [
            {
                "public_key": "pk1",
                "signature": "sig1",
            },
            {
                "public_key": "pk2",
                "signature": "sig2",
            },
        ],
    }

    anchor_file = tmp_path / "ledger.anchor"
    anchor_file.write_text(json.dumps(anchor))

    monkeypatch.setenv(
        "ANCHOR_FILE",
        str(anchor_file),
    )

    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend._verify_signature",
        lambda *args, **kwargs: None,
    )

    backend._verify_anchor(Table.VERIFICATION)