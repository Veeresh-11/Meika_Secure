# app/security/test_postgres_store_full.py

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.postgres_store import (
    PostgresEvidenceStore,
)
from app.security.errors import SecurityInvariantViolation


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

class FakeCursor:
    def __init__(self, fetchone_values=None, fetchall_values=None):
        self.fetchone_values = list(fetchone_values or [])
        self.fetchall_values = fetchall_values or []
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        if self.fetchone_values:
            return self.fetchone_values.pop(0)
        return None

    def fetchall(self):
        return self.fetchall_values

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, cursor_obj):
        self.cursor_obj = cursor_obj
        self.autocommit = False

    def cursor(self, *args, **kwargs):
        return self.cursor_obj

    def set_session(self, **kwargs):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


def make_record():
    return EvidenceRecord(
        sequence_number=0,
        previous_hash=None,
        payload_hash="payload",
        record_hash="record",
    )


# ---------------------------------------------------------
# __init__
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_init_success(mock_connect, mock_validate):
    conn = Mock()
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    assert store._dsn == "dsn"
    mock_validate.assert_called_once()


@patch("app.security.evidence.postgres_store.validate_schema")
def test_init_import_error(mock_validate, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg2":
            raise ImportError()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(RuntimeError):
        PostgresEvidenceStore("dsn")


# ---------------------------------------------------------
# append success
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_append_success(mock_connect, mock_validate):
    cursor = FakeCursor(
        fetchone_values=[
            None,     # current head
            (0,),     # next sequence
        ]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    result = store.append(make_record())

    assert result == "record"


# ---------------------------------------------------------
# fork detection
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_append_fork_detected(mock_connect, mock_validate):
    cursor = FakeCursor(
        fetchone_values=[
            ("unexpected_hash",),
        ]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    with pytest.raises(SecurityInvariantViolation):
        store.append(make_record())


# ---------------------------------------------------------
# sequence collision
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_append_sequence_collision(mock_connect, mock_validate):
    record = make_record()

    cursor = FakeCursor(
        fetchone_values=[
            None,
            (99,),
        ]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    with pytest.raises(SecurityInvariantViolation):
        store.append(record)


# ---------------------------------------------------------
# rollback branch
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_append_general_exception(mock_connect, mock_validate):

    class ExplodingCursor(FakeCursor):
        def execute(self, sql, params=None):
            raise RuntimeError("boom")

    conn = FakeConnection(ExplodingCursor())
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    with pytest.raises(SecurityInvariantViolation):
        store.append(make_record())


# ---------------------------------------------------------
# unlock failure branch
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_append_unlock_failure(mock_connect, mock_validate):

    class UnlockFailCursor(FakeCursor):
        def execute(self, sql, params=None):
            if "pg_advisory_unlock" in sql:
                raise RuntimeError("unlock fail")
            super().execute(sql, params)

    cursor = UnlockFailCursor(
        fetchone_values=[
            None,
            (0,),
        ]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    assert store.append(make_record()) == "record"


# ---------------------------------------------------------
# last_hash
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_last_hash(mock_connect, mock_validate):
    cursor = FakeCursor(
        fetchone_values=[
            ("abc123",),
        ]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    assert store.last_hash() == "abc123"


@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_last_hash_none(mock_connect, mock_validate):
    cursor = FakeCursor(
        fetchone_values=[None]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    assert store.last_hash() is None


# ---------------------------------------------------------
# next_sequence
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_next_sequence(mock_connect, mock_validate):
    cursor = FakeCursor(
        fetchone_values=[(42,)]
    )

    conn = FakeConnection(cursor)
    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")

    assert store.next_sequence() == 42


# ---------------------------------------------------------
# get_all
# ---------------------------------------------------------

@patch("app.security.evidence.postgres_store.validate_schema")
@patch("psycopg2.connect")
def test_get_all(mock_connect, mock_validate):

    row = {
        "sequence_number": 1,
        "previous_hash": "p",
        "payload_hash": "x",
        "record_hash": "r",
    }

    cursor = FakeCursor(
        fetchall_values=[row]
    )

    conn = FakeConnection(cursor)

    fake_psycopg2 = SimpleNamespace(
        extras=SimpleNamespace(DictCursor=object)
    )

    mock_connect.return_value = conn

    store = PostgresEvidenceStore("dsn")
    store._psycopg2 = fake_psycopg2

    records = store.get_all()

    assert len(records) == 1
    assert records[0].record_hash == "r"