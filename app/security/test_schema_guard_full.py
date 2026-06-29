# app/security/test_schema_guard_full.py

from unittest.mock import Mock, patch

import pytest

from app.security.schema_guard import (
    compute_schema_checksum,
    validate_schema,
)


# ---------------------------------------------------------
# checksum
# ---------------------------------------------------------

def test_compute_schema_checksum(tmp_path):
    p = tmp_path / "schema.sql"
    p.write_text("CREATE TABLE test;")

    result = compute_schema_checksum(str(p))

    assert isinstance(result, str)
    assert len(result) == 64


# ---------------------------------------------------------
# missing psycopg2
# ---------------------------------------------------------

def test_validate_schema_import_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg2":
            raise ImportError()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    with pytest.raises(RuntimeError):
        validate_schema("dsn", "fake.sql")


# ---------------------------------------------------------
# missing metadata
# ---------------------------------------------------------

@patch("app.security.schema_guard.compute_schema_checksum")
@patch("psycopg2.connect")
def test_validate_schema_metadata_missing(
    mock_connect,
    mock_checksum,
):
    mock_checksum.return_value = "checksum"

    cur = Mock()
    cur.fetchone.return_value = None

    conn = Mock()
    conn.cursor.return_value = cur

    mock_connect.return_value = conn

    with pytest.raises(RuntimeError):
        validate_schema("dsn", "schema.sql")


# ---------------------------------------------------------
# version mismatch
# ---------------------------------------------------------

@patch("app.security.schema_guard.compute_schema_checksum")
@patch("psycopg2.connect")
def test_validate_schema_version_mismatch(
    mock_connect,
    mock_checksum,
):
    mock_checksum.return_value = "checksum"

    cur = Mock()
    cur.fetchone.return_value = (
        "WRONG_VERSION",
        "checksum",
    )

    conn = Mock()
    conn.cursor.return_value = cur

    mock_connect.return_value = conn

    with pytest.raises(RuntimeError):
        validate_schema("dsn", "schema.sql")


# ---------------------------------------------------------
# checksum mismatch
# ---------------------------------------------------------

@patch("app.security.schema_guard.compute_schema_checksum")
@patch("psycopg2.connect")
def test_validate_schema_checksum_mismatch(
    mock_connect,
    mock_checksum,
):
    from app.security.version import SCHEMA_VERSION

    mock_checksum.return_value = "expected"

    cur = Mock()
    cur.fetchone.return_value = (
        SCHEMA_VERSION,
        "different",
    )

    conn = Mock()
    conn.cursor.return_value = cur

    mock_connect.return_value = conn

    with pytest.raises(RuntimeError):
        validate_schema("dsn", "schema.sql")


# ---------------------------------------------------------
# success
# ---------------------------------------------------------

@patch("app.security.schema_guard.compute_schema_checksum")
@patch("psycopg2.connect")
def test_validate_schema_success(
    mock_connect,
    mock_checksum,
):
    from app.security.version import SCHEMA_VERSION

    mock_checksum.return_value = "checksum"

    cur = Mock()
    cur.fetchone.return_value = (
        SCHEMA_VERSION,
        "checksum",
    )

    conn = Mock()
    conn.cursor.return_value = cur

    mock_connect.return_value = conn

    validate_schema("dsn", "schema.sql")

    conn.close.assert_called_once()