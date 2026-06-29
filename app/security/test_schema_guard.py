# app/security/test_schema_guard.py

import pytest
from unittest.mock import Mock, patch

from app.security.schema_guard import (
    compute_schema_checksum,
    validate_schema,
)
from app.security.version import SCHEMA_VERSION


def test_compute_schema_checksum(tmp_path):
    f = tmp_path / "schema.sql"
    f.write_text("CREATE TABLE test();")

    checksum = compute_schema_checksum(str(f))

    assert isinstance(checksum, str)
    assert len(checksum) == 64


def test_validate_schema_success(tmp_path):
    schema = tmp_path / "schema.sql"
    schema.write_text("test")

    with patch(
        "app.security.schema_guard.compute_schema_checksum"
    ) as checksum_mock:

        checksum_mock.return_value = "abc123"

        conn = Mock()
        cur = Mock()

        conn.cursor.return_value = cur
        cur.fetchone.return_value = (
            SCHEMA_VERSION,
            "abc123",
        )

        fake_psycopg = Mock()
        fake_psycopg.connect.return_value = conn

        with patch.dict(
            "sys.modules",
            {"psycopg2": fake_psycopg},
        ):
            validate_schema(
                "postgres://fake",
                str(schema),
            )


def test_validate_schema_missing_metadata(tmp_path):
    schema = tmp_path / "schema.sql"
    schema.write_text("test")

    with patch(
        "app.security.schema_guard.compute_schema_checksum"
    ) as checksum_mock:

        checksum_mock.return_value = "abc123"

        conn = Mock()
        cur = Mock()

        conn.cursor.return_value = cur
        cur.fetchone.return_value = None

        fake_psycopg = Mock()
        fake_psycopg.connect.return_value = conn

        with patch.dict(
            "sys.modules",
            {"psycopg2": fake_psycopg},
        ):
            with pytest.raises(RuntimeError):
                validate_schema(
                    "postgres://fake",
                    str(schema),
                )


def test_validate_schema_version_mismatch(tmp_path):
    schema = tmp_path / "schema.sql"
    schema.write_text("test")

    with patch(
        "app.security.schema_guard.compute_schema_checksum"
    ) as checksum_mock:

        checksum_mock.return_value = "abc123"

        conn = Mock()
        cur = Mock()

        conn.cursor.return_value = cur
        cur.fetchone.return_value = (
            "999.0.0",
            "abc123",
        )

        fake_psycopg = Mock()
        fake_psycopg.connect.return_value = conn

        with patch.dict(
            "sys.modules",
            {"psycopg2": fake_psycopg},
        ):
            with pytest.raises(RuntimeError):
                validate_schema(
                    "postgres://fake",
                    str(schema),
                )


def test_validate_schema_checksum_mismatch(tmp_path):
    schema = tmp_path / "schema.sql"
    schema.write_text("test")

    with patch(
        "app.security.schema_guard.compute_schema_checksum"
    ) as checksum_mock:

        checksum_mock.return_value = "expected"

        conn = Mock()
        cur = Mock()

        conn.cursor.return_value = cur
        cur.fetchone.return_value = (
            SCHEMA_VERSION,
            "actual",
        )

        fake_psycopg = Mock()
        fake_psycopg.connect.return_value = conn

        with patch.dict(
            "sys.modules",
            {"psycopg2": fake_psycopg},
        ):
            with pytest.raises(RuntimeError):
                validate_schema(
                    "postgres://fake",
                    str(schema),
                )