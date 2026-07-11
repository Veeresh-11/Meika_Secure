from unittest.mock import MagicMock, patch

import pytest

from app.security.persistence.db import get_connection


def test_get_connection_success():

    fake_conn = MagicMock()

    fake_cursor = object()

    with patch(
        "psycopg2.connect",
        return_value=fake_conn,
    ) as connect:

        with patch(
            "psycopg2.extras.RealDictCursor",
            fake_cursor,
        ):

         conn = get_connection()

    assert conn is fake_conn

    kwargs = connect.call_args.kwargs

    assert kwargs["host"] is not None
    assert kwargs["port"] is not None
    assert kwargs["user"] is not None
    assert kwargs["password"] is not None
    assert kwargs["dbname"] is not None
    assert kwargs["cursor_factory"] is fake_cursor


def test_get_connection_import_error(monkeypatch):

    import builtins

    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg2":
            raise ImportError
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(
        builtins,
        "__import__",
        fake_import,
    )

    with pytest.raises(
        RuntimeError,
        match="psycopg2 is required",
    ):
        get_connection()