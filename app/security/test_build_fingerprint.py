from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

import pytest

from app.security.build_fingerprint import (
    _module_file,
    compute_build_hash,
)


def test_module_file_success():

    fake_spec = SimpleNamespace(
        origin="/tmp/test.py",
    )

    with patch(
        "importlib.util.find_spec",
        return_value=fake_spec,
    ):
        path = _module_file(
            "app.security.test",
        )

    assert path == Path("/tmp/test.py")


def test_module_file_not_found():

    with patch(
        "importlib.util.find_spec",
        return_value=None,
    ):
        with pytest.raises(
            RuntimeError,
            match="Cannot resolve module",
        ):
            _module_file(
                "missing.module",
            )


def test_module_file_missing_origin():

    fake_spec = SimpleNamespace(
        origin=None,
    )

    with patch(
        "importlib.util.find_spec",
        return_value=fake_spec,
    ):
        with pytest.raises(
            RuntimeError,
            match="Cannot resolve module",
        ):
            _module_file(
                "missing.origin",
            )


def test_compute_build_hash():

    fake_spec = SimpleNamespace(
        origin="/tmp/test.py",
    )

    with patch(
        "importlib.util.find_spec",
        return_value=fake_spec,
    ):
        with patch(
            "builtins.open",
            mock_open(
                read_data=b"kernel-data"
            ),
        ):
            result = compute_build_hash()

    assert isinstance(result, str)
    assert len(result) == 64