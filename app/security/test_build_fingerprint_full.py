from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

from app.security.build_fingerprint import (
    _module_file,
    compute_build_hash,
)


def test_module_file_failure():

    with patch(
        "importlib.util.find_spec",
        return_value=None,
    ):
        with pytest.raises(RuntimeError):
            _module_file("missing.module")


def test_module_file_success():

    class Spec:
        origin = "/tmp/test.py"

    with patch(
        "importlib.util.find_spec",
        return_value=Spec(),
    ):
        path = _module_file(
            "anything"
        )

    assert path == Path("/tmp/test.py")


def test_compute_build_hash():

    fake_data = b"abc"

    class Spec:
        origin = "/tmp/test.py"

    with patch(
        "importlib.util.find_spec",
        return_value=Spec(),
    ):
        with patch(
            "builtins.open",
            mock_open(read_data=fake_data),
        ):
            digest = compute_build_hash()

    assert isinstance(
        digest,
        str,
    )

    assert len(digest) == 64