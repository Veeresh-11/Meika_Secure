import time
import os

from app.security.track_d.storage.sqlite_backend import (
    SQLiteBackend,
    Signer,
    Table,
)


def test_sqlite_append_with_quorum(tmp_path):
    db_path = tmp_path / "test.db"

    # ✅ isolate anchor file per test
    anchor_file = tmp_path / "ledger.anchor"
    os.environ["ANCHOR_FILE"] = str(anchor_file)

    db = SQLiteBackend(str(db_path))

    s1 = Signer("a" * 64)
    s2 = Signer("b" * 64)

    db.register_signer(s1.get_public_key())
    db.register_signer(s2.get_public_key())

    entry = {
        "test": True,
        "timestamp": time.time(),
    }

    db.append(Table.VERIFICATION, entry, [s1, s2])

    # ✅ verify anchor created in isolated path
    assert anchor_file.exists()

    db.close()
    
import pytest
from unittest.mock import Mock, patch

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from app.security.track_d.storage.sqlite_backend import (
    Signer,
    LocalSigner,
    RemoteSigner,
    PolicyEngine,
    ExternalAnchor,
    _verify_signature,
)


def _private_hex():
    return SigningKey.generate().encode(
        encoder=HexEncoder
    ).decode()


# ---------------------------------------------------------
# Signer
# ---------------------------------------------------------

def test_signer_sign_and_verify():

    sk = _private_hex()

    signer = Signer(sk)

    msg = "hello"

    sig = signer.sign(msg)

    _verify_signature(
        signer.get_public_key(),
        sig,
        msg,
    )


def test_local_signer_sign_and_verify():

    sk = _private_hex()

    signer = LocalSigner(sk)

    msg = "secure"

    sig = signer.sign(msg)

    _verify_signature(
        signer.get_public_key(),
        sig,
        msg,
    )


def test_verify_signature_invalid_signature():

    sk = _private_hex()

    signer = Signer(sk)

    with pytest.raises(Exception):
        _verify_signature(
            signer.get_public_key(),
            "00" * 64,
            "hello",
        )


# ---------------------------------------------------------
# Remote signer
# ---------------------------------------------------------

@patch("app.security.track_d.storage.sqlite_backend.requests.post")
def test_remote_sign(mock_post):

    response = Mock()

    response.raise_for_status.return_value = None

    response.json.return_value = {
        "signature": "abc"
    }

    mock_post.return_value = response

    signer = RemoteSigner("https://server")

    assert signer.sign("hello") == "abc"

    mock_post.assert_called_once()


@patch("app.security.track_d.storage.sqlite_backend.requests.get")
def test_remote_public_key(mock_get):

    response = Mock()

    response.raise_for_status.return_value = None

    response.json.return_value = {
        "public_key": "pk"
    }

    mock_get.return_value = response

    signer = RemoteSigner("https://server")

    assert signer.get_public_key() == "pk"

    mock_get.assert_called_once()


# ---------------------------------------------------------
# Policy engine
# ---------------------------------------------------------

def test_policy_engine_accepts_timestamp():

    p = PolicyEngine()

    assert p.validate(
        {"timestamp": "2026"}
    ) is True


def test_policy_engine_rejects_missing_timestamp():

    p = PolicyEngine()

    assert p.validate({}) is False


# ---------------------------------------------------------
# External anchor
# ---------------------------------------------------------

def test_external_anchor_verify():

    a = ExternalAnchor()

    assert a.verify("abc") is True


def test_external_anchor_publish():

    a = ExternalAnchor()

    assert a.publish("abc", []) is None