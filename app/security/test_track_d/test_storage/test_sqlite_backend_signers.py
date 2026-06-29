import hashlib
import json

import pytest

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from app.security.track_d.storage.sqlite_backend import (
    Signer,
    Table,
    SCHEMA_VERSION,
    REQUIRED_SIGNATURES,
    _canonical,
    _hash_entry,
    _chain_hash,
    _verify_signature,
)

from app.security.track_d.storage.sqlite_backend import (
    LocalSigner,
    RemoteSigner,
    PolicyEngine,
    ExternalAnchor,
    requests
)

# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------


@pytest.fixture
def signing_key():
    return SigningKey.generate()


@pytest.fixture
def signer(signing_key):
    return Signer(
        signing_key.encode(
            encoder=HexEncoder,
        ).decode()
    )


# ---------------------------------------------------------
# Constants
# ---------------------------------------------------------


def test_schema_version():
    assert SCHEMA_VERSION == 3


def test_required_signatures():
    assert REQUIRED_SIGNATURES == 2


# ---------------------------------------------------------
# Enum
# ---------------------------------------------------------


def test_table_values():
    assert Table.VERIFICATION.value == "verification_ledger"
    assert Table.TRANSPARENCY.value == "transparency_log"
    assert Table.GOVERNANCE.value == "governance_policies"


def test_table_count():
    assert len(Table) == 3


# ---------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------


def test_canonical_is_bytes():
    value = _canonical({"a": 1})
    assert isinstance(value, bytes)


def test_canonical_is_deterministic():
    left = {
        "b": 2,
        "a": 1,
    }

    right = {
        "a": 1,
        "b": 2,
    }

    assert _canonical(left) == _canonical(right)


def test_canonical_matches_expected():
    assert (
        _canonical({"x": 1, "y": 2})
        == b'{"x":1,"y":2}'
    )


# ---------------------------------------------------------
# Entry Hash
# ---------------------------------------------------------


def test_hash_entry_returns_sha256():
    entry = {"abc": 123}

    expected = hashlib.sha256(
        _canonical(entry)
    ).hexdigest()

    assert _hash_entry(entry) == expected


def test_hash_entry_deterministic():
    entry = {"a": 1}

    assert (
        _hash_entry(entry)
        == _hash_entry(entry)
    )


def test_hash_entry_changes():
    assert (
        _hash_entry({"a": 1})
        != _hash_entry({"a": 2})
    )


# ---------------------------------------------------------
# Chain Hash
# ---------------------------------------------------------


def test_chain_hash_genesis():
    entry_hash = hashlib.sha256(
        b"abc"
    ).hexdigest()

    expected = hashlib.sha256(
        entry_hash.encode()
    ).hexdigest()

    assert (
        _chain_hash(entry_hash, None)
        == expected
    )


def test_chain_hash_with_previous():
    entry_hash = "a" * 64
    prev = "b" * 64

    expected = hashlib.sha256(
        (prev + entry_hash).encode()
    ).hexdigest()

    assert (
        _chain_hash(entry_hash, prev)
        == expected
    )


def test_chain_hash_changes():
    assert (
        _chain_hash("a", None)
        != _chain_hash("b", None)
    )


# ---------------------------------------------------------
# Signer
# ---------------------------------------------------------


def test_signer_public_key(signer):
    key = signer.get_public_key()

    assert isinstance(key, str)
    assert len(key) > 10


def test_signer_sign_returns_hex(signer):
    sig = signer.sign("hello")

    assert isinstance(sig, str)
    bytes.fromhex(sig)


def test_signatures_are_deterministic_for_same_message(signer):
    sig1 = signer.sign("abc")
    sig2 = signer.sign("abc")

    assert sig1 == sig2


def test_signatures_change_for_different_messages(signer):
    sig1 = signer.sign("abc")
    sig2 = signer.sign("xyz")

    assert sig1 != sig2


# ---------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------


def test_verify_signature_success(signer):
    message = "secure message"

    signature = signer.sign(message)

    _verify_signature(
        signer.get_public_key(),
        signature,
        message,
    )


def test_verify_signature_modified_message_fails(signer):
    signature = signer.sign("original")

    with pytest.raises(Exception):
        _verify_signature(
            signer.get_public_key(),
            signature,
            "tampered",
        )


def test_verify_signature_modified_signature_fails(signer):
    signature = signer.sign("hello")

    bad = "00" + signature[2:]

    with pytest.raises(Exception):
        _verify_signature(
            signer.get_public_key(),
            bad,
            "hello",
        )


def test_verify_signature_wrong_public_key(signing_key):
    signer1 = Signer(
        signing_key.encode(
            encoder=HexEncoder,
        ).decode()
    )

    signer2 = Signer(
        SigningKey.generate()
        .encode(
            encoder=HexEncoder,
        )
        .decode()
    )

    signature = signer1.sign("abc")

    with pytest.raises(Exception):
        _verify_signature(
            signer2.get_public_key(),
            signature,
            "abc",
        )
        
# ---------------------------------------------------------
# LocalSigner
# ---------------------------------------------------------


@pytest.fixture
def local_signer():
    sk = SigningKey.generate()

    return LocalSigner(
        sk.encode(
            encoder=HexEncoder,
        ).decode()
    )


def test_local_signer_public_key(local_signer):
    key = local_signer.get_public_key()

    assert isinstance(key, str)
    assert len(key) > 10


def test_local_signer_sign_returns_hex(local_signer):
    sig = local_signer.sign("hello")

    assert isinstance(sig, str)

    bytes.fromhex(sig)


def test_local_signer_same_message_same_signature(local_signer):
    sig1 = local_signer.sign("abc")
    sig2 = local_signer.sign("abc")

    assert sig1 == sig2


def test_local_signer_different_messages(local_signer):
    sig1 = local_signer.sign("abc")
    sig2 = local_signer.sign("xyz")

    assert sig1 != sig2


def test_local_signer_signature_verifies(local_signer):
    message = "verification"

    signature = local_signer.sign(message)

    _verify_signature(
        local_signer.get_public_key(),
        signature,
        message,
    )


# ---------------------------------------------------------
# RemoteSigner
# ---------------------------------------------------------


class FakeResponse:

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_remote_sign(monkeypatch):

    def fake_post(url, json, timeout):
        assert url.endswith("/sign")
        assert timeout == 5
        assert json["message"] == "hello"

        return FakeResponse(
            {
                "signature": "deadbeef",
            }
        )

    monkeypatch.setattr(
        requests,
        "post",
        fake_post,
    )

    signer = RemoteSigner("https://remote")

    assert signer.sign("hello") == "deadbeef"


def test_remote_get_public_key(monkeypatch):

    def fake_get(url, timeout):
        assert url.endswith("/public_key")
        assert timeout == 5

        return FakeResponse(
            {
                "public_key": "PUBLICKEY",
            }
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    signer = RemoteSigner("https://remote")

    assert signer.get_public_key() == "PUBLICKEY"


def test_remote_sign_http_error(monkeypatch):

    class BadResponse:

        def raise_for_status(self):
            raise RuntimeError("HTTP 500")

    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: BadResponse(),
    )

    signer = RemoteSigner("https://remote")

    with pytest.raises(RuntimeError):
        signer.sign("hello")


def test_remote_public_key_http_error(monkeypatch):

    class BadResponse:

        def raise_for_status(self):
            raise RuntimeError("HTTP 500")

    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: BadResponse(),
    )

    signer = RemoteSigner("https://remote")

    with pytest.raises(RuntimeError):
        signer.get_public_key()


# ---------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------


def test_policy_engine_accepts_timestamp():
    engine = PolicyEngine()

    assert engine.validate(
        {
            "timestamp": "2026-01-01T00:00:00Z",
        }
    )


def test_policy_engine_rejects_missing_timestamp():
    engine = PolicyEngine()

    assert engine.validate({}) is False


def test_policy_engine_accepts_extra_fields():
    engine = PolicyEngine()

    assert engine.validate(
        {
            "timestamp": "2026",
            "user": "alice",
            "value": 123,
        }
    )


# ---------------------------------------------------------
# ExternalAnchor
# ---------------------------------------------------------


def test_external_anchor_publish():
    anchor = ExternalAnchor()

    assert (
        anchor.publish(
            "abc",
            [],
        )
        is None
    )


def test_external_anchor_verify():
    anchor = ExternalAnchor()

    assert anchor.verify("abc") is True
    
# ---------------------------------------------------------
# NaCl unavailable branches
# ---------------------------------------------------------


def test_signer_requires_nacl(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend.SigningKey",
        None,
    )

    with pytest.raises(
        RuntimeError,
        match="nacl is required for sqlite backend",
    ):
        Signer("00" * 32)


def test_local_signer_requires_nacl(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend.SigningKey",
        None,
    )

    with pytest.raises(
        RuntimeError,
        match="nacl is required for sqlite backend",
    ):
        LocalSigner("00" * 32)


def test_verify_signature_requires_nacl(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.security.track_d.storage.sqlite_backend.SigningKey",
        None,
    )

    with pytest.raises(
        RuntimeError,
        match="nacl is required for sqlite backend",
    ):
        _verify_signature(
            "deadbeef",
            "deadbeef",
            "message",
        )