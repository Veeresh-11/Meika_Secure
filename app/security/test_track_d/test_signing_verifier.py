import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.verifier import ExportVerifier


CREATED = "2025-01-01T00:00:00Z"
NOW = "2025-01-02T00:00:00Z"


def build_trust():
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    trust = TrustStore()

    trust.add_trusted_key(
        key_id="key1",
        public_key_bytes=public.public_bytes_raw(),
        created_at=CREATED,
    )

    return trust, private


def build_bundle(private):
    payload = {
        "document": "hello",
        "counter": 1,
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    bundle_hash = hashlib.sha256(canonical).hexdigest()

    signature = private.sign(canonical).hex()

    bundle = dict(payload)

    bundle.update(
        {
            "key_id": "key1",
            "signature": signature,
            "bundle_hash": bundle_hash,
            "hash_algorithm": "SHA-256",
            "signing_algorithm": "Ed25519",
        }
    )

    return bundle


# ---------------------------------------------------------
# Success
# ---------------------------------------------------------


def test_verify_success():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    assert verifier.verify(
        build_bundle(private),
        NOW,
    )


# ---------------------------------------------------------
# Missing fields
# ---------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "key_id",
        "signature",
        "bundle_hash",
        "hash_algorithm",
        "signing_algorithm",
    ],
)
def test_missing_required_field(field):
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)

    del bundle[field]

    with pytest.raises(
        ValueError,
        match="Missing required field",
    ):
        verifier.verify(bundle, NOW)


# ---------------------------------------------------------
# Algorithms
# ---------------------------------------------------------


def test_hash_algorithm():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)
    bundle["hash_algorithm"] = "SHA1"

    with pytest.raises(
        ValueError,
        match="Unsupported hash algorithm",
    ):
        verifier.verify(bundle, NOW)


def test_signing_algorithm():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)
    bundle["signing_algorithm"] = "RSA"

    with pytest.raises(
        ValueError,
        match="Unsupported signing algorithm",
    ):
        verifier.verify(bundle, NOW)


def test_trust_algorithm(monkeypatch):
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    monkeypatch.setattr(
        trust,
        "get_algorithm",
        lambda *_: "RSA",
    )

    with pytest.raises(
        ValueError,
        match="TrustStore algorithm mismatch",
    ):
        verifier.verify(
            build_bundle(private),
            NOW,
        )


# ---------------------------------------------------------
# Hash validation
# ---------------------------------------------------------


def test_bundle_hash_mismatch():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)
    bundle["bundle_hash"] = "0" * 64

    with pytest.raises(
        ValueError,
        match="Bundle hash mismatch",
    ):
        verifier.verify(bundle, NOW)


# ---------------------------------------------------------
# Signature encoding
# ---------------------------------------------------------


def test_signature_encoding():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)
    bundle["signature"] = "nothex"

    with pytest.raises(
        ValueError,
        match="Invalid signature encoding",
    ):
        verifier.verify(bundle, NOW)


# ---------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------


def test_lifecycle_called(monkeypatch):
    trust, private = build_trust()

    called = False

    def fake(*args):
        nonlocal called
        called = True

    monkeypatch.setattr(
        trust,
        "validate_lifecycle",
        fake,
    )

    ExportVerifier(trust).verify(
        build_bundle(private),
        NOW,
    )

    assert called


def test_invalid_signature():
    trust, private = build_trust()

    verifier = ExportVerifier(trust)

    bundle = build_bundle(private)

    bundle["signature"] = (
        private.sign(b"wrong").hex()
    )

    with pytest.raises(Exception):
        verifier.verify(bundle, NOW)