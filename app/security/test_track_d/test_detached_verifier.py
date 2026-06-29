import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.security.track_d.signing.detached_verifier import (
    DetachedVerifier,
)
from app.security.track_d.signing.trust_store import TrustStore


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

CREATED = "2025-01-01T00:00:00Z"
NOW = "2025-01-02T00:00:00Z"


def build_trust():
    private = Ed25519PrivateKey.generate()
    public = private.public_key()

    trust = TrustStore()

    trust.add_trusted_key(
        key_id="k1",
        public_key_bytes=public.public_bytes_raw(),
        created_at=CREATED,
    )

    return trust, private


def build_payload():
    return {
        "message": "hello",
        "value": 123,
    }


def payload_hash(payload):
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    return hashlib.sha256(canonical).hexdigest()


def build_signature(private, payload):
    ph = payload_hash(payload)

    sig = private.sign(
        ph.encode("utf-8"),
    ).hex()

    return {
        "type": "DETACHED",
        "hash_algorithm": "SHA-256",
        "key_id": "k1",
        "signature": sig,
        "signed_at": NOW,
        "payload_hash": ph,
        "algorithm": "Ed25519",
    }


# ---------------------------------------------------------
# Success
# ---------------------------------------------------------


def test_verify_success():
    trust, private = build_trust()

    payload = build_payload()

    verifier = DetachedVerifier(trust)

    assert verifier.verify(
        payload=payload,
        signature_object=build_signature(
            private,
            payload,
        ),
        now_utc=NOW,
    )


# ---------------------------------------------------------
# Structure validation
# ---------------------------------------------------------


def test_invalid_type():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["type"] = "BAD"

    with pytest.raises(
        ValueError,
        match="Invalid signature type",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


def test_invalid_hash_algorithm():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["hash_algorithm"] = "SHA1"

    with pytest.raises(
        ValueError,
        match="Unsupported hash algorithm",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


@pytest.mark.parametrize(
    "field",
    [
        "key_id",
        "signature",
        "signed_at",
        "payload_hash",
        "algorithm",
    ],
)
def test_missing_required_fields(field):
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    del sig[field]

    with pytest.raises(
        ValueError,
        match="Missing required field",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


# ---------------------------------------------------------
# Date checks
# ---------------------------------------------------------


def test_future_signature():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["signed_at"] = "2030-01-01T00:00:00Z"

    with pytest.raises(
        ValueError,
        match="future",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


def test_before_activation():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["signed_at"] = "2024-01-01T00:00:00Z"

    with pytest.raises(
        ValueError,
        match="activation",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


def test_expired_signature():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["expires_at"] = "2025-01-01T12:00:00Z"

    with pytest.raises(
        ValueError,
        match="expired",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


# ---------------------------------------------------------
# Algorithm
# ---------------------------------------------------------


def test_algorithm_mismatch():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["algorithm"] = "RSA"

    with pytest.raises(
        ValueError,
        match="Algorithm mismatch",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


def test_payload_hash_mismatch():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["payload_hash"] = "0" * 64

    with pytest.raises(
        ValueError,
        match="Payload hash mismatch",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


# ---------------------------------------------------------
# Replay
# ---------------------------------------------------------


def test_replay_detection():
    trust, private = build_trust()

    payload = build_payload()

    verifier = DetachedVerifier(trust)

    sig = build_signature(
        private,
        payload,
    )

    assert verifier.verify(
        payload=payload,
        signature_object=sig,
        now_utc=NOW,
    )

    with pytest.raises(
        ValueError,
        match="Replay detected",
    ):
        verifier.verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )


# ---------------------------------------------------------
# Signature encoding
# ---------------------------------------------------------


def test_invalid_signature_encoding():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["signature"] = "nothex"

    with pytest.raises(
        ValueError,
        match="Invalid signature encoding",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )
        
def test_invalid_now_timestamp():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    with pytest.raises(
        ValueError,
        match="RFC3339 UTC",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc="2025-01-02",   # Missing Z suffix
        )

def test_signature_not_yet_expired():
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    sig["expires_at"] = "2025-01-03T00:00:00Z"

    verifier = DetachedVerifier(trust)

    assert verifier.verify(
        payload=payload,
        signature_object=sig,
        now_utc=NOW,
    )
    
def test_trust_store_algorithm_not_ed25519(monkeypatch):
    trust, private = build_trust()

    payload = build_payload()
    sig = build_signature(private, payload)

    monkeypatch.setattr(
        trust,
        "get_algorithm",
        lambda key_id: "RSA",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported algorithm",
    ):
        DetachedVerifier(trust).verify(
            payload=payload,
            signature_object=sig,
            now_utc=NOW,
        )
        
