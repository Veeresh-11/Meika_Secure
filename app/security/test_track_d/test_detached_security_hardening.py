import pytest
from copy import deepcopy

from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.detached_signer import generate_detached_signature
from app.security.track_d.signing.detached_verifier import DetachedVerifier
from app.security.track_d.signing.trust_store import TrustStore


def _payload():
    return {
        "data": "secure",
        "version": 1,
    }


def _setup():
    signer = Ed25519Signer.generate()

    trust = TrustStore()
    trust.add_trusted_key(
        key_id=signer.key_id(),
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
    )

    signature = generate_detached_signature(
        payload=_payload(),
        signer=signer,
        signed_at_utc="2026-06-01T00:00:00Z",
    )

    verifier = DetachedVerifier(trust)

    return signer, trust, signature, verifier


# ---------------------------------------------------
# Tier 1 – Cryptographic Integrity
# ---------------------------------------------------

def test_payload_bit_flip_fails():
    signer, trust, signature, verifier = _setup()

    tampered = deepcopy(_payload())
    tampered["data"] = "hacked"

    with pytest.raises(Exception):
        verifier.verify(
            payload=tampered,
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_truncated_signature_fails():
    signer, trust, signature, verifier = _setup()

    signature["signature"] = signature["signature"][:10]

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_signature_wraparound_fails():
    signer, trust, signature, verifier = _setup()

    signature["signature"] += "00"

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_hash_mismatch_fails():
    signer, trust, signature, verifier = _setup()

    signature["payload_hash"] = "deadbeef"

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


# ---------------------------------------------------
# Tier 2 – Temporal Logic
# ---------------------------------------------------

def test_future_dated_signature_fails():
    signer, trust, signature, verifier = _setup()

    signature["signed_at"] = "2030-01-01T00:00:00Z"

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_expired_key_fails():
    signer = Ed25519Signer.generate()

    trust = TrustStore()
    trust.add_trusted_key(
        key_id=signer.key_id(),
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
        expires_at="2026-02-01T00:00:00Z",
    )

    signature = generate_detached_signature(
        payload=_payload(),
        signer=signer,
        signed_at_utc="2026-01-15T00:00:00Z",
    )

    verifier = DetachedVerifier(trust)

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_revoked_key_fails():
    signer, trust, signature, verifier = _setup()

    trust.revoke(signer.key_id(), "2026-05-01T00:00:00Z")

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )


def test_non_utc_timestamp_rejected():
    signer, trust, signature, verifier = _setup()

    signature["signed_at"] = "2026-06-01T00:00:00+05:30"

    with pytest.raises(ValueError):
        verifier.verify(
            payload=_payload(),
            signature_object=signature,
            now_utc="2026-06-01T00:00:01Z",
        )
