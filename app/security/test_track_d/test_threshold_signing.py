import pytest
from app.security.track_d.signing.threshold_signer import generate_threshold_signature
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.trust_store import TrustStore


def _payload():
    return {"data": "critical export"}


def _setup():

    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()
    s3 = Ed25519Signer.generate()

    trust = TrustStore()

    for s in [s1, s2, s3]:
        trust.add_trusted_key(
            key_id=s.key_id(),
            public_key_bytes=s.public_key_bytes(),
            created_at="2026-01-01T00:00:00Z",
        )

    return s1, s2, s3, trust


def test_2_of_3_passes():
    s1, s2, s3, trust = _setup()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2, s3],
        threshold=2,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    verifier = ThresholdVerifier(trust)

    assert verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )


def test_invalid_threshold_rejected_at_generation():
    s1, s2, s3, trust = _setup()

    with pytest.raises(Exception):
        generate_threshold_signature(
            payload=_payload(),
            signers=[s1],
            threshold=2,
            signed_at_utc="2026-02-01T00:00:00Z",
        )

def test_revoked_signer_excluded():
    s1, s2, s3, trust = _setup()

    trust.revoke(s3.key_id(), "2026-01-15T00:00:00Z")

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2, s3],
        threshold=3,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    verifier = ThresholdVerifier(trust)

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-02-01T00:00:01Z",
        )
import pytest

from app.security.track_d.signing.threshold_signer import (
    generate_threshold_signature,
)


class FakeSigner:
    def __init__(self, key_id):
        self._key_id = key_id

    def key_id(self):
        return self._key_id

    def algorithm(self):
        return "TEST"

    def sign(self, payload):
        return ("deadbeef", self._key_id)


def test_threshold_must_be_positive():
    with pytest.raises(
        ValueError,
        match="Threshold must be positive",
    ):
        generate_threshold_signature(
            payload={"x": 1},
            signers=[FakeSigner("k1")],
            threshold=0,
            signed_at_utc="2026-01-01T00:00:00Z",
        )


def test_invalid_timestamp_rejected():
    with pytest.raises(
        ValueError,
        match="RFC3339",
    ):
        generate_threshold_signature(
            payload={"x": 1},
            signers=[FakeSigner("k1")],
            threshold=1,
            signed_at_utc="invalid",
        )


def test_duplicate_signer_key_detected():
    signer1 = FakeSigner("same")
    signer2 = FakeSigner("same")

    with pytest.raises(
        ValueError,
        match="Duplicate signer key detected",
    ):
        generate_threshold_signature(
            payload={"x": 1},
            signers=[signer1, signer2],
            threshold=1,
            signed_at_utc="2026-01-01T00:00:00Z",
        )


class BadSigner(FakeSigner):
    def sign(self, payload):
        return ("deadbeef", "different_key")


def test_mismatched_key_id_detected():
    with pytest.raises(
        ValueError,
        match="Signer returned mismatched key_id",
    ):
        generate_threshold_signature(
            payload={"x": 1},
            signers=[BadSigner("real_key")],
            threshold=1,
            signed_at_utc="2026-01-01T00:00:00Z",
        )