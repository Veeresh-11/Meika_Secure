import pytest
from copy import deepcopy
from datetime import datetime, timezone

from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.detached_signer import generate_detached_signature
from app.security.track_d.signing.detached_verifier import DetachedVerifier
from app.security.track_d.signing.trust_store import TrustStore


def _payload():
    return {"data": "secure"}


def _setup():
    signer = Ed25519Signer.generate()

    trust = TrustStore()
    trust.add_trusted_key(
        key_id=signer.key_id(),
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
    )

    verifier = DetachedVerifier(trust)

    sig = generate_detached_signature(
        payload=_payload(),
        signer=signer,
        signed_at_utc="2026-02-01T00:00:00Z",
        expires_at_utc="2026-03-01T00:00:00Z",
    )

    return signer, trust, sig, verifier


def test_activation_enforced():
    signer = Ed25519Signer.generate()
    trust = TrustStore()

    trust.add_trusted_key(
        key_id=signer.key_id(),
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-05-01T00:00:00Z",
    )

    verifier = DetachedVerifier(trust)

    sig = generate_detached_signature(
        payload=_payload(),
        signer=signer,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-02-02T00:00:00Z",
        )


def test_expiration_enforced():
    signer, trust, sig, verifier = _setup()

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-04-01T00:00:00Z",
        )


def test_replay_detection():
    signer, trust, sig, verifier = _setup()

    verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-02T00:00:00Z",
    )

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-02-02T00:00:00Z",
        )
