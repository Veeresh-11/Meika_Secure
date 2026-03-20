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
