import pytest

from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.detached_signer import generate_detached_signature
from app.security.track_d.signing.detached_verifier import DetachedVerifier
from app.security.track_d.signing.trust_store import TrustStore


def _sample_payload():
    return {
        "export_type": "SOC2_TYPE_II",
        "period_start": "2026-01-01T00:00:00Z",
        "period_end": "2026-03-31T23:59:59Z",
        "generated_at": "2026-03-31T23:59:59Z",
        "kernel_version": "1.0.0",
        "hash_algorithm": "SHA-256",
        "records": [{"id": 1}],
        "controls": {},
        "bundle_hash": "abc",
    }


def test_detached_sign_and_verify():
    signer = Ed25519Signer.generate()

    trust_store = TrustStore()
    trust_store.add_trusted_key(
        key_id=signer.key_id(),
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
    )

    signature = generate_detached_signature(
        payload=_sample_payload(),
        signer=signer,
        signed_at_utc="2026-04-01T00:00:00Z",
    )

    verifier = DetachedVerifier(trust_store)

    assert verifier.verify(
        payload=_sample_payload(),
        signature_object=signature,
        now_utc="2026-04-01T00:00:01Z",
    )
