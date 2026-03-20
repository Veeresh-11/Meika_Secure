import hashlib
import json

from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner


def _canonical(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _payload():
    return {"data": "secure"}


def test_signature_flood_attack():

    trust = TrustStore()
    signer = Ed25519LocalSigner()
    key_id = signer.key_id()

    trust.register_key(
        key_id=key_id,
        public_key=bytes.fromhex(signer.public_key_hex()),
        algorithm="Ed25519",
        weight=1,
        roles=["admin"],
        created_at="2026-01-01T00:00:00Z",
    )

    payload = _payload()
    payload_hash = hashlib.sha256(_canonical(payload)).hexdigest()

    sig_hex = signer.sign(payload_hash.encode())

    # Flood with many duplicate entries of same signer
    signatures = [
        {"key_id": key_id, "signature": sig_hex}
        for _ in range(500)
    ]

    signature_object = {
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "policy_family": None,
        "policy_version": None,
        "signed_at": "2026-02-01T00:00:00Z",
        "signatures": signatures,
    }

    verifier = ThresholdVerifier(trust_store=trust)

    # Should fail due to duplicate signer detection
    try:
        verifier.verify(
            payload=payload,
            signature_object=signature_object,
            now_utc="2026-02-01T00:00:01Z",
        )
    except ValueError:
        return

    assert False, "Flood attack was not rejected"
