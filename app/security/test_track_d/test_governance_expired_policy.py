import hashlib
import json
import pytest

from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner
from app.security.track_d.governance.governance_registry import GovernanceRegistry


def _canonical(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_expired_policy_rejected():

    trust = TrustStore()
    governance = GovernanceRegistry()
    signer = Ed25519LocalSigner()
    key_id = signer.key_id()

    trust.register_key(
        key_id=key_id,
        public_key=bytes.fromhex(signer.public_key_hex()),
        algorithm="Ed25519",
        weight=10,
        roles=["admin"],
        created_at="2026-01-01T00:00:00Z",
    )

    governance.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2020-01-01T00:00:00Z",
        minimum_weight=10,
        required_roles=["admin"],
    )

    governance.expire_policy("CORE", 1, "2021-01-01T00:00:00Z")

    payload = {"data": "secure"}
    payload_hash = hashlib.sha256(_canonical(payload)).hexdigest()

    sig_hex = signer.sign(payload_hash.encode())

    signature_object = {
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "policy_family": "CORE",
        "policy_version": 1,
        "signed_at": "2026-02-01T00:00:00Z",
        "signatures": [
            {"key_id": key_id, "signature": sig_hex}
        ],
    }

    verifier = ThresholdVerifier(
        trust_store=trust,
        governance_registry=governance,
    )

    with pytest.raises(ValueError):
        verifier.verify(
            payload=payload,
            signature_object=signature_object,
            now_utc="2026-02-01T00:00:01Z",
        )
