import pytest
import hashlib
import json
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.governance.governance_registry import GovernanceRegistry
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner
from app.security.track_d.signing.threshold_signer import generate_threshold_signature

def test_role_escalation_rejected():

    trust = TrustStore()
    governance = GovernanceRegistry()
    signer = Ed25519LocalSigner()
    key_id = signer.key_id()

    trust.register_key(
        key_id=key_id,
        public_key=bytes.fromhex(signer.public_key_hex()),
        algorithm="Ed25519",
        weight=10,
        roles=["viewer"],  # not admin
        created_at="2026-01-01T00:00:00Z",
    )

    governance.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=10,
        required_roles=["admin"],
    )

    payload = {"data": "secure"}
    payload_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    sig_hex, _ = signer.sign(payload_hash.encode())

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
