import pytest
from datetime import datetime, timezone
import json
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.governance.governance_registry import GovernanceRegistry


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _utc_now():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _basic_payload():
    return {"data": "secure"}


# ---------------------------------------------------------
# 1️⃣ Duplicate Signer Attack
# ---------------------------------------------------------

def test_threshold_duplicate_signer_rejected():

    trust = TrustStore()

    signer = Ed25519LocalSigner()
    key_id = signer.key_id()

    trust.register_key(
        key_id=key_id,
        public_key=bytes.fromhex(signer.public_key_hex()),
        algorithm="Ed25519",
        weight=5,
        roles=["admin"],
        created_at=_utc_now(),
    )

    payload = _basic_payload()

    payload_hash = signer.sign(
        b"dummy"
    )[0]  # irrelevant for structure

    sig_hex, _ = signer.sign(b"attack")

    signature_object = {
        "hash_algorithm": "SHA-256",
        "payload_hash": "invalid",  # will be corrected below
        "policy_family": None,
        "policy_version": None,
        "signed_at": _utc_now(),
        "signatures": [
            {"key_id": key_id, "signature": sig_hex},
            {"key_id": key_id, "signature": sig_hex},  # duplicate
        ],
    }

    # Fix payload_hash properly
    import hashlib, json
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature_object["payload_hash"] = hashlib.sha256(canonical).hexdigest()

    verifier = ThresholdVerifier(trust_store=trust)

    with pytest.raises(ValueError):
        verifier.verify(
            payload=payload,
            signature_object=signature_object,
            now_utc=_utc_now(),
        )


# ---------------------------------------------------------
# 2️⃣ Unsupported Algorithm Attack
# ---------------------------------------------------------

def test_threshold_unsupported_algorithm_rejected():

    trust = TrustStore()
    signer = Ed25519LocalSigner()
    key_id = signer.key_id()

    trust.register_key(
        key_id=key_id,
        public_key=bytes.fromhex(signer.public_key_hex()),
        algorithm="RSA",  # malicious algorithm mismatch
        weight=5,
        roles=["admin"],
        created_at=_utc_now(),
    )

    payload = _basic_payload()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    import hashlib
    payload_hash = hashlib.sha256(canonical).hexdigest()

    sig_hex, _ = signer.sign(payload_hash.encode())

    signature_object = {
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "policy_family": None,
        "policy_version": None,
        "signed_at": _utc_now(),
        "signatures": [
            {"key_id": key_id, "signature": sig_hex},
        ],
    }

    verifier = ThresholdVerifier(trust_store=trust)

    with pytest.raises(ValueError):
        verifier.verify(
            payload=payload,
            signature_object=signature_object,
            now_utc=_utc_now(),
        )


# ---------------------------------------------------------
# 3️⃣ Governance Downgrade Simulation
# ---------------------------------------------------------

def test_governance_downgrade_attack_blocked():

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
        created_at=_utc_now(),
    )

    governance.add_policy(
        policy_family="CORE",
        version=1,
        effective_from="2025-01-01T00:00:00Z",
        minimum_weight=10,
        required_roles=["admin"],
    )

    governance.add_policy(
        policy_family="CORE",
        version=2,
        effective_from="2025-02-01T00:00:00Z",
        minimum_weight=10,
        required_roles=["admin"],
    )

    payload = _basic_payload()
    import hashlib, json
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload_hash = hashlib.sha256(canonical).hexdigest()

    sig_hex, _ = signer.sign(payload_hash.encode())

    # Attempt to use version 1 after version 2 active
    signature_object = {
        "hash_algorithm": "SHA-256",
        "payload_hash": payload_hash,
        "policy_family": "CORE",
        "policy_version": 1,
        "signed_at": "2025-03-01T00:00:00Z",
        "signatures": [
            {"key_id": key_id, "signature": sig_hex},
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
            now_utc="2025-03-01T00:00:00Z",
        )
