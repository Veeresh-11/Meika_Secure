"""
TRACK D — Signature Tamper Resistance Tests

Simulates real-world attack scenarios:

- Payload tampering
- Hash manipulation
- Signature corruption
- Revoked key usage
- Expired key usage

These tests model:
- Malware modification
- Insider tampering
- Storage corruption
- Replay attack attempts
"""

import pytest
from copy import deepcopy

from app.security.track_d.export_soc2 import generate_soc2_export
from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.verifier import ExportVerifier
from app.security.track_d.signing.key_registry import KeyRegistry


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _sample_evidence():
    return [
        {"id": "evt-1", "action": "ALLOW"},
        {"id": "evt-2", "action": "DENY"},
    ]


def _control_mapping():
    return {"CC6.1": ["evt-1", "evt-2"]}


def _build_signed_bundle():
    signer = Ed25519Signer.generate()

    export = generate_soc2_export(
        evidence_records=_sample_evidence(),
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping=_control_mapping(),
        signer=signer,
    )

    trust_store = TrustStore()
    trust_store.add_trusted_key(
        key_id=export["key_id"],
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    )

    verifier = ExportVerifier(trust_store)

    return export, verifier


# ---------------------------------------------------------
# Tests
# ---------------------------------------------------------

def test_modify_record_after_signing_fails():
    export, verifier = _build_signed_bundle()

    tampered = deepcopy(export)
    tampered["records"][0]["action"] = "DENY"

    with pytest.raises(Exception):
        verifier.verify(tampered, now_utc="2026-04-01T00:00:00Z")


def test_modify_bundle_hash_only_fails():
    export, verifier = _build_signed_bundle()

    tampered = deepcopy(export)
    tampered["bundle_hash"] = "0" * 64

    with pytest.raises(Exception):
        verifier.verify(tampered, now_utc="2026-04-01T00:00:00Z")


def test_modify_signature_only_fails():
    export, verifier = _build_signed_bundle()

    tampered = deepcopy(export)
    tampered["signature"] = "0" * len(export["signature"])

    with pytest.raises(Exception):
        verifier.verify(tampered, now_utc="2026-04-01T00:00:00Z")


def test_revoked_key_fails_verification():
    signer = Ed25519Signer.generate()

    registry = KeyRegistry()
    registry.register_key(
        key_id="key-1",
        algorithm="Ed25519",
        created_at="2026-01-01T00:00:00Z",
        signer=signer,
        make_active=True,
    )

    export = generate_soc2_export(
        evidence_records=_sample_evidence(),
        kernel_version="1.0.0",
        export_period={
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-03-31T23:59:59Z",
        },
        control_mapping=_control_mapping(),
        signer=signer,
    )

    trust_store = TrustStore()
    trust_store.add_trusted_key(
        key_id=export["key_id"],
        public_key_bytes=signer.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
    )

    trust_store.revoke(export["key_id"], revoked_at="2026-04-01T00:00:00Z")

    verifier = ExportVerifier(trust_store)

    with pytest.raises(Exception):
        verifier.verify(export, now_utc="2026-05-01T00:00:00Z")


def test_expired_key_fails_verification():
    export, verifier = _build_signed_bundle()

    # Simulate expiration by verifying far future
    with pytest.raises(Exception):
        verifier.verify(export, now_utc="2035-01-01T00:00:00Z")
