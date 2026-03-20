import pytest

from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.signing.threshold_signer import generate_threshold_signature
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.audit.verification_ledger import VerificationLedger
from app.security.track_d.transparency.transparency_log import TransparencyLog


def _payload():
    return {"data": "transparency export"}


def _setup():

    # Generate signers
    s1 = Ed25519Signer.generate()
    s2 = Ed25519Signer.generate()

    # Trust store
    trust = TrustStore()

    for s in [s1, s2]:
        trust.add_trusted_key(
            key_id=s.key_id(),
            public_key_bytes=s.public_key_bytes(),
            created_at="2026-01-01T00:00:00Z",
            weight=3,
            roles=["SECURITY_OFFICER"],
        )

    # Transparency log
    transparency_log = TransparencyLog()

    # Immutable verification ledger
    ledger = VerificationLedger()

    # Threshold verifier
    verifier = ThresholdVerifier(
        trust_store=trust,
        governance_registry=None,
        ledger=ledger,
        transparency_log=transparency_log,
    )

    return s1, s2, trust, verifier, transparency_log, ledger


# -------------------------------------------------
# Test: Transparency entry created on PASS
# -------------------------------------------------

def test_transparency_log_on_success():

    s1, s2, trust, verifier, transparency_log, ledger = _setup()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2],
        threshold=2,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    assert verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    # Transparency log must contain entry
    assert len(transparency_log._entries) == 1
    assert transparency_log._entries[0]["result"] == "PASS"


# -------------------------------------------------
# Test: Transparency entry created on FAIL
# -------------------------------------------------

def test_transparency_log_on_failure():

    s1, s2, trust, verifier, transparency_log, ledger = _setup()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2],
        threshold=2,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    # Corrupt payload hash
    sig["payload_hash"] = "tampered"

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-02-01T00:00:01Z",
        )

    assert len(transparency_log._entries) == 1
    assert transparency_log._entries[0]["result"] == "FAIL"


# -------------------------------------------------
# Test: Transparency log chain integrity
# -------------------------------------------------

def test_transparency_chain_integrity():

    s1, s2, trust, verifier, transparency_log, ledger = _setup()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2],
        threshold=2,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    assert transparency_log.validate_chain()


# -------------------------------------------------
# Test: Transparency tampering detection
# -------------------------------------------------

def test_transparency_tampering_detected():

    s1, s2, trust, verifier, transparency_log, ledger = _setup()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1, s2],
        threshold=2,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    # Tamper with log entry
    transparency_log._entries[0]["result"] = "HACKED"

    with pytest.raises(Exception):
        transparency_log.validate_chain()
