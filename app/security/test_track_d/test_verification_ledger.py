import pytest

from app.security.track_d.signing.threshold_verifier import ThresholdVerifier
from app.security.track_d.signing.threshold_signer import generate_threshold_signature
from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.ed25519_provider import Ed25519Signer
from app.security.track_d.audit.verification_ledger import VerificationLedger


def _payload():
    return {"type": "EXPORT", "data": "ledger-test"}


def _setup():

    s1 = Ed25519Signer.generate()
    trust = TrustStore()

    trust.add_trusted_key(
        key_id=s1.key_id(),
        public_key_bytes=s1.public_key_bytes(),
        created_at="2026-01-01T00:00:00Z",
    )

    ledger = VerificationLedger()

    sig = generate_threshold_signature(
        payload=_payload(),
        signers=[s1],
        threshold=1,
        signed_at_utc="2026-02-01T00:00:00Z",
    )

    verifier = ThresholdVerifier(trust, ledger=ledger)

    return verifier, sig, ledger


def test_success_logs_pass():
    verifier, sig, ledger = _setup()

    assert verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    assert len(ledger._chain) == 1
    assert ledger._chain[0]["result"] == "PASS"


def test_failure_logs_fail():
    verifier, sig, ledger = _setup()

    sig["payload_hash"] = "corrupted"

    with pytest.raises(Exception):
        verifier.verify(
            payload=_payload(),
            signature_object=sig,
            now_utc="2026-02-01T00:00:01Z",
        )

    assert len(ledger._chain) == 1
    assert ledger._chain[0]["result"] == "FAIL"


def test_chain_validation():
    verifier, sig, ledger = _setup()

    verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    assert ledger.validate_chain()


def test_tampering_detected():
    verifier, sig, ledger = _setup()

    verifier.verify(
        payload=_payload(),
        signature_object=sig,
        now_utc="2026-02-01T00:00:01Z",
    )

    # Tamper with ledger
    ledger._chain[0]["result"] = "HACKED"

    assert not ledger.validate_chain()
