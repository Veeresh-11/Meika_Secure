import pytest

from app.security.track_d.signing.trust_store import TrustStore
from app.security.track_d.signing.threshold_verifier import ThresholdVerifier

def test_missing_fields_rejected():

    verifier = ThresholdVerifier(trust_store=TrustStore())

    with pytest.raises(Exception):
        verifier.verify(
            payload={},
            signature_object={},
            now_utc="2026-01-01T00:00:00Z",
        )
