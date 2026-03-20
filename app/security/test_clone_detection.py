from app.security.webauthn.models import WebAuthnCredential
from app.security.webauthn.assertion import verify_assertion
from datetime import datetime
import pytest
pytestmark = pytest.mark.track_a

def test_clone_detected():
    cred = WebAuthnCredential(
        credential_id=b"1",
        public_key=b"pk",
        sign_count=10,
        hardware_backed=True,
        attestation_verified=True,
        attestation_type="tpm",
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
    )

    with pytest.raises(ValueError):
        verify_assertion({"sign_count": 5}, cred)

    assert cred.revoked is True
