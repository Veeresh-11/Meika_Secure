import pytest
from datetime import datetime, timezone

from app.security.webauthn.assertion import AssertionVerificationError, verify_assertion
from app.security.webauthn.models import WebAuthnCredential


def make_credential():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return WebAuthnCredential(
        credential_id=b"cred1",
        public_key=b"pubkey",
        sign_count=10,
        hardware_backed=False,
        attestation_verified=True,
        attestation_type="none",
        created_at=now,
        last_used_at=now,
        revoked=False,
    )


@pytest.mark.parametrize("assertion", [{"sign_count": 11}, {"sign_count": 10}, {}])
def test_legacy_counter_only_assertions_fail_closed(assertion):
    with pytest.raises(AssertionVerificationError, match="Legacy counter-only"):
        verify_assertion(assertion, make_credential())
