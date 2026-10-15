from datetime import datetime, timezone

import pytest

from app.security.webauthn.assertion import AssertionVerificationError, verify_assertion
from app.security.webauthn.models import WebAuthnCredential


def test_legacy_counter_only_assertion_fails_closed_without_mutating_credential():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    credential = WebAuthnCredential(
        credential_id=b"1",
        public_key=b"pk",
        sign_count=10,
        hardware_backed=False,
        attestation_verified=True,
        attestation_type="none",
        created_at=now,
        last_used_at=now,
    )

    with pytest.raises(AssertionVerificationError, match="Legacy counter-only"):
        verify_assertion({"sign_count": 5}, credential)

    # Do not revoke a credential based only on an unauthenticated counter field.
    # Clone detection must be based on a cryptographically verified assertion.
    assert credential.revoked is False
