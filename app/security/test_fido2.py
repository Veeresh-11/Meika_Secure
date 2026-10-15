import pytest

from app.security.webauthn.fido2 import (
    FIDO2VerificationError,
    generate_authentication_options_json,
    generate_registration_options_json,
    verify_authentication,
    verify_registration,
    issue_enrollment_token,
    verify_enrollment_token,
)


def test_registration_options_follow_webauthn_shape():
    options = generate_registration_options_json(
        rp_id="localhost",
        rp_name="Meika Test",
        user_id=b"user-123",
        user_name="user@example.test",
        challenge="dGVzdC1jaGFsbGVuZ2U",
    )
    assert options["challenge"] == "dGVzdC1jaGFsbGVuZ2U"
    assert options["rp"]["id"] == "localhost"
    assert options["user"]["name"] == "user@example.test"
    assert any(item["type"] == "public-key" for item in options["pubKeyCredParams"])


def test_authentication_options_require_user_verification():
    options = generate_authentication_options_json(
        rp_id="localhost",
        challenge="dGVzdC1jaGFsbGVuZ2U",
        credential_ids=["Y3JlZGVudGlhbC0x"],
    )
    assert options["challenge"] == "dGVzdC1jaGFsbGVuZ2U"
    assert options["rpId"] == "localhost"
    assert options["allowCredentials"][0]["id"] == "Y3JlZGVudGlhbC0x"
    assert options["userVerification"] == "required"


@pytest.mark.parametrize(
    "verifier",
    [
        lambda: verify_registration(
            credential={"id": "fake", "type": "public-key", "response": {}},
            challenge="dGVzdC1jaGFsbGVuZ2U",
            expected_origin="https://meika.example.com",
            expected_rp_id="meika.example.com",
        ),
        lambda: verify_authentication(
            credential={"id": "fake", "type": "public-key", "response": {}},
            challenge="dGVzdC1jaGFsbGVuZ2U",
            expected_origin="https://meika.example.com",
            expected_rp_id="meika.example.com",
            credential_public_key="cHVibGljLWtleQ",
            current_sign_count=0,
        ),
    ],
)
def test_invalid_credential_payloads_fail_closed(verifier):
    with pytest.raises(FIDO2VerificationError):
        verifier()



def test_enrollment_token_is_short_lived_and_purpose_scoped():
    token = issue_enrollment_token("user-123")
    claims = verify_enrollment_token(token)
    assert claims["sub"] == "user-123"
    assert claims["purpose"] == "webauthn-enroll"
    assert claims["jti"]


def test_access_token_cannot_be_used_as_enrollment_token():
    import jwt
    from datetime import datetime, timezone, timedelta
    from app.security.tokens.config import TokenConfig

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": TokenConfig.ISSUER,
            "aud": TokenConfig.AUDIENCE,
            "sub": "user-123",
            "purpose": "access",
            "jti": "access-token",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        TokenConfig.SECRET_KEY,
        algorithm=TokenConfig.ALGORITHM,
    )
    with pytest.raises(FIDO2VerificationError, match="Invalid enrollment authorization"):
        verify_enrollment_token(token)
