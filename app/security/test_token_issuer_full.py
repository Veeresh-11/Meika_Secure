import hashlib
import jwt
from unittest.mock import patch

from app.security.tokens.issuer import (
    hash_public_key,
    issue_device_bound_token,
    SECRET,
    ALGO,
)


DEVICE_KEY = b"device-public-key"


def test_hash_public_key():

    expected = hashlib.sha256(
        DEVICE_KEY
    ).hexdigest()

    assert (
        hash_public_key(DEVICE_KEY)
        == expected
    )


def test_issue_device_bound_token():

    token = issue_device_bound_token(
        user_id="user1",
        device_id="dev1",
        device_public_key=DEVICE_KEY,
        ttl_minutes=5,
    )

    payload = jwt.decode(
        token,
        SECRET,
        algorithms=[ALGO],
        audience="meika-api",
    )

    assert payload["sub"] == "user1"
    assert payload["did"] == "dev1"

    assert payload["dkh"] == hashlib.sha256(
        DEVICE_KEY
    ).hexdigest()

    assert "exp" in payload
    
def test_issue_token_without_optional_claims():

    with patch(
        "app.security.tokens.issuer.jwt.encode",
        return_value="token",
    ) as encode:

        issue_device_bound_token(
            user_id="user",
            device_id="device",
            device_public_key=b"pk",
            session_id=None,
            jwt_id=None,
        )

    payload = encode.call_args.args[0]

    assert "sid" not in payload
    assert "jti" not in payload
    

def test_issue_token_with_session_and_jwt_id():

    with patch(
        "app.security.tokens.issuer.jwt.encode",
        return_value="token",
    ) as encode:

        token = issue_device_bound_token(
            user_id="user-123",
            device_id="device-123",
            device_public_key=b"public-key",
            session_id="session-123",
            jwt_id="jwt-123",
        )

    assert token == "token"

    payload = encode.call_args.args[0]

    assert payload["sid"] == "session-123"
    assert payload["jti"] == "jwt-123"