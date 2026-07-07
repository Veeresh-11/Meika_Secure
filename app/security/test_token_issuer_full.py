import hashlib
import jwt

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