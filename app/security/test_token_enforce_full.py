import hashlib
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.security.tokens.enforce import (
    enforce_device_bound_token,
    SECRET,
    ALGO,
)
from app.security.tokens.issuer import issue_device_bound_token
from app.security.errors import SecurityError
from app.security.tokens.config import TokenConfig


DEVICE_KEY = b"device-public-key"


def make_token(dkh, exp=None):

    payload = {
        "iss": TokenConfig.ISSUER,
        "aud": TokenConfig.AUDIENCE,
        "sub": "user1",
        "dkh": dkh,
    }

    if exp is not None:
        payload["exp"] = exp

    return jwt.encode(
        payload,
        SECRET,
        algorithm=ALGO,
    )


def test_valid_device_bound_token():

    dkh = hashlib.sha256(
        DEVICE_KEY
    ).hexdigest()

    token = make_token(
        dkh,
        datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
    )

    payload = enforce_device_bound_token(
        token,
        DEVICE_KEY,
    )

    assert payload["sub"] == "user1"


def test_expired_token():

    dkh = hashlib.sha256(
        DEVICE_KEY
    ).hexdigest()

    token = make_token(
        dkh,
        datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5),
    )

    with pytest.raises(SecurityError, match="Token expired"):
        enforce_device_bound_token(
            token,
            DEVICE_KEY,
        )


def test_invalid_token():

    with pytest.raises(SecurityError, match="Invalid token"):
        enforce_device_bound_token(
            "not-a-jwt",
            DEVICE_KEY,
        )


def test_wrong_device_binding():

    token = make_token(
        "wrong-device-hash",
        datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
    )

    with pytest.raises(
        SecurityError,
        match="Token not bound to this device",
    ):
        enforce_device_bound_token(
            token,
            DEVICE_KEY,
        )
        
def test_invalid_issuer():

    token = issue_device_bound_token(
        user_id="user",
        device_id="device",
        device_public_key=b"pk",
    )

    payload = jwt.decode(
        token,
        SECRET,
        algorithms=[ALGO],
        options={
            "verify_signature": True,
            "verify_aud": False,
            "verify_iss": False,
        },
    )

    payload["iss"] = "evil"

    bad = jwt.encode(
        payload,
        SECRET,
        algorithm=ALGO,
    )

    with pytest.raises(SecurityError, match="Invalid issuer"):
        enforce_device_bound_token(
            bad,
            b"pk",
        )

def test_invalid_audience():

    token = issue_device_bound_token(
        user_id="user",
        device_id="device",
        device_public_key=b"pk",
    )

    payload = jwt.decode(
        token,
        SECRET,
        algorithms=[ALGO],
        options={
            "verify_signature": True,
            "verify_aud": False,
            "verify_iss": False,
        },
    )

    payload["aud"] = "evil-api"

    bad = jwt.encode(
        payload,
        SECRET,
        algorithm=ALGO,
    )

    with pytest.raises(SecurityError, match="Invalid audience"):
        enforce_device_bound_token(
            bad,
            b"pk",
        )

@pytest.mark.parametrize(
    ("missing_claim", "expected_error"),
    [
        ("iss", "Invalid issuer"),
        ("aud", "Invalid audience"),
    ],
)
def test_missing_issuer_or_audience_is_rejected(missing_claim, expected_error):
    payload = {
        "iss": TokenConfig.ISSUER,
        "aud": TokenConfig.AUDIENCE,
        "sub": "user1",
        "dkh": hashlib.sha256(DEVICE_KEY).hexdigest(),
        "exp": datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
    }
    payload.pop(missing_claim)
    token = jwt.encode(payload, SECRET, algorithm=ALGO)

    with pytest.raises(SecurityError, match=expected_error):
        enforce_device_bound_token(token, DEVICE_KEY)

