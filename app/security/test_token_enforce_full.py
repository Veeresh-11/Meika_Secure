import hashlib
from datetime import datetime, timedelta

import jwt
import pytest

from app.security.tokens.enforce import (
    enforce_device_bound_token,
    SECRET,
    ALGO,
)

from app.security.errors import SecurityError


DEVICE_KEY = b"device-public-key"


def make_token(dkh, exp=None):

    payload = {
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
        datetime.utcnow() + timedelta(minutes=5),
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
        datetime.utcnow() - timedelta(minutes=5),
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
        datetime.utcnow() + timedelta(minutes=5),
    )

    with pytest.raises(
        SecurityError,
        match="Token not bound to this device",
    ):
        enforce_device_bound_token(
            token,
            DEVICE_KEY,
        )