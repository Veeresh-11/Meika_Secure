import pytest

jwt = pytest.importorskip("jwt")
pytestmark = [
    pytest.mark.track_b,
    pytest.mark.kernel,
]

from app.security.tokens.issuer import issue_device_bound_token
from app.security.tokens.enforce import enforce_device_bound_token

def test_token_replay_on_other_device_fails():
    token = issue_device_bound_token(
        user_id="u1",
        device_id="d1",
        device_public_key=b"device-A",
    )

    with pytest.raises(Exception):
        enforce_device_bound_token(
            token=token,
            device_public_key=b"device-B",
        )
