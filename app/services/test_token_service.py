from types import SimpleNamespace
from unittest.mock import patch

from app.services.token_service import TokenService


def test_issue_access_token():

    grant = SimpleNamespace(
        user_id="user-123",
        session_id="session-456",
        device_id="device-789",
        jwt_id="jwt-abc",
    )

    with patch(
        "app.services.token_service.GrantService.validate"
    ) as validate, patch(
        "app.services.token_service.issue_device_bound_token",
        return_value="jwt-token",
    ) as issuer:

        token = TokenService.issue_access_token(
            grant=grant,
            device_public_key=b"public-key",
        )

    assert token == "jwt-token"

    validate.assert_called_once_with(grant)

    issuer.assert_called_once()

    kwargs = issuer.call_args.kwargs

    assert kwargs["user_id"] == "user-123"
    assert kwargs["session_id"] == "session-456"
    assert kwargs["device_id"] == "device-789"
    assert kwargs["device_public_key"] == b"public-key"
    assert kwargs["jwt_id"] == "jwt-abc"