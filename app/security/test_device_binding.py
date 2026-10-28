import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import jwt
import pytest

from app.security.device_binding import resolve_registered_device_binding
from app.security.errors import SecurityError


def _token(user_id, device_id):
    # Ephemeral test-only key: avoid hardcoded credentials and short-key warnings.
    return jwt.encode(
        {"sub": str(user_id), "did": str(device_id)},
        secrets.token_bytes(32),
        algorithm="HS256",
    )


def _fake_database(credential, device):
    query = MagicMock()
    query.join.return_value = query
    query.filter.return_value = query
    query.all.return_value = [(credential, device)]

    db = MagicMock()
    db.query.return_value = query

    session_context = MagicMock()
    session_context.__enter__.return_value = db
    session_context.__exit__.return_value = False
    return session_context, db, query


def test_resolves_registered_key_and_returns_typed_device_snapshot():
    user_id = uuid4()
    device_id = uuid4()
    credential = SimpleNamespace(
        user_id=user_id,
        public_key="stored-public-key",
        hardware_backed=True,
        attestation_verified=True,
        revoked=False,
    )
    device = SimpleNamespace(
        id=device_id,
        device_identifier="credential-id-123",
        state="ACTIVE",
    )
    session_context, db, query = _fake_database(credential, device)
    token = _token(user_id, device_id)
    verified_payload = {"sub": str(user_id), "did": str(device_id)}

    with patch(
        "app.security.device_binding.SessionLocal",
        return_value=session_context,
    ), patch(
        "app.security.device_binding.enforce_device_bound_token",
        return_value=verified_payload,
    ) as verify:
        result = resolve_registered_device_binding(
            token=token,
            requested_device_identifier="credential-id-123",
        )

    verify.assert_called_once_with(
        token=token,
        device_public_key=b"stored-public-key",
    )
    assert result.payload == verified_payload
    assert result.device.device_id == str(device_id)
    assert result.device.registered is True
    assert result.device.binding_valid is True
    assert result.device.secure_boot is False
    query.filter.assert_called_once()
    db.close.assert_not_called()


def test_rejects_request_device_identifier_mismatch():
    user_id = uuid4()
    device_id = uuid4()
    credential = SimpleNamespace(
        user_id=user_id,
        public_key="stored-public-key",
        hardware_backed=True,
        attestation_verified=True,
        revoked=False,
    )
    device = SimpleNamespace(
        id=device_id,
        device_identifier="credential-id-123",
        state="ACTIVE",
    )
    session_context, _, _ = _fake_database(credential, device)

    with patch(
        "app.security.device_binding.SessionLocal",
        return_value=session_context,
    ), patch(
        "app.security.device_binding.enforce_device_bound_token"
    ) as verify:
        with pytest.raises(SecurityError, match="not bound"):
            resolve_registered_device_binding(
                token=_token(user_id, device_id),
                requested_device_identifier="attacker-controlled-id",
            )

    verify.assert_not_called()


def test_malformed_token_fails_closed():
    user_id = uuid4()
    device_id = uuid4()
    credential = SimpleNamespace(
        user_id=user_id,
        public_key="stored-public-key",
        hardware_backed=True,
        attestation_verified=True,
        revoked=False,
    )
    device = SimpleNamespace(
        id=device_id,
        device_identifier="credential-id-123",
        state="ACTIVE",
    )
    session_context, _, _ = _fake_database(credential, device)

    with patch(
        "app.security.device_binding.SessionLocal",
        return_value=session_context,
    ):
        with pytest.raises(SecurityError, match="not bound"):
            resolve_registered_device_binding(
                token="not-a-jwt",
                requested_device_identifier="credential-id-123",
            )
