"""Production FIDO2/WebAuthn primitives backed by py_webauthn.

These functions verify browser-provided ceremony responses cryptographically.
They deliberately do not accept client-supplied trust booleans.
"""
from __future__ import annotations

import json
from typing import Any, Sequence

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)


class FIDO2VerificationError(ValueError):
    """A WebAuthn ceremony failed cryptographic or origin/RP validation."""


def _options_dict(options: Any) -> dict[str, Any]:
    return json.loads(options_to_json(options))


def generate_registration_options_json(
    *,
    rp_id: str,
    rp_name: str,
    user_id: bytes,
    user_name: str,
    challenge: str,
    exclude_credential_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Create standards-compliant PublicKeyCredentialCreationOptions."""
    try:
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_name,
            challenge=base64url_to_bytes(challenge),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(value))
                for value in exclude_credential_ids
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return _options_dict(options)
    except Exception as exc:
        raise FIDO2VerificationError("Unable to generate WebAuthn registration options") from exc


def verify_registration(
    *,
    credential: dict[str, Any],
    challenge: str,
    expected_origin: str | Sequence[str],
    expected_rp_id: str,
) -> dict[str, Any]:
    """Cryptographically verify a navigator.credentials.create() response."""
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_origin=list(expected_origin) if not isinstance(expected_origin, str) else expected_origin,
            expected_rp_id=expected_rp_id,
            require_user_verification=True,
        )
    except Exception as exc:
        raise FIDO2VerificationError("WebAuthn registration verification failed") from exc

    from webauthn.helpers import bytes_to_base64url

    return {
        "credential_id": bytes_to_base64url(verified.credential_id),
        "public_key": bytes_to_base64url(verified.credential_public_key),
        "sign_count": verified.sign_count,
        "attestation_type": verified.fmt,
        "hardware_backed": False,
        "attestation_verified": True,
    }


def generate_authentication_options_json(
    *,
    rp_id: str,
    challenge: str,
    credential_ids: Sequence[str],
) -> dict[str, Any]:
    """Create standards-compliant PublicKeyCredentialRequestOptions."""
    try:
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=base64url_to_bytes(challenge),
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(value))
                for value in credential_ids
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return _options_dict(options)
    except Exception as exc:
        raise FIDO2VerificationError("Unable to generate WebAuthn authentication options") from exc


def verify_authentication(
    *,
    credential: dict[str, Any],
    challenge: str,
    expected_origin: str | Sequence[str],
    expected_rp_id: str,
    credential_public_key: str,
    current_sign_count: int,
) -> dict[str, Any]:
    """Cryptographically verify a navigator.credentials.get() response."""
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_origin=list(expected_origin) if not isinstance(expected_origin, str) else expected_origin,
            expected_rp_id=expected_rp_id,
            credential_public_key=base64url_to_bytes(credential_public_key),
            credential_current_sign_count=current_sign_count,
            require_user_verification=True,
        )
    except Exception as exc:
        raise FIDO2VerificationError("WebAuthn authentication verification failed") from exc

    return {
        "credential_id": verified.credential_id,
        "new_sign_count": verified.new_sign_count,
        "user_verified": verified.user_verified,
        "credential_device_type": str(verified.credential_device_type),
        "credential_backed_up": verified.credential_backed_up,
    }
