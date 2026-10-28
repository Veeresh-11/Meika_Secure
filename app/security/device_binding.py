"""Resolve a JWT's device binding against persisted, tenant-scoped credentials.

JWT claims are treated as untrusted lookup hints until signature, issuer,
audience, expiry and device-key binding are verified by enforce_device_bound_token.
"""
from dataclasses import dataclass
from uuid import UUID

import jwt

from app.db.device_models import Device
from app.db.models import User
from app.db.session import SessionLocal
from app.db.webauthn_models import WebAuthnCredential
from app.security.device.constants import DEVICE_STATE_ACTIVE
from app.security.device_snapshot import DeviceSnapshot
from app.security.errors import SecurityError
from app.security.tokens.enforce import enforce_device_bound_token


@dataclass(frozen=True)
class ResolvedDeviceBinding:
    payload: dict
    device: DeviceSnapshot


def resolve_registered_device_binding(
    *,
    token: str,
    requested_device_identifier: str,
) -> ResolvedDeviceBinding:
    """Resolve and verify a token against an active registered device credential.

    The request header is only a selector, never a source of key material.
    """
    if not isinstance(token, str) or not token:
        raise SecurityError("Invalid token")
    if not isinstance(requested_device_identifier, str) or not requested_device_identifier:
        raise SecurityError("Missing device identity")

    try:
        # Unverified claims are used only to narrow the database lookup. No
        # authorization decision is made until enforce_device_bound_token passes.
        unverified = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        user_id = UUID(unverified["sub"])
        device_id = UUID(unverified["did"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError, AttributeError):
        raise SecurityError("Invalid token") from None

    with SessionLocal() as db:
        rows = (
            db.query(WebAuthnCredential, Device)
            .join(Device, Device.id == WebAuthnCredential.device_id)
            .join(User, User.id == WebAuthnCredential.user_id)
            .filter(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.device_id == device_id,
                WebAuthnCredential.tenant_id == User.tenant_id,
                WebAuthnCredential.tenant_id == Device.tenant_id,
                WebAuthnCredential.revoked.is_(False),
                Device.user_id == user_id,
                Device.state == DEVICE_STATE_ACTIVE,
                User.status == "active",
            )
            .all()
        )

        for credential, registered_device in rows:
            if requested_device_identifier not in {
                str(registered_device.id),
                registered_device.device_identifier,
            }:
                continue

            public_key = credential.public_key
            if not isinstance(public_key, str) or not public_key:
                continue

            try:
                payload = enforce_device_bound_token(
                    token=token,
                    device_public_key=public_key.encode("utf-8"),
                )
            except SecurityError:
                # Another credential may belong to the same device. Continue
                # only through persisted active credentials for this exact
                # user/device/tenant tuple.
                continue

            if payload.get("sub") != str(user_id) or payload.get("did") != str(device_id):
                continue

            return ResolvedDeviceBinding(
                payload=payload,
                device=DeviceSnapshot(
                    device_id=str(registered_device.id),
                    registered=True,
                    state=str(registered_device.state).lower(),
                    hardware_backed=bool(credential.hardware_backed),
                    attestation_verified=bool(credential.attestation_verified),
                    binding_valid=True,
                    # The schema has no verified secure-boot measurement;
                    # do not assert secure boot without evidence.
                    secure_boot=False,
                ),
            )

    raise SecurityError("Token not bound to an active registered device")
