"""Resolve JWT device bindings against persisted, tenant-scoped credentials.

The token is verified against candidate registered credentials; unverified claims
are never used to choose a principal or device.
"""
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import or_

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

    The request header selects candidate device records but is never key material.
    """
    if not isinstance(token, str) or not token:
        raise SecurityError("Invalid token")
    if (
        not isinstance(requested_device_identifier, str)
        or not requested_device_identifier
    ):
        raise SecurityError("Missing device identity")

    # The request identifier is only a selector. Do not decode an unverified JWT
    # to discover the user/device; verify it against active registered keys first.
    device_predicates = [
        Device.device_identifier == requested_device_identifier,
    ]
    try:
        requested_device_uuid = UUID(requested_device_identifier)
    except (TypeError, ValueError, AttributeError):
        requested_device_uuid = None
    if requested_device_uuid is not None:
        device_predicates.append(Device.id == requested_device_uuid)

    with SessionLocal() as db:
        rows = (
            db.query(WebAuthnCredential, Device)
            .join(Device, Device.id == WebAuthnCredential.device_id)
            .join(User, User.id == WebAuthnCredential.user_id)
            .filter(
                or_(*device_predicates),
                WebAuthnCredential.tenant_id == User.tenant_id,
                WebAuthnCredential.tenant_id == Device.tenant_id,
                WebAuthnCredential.revoked.is_(False),
                Device.user_id == WebAuthnCredential.user_id,
                Device.state == DEVICE_STATE_ACTIVE,
                User.status == "active",
            )
            .all()
        )

        for credential, registered_device in rows:
            public_key = credential.public_key
            if not isinstance(public_key, str) or not public_key:
                continue

            try:
                payload = enforce_device_bound_token(
                    token=token,
                    device_public_key=public_key.encode("utf-8"),
                )
            except SecurityError:
                # Try only other persisted active credentials for this selected
                # device. No unverified token claims are trusted for lookup.
                continue

            if (
                payload.get("sub") != str(credential.user_id)
                or payload.get("did") != str(registered_device.id)
            ):
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
                    # No verified secure-boot measurement exists in the schema.
                    secure_boot=False,
                ),
            )

    raise SecurityError("Token not bound to an active registered device")
