from datetime import datetime

from sqlalchemy.orm import Session

from app.db.device_models import Device

from app.security.device.constants import (
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_SUSPENDED,
    DEVICE_STATE_QUARANTINED,
    DEVICE_STATE_REVOKED,
    TRUST_UNKNOWN,
    TRUST_LOW,
    TRUST_MEDIUM,
    TRUST_HIGH,
    TRUST_CRITICAL,
)


VALID_STATES = {
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_SUSPENDED,
    DEVICE_STATE_QUARANTINED,
    DEVICE_STATE_REVOKED,
}

VALID_TRUST = {
    TRUST_UNKNOWN,
    TRUST_LOW,
    TRUST_MEDIUM,
    TRUST_HIGH,
    TRUST_CRITICAL,
}


class DeviceService:
    """
    Persistent Device lifecycle.

    A Device represents a physical endpoint.

    Future consumers:

        • Device Trust Engine
        • Session Guardian
        • MIS
    """

    @staticmethod
    def register(
        db: Session,
        *,
        user_id,
        device_identifier: str,
        device_name: str,
        device_type: str = "unknown",
        hardware_backed: bool = False,
        attestation_verified: bool = False,
    ) -> Device:

        now = datetime.utcnow()

        device = Device(
            user_id=user_id,
            device_identifier=device_identifier,
            device_name=device_name,
            device_type=device_type,
            hardware_backed=hardware_backed,
            attestation_verified=attestation_verified,
            trust_level=TRUST_LOW,
            state=DEVICE_STATE_ACTIVE,
            registered_at=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )

        db.add(device)
        db.commit()
        db.refresh(device)

        return device

    @staticmethod
    def get(
        db: Session,
        *,
        device_id,
    ) -> Device | None:

        return (
            db.query(Device)
            .filter(Device.id == device_id)
            .first()
        )

    @staticmethod
    def get_by_identifier(
        db: Session,
        *,
        device_identifier: str,
    ) -> Device | None:

        return (
            db.query(Device)
            .filter(
                Device.device_identifier == device_identifier
            )
            .first()
        )

    @staticmethod
    def touch(
        db: Session,
        *,
        device: Device,
    ) -> Device:

        device.last_seen = datetime.utcnow()
        device.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(device)

        return device

    @staticmethod
    def update_trust(
        db: Session,
        *,
        device: Device,
        trust_level: str,
    ) -> Device:

        if trust_level not in VALID_TRUST:
            raise ValueError(
                f"Invalid trust level: {trust_level}"
            )

        device.trust_level = trust_level
        device.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(device)

        return device

    @staticmethod
    def update_state(
        db: Session,
        *,
        device: Device,
        state: str,
    ) -> Device:

        if state not in VALID_STATES:
            raise ValueError(
                f"Invalid device state: {state}"
            )

        device.state = state
        device.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(device)

        return device

    @staticmethod
    def revoke(
        db: Session,
        *,
        device: Device,
    ) -> Device:

        device.state = DEVICE_STATE_REVOKED
        device.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(device)

        return device