from sqlalchemy.orm import Session

from app.services.device_service import DeviceService


class DeviceRegistry:
    """
    Database-backed device registry.

    This registry is intentionally stateless. It delegates all
    persistence operations to DeviceService while preserving the
    interface used throughout the security pipeline.

    A SQLAlchemy Session is passed into each method rather than
    stored on the registry instance. This keeps the registry
    compatible with FastAPI's request-scoped dependency injection
    and avoids stale database sessions.
    """

    def register(
        self,
        db: Session,
        *,
        user_id,
        device_identifier: str,
        device_name: str,
        device_type: str = "unknown",
        hardware_backed: bool = False,
        attestation_verified: bool = False,
    ):
        return DeviceService.register(
            db=db,
            user_id=user_id,
            device_identifier=device_identifier,
            device_name=device_name,
            device_type=device_type,
            hardware_backed=hardware_backed,
            attestation_verified=attestation_verified,
        )

    def get(
        self,
        db: Session,
        *,
        device_id,
    ):
        return DeviceService.get(
            db=db,
            device_id=device_id,
        )

    def get_by_identifier(
        self,
        db: Session,
        *,
        device_identifier: str,
    ):
        return DeviceService.get_by_identifier(
            db=db,
            device_identifier=device_identifier,
        )

    def is_registered(
        self,
        db: Session,
        *,
        device_identifier: str,
    ) -> bool:
        return (
            DeviceService.get_by_identifier(
                db=db,
                device_identifier=device_identifier,
            )
            is not None
        )