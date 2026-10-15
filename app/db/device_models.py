from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
)
from sqlalchemy.dialects.postgresql import UUID

from app.db.models import Base


class Device(Base):
    """
    Persistent registered device.

    A Device represents the physical or logical endpoint
    owned by a user.

    Sessions and Credentials attach to Devices.
    """

    __tablename__ = "devices"

    __table_args__ = (
        Index("ix_devices_user_id", "user_id"),
        Index("ix_devices_tenant_id", "tenant_id"),
        Index("ix_devices_identifier", "device_identifier"),
        {"schema": "identity"},
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )

    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.organizations.id"),
        nullable=False,
    )

    #
    # Stable identifier supplied by registration
    #
    device_identifier = Column(
        String,
        nullable=False,
        unique=True,
    )

    #
    # Human-readable name
    #
    device_name = Column(
        String,
        nullable=False,
    )

    #
    # laptop
    # mobile
    # tablet
    # security-key
    #
    device_type = Column(
        String,
        nullable=False,
        default="unknown",
    )

    #
    # Hardware trust
    #
    hardware_backed = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    attestation_verified = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    #
    # Runtime trust
    #
    trust_level = Column(
        String,
        nullable=False,
        default="UNKNOWN",
    )

    #
    # ACTIVE
    # REVOKED
    # SUSPENDED
    # QUARANTINED
    #
    state = Column(
        String,
        nullable=False,
        default="ACTIVE",
    )

    registered_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    last_seen = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    last_attested_at = Column(
        DateTime,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )