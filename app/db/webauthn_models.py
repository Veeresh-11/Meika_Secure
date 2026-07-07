from datetime import datetime, timedelta
import uuid

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Integer,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID

from app.db.models import Base


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"
    __table_args__ = {"schema": "identity"}

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

    challenge = Column(
        String,
        nullable=False,
        unique=True,
    )

    purpose = Column(
        String,
        nullable=False,
    )

    used = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    expires_at = Column(
        DateTime,
        default=lambda: datetime.utcnow() + timedelta(minutes=5),
    )


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"
    __table_args__ = {"schema": "identity"}

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

    credential_id = Column(
        String,
        unique=True,
        nullable=False,
    )
    
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.devices.id"),
        nullable=False,
    )

    public_key = Column(
        String,
        nullable=False,
    )

    sign_count = Column(
        Integer,
        default=0,
        nullable=False,
    )

    hardware_backed = Column(
        Boolean,
        default=True,
    )

    attestation_verified = Column(
        Boolean,
        default=True,
    )

    attestation_type = Column(
        String,
        nullable=False,
    )

    revoked = Column(
        Boolean,
        default=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    last_used_at = Column(
        DateTime,
        default=datetime.utcnow,
    )