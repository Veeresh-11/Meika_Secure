from datetime import datetime, timedelta
import uuid

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Integer,
    ForeignKey,
    Enum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.schema import Index

from app.db.models import Base


class Grant(Base):
    """
    Persistent authorization grant.

    A Grant is the authoritative server-side authorization object.
    JWTs are signed representations of Grants.

    Future layers:
        • Session Guardian
        • Meika Intelligence System (MIS)
        • Enterprise Federation
    """

    __tablename__ = "grants"
    __table_args__ = (
        Index("ix_grants_user_id", "user_id"),
        Index("ix_grants_device_id", "device_id"),
        Index("ix_grants_session_id", "session_id"),
        Index("ix_grants_jwt_id", "jwt_id"),
        {"schema": "identity"}
    )

    #
    # Identity
    #

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

    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.sessions.id"),
        nullable=False,
    )

    credential_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.webauthn_credentials.id"),
        nullable=False,
    )

    #
    # Authorization
    #

    grant_type = Column(
        String,
        nullable=False,
        default="access",
    )

    grant_version = Column(
        Integer,
        nullable=False,
        default=1,
    )

    jwt_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        default=uuid.uuid4,
    )

    #
    # Runtime Security
    #

    risk_level = Column(
        Enum("LOW", "MEDIUM", "HIGH","CRITICAL", name="risk_level", schema="identity"),
        nullable=False,
        default="LOW",
    )

    guardian_state = Column(
        Enum("WATCHING", "OBSERVING", "ALERT","CONTAINMENT","TERMINATED", name="guardian_state" , schema="identity"),
        nullable=False,
        default="WATCHING",
    )

    #
    # Device Context
    #

    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.devices.id"),
        nullable=False,
    )

    ip_address = Column(
        String,
        nullable=True,
    )

    #
    # Audit
    #

    created_by = Column(
        String,
        nullable=False,
        default="webauthn",
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    issued_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    expires_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.utcnow() + timedelta(hours=1),
    )

    last_used_at = Column(
        DateTime,
        nullable=True,
    )

    last_used_ip = Column(
        String,
        nullable=True,
    )

    #
    # Revocation
    #

    revoked = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    revoked_at = Column(
        DateTime,
        nullable=True,
    )

    revocation_reason = Column(
        String,
        nullable=True,
    )