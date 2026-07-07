from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# ==========================================================
# User
# ==========================================================

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "identity"}

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
    )

    display_name = Column(
        String,
    )

    status = Column(
        String,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )


# ==========================================================
# Password Credentials
# ==========================================================

class Credential(Base):
    __tablename__ = "credentials"
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

    type = Column(
        String,
        nullable=False,
    )

    secret_ref = Column(
        Text,
        nullable=False,
    )

    status = Column(
        String,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    last_used_at = Column(
        DateTime,
    )


# ==========================================================
# Authentication Session
# ==========================================================

class Session(Base):
    __tablename__ = "sessions"

    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_device_id", "device_id"),
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

    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.devices.id"),
        nullable=True,
    )

    issued_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    expires_at = Column(
        DateTime,
        nullable=False,
    )

    revoked = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    last_seen = Column(
        DateTime,
        default=datetime.utcnow,
    )


# ==========================================================
# Audit Log
# ==========================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = {"schema": "identity"}

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    actor_type = Column(
        String,
        nullable=False,
    )

    actor_id = Column(
        UUID(as_uuid=True),
    )

    action = Column(
        String,
        nullable=False,
    )

    resource = Column(
        String,
        nullable=False,
    )

    ip_address = Column(
        String,
    )

    user_agent = Column(
        String,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
    )