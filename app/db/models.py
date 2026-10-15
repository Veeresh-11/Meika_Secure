from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# ==========================================================
# Organization / Tenant
# ==========================================================

class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = {"schema": "identity"}

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="ACTIVE")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)


# ==========================================================
# User — tenant-scoped identity record
# ==========================================================

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="users_tenant_email_key"),
        Index("ix_users_tenant_id", "tenant_id"),
        {"schema": "identity"},
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.organizations.id"),
        nullable=False,
    )

    email = Column(
        String,
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
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
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
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
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
        Index("ix_sessions_tenant_id", "tenant_id"),
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

    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.devices.id"),
        nullable=True,
    )

    issued_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
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
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )


# ==========================================================
# Audit Log
# ==========================================================

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_id", "tenant_id"),
        {"schema": "identity"},
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("identity.organizations.id"),
        nullable=False,
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
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )