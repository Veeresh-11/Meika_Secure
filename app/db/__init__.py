"""
Import every ORM model so SQLAlchemy registers them
with the shared Base.metadata.
"""

from app.db.models import Base

# Core models
from app.db.models import User, Credential, Session, AuditLog

# Device
from app.db.device_models import Device

# Grants
from app.db.grant_models import Grant

# WebAuthn
from app.db.webauthn_models import (
    WebAuthnChallenge,
    WebAuthnCredential,
)

__all__ = [
    "Base",
    "User",
    "Credential",
    "Session",
    "AuditLog",
    "Device",
    "Grant",
    "WebAuthnChallenge",
    "WebAuthnCredential",
]