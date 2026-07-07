from sqlalchemy import Column, String, Boolean, DateTime
from app.db.models import Credential
import uuid
from datetime import datetime

class WebAuthnChallenge(Credential):
    __tablename__ = "webauthn_challenges"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    user_id = Column(String, nullable=False)

    challenge = Column(String, nullable=False, unique=True)

    purpose = Column(String, nullable=False)

    used = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    expires_at = Column(DateTime, nullable=False)