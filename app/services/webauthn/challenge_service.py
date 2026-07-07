from datetime import datetime

from sqlalchemy.orm import Session

from app.db.webauthn_models import WebAuthnChallenge
from app.security.webauthn.challenge import generate_challenge


class ChallengeService:

    @staticmethod
    def create(
        db: Session,
        *,
        user_id,
        purpose: str,
    ) -> WebAuthnChallenge:

        challenge = generate_challenge()

        record = WebAuthnChallenge(
            user_id=user_id,
            challenge=challenge,
            purpose=purpose,
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return record

    @staticmethod
    def get(
        db: Session,
        *,
        challenge: str,
    ) -> WebAuthnChallenge | None:

        return (
            db.query(WebAuthnChallenge)
            .filter(
                WebAuthnChallenge.challenge == challenge
            )
            .first()
        )

    @staticmethod
    def validate(
        challenge: WebAuthnChallenge,
    ):

        if challenge is None:
            raise ValueError("Challenge not found")

        if challenge.used:
            raise ValueError("Challenge already used")

        if challenge.expires_at < datetime.utcnow():
            raise ValueError("Challenge expired")

    @staticmethod
    def consume(
        db: Session,
        challenge: WebAuthnChallenge,
    ):

        challenge.used = True

        db.commit()

    @staticmethod
    def cleanup(
        db: Session,
    ):

        db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.expires_at < datetime.utcnow()
        ).delete()

        db.commit()