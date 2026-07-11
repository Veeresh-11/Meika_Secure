from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.services.webauthn.challenge_service import ChallengeService


def test_validate_missing():
    with pytest.raises(ValueError, match="Challenge not found"):
        ChallengeService.validate(None)


def test_validate_used():
    challenge = MagicMock(
        used=True,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )

    with pytest.raises(ValueError, match="already used"):
        ChallengeService.validate(challenge)


def test_validate_expired():
    challenge = MagicMock(
        used=False,
        expires_at=datetime.utcnow() - timedelta(minutes=1),
    )

    with pytest.raises(ValueError, match="expired"):
        ChallengeService.validate(challenge)


def test_validate_success():
    challenge = MagicMock(
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )

    ChallengeService.validate(challenge)
    
def test_consume():
    db = MagicMock()

    challenge = MagicMock()
    challenge.used = False

    ChallengeService.consume(
        db=db,
        challenge=challenge,
    )

    assert challenge.used is True
    db.commit.assert_called_once()
    
def test_cleanup():
    db = MagicMock()

    ChallengeService.cleanup(db)

    db.query.return_value.filter.return_value.delete.assert_called_once()
    db.commit.assert_called_once()
    
def test_create():

    db = MagicMock()

    record = MagicMock()

    with patch(
        "app.services.webauthn.challenge_service.generate_challenge",
        return_value="challenge-123",
    ):
        with patch(
            "app.services.webauthn.challenge_service.WebAuthnChallenge",
            return_value=record,
        ) as model:

            result = ChallengeService.create(
                db=db,
                user_id="user-1",
                purpose="register",
            )

    assert result is record

    model.assert_called_once_with(
        user_id="user-1",
        challenge="challenge-123",
        purpose="register",
    )

    db.add.assert_called_once_with(record)
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(record)