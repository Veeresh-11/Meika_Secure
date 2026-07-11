import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock
from app.services.session_service import SessionService

def test_validate_missing():
    with pytest.raises(ValueError, match="Session not found"):
        SessionService.validate(None)


def test_validate_revoked():
    session = MagicMock(
        revoked=True,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    with pytest.raises(ValueError, match="revoked"):
        SessionService.validate(session)


def test_validate_expired():
    session = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="expired"):
        SessionService.validate(session)


def test_validate_success():
    session = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    SessionService.validate(session)
    
def test_touch():
    db = MagicMock()

    session = MagicMock()

    SessionService.touch(
        db=db,
        session=session,
    )

    assert session.last_seen is not None

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke():
    db = MagicMock()

    session = MagicMock(revoked=False)

    SessionService.revoke(
        db=db,
        session=session,
    )

    assert session.revoked is True

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke_all_user_sessions():
    db = MagicMock()

    s1 = MagicMock(revoked=False)
    s2 = MagicMock(revoked=False)

    db.query.return_value.filter.return_value.all.return_value = [
        s1,
        s2,
    ]

    count = SessionService.revoke_all_user_sessions(
        db=db,
        user_id=1,
    )

    assert count == 2

    assert s1.revoked
    assert s2.revoked

    db.commit.assert_called_once()
    
def test_cleanup():
    db = MagicMock()

    s1 = MagicMock(revoked=False)
    s2 = MagicMock(revoked=False)

    db.query.return_value.filter.return_value.all.return_value = [
        s1,
        s2,
    ]

    count = SessionService.cleanup(db)

    assert count == 2

    assert s1.revoked
    assert s2.revoked

    db.commit.assert_called_once()
    
def test_create():
    db = MagicMock()

    session = SessionService.create(
        db=db,
        user_id=1,
        device_id=2,
    )

    assert session.user_id == 1
    assert session.device_id == 2
    assert session.revoked is False
    assert session.last_seen is not None
    assert session.issued_at is not None
    assert session.expires_at is not None

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_get():
    db = MagicMock()

    fake = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = fake

    result = SessionService.get(
        db=db,
        session_id=123,
    )

    assert result is fake
