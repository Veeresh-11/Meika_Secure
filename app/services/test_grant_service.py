
from unittest.mock import MagicMock
from app.services.grant_service import GrantService


def test_create_grant():

    db = MagicMock()

    grant = GrantService.create(
        db=db,
        user_id=123,
        device_id=456,
        session_id="session-789",
        credential_id="credential-abc",
        jwt_id="jwt-xyz",
    )

    assert grant.user_id == 123
    assert grant.device_id == 456
    assert grant.session_id == "session-789"
    assert grant.credential_id == "credential-abc"
    assert grant.jwt_id == "jwt-xyz"
    assert grant.grant_type == "access"
    assert grant.created_by == "webauthn"
    assert grant.revoked is False

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_get_grant():

    db = MagicMock()

    grant = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = grant

    result = GrantService.get(
        db=db,
        grant_id=1,
    )

    assert result == grant
    
def test_revoke_grant():

    db = MagicMock()

    grant = MagicMock()

    grant.revoked = False

    GrantService.revoke(
        db=db,
        grant=grant,
        reason="logout",
    )

    assert grant.revoked is True
    assert grant.revoked_at is not None
    assert grant.revocation_reason == "logout"

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_touch_grant():

    db = MagicMock()

    grant = MagicMock()

    grant.last_used_at = None
    grant.last_used_ip = None

    GrantService.touch(
        db=db,
        grant=grant,
        ip_address="127.0.0.1",
    )

    assert grant.last_used_at is not None
    assert grant.last_used_ip == "127.0.0.1"

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke_all_user_grants():

    db = MagicMock()

    grant1 = MagicMock(revoked=False)
    grant2 = MagicMock(revoked=False)

    db.query.return_value.filter.return_value.all.return_value = [
        grant1,
        grant2,
    ]

    count = GrantService.revoke_all_for_user(
        db=db,
        user_id=123,
        reason="Bulk revocation",
    )

    assert count == 2

    assert grant1.revoked is True
    assert grant2.revoked is True

    assert grant1.revoked_at is not None
    assert grant2.revoked_at is not None

    assert grant1.revocation_reason == "Bulk revocation"
    assert grant2.revocation_reason == "Bulk revocation"

    db.commit.assert_called_once()