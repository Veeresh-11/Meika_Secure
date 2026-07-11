import pytest
from unittest.mock import MagicMock
from app.services.grant_service import GrantService
from datetime import datetime, timedelta


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
    
def test_validate_none():
    with pytest.raises(ValueError, match="Grant not found"):
        GrantService.validate(None)


def test_validate_revoked():
    grant = MagicMock(
        revoked=True,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="ACTIVE",
        risk_level="LOW",
    )

    with pytest.raises(ValueError, match="Grant revoked"):
        GrantService.validate(grant)


def test_validate_expired():
    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() - timedelta(seconds=1),
        guardian_state="ACTIVE",
        risk_level="LOW",
    )

    with pytest.raises(ValueError, match="Grant expired"):
        GrantService.validate(grant)


def test_validate_terminated():
    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="TERMINATED",
        risk_level="LOW",
    )

    with pytest.raises(ValueError, match="Session terminated"):
        GrantService.validate(grant)


def test_validate_containment():
    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="CONTAINMENT",
        risk_level="LOW",
    )

    with pytest.raises(ValueError, match="Session contained"):
        GrantService.validate(grant)


def test_validate_critical():
    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="ACTIVE",
        risk_level="CRITICAL",
    )

    with pytest.raises(ValueError, match="critical risk"):
        GrantService.validate(grant)


def test_validate_success():
    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="ACTIVE",
        risk_level="LOW",
    )

    GrantService.validate(grant)
    
def test_get_by_session():
    db = MagicMock()

    grants = [MagicMock(), MagicMock()]

    db.query.return_value.filter.return_value.all.return_value = grants

    result = GrantService.get_by_session(
        db=db,
        session_id="abc",
    )

    assert result == grants
    
def test_get_by_jwt_id():
    db = MagicMock()

    grant = MagicMock()

    db.query.return_value.filter.return_value.first.return_value = grant

    result = GrantService.get_by_jwt_id(
        db=db,
        jwt_id="jwt",
    )

    assert result is grant
    
def test_refresh():
    db = MagicMock()

    grant = MagicMock(
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        guardian_state="ACTIVE",
        risk_level="LOW",
    )

    GrantService.refresh(
        db=db,
        grant=grant,
    )

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_update_guardian_state():
    db = MagicMock()

    grant = MagicMock()

    GrantService.update_guardian_state(
        db=db,
        grant=grant,
        state="CONTAINMENT",
    )

    assert grant.guardian_state == "CONTAINMENT"

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_touch_without_ip():
    db = MagicMock()

    grant = MagicMock()
    grant.last_used_ip = None

    GrantService.touch(
        db=db,
        grant=grant,
    )

    assert grant.last_used_at is not None
    assert grant.last_used_ip is None

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke():
    db = MagicMock()

    grant = MagicMock(revoked=False)

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
    
def test_revoke_by_session():
    db = MagicMock()

    g1 = MagicMock(revoked=False)
    g2 = MagicMock(revoked=False)

    db.query.return_value.filter.return_value.all.return_value = [
        g1,
        g2,
    ]

    count = GrantService.revoke_by_session(
        db=db,
        session_id="session-1",
    )

    assert count == 2

    assert g1.revoked
    assert g2.revoked

    db.commit.assert_called_once()
    
def test_cleanup_expired():
    db = MagicMock()

    g1 = MagicMock(revoked=False)
    g2 = MagicMock(revoked=False)

    db.query.return_value.filter.return_value.all.return_value = [
        g1,
        g2,
    ]

    count = GrantService.cleanup_expired(db)

    assert count == 2

    assert g1.revoked
    assert g2.revoked

    assert g1.revocation_reason == "Grant expired"
    assert g2.revocation_reason == "Grant expired"

    db.commit.assert_called_once()
    
def test_revoke():
    db = MagicMock()

    grant = MagicMock()
    grant.revoked = False

    result = GrantService.revoke(
        db=db,
        grant=grant,
        reason="logout",
    )

    assert result is grant
    assert grant.revoked is True
    assert grant.revoked_at is not None
    assert grant.revocation_reason == "logout"

    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(grant)
    
def test_elevate_risk():

    db = MagicMock()

    grant = MagicMock()
    grant.risk_level = "LOW"

    result = GrantService.elevate_risk(
        db=db,
        grant=grant,
        risk_level="HIGH",
    )

    assert result is grant
    assert grant.risk_level == "HIGH"

    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(grant)