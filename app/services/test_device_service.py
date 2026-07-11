import uuid

import pytest
from unittest.mock import MagicMock, patch

from app.db.models import User
from app.services.device_service import DeviceService

from app.security.device.constants import (
    DEVICE_STATE_REVOKED,
    TRUST_HIGH,
)

from app.security.device.constants import (
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_SUSPENDED,
    DEVICE_STATE_QUARANTINED,
    DEVICE_STATE_REVOKED,)


def create_test_user(db_session) -> User:
    """
    Create a valid user for device tests.
    """

    user = User(
        id=uuid.uuid4(),
        email=f"{uuid.uuid4()}@example.com",
        display_name="Test User",
        status="active",
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


def test_register_device(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device123",
        device_name="Pixel 9",
    )

    assert device.id is not None
    assert device.user_id == user.id
    assert device.device_identifier == "device123"


def test_get_device(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device123",
        device_name="Pixel",
    )

    loaded = DeviceService.get(
        db=db_session,
        device_id=device.id,
    )

    assert loaded is not None
    assert loaded.id == device.id


def test_get_by_identifier(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="abc",
        device_name="Laptop",
    )

    loaded = DeviceService.get_by_identifier(
        db=db_session,
        device_identifier="abc",
    )

    assert loaded is not None
    assert loaded.id == device.id


def test_touch(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="touch",
        device_name="Device",
    )

    previous = device.last_seen

    device = DeviceService.touch(
        db=db_session,
        device=device,
    )

    assert device.last_seen >= previous


def test_update_trust(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="trust",
        device_name="Device",
    )

    DeviceService.update_trust(
        db=db_session,
        device=device,
        trust_level=TRUST_HIGH,
    )

    assert device.trust_level == TRUST_HIGH


def test_update_state(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="state",
        device_name="Device",
    )

    DeviceService.revoke(
        db=db_session,
        device=device,
    )

    assert device.state == DEVICE_STATE_REVOKED


def test_invalid_state(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="badstate",
        device_name="Device",
    )

    with pytest.raises(ValueError):

        DeviceService.update_state(
            db=db_session,
            device=device,
            state="INVALID",
        )


def test_invalid_trust(db_session):

    user = create_test_user(db_session)

    device = DeviceService.register(
        db=db_session,
        user_id=user.id,
        device_identifier="badtrust",
        device_name="Device",
    )

    with pytest.raises(ValueError):

        DeviceService.update_trust(
            db=db_session,
            device=device,
            trust_level="INVALID",
        )
        
def test_update_trust_invalid():
    db = MagicMock()

    device = MagicMock()

    with pytest.raises(ValueError):
        DeviceService.update_trust(
            db=db,
            device=device,
            trust_level="INVALID",
        )
        
def test_update_state_invalid():
    db = MagicMock()

    device = MagicMock()

    with pytest.raises(ValueError):
        DeviceService.update_state(
            db=db,
            device=device,
            state="INVALID",
        )
        
def test_update_state():
    db = MagicMock()

    device = MagicMock()

    DeviceService.update_state(
        db=db,
        device=device,
        state=DEVICE_STATE_SUSPENDED,
    )

    assert device.state == DEVICE_STATE_SUSPENDED

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_update_trust():
    db = MagicMock()

    device = MagicMock()

    DeviceService.update_trust(
        db=db,
        device=device,
        trust_level=TRUST_HIGH,
    )

    assert device.trust_level == TRUST_HIGH

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
def test_revoke_device():
    db = MagicMock()

    device = MagicMock()

    DeviceService.revoke(
        db=db,
        device=device,
    )

    assert device.state == DEVICE_STATE_REVOKED
    assert device.updated_at is not None

    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    
