import uuid

import pytest

from app.db.models import User
from app.services.device_service import DeviceService

from app.security.device.constants import (
    DEVICE_STATE_REVOKED,
    TRUST_HIGH,
)


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