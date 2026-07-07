from app.db.models import User
from app.security.device.registry import DeviceRegistry


def create_user(db_session):

    user = User(
        email="registry@example.com",
        display_name="Registry Test",
        status="ACTIVE",
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


def test_register_and_lookup_success(db_session):

    user = create_user(db_session)

    registry = DeviceRegistry()

    device = registry.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device-1",
        device_name="Pixel 9",
        device_type="phone",
        hardware_backed=True,
        attestation_verified=True,
    )

    assert device is not None

    assert registry.is_registered(
        db=db_session,
        device_identifier="device-1",
    ) is True


def test_lookup_unknown_device(db_session):

    registry = DeviceRegistry()

    assert registry.is_registered(
        db=db_session,
        device_identifier="missing-device",
    ) is False


def test_get_by_identifier(db_session):

    user = create_user(db_session)

    registry = DeviceRegistry()

    registry.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device-2",
        device_name="MacBook",
        device_type="laptop",
    )

    device = registry.get_by_identifier(
        db=db_session,
        device_identifier="device-2",
    )

    assert device is not None
    assert device.device_identifier == "device-2"