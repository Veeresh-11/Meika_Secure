from app.db.models import User
from app.security.device.registry import DeviceRegistry


def create_user(db_session):

    user = User(
        email="registry-full@example.com",
        display_name="Registry Full Test",
        status="ACTIVE",
    )

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    return user


def test_register_and_lookup(db_session):

    user = create_user(db_session)

    registry = DeviceRegistry()

    device = registry.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device-10",
        device_name="ThinkPad",
        device_type="laptop",
    )

    loaded = registry.get(
        db=db_session,
        device_id=device.id,
    )

    assert loaded.id == device.id
    assert loaded.device_identifier == "device-10"


def test_lookup_by_identifier(db_session):

    user = create_user(db_session)

    registry = DeviceRegistry()

    registry.register(
        db=db_session,
        user_id=user.id,
        device_identifier="device-20",
        device_name="Surface",
        device_type="laptop",
    )

    device = registry.get_by_identifier(
        db=db_session,
        device_identifier="device-20",
    )

    assert device is not None
    assert device.device_name == "Surface"


def test_unknown_device(db_session):

    registry = DeviceRegistry()

    device = registry.get_by_identifier(
        db=db_session,
        device_identifier="unknown",
    )

    assert device is None