# app/security/test_device_registry.py

from app.security.device.registry import DeviceRegistry


def test_register_and_lookup_success():

    registry = DeviceRegistry()

    registry.register(
        "device-1",
        "user-1",
    )

    assert registry.is_registered(
        "device-1",
        "user-1",
    ) is True


def test_lookup_wrong_principal():

    registry = DeviceRegistry()

    registry.register(
        "device-1",
        "user-1",
    )

    assert registry.is_registered(
        "device-1",
        "user-2",
    ) is False


def test_lookup_unknown_device():

    registry = DeviceRegistry()

    assert registry.is_registered(
        "missing-device",
        "user-1",
    ) is False