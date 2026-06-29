from app.security.device.registry import DeviceRegistry


def test_register_and_lookup():

    registry = DeviceRegistry()

    registry.register(
        "dev1",
        "user1",
    )

    assert registry.is_registered(
        "dev1",
        "user1",
    ) is True


def test_wrong_principal():

    registry = DeviceRegistry()

    registry.register(
        "dev1",
        "user1",
    )

    assert registry.is_registered(
        "dev1",
        "user2",
    ) is False


def test_unknown_device():

    registry = DeviceRegistry()

    assert registry.is_registered(
        "missing",
        "user1",
    ) is False