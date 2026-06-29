from types import SimpleNamespace

from app.security.device_snapshot import DeviceSnapshot


def test_device_snapshot_defaults():

    snap = DeviceSnapshot(
        device_id="dev1",
    )

    assert snap.device_id == "dev1"
    assert snap.registered is False
    assert snap.hardware_backed is False
    assert snap.clone_confirmed is False


def test_from_context_dict():

    ctx = {
        "device_id": "dev1",
        "registered": True,
        "state": "active",
        "hardware_backed": True,
        "attestation_verified": True,
        "binding_valid": True,
        "secure_boot": True,
        "replay_detected": False,
        "compromised": False,
        "clone_confirmed": False,
    }

    snap = DeviceSnapshot.from_context(ctx)

    assert snap.device_id == "dev1"
    assert snap.registered is True
    assert snap.state == "active"
    assert snap.hardware_backed is True
    assert snap.secure_boot is True


def test_from_context_dict_defaults():

    snap = DeviceSnapshot.from_context(
        {
            "device_id": "dev1",
        }
    )

    assert snap.registered is False
    assert snap.hardware_backed is False
    assert snap.compromised is False


def test_from_context_object():

    obj = SimpleNamespace(
        device_id="dev2",
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        secure_boot=True,
        replay_detected=False,
        compromised=False,
        clone_confirmed=False,
    )

    snap = DeviceSnapshot.from_context(obj)

    assert snap.device_id == "dev2"
    assert snap.registered is True
    assert snap.hardware_backed is True


def test_from_context_object_defaults():

    obj = SimpleNamespace(
        device_id="dev3",
    )

    snap = DeviceSnapshot.from_context(obj)

    assert snap.registered is False
    assert snap.attestation_verified is False
    assert snap.clone_confirmed is False


def test_to_dict():

    snap = DeviceSnapshot(
        device_id="dev1",
        registered=True,
        state="active",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        secure_boot=True,
        replay_detected=False,
        compromised=False,
        clone_confirmed=False,
    )

    data = snap.to_dict()

    assert data["device_id"] == "dev1"
    assert data["registered"] is True
    assert data["state"] == "active"
    assert data["hardware_backed"] is True
    assert data["secure_boot"] is True