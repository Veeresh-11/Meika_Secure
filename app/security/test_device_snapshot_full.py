# app/security/test_device_snapshot_full.py

from types import SimpleNamespace

from app.security.device_snapshot import DeviceSnapshot


def test_from_context_dict():

    data = {
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

    snap = DeviceSnapshot.from_context(data)

    assert snap.device_id == "dev1"
    assert snap.registered is True
    assert snap.state == "active"
    assert snap.hardware_backed is True
    assert snap.attestation_verified is True
    assert snap.binding_valid is True
    assert snap.secure_boot is True
    assert snap.replay_detected is False
    assert snap.compromised is False
    assert snap.clone_confirmed is False


def test_from_context_object():

    obj = SimpleNamespace(
        device_id="dev2",
        registered=True,
        state="revoked",
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        secure_boot=True,
        replay_detected=True,
        compromised=True,
        clone_confirmed=True,
    )

    snap = DeviceSnapshot.from_context(obj)

    assert snap.device_id == "dev2"
    assert snap.state == "revoked"
    assert snap.replay_detected is True
    assert snap.compromised is True
    assert snap.clone_confirmed is True


def test_to_dict():

    snap = DeviceSnapshot(
        device_id="dev3",
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

    assert data["device_id"] == "dev3"
    assert data["registered"] is True
    assert data["state"] == "active"
    assert data["hardware_backed"] is True
    assert data["attestation_verified"] is True
    assert data["binding_valid"] is True
    assert data["secure_boot"] is True
    assert data["replay_detected"] is False
    assert data["compromised"] is False
    assert data["clone_confirmed"] is False