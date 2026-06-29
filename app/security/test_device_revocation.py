from app.security.device.revocation import (
    revoke_device_identity,
)


def test_revoke_device_identity():

    device = {
        "identity": {}
    }

    revoke_device_identity(
        device,
        "COMPROMISED",
    )

    assert (
        device["identity"]["revoked"]
        is True
    )

    assert (
        device["identity"]["revocation_reason"]
        == "COMPROMISED"
    )