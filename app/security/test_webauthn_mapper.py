from datetime import datetime

from app.security.webauthn.mapper import (
    build_device_identity_from_webauthn,
)


def test_mapper_builds_identity():
    ts = datetime.utcnow()

    identity = build_device_identity_from_webauthn(
        hardware_backed=True,
        attestation_verified=True,
        binding_valid=True,
        clone_confirmed=False,
        replay_detected=False,
        last_attested_at=ts,
    )

    assert identity.hardware_backed is True
    assert identity.attestation_verified is True
    assert identity.binding_valid is True
    assert identity.clone_confirmed is False
    assert identity.replay_detected is False
    assert identity.last_attested_at == ts