from dataclasses import dataclass

from app.db.device_models import Device


@dataclass(frozen=True)
class DeviceTrustContext:
    """
    Immutable input to the Trust Evaluator.
    """

    device: Device

    credential_count: int

    session_count: int

    failed_auth_count: int

    recent_replay_detected: bool

    impossible_travel: bool

    behavior_anomaly: bool