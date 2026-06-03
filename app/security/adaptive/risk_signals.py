from dataclasses import dataclass


@dataclass(frozen=True)
class RiskSignals:
    new_device: bool = False
    vpn_detected: bool = False
    tor_detected: bool = False
    failed_login_count: int = 0
    admin_request: bool = False