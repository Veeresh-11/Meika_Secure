class DevicePostureEvaluator:
    """
    Evaluates raw posture signals.
    Returns structured facts for policy.
    """

    REQUIRED_SIGNALS = [
        "secure_boot",
        "disk_encrypted",
        "os_up_to_date",
    ]

    def evaluate(self, signals: dict) -> dict:
        return {
            signal: bool(signals.get(signal))
            for signal in self.REQUIRED_SIGNALS
        }
