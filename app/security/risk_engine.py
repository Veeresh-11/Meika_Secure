import hashlib


class RiskLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskEngine:

    def __init__(self):
        self._known_devices = {}

    def assess(self, context, claims) -> str:
        """
        Returns: low / medium / high
        """

        risk_score = 0

        # -----------------------------
        # 1️⃣ Device anomaly
        # -----------------------------
        device_id = getattr(context, "device_id", None)
        user = getattr(context, "principal_id", None)

        if device_id and user:
            known = self._known_devices.get(user, set())

            if device_id not in known:
                risk_score += 2  # new device

        # -----------------------------
        # 2️⃣ Token reuse / suspicious pattern
        # -----------------------------
        if not claims.get("device_state_hash"):
            risk_score += 1

        # -----------------------------
        # 3️⃣ Time anomaly (future skew already handled)
        # -----------------------------
        # placeholder for geo/time analysis

        # -----------------------------
        # DECISION
        # -----------------------------
        if risk_score >= 3:
            return RiskLevel.HIGH
        elif risk_score == 2:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def register_device(self, context):
        user = getattr(context, "principal_id", None)
        device_id = getattr(context, "device_id", None)

        if user and device_id:
            self._known_devices.setdefault(user, set()).add(device_id)