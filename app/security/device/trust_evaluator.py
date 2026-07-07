from app.security.device.constants import (
    DEVICE_STATE_ACTIVE,
    DEVICE_STATE_REVOKED,
    DEVICE_STATE_SUSPENDED,
    TRUST_LOW,
    TRUST_MEDIUM,
    TRUST_HIGH,
    TRUST_CRITICAL,
)

from .trust_context import DeviceTrustContext
from .trust_result import TrustResult

from .trust_score import (
    MAX_TRUST_SCORE,
    HARDWARE_BACKED_BONUS,
    ATTESTATION_VERIFIED_BONUS,
    KNOWN_DEVICE_BONUS,
    LOW_CREDENTIAL_COUNT_BONUS,
    RECENT_ACTIVITY_BONUS,
    FAILED_AUTH_PENALTY,
    REPLAY_ATTACK_PENALTY,
    IMPOSSIBLE_TRAVEL_PENALTY,
    BEHAVIOR_ANOMALY_PENALTY,
    DEVICE_REVOKED_PENALTY,
    DEVICE_SUSPENDED_PENALTY,
)


class TrustEvaluator:
    """
    Deterministic Device Trust Engine.

    Input:
        DeviceTrustContext

    Output:
        TrustResult
    """

    @staticmethod
    def evaluate(
        context: DeviceTrustContext,
    ) -> TrustResult:

        score = 0

        reasons = []

        device = context.device

        #
        # Positive signals
        #

        if device.hardware_backed:
            score += HARDWARE_BACKED_BONUS
            reasons.append("Hardware-backed credential")

        if device.attestation_verified:
            score += ATTESTATION_VERIFIED_BONUS
            reasons.append("Attestation verified")

        if context.credential_count == 1:
            score += LOW_CREDENTIAL_COUNT_BONUS

        if device.state == DEVICE_STATE_ACTIVE:
            score += KNOWN_DEVICE_BONUS

        #
        # Negative signals
        #

        score += (
            context.failed_auth_count
            * FAILED_AUTH_PENALTY
        )

        if context.recent_replay_detected:
            score += REPLAY_ATTACK_PENALTY
            reasons.append("Replay detected")

        if context.impossible_travel:
            score += IMPOSSIBLE_TRAVEL_PENALTY
            reasons.append("Impossible travel")

        if context.behavior_anomaly:
            score += BEHAVIOR_ANOMALY_PENALTY
            reasons.append("Behavior anomaly")

        if device.state == DEVICE_STATE_SUSPENDED:
            score += DEVICE_SUSPENDED_PENALTY

        if device.state == DEVICE_STATE_REVOKED:
            score += DEVICE_REVOKED_PENALTY

        score = max(0, min(MAX_TRUST_SCORE, score))

        #
        # Classification
        #

        if score >= 80:
            trust = TRUST_HIGH
            risk = "LOW"

        elif score >= 60:
            trust = TRUST_MEDIUM
            risk = "MEDIUM"

        elif score >= 30:
            trust = TRUST_LOW
            risk = "HIGH"

        else:
            trust = TRUST_CRITICAL
            risk = "CRITICAL"

        return TrustResult(
            score=score,
            trust_level=trust,
            risk_level=risk,
            reasons=tuple(reasons),
        )