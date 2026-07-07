"""
Device Trust Scoring Policy.

This module defines the deterministic scoring model used by the
Device Trust Engine.

Only constants belong here.
No business logic.
"""

# Maximum achievable score
MAX_TRUST_SCORE = 100

# ---------------------------------------------------------------------
# Positive Factors
# ---------------------------------------------------------------------

HARDWARE_BACKED_BONUS = 30

ATTESTATION_VERIFIED_BONUS = 30

KNOWN_DEVICE_BONUS = 15

RECENT_ACTIVITY_BONUS = 5

LOW_CREDENTIAL_COUNT_BONUS = 10
# ---------------------------------------------------------------------
# Negative Factors
# ---------------------------------------------------------------------

FAILED_AUTH_PENALTY = -10

REPLAY_ATTACK_PENALTY = -40

IMPOSSIBLE_TRAVEL_PENALTY = -25

BEHAVIOR_ANOMALY_PENALTY = -20

DEVICE_SUSPENDED_PENALTY = -25

DEVICE_REVOKED_PENALTY = -100