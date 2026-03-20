# app/security/test_law_freeze/test_deny_reason_enum_freeze.py

from app.security.results import DenyReason


EXPECTED_REASONS = {
    'DEFAULT_DENY', 'DEVICE_ATTESTATION_FAILED', 'DEVICE_BINDING_INVALID', 'DEVICE_CLONED', 'DEVICE_COMPROMISED', 'DEVICE_INSECURE_BOOT', 'DEVICE_NOT_HARDWARE_BACKED', 'DEVICE_NOT_REGISTERED', 'DEVICE_REVOKED', 'EXPIRED_GRANT', 'GRANT_SCOPE_MISMATCH', 'MISSING_CONTEXT', 'MISSING_EVIDENCE', 'POLICY_DENY', 'POLICY_INVALID_RESULT', 'SNAPSHOT_EXPIRED', 'UNAUTHENTICATED'}


def test_deny_reason_enum_frozen():
    actual = {r.name for r in DenyReason}
    assert actual == EXPECTED_REASONS
