from app.security.results import DenyReason

def test_deny_reason_values_unique():
    values = [r.value for r in DenyReason]
    assert len(values) == len(set(values)), "Duplicate DenyReason values detected"
