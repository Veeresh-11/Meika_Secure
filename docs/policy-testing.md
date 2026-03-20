# Policy Testing Framework

## Purpose

Policy testing ensures that Meika Authenticator’s security guarantees
are enforced deterministically and cannot silently fail open.

All policies must be testable, reproducible, and evidence-backed.

---

## Testing Principles

Policy tests must be:
- Deterministic (same input → same decision)
- Stateless (no session assumptions)
- Evidence-aware
- Grant-aware
- Containment-aware

If a policy cannot be tested, it is considered invalid.

---

## Test Scope

Policy tests validate:
- Authentication decisions
- Device trust enforcement
- Grant enforcement
- Investigation access
- Containment behavior

---

## Mandatory Assertions

Every policy test MUST assert:
- Final decision (allow / restrict / deny)
- Human-readable explanation
- Evidence reference existence
- Grant state (if applicable)
- Device state (if applicable)

Tests that omit any of these are invalid.

---

## Fail-Closed Guarantee

All tests must confirm that:
- Missing data restricts or denies access
- Ambiguity never grants access
- Evidence failure blocks privilege

---

## Audit Alignment

Policy tests are named to be audit-readable, e.g.:

- test_admin_elevation_denied_without_grant
- test_device_posture_missing_restricts_access

An auditor should understand the test purpose by name alone.
