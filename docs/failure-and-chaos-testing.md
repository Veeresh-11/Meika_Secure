# Failure & Chaos Testing

## Purpose

Failure and chaos testing ensures that infrastructure failures,
partial outages, and anomalies never weaken Zero Trust enforcement.

---

## Failure Domains

The system is tested against:
- Policy engine outages
- Evidence store failures
- Time and clock anomalies
- Network partitions
- Resource exhaustion
- Service restarts

---

## Fail-Closed Guarantees

Under failure conditions:
- Privileged access is denied
- Investigation access is denied
- No cached trust is used
- No fallback access exists

---

## Safe-Restricted Mode

When critical dependencies fail, Meika enters safe-restricted mode:

- No privileged access
- No investigation access
- Authentication only if policy allows
- Clear evidence explaining restriction

There is no manual override.

---

## Recovery Guarantees

After recovery:
- No trust is restored implicitly
- No grants are resurrected
- Devices remain degraded if degraded

Recovery is deliberate and auditable.
