# Proof Obligations

## Purpose

This document maps security invariants
to enforcement mechanisms and proofs.

---

## Proof Sources

Each invariant is proven by a combination of:
- Code structure
- Policy rules
- Automated tests
- Runtime evidence

---

## Proof Mapping

| Invariant | Proof Source |
|---------|--------------|
| Explicit intent | policy_enforcer |
| Grant-bound privilege | grant_enforcer |
| No standing privilege | policy + expiry |
| Evidence precedence | evidence writer |
| Containment dominance | containment_enforcer |
| Fail-closed recovery | chaos tests |
| Restrictive risk | risk_policy.yaml |

---

## Review Rule

If an invariant cannot be demonstrated via:
- Code
- Tests
- Evidence

then the invariant is considered violated.
