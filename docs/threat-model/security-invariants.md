# Security Invariants & Proof Obligations

## Core Invariants

1. No access without explicit intent
2. No privilege without a valid grant
3. No standing administrative privilege
4. Evidence exists for every privileged action
5. Evidence failure blocks privilege
6. Containment revokes power immediately
7. Failures never grant access

---

## Proof Obligations

The system must prove:

- Authorization decisions are policy-driven
- Grants expire and cannot be extended
- Revoked grants cannot be reused
- Containment overrides all access
- Recovery does not restore trust

---

## Enforcement Mapping

| Invariant | Enforced By |
|---------|-------------|
| Intent required | policy_enforcer |
| Grant required | grant_enforcer |
| No standing admin | policy + tests |
| Evidence required | evidence writer |
| Containment | containment_enforcer |
| Fail-closed | chaos tests |

---

## Formal Review Rule

If an invariant cannot be proven by:
- Code
- Tests
- Evidence

Then the invariant is considered violated.
