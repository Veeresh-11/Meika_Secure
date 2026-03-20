# Trust Boundaries & Asset Inventory

## Purpose

This document defines all assets, principals, and trust boundaries
within Meika Authenticator.

No trust is assumed implicitly.

---

## Assets

### High-Value Assets
- Authentication decisions
- Authorization decisions
- JIT grants
- Investigation grants
- Containment state
- Evidence records
- Policy definitions

### Supporting Assets
- Device posture signals
- External identity assertions
- WebAuthn credentials
- SIEM/SOAR exports

---

## Principals

- Users (authenticated, intent-bound)
- Devices (identified, posture-evaluated)
- Administrators (no standing privilege)
- Investigators (read-only, scoped)
- External IdPs (authentication sources only)
- Observability systems (non-authoritative)

---

## Trust Boundaries

| Boundary | Description |
|--------|-------------|
| User ↔ Meika | Authenticated, intent-bound |
| Device ↔ Meika | Cryptographically verified |
| IdP ↔ Meika | Assertion verification only |
| Meika ↔ Evidence Store | Append-only, authoritative |
| Meika ↔ SIEM/SOAR | One-way, non-authoritative |

---

## Explicit Non-Trust

The following are never trusted:
- Sessions
- IP addresses
- Network location
- Time alone
- Admin identity alone
