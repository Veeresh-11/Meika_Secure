# Device Trust Model

## Purpose

Device trust in Meika Authenticator is a **restrictive-only control** used to reduce risk
without introducing implicit trust, session trust, or standing privileges.

A device is never “trusted”.
A device can only be **evaluated**, **restricted**, or **revoked**.

---

## Non-Goals (Explicit)

Device trust does NOT provide:
- Remembered devices
- Session persistence
- MFA downgrade
- Privilege acceleration
- Network or IP-based trust
- Administrative bypass

Any feature requiring these is **forbidden by design**.

---

## Device Identity

Each device is represented as a **non-human principal** with:
- A cryptographic keypair generated on-device
- A stable, non-guessable `device_id`
- Explicit lifecycle states

Devices are issued identities only after:
- User authentication
- Explicit intent
- Policy evaluation
- Evidence capture

---

## Device Trust States

| State | Meaning | Effect |
|-----|-------|-------|
| new | Recently registered | Highly restricted |
| observed | Signals collected | Restricted |
| known | Consistent behavior | Less restricted |
| degraded | Risk or inconsistency | Heavily restricted |
| revoked | Explicitly disabled | No access |

State transitions are **policy-driven** and **audited**.

---

## Restrictive-Only Rule

Device state and posture:
- MAY deny or restrict access
- MUST NOT grant access
- MUST NOT override authentication results

---

## Policy Integration

Device trust is evaluated by the **same policy engine** used for:
- Authentication
- Authorization
- Admin elevation
- Investigation access

No separate decision paths exist.

---

## Evidence Requirements

Every device-related decision MUST emit evidence that explains:
- What was evaluated
- What was missing or present
- Why the decision occurred

If a decision cannot be explained, it cannot exist.
