# Operational Visibility & Explainability

## Purpose

Operational visibility in Meika Authenticator ensures that every security decision
is observable, explainable, and auditable without granting additional access.

Visibility exists to prove Zero Trust enforcement, not to bypass it.

---

## Visibility Planes

Meika exposes three visibility planes:

- Decision Plane: why access decisions occurred
- Grant Plane: where temporary privilege existed
- Containment Plane: how and why privilege was removed

No other visibility planes are permitted.

---

## Decision Visibility

Every access decision records:
- Who made the request
- From which device
- Under which intent
- Which policies evaluated
- What result occurred
- Why the result occurred
- Evidence reference

Decisions are immutable facts.

---

## Grant Visibility

Grants are observable but never editable.

Operators can see:
- Active grants
- Expired grants
- Revoked grants

Operators cannot extend, renew, or recreate grants.

---

## Containment Visibility

Containment events are high-priority and always visible.

Containment records include:
- Trigger reason
- Policy involved
- Grants revoked
- Device state changes
- Execution abort points
- Evidence reference

Containment cannot be hidden or suppressed.

---

## Explainability Guarantee

Every decision and containment event must produce a single-sentence,
human-readable explanation.

If an explanation cannot be produced, the action must not occur.

---

## Safety Guarantees

Operational visibility:
- Does not grant access
- Does not change policy outcomes
- Does not allow overrides
- Does not weaken containment

If ambiguity exists, access is denied.
