# Backpressure, Rate Limiting & Load Shedding

## Purpose

Protect Meika Authenticator under high load
without relaxing Zero-Trust guarantees.

---

## Rate Limiting

Rate limits are applied per:
- User
- Device
- Intent

Privileged intents have stricter limits.

Repeated abuse may trigger containment.

---

## Backpressure Rules

- Evidence backlog → block privileged access
- Policy engine saturation → deny new privilege
- SIEM/SOAR queues drop events without affecting enforcement

---

## Load Shedding Strategy

When under extreme load:
1. Shed non-privileged requests
2. Preserve enforcement paths
3. Preserve evidence writes
4. Preserve containment checks

---

## Forbidden Behavior

- Skipping posture checks
- Skipping evidence capture
- Allowing access to reduce load

Security always beats availability.
