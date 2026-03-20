# Horizontal Scaling & Statelessness Model

## Purpose

This document describes how Meika Authenticator scales horizontally
without introducing implicit trust or stateful privilege.

---

## Stateless Enforcement

All enforcement components are stateless:

- Policy engine
- Grant enforcement
- Containment checks

No authorization state survives process restarts.

---

## Scaling Model

- Multiple replicas behind a load balancer
- Deterministic policy evaluation for identical inputs
- Grant and evidence stores are external and authoritative
- Clock skew is handled conservatively (expire early)

---

## Restart Guarantees

On restart:
- No grants are restored
- No trust is assumed
- All decisions are re-evaluated

---

## Security Guarantee

Scaling does not:
- Introduce cached authority
- Introduce session affinity for privilege
- Introduce fail-open paths
