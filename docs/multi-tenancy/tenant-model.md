# Tenant Model

## Purpose

Define strict tenant isolation in Meika Authenticator.

Tenants are security boundaries, not labels.

---

## Tenant Definition

A tenant is defined as:
- Independent policy namespace
- Independent evidence store
- Independent grant lifecycle
- Independent containment state

---

## Isolation Guarantees

The following MUST be tenant-scoped:
- Policies
- Grants
- Devices
- Evidence
- Investigations
- Containment events

No cross-tenant reads or writes are permitted.

---

## Tenant Identity

Every request MUST include tenant_id.
Missing tenant_id ⇒ DENY.
