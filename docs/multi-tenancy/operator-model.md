# Operator Model

## Purpose

Define what operators can and cannot do
in a multi-tenant deployment.

---

## Operator Capabilities

Operators may:
- Observe system health
- View metrics
- Respond to incidents externally

Operators may NOT:
- Access tenant data
- Modify tenant policy
- Grant or revoke access
- Clear containment

---

## Operator Access

Operator access is:
- Read-only
- Non-tenant scoped
- Logged and evidenced
