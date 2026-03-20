# Upgrade & Migration Safety

## Purpose

Ensure upgrades do not introduce trust
or break isolation.

---

## Upgrade Rules

- No schema migration grants privilege
- No default grants introduced
- Policies versioned per tenant
- Rollbacks do not restore trust

---

## Migration Failure Handling

If migration fails:
- Privileged access blocked
- Evidence preserved
- Manual review required
