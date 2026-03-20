# Tenant Isolation Invariants

## Invariant T1 — No Cross-Tenant Access

Formal:
∀ request r:
  tenant(r) ≠ tenant(resource) ⇒ deny

---

## Invariant T2 — No Global Admin

There is no global administrative privilege.

Operators are tenant-scoped and restricted.

---

## Invariant T3 — Evidence Isolation

Evidence is tenant-bound and immutable.

Formal:
evidence(e) ⇒ tenant(e) fixed forever
