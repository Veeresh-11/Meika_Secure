# Hardening Checklist

## Purpose

Prevent security regressions during performance optimization.

---

## Mandatory Checks

- ☐ No cached authorization decisions
- ☐ No session authority introduced
- ☐ Evidence remains synchronous for privilege
- ☐ Containment triggers under load
- ☐ Timeouts fail closed
- ☐ Rate limits are policy-aware

---

## Release Gate

Sprint 8 is considered complete only if
all checklist items pass under load testing.
