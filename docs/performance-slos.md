# Performance SLOs & Latency Budgets

## Purpose

This document defines explicit latency and reliability targets for
Meika Authenticator’s Zero-Trust enforcement paths.

Performance optimization must never weaken:
- Authorization correctness
- Evidence guarantees
- Containment behavior
- Fail-closed semantics

If performance and security conflict, security wins.

---

## Scope

These SLOs apply to:
- Authentication evaluation
- Policy enforcement
- Grant validation
- Containment checks
- Evidence persistence

They do NOT apply to:
- UI rendering
- SIEM/SOAR export latency
- External IdP response times (measured separately)

---

## Latency Budgets

| Enforcement Path | P50 | P95 | P99 |
|-----------------|-----|-----|-----|
| Authentication (non-privileged) | ≤ 50 ms | ≤ 120 ms | ≤ 200 ms |
| Policy evaluation | ≤ 30 ms | ≤ 80 ms | ≤ 150 ms |
| JIT grant validation | ≤ 20 ms | ≤ 60 ms | ≤ 120 ms |
| Containment checks | ≤ 10 ms | ≤ 30 ms | ≤ 60 ms |
| Evidence write (sync, privileged) | ≤ 40 ms | ≤ 100 ms | ≤ 200 ms |

---

## Security Constraints

The following are explicitly forbidden to meet latency targets:

- Caching authorization decisions
- Skipping posture checks
- Asynchronous evidence writes for privileged actions
- Session-based privilege reuse
- Fail-open timeouts

Timeouts MUST result in:
- Deny (preferred)
- Restrict (only where explicitly safe)

---

## SLO Breach Handling

If latency budgets are exceeded:

1. Alerts are raised
2. Privileged access MAY be blocked
3. System MAY enter safe-restricted mode
4. No access is granted to preserve availability

---

## Measurement Requirements

Latency measurements must:
- Be taken at enforcement boundaries
- Include cryptographic verification
- Include evidence persistence
- Exclude SIEM/SOAR export

Synthetic benchmarks are insufficient alone.

