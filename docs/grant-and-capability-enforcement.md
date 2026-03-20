# Grant & Capability Enforcement

## Purpose

Grant enforcement ensures that **privileged actions only execute when a valid,
active, and scoped grant exists**.

Grants are not trust.
Grants are temporary constraints enforced at runtime.

---

## Grant Types

### JIT Elevation Grant
- Enables a single privileged intent
- Time-bounded
- Device-bound
- High-risk

### Investigation Access Grant
- Enables read-only investigative intents
- Incident-scoped
- Query-by-query enforcement
- Time-bounded

---

## Runtime Enforcement Location

Grant enforcement is implemented in:


No grant → no execution.

---

## Grant Matching Rules

A grant is valid only if:

- grant.intent == request.intent
- grant.user_id == request.user
- grant.device_id == request.device
- current_time < expires_at
- grant is not revoked

Wildcards are forbidden.

---

## Grant Expiry & Revocation

Grants are revoked automatically when:

- They expire
- Containment triggers
- Device posture degrades
- Security revokes explicitly

Revocation is immediate and global.

---

## Grant Binding

When a grant is validated:

- `grant_id` MUST be attached to:
  - Request context
  - Evidence
  - Logs

If execution cannot reference a grant_id, execution MUST abort.

---

## Investigation Grant Enforcement

Investigation grants are enforced per query:

- Validate grant for each query
- Validate incident scope
- Validate read-only behavior
- Log parameters

Any violation denies the query.

---

## Evidence Requirements

For each privileged execution:

### Before Execution
- Grant ID
- Grant expiry
- Validation result

### During Execution
- Each privileged action
- Parameters
- Scope

### After Execution
- Completion status
- Time used

Evidence failure aborts execution.

---

## Forbidden Patterns

- Admin sessions
- Auto-renewed grants
- Role-based shortcuts
- Cached privilege flags
- Emergency grant bypass

If access exists without a grant, it is a vulnerability.

