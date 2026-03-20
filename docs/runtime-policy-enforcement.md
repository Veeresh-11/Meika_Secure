# Runtime Policy Enforcement

## Purpose

Runtime policy enforcement ensures that **no request reaches protected logic**
unless it has been explicitly evaluated and approved by Meika’s policy engine.

All enforcement is **fail-closed**, **non-bypassable**, and **evidence-backed**.

---

## Enforcement Invariants

Runtime enforcement MUST satisfy:

- No request executes without an explicit intent
- Authentication, authorization, investigation, and admin access use the same policy engine
- Evidence capture is mandatory for privileged actions
- If evidence writing fails, execution MUST fail
- No session or cached trust is allowed

---

## Enforcement Location

All runtime enforcement occurs at a single choke point:


Any failure aborts execution.

---

## Intent Requirement

Every request MUST declare an explicit intent.

Examples:
- auth:authenticate
- admin:rotate_key
- investigate:view_auth_events

Missing intent results in immediate denial.

There is no default intent.

---

## Decision Outcomes

| Decision | Runtime Effect |
|--------|----------------|
| allow | Execute normally |
| restrict | Execute with reduced scope |
| deny | Abort execution |

Restriction is preferred over denial when safe.

---

## Evidence Dependency

Runtime enforcement depends on evidence integrity.

If evidence capture is unavailable:
- Privileged access MUST fail
- Admin and investigation access MUST be blocked

This is intentional and non-configurable.

---

## Forbidden Patterns

The following are forbidden at runtime:

- Inline authorization checks
- Feature flags for admin access
- Hardcoded allowlists
- Debug bypass switches
- Cached privilege state

Any such code is a security defect.

---

## Guarantee

If a request executes, Meika can always answer:
- Who executed it
- From which device
- Under which intent
- Why it was allowed
- What policy approved it
