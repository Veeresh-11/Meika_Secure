
---

### 5.2 Policy DENY Requirements

If a policy recommends `DENY`:

- It MUST include evidence
- Evidence MUST explain *why* the policy denied
- Missing evidence is a **hard violation**

Policy DENY without evidence is **forbidden**.

The kernel MUST reject such output.

---

### 5.3 Policy ALLOW Is Not Authority

A policy recommending `ALLOW`:

- Does not bypass Track-A
- Does not bypass device or grant checks
- Does not bypass evidence requirements
- Does not imply trust

Policy ALLOW is **optimistic advice only**.

---

## 6. EVIDENCE CONTRACT (NORMATIVE)

### 6.1 Append-Only Requirement

Evidence systems MUST:

- Never delete records
- Never overwrite records
- Never mutate prior entries

Evidence stores are **write-once memory**.

Violations are **SecurityInvariantViolations**.

---

### 6.2 Evidence Commit Rules

| Decision | Evidence Required |
|--------|------------------|
| DENY | ✅ (kernel auto-generated) |
| ALLOW | ✅ (kernel enforced) |

Failure to commit evidence on ALLOW MUST:

- Fail closed
- Abort execution
- Raise a kernel invariant violation

---

### 6.3 Determinism Scope

Evidence hashing:

- MAY vary across executions
- MUST preserve chain integrity
- MUST cryptographically bind:
  - Context
  - Decision
  - Prior evidence

Evidence hash determinism is **NOT a Track-A requirement**.

---

## 7. SecureIDKernel ROLE

`SecureIDKernel` is a **bridge**, not a lawmaker.

It exists to:
- Extend `SecurityPipeline`
- Commit evidence
- Enforce fail-closed semantics
- Guard observability

It MUST NOT:
- Re-implement Track-A logic
- Change enforcement order
- Introduce new authority paths

---

## 8. OBSERVABILITY (STRICTLY NON-AUTHORITATIVE)

Observability systems:

- MUST be best-effort only
- MUST NOT affect decisions
- MUST NOT raise enforcement-visible exceptions
- MUST NOT block execution

Observability is **voice**, never law.

---

## 9. TEST CLASSIFICATION (REQUIRED)

All tests MUST be explicitly classified.

### 9.1 Track-A Tests

```python
@pytest.mark.track_a
Properties:

Kernel law

Deterministic

Side-effect free

Read-only after freeze

9.2 Track-B Tests
@pytest.mark.kernel
@pytest.mark.evidence


Properties:

Subordinate to Track-A

Must not require Track-A changes

May assume kernel enforcement

10. CHANGE CONTROL

Any Track-B change that:

Weakens Track-A guarantees

Introduces implicit authority

Blurs advisory vs enforcement boundaries

Is invalid, regardless of test results.

Track-B evolves by constraint, not power.

11. STATUS

Track-B is:

Active

Subordinate

Constrained by design

Explicitly non-authoritative

Its purpose is to extend capability without extending authority.

END RFC-MEIKA-TRACK-B-001

---

