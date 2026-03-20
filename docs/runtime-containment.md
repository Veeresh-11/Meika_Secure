# Runtime Containment & Automatic Revocation

## Purpose

Runtime containment ensures that malicious or unsafe behavior is stopped
immediately, even during active execution.

Containment removes power.
It never grants power.

---

## Containment Triggers

Containment is triggered by policy-evaluated signals, including:
- Repeated denied elevation attempts
- Investigation scope violations
- Evidence tampering attempts
- Device posture degradation
- Abnormal privileged activity

Triggers are defined in containment_policy.yaml.

---

## Enforcement Points

Containment checks occur:
- Before privileged execution
- During execution
- After execution

Containment may trigger at any point.

---

## Runtime Behavior

When containment triggers:
- All active grants are revoked
- In-flight execution is aborted
- Device state is degraded
- New privileged access is denied
- Evidence is emitted

No human override exists.

---

## Evidence Guarantees

Containment produces immutable, append-only evidence that explains:
- Why containment occurred
- What actions were taken
- Which grants were revoked
- Where execution was aborted

If evidence cannot be written, privileged access remains blocked.

---

## Safety Guarantees

Containment favors safety over availability.
If ambiguity exists, execution is denied.
