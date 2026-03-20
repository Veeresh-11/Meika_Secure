# Adversarial Testing

## Purpose

Adversarial testing validates Meika Authenticator under assume-breach conditions.

The system is tested as if attackers already have:
- Valid credentials
- Legitimate devices
- Knowledge of policies

---

## Threat Classes

Adversarial testing covers:

- Malicious administrators
- Compromised devices
- Malicious investigators
- Evidence tampering attempts
- Incident pressure and chaos

---

## Expected Guarantees

Under all adversarial scenarios:
- Privilege cannot accumulate
- Scope cannot be exceeded
- Evidence cannot be suppressed
- Containment triggers automatically
- Recovery does not restore trust

---

## Containment Expectations

Adversarial behavior must result in:
- Immediate grant revocation
- Device degradation
- Evidence emission
- No human override

---

## Evidence Requirements

Every adversarial test must produce evidence explaining:
- What behavior was detected
- Why containment occurred
- What actions were taken

Adversarial success is defined as:
> The attacker gains no additional power.
