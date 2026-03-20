# Meika Authenticator – Authentication Protocol (Sprint 3)

## Core Principle
Identity is the only trust anchor.
Sessions, tokens, and devices are non-authoritative.

## Protocol Flow

1. Authentication Challenge Issued
   - Bound to identity, device, policy, and time
   - Short-lived (≤ 30 seconds)
   - Non-replayable

2. Proof Generation
   - Cryptographic proof using:
     - Passkey / biometric / hybrid OTP
   - Proof bound to challenge hash
   - Proof never reusable

3. Signed Intent
   - User intent explicitly signed
   - Prevents invisible or coerced actions

4. Policy Evaluation
   - Authentication policy
   - Risk policy
   - Device & context checks

5. Decision Emission
   - Allow / Step-Up / Deny
   - Evidence always recorded

## Explicit Guarantees

- Session hijack ≠ account compromise
- Token replay without proof fails
- Sensitive actions always revalidated
- Failure → fail closed

## Forbidden

- Password-only authentication
- SMS OTP
- MFA downgrade
- Silent policy bypass

