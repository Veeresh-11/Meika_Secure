# Supported Authentication Methods

## Primary (Default)
- Passkeys (FIDO2 / platform-backed)

## Secondary (Smartphone-Accessible)
- Biometric-gated Hybrid OTP
  - OTP visible only after biometric unlock
  - OTP generated via multi-stage cryptographic transformation
  - OTP invalidated immediately after use

## Emergency (Break-Glass)
- Time-boxed
- Hardware-backed
- Mandatory audit & alerting

## Explicitly Forbidden
- Password-only
- SMS OTP
- Shared credentials

## Runtime Enforcement & Grants

All authentication and authorization decisions in Meika are enforced at runtime
using explicit policy evaluation and grant validation.

Privileged actions require:
- Explicit intent
- Valid device identity
- Fresh posture signals
- Policy approval
- Active grant (if required)
- Successful evidence capture

No privilege is stored in sessions or tokens.

Just-In-Time elevation and investigation access are enforced per request,
not per login.

This ensures all elevated access is temporary, scoped, and auditable.
