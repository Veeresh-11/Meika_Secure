# Failure & Degradation Modes

## Defaults
- Fail closed
- No implicit allow
- No auth bypass

## Last-Known-Good
- Cached signed policy
- Time-limited usage
- Evidence recorded

## Explicitly Forbidden
- Disable auth to restore service
- Emergency access without audit

## Malicious Admin Containment

Meika Authenticator assumes administrator compromise is possible.

Upon detection of malicious or unsafe behavior:
- All elevation is revoked
- Devices are degraded
- Evidence is preserved
- Recovery requires independent review

No backdoors exist for administrators.
