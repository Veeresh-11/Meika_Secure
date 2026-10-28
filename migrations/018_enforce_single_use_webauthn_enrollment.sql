-- Ensure an enrollment token jti can create at most one registration challenge.
-- The partial unique index only applies to enrollment-purpose rows; ordinary
-- registration/authentication challenges remain unrestricted.
CREATE UNIQUE INDEX IF NOT EXISTS uq_webauthn_enrollment_purpose
    ON identity.webauthn_challenges (purpose)
    WHERE purpose LIKE 'fido2-register:%';
