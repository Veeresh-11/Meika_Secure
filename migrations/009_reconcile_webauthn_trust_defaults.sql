-- Meika Secure ID
-- 009_reconcile_webauthn_trust_defaults.sql
--
-- Reconcile historical WebAuthn trust defaults with the
-- current security model.
--
-- Historical migration 004 used TRUE defaults for
-- hardware_backed and attestation_verified.
--
-- The current application requires these values explicitly
-- and treats positive trust as something that must be
-- established, not inferred from omission.
--
-- This migration does not rewrite existing explicit values.

BEGIN;

-- ==========================================================
-- 1. Refuse to silently convert ambiguous existing data
-- ==========================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.webauthn_credentials
        WHERE hardware_backed IS NULL
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.webauthn_credentials.hardware_backed: NULL value found';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity.webauthn_credentials
        WHERE attestation_verified IS NULL
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.webauthn_credentials.attestation_verified: NULL value found';
    END IF;
END
$$;

-- ==========================================================
-- 2. Remove historical permissive defaults
-- ==========================================================

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN hardware_backed DROP DEFAULT;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN attestation_verified DROP DEFAULT;

-- ==========================================================
-- 3. Enforce explicit trust state
-- ==========================================================

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN hardware_backed SET DEFAULT FALSE;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN hardware_backed SET NOT NULL;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN attestation_verified SET DEFAULT FALSE;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN attestation_verified SET NOT NULL;

COMMIT;
