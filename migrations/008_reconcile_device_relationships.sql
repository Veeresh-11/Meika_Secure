
-- ============================================================
-- 008: Reconcile device relationships
--
-- Align the database with the current application model:
--
--   webauthn_credentials.device_id -> devices.id
--   grants.device_id                -> devices.id
--
-- This migration intentionally does not modify migrations 000-007.
-- ============================================================


-- ------------------------------------------------------------
-- 1. Add WebAuthn credential -> device relationship
-- ------------------------------------------------------------

ALTER TABLE identity.webauthn_credentials
    ADD COLUMN IF NOT EXISTS device_id UUID;


-- ------------------------------------------------------------
-- 2. Existing-data safety check
--
-- A production database containing WebAuthn credentials created
-- before this migration cannot safely invent a device relationship.
-- Fail explicitly rather than silently assigning the wrong device.
-- ------------------------------------------------------------

DO $$
DECLARE
    credential_count BIGINT;
    unbound_count BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO credential_count
    FROM identity.webauthn_credentials;

    SELECT COUNT(*)
    INTO unbound_count
    FROM identity.webauthn_credentials
    WHERE device_id IS NULL;

    IF credential_count > 0 AND unbound_count > 0 THEN
        RAISE EXCEPTION
            'Migration 008 requires WebAuthn credential device backfill: % of % credentials have NULL device_id',
            unbound_count,
            credential_count;
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 3. Enforce WebAuthn device_id
-- ------------------------------------------------------------

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN device_id SET NOT NULL;


-- ------------------------------------------------------------
-- 4. Add WebAuthn credential -> device FK
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'webauthn_credentials_device_id_fkey'
          AND conrelid = 'identity.webauthn_credentials'::regclass
    ) THEN
        ALTER TABLE identity.webauthn_credentials
            ADD CONSTRAINT webauthn_credentials_device_id_fkey
            FOREIGN KEY (device_id)
            REFERENCES identity.devices(id);
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 5. Add Grant -> device FK
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'grants_device_id_fkey'
          AND conrelid = 'identity.grants'::regclass
    ) THEN
        ALTER TABLE identity.grants
            ADD CONSTRAINT grants_device_id_fkey
            FOREIGN KEY (device_id)
            REFERENCES identity.devices(id);
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 6. Index the WebAuthn device relationship
-- ------------------------------------------------------------

CREATE INDEX IF NOT EXISTS
    ix_webauthn_credentials_device_id
ON identity.webauthn_credentials(device_id);


-- ------------------------------------------------------------
-- 7. Index the Grant device relationship
-- ------------------------------------------------------------

CREATE INDEX IF NOT EXISTS
    ix_grants_device_id
ON identity.grants(device_id);


