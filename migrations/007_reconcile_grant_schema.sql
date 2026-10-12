-- Meika Secure ID
-- 007_reconcile_grant_schema.sql
--
-- Reconcile identity.grants with the current SQLAlchemy Grant model.
--
-- Historical migration 005 created several fields with weaker/older
-- definitions. This migration upgrades the existing schema without
-- rewriting migration history.


-- ==========================================================
-- 1. Validate legacy values before converting constrained types
-- ==========================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.grants
        WHERE risk_level NOT IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.grants.risk_level: invalid legacy value found';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity.grants
        WHERE guardian_state NOT IN (
            'WATCHING',
            'OBSERVING',
            'ALERT',
            'CONTAINMENT',
            'TERMINATED'
        )
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.grants.guardian_state: invalid legacy value found. '
            'Legacy ACTIVE/UNMONITORED values require explicit data remediation.';
    END IF;
END
$$;

-- ==========================================================
-- 2. Add fields required by the current Grant model
-- ==========================================================

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS grant_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT 'webauthn';

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP;

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS last_used_ip TEXT;

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS revocation_reason TEXT;

-- ==========================================================
-- 3. Convert jwt_id from TEXT to UUID
-- ==========================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.grants
        WHERE jwt_id IS NULL
           OR btrim(jwt_id) = ''
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.grants.jwt_id: NULL or empty value found';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM identity.grants
        WHERE btrim(jwt_id) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.grants.jwt_id: non-UUID legacy value found';
    END IF;
END
$$;

ALTER TABLE identity.grants
    ALTER COLUMN jwt_id DROP DEFAULT;

ALTER TABLE identity.grants
    ALTER COLUMN jwt_id TYPE UUID
    USING btrim(jwt_id)::UUID;

ALTER TABLE identity.grants
    ALTER COLUMN jwt_id SET NOT NULL;

-- ==========================================================
-- 4. Convert risk_level TEXT -> identity.risk_level
-- ==========================================================

ALTER TABLE identity.grants
    ALTER COLUMN risk_level DROP DEFAULT;

ALTER TABLE identity.grants
    ALTER COLUMN risk_level TYPE identity.risk_level
    USING risk_level::identity.risk_level;

ALTER TABLE identity.grants
    ALTER COLUMN risk_level SET DEFAULT 'LOW'::identity.risk_level;

ALTER TABLE identity.grants
    ALTER COLUMN risk_level SET NOT NULL;

-- ==========================================================
-- 5. Convert guardian_state TEXT -> identity.guardian_state
-- ==========================================================

ALTER TABLE identity.grants
    ALTER COLUMN guardian_state DROP DEFAULT;

ALTER TABLE identity.grants
    ALTER COLUMN guardian_state TYPE identity.guardian_state
    USING guardian_state::identity.guardian_state;

ALTER TABLE identity.grants
    ALTER COLUMN guardian_state SET DEFAULT 'WATCHING'::identity.guardian_state;

ALTER TABLE identity.grants
    ALTER COLUMN guardian_state SET NOT NULL;

-- ==========================================================
-- 6. device_id is required by the current Grant model
-- ==========================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.grants
        WHERE device_id IS NULL
    ) THEN
        RAISE EXCEPTION
            'Cannot migrate identity.grants.device_id: NULL legacy value found';
    END IF;
END
$$;

ALTER TABLE identity.grants
    ALTER COLUMN device_id SET NOT NULL;

-- ==========================================================
-- 7. Ensure expected indexes exist
-- ==========================================================

CREATE INDEX IF NOT EXISTS ix_grants_user_id
    ON identity.grants(user_id);

CREATE INDEX IF NOT EXISTS ix_grants_device_id
    ON identity.grants(device_id);

CREATE INDEX IF NOT EXISTS ix_grants_session_id
    ON identity.grants(session_id);

CREATE INDEX IF NOT EXISTS ix_grants_jwt_id
    ON identity.grants(jwt_id);

-- ==========================================================
-- 8. Ensure jwt_id uniqueness
-- ==========================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'grants_jwt_id_key'
          AND conrelid = 'identity.grants'::regclass
    ) THEN
        ALTER TABLE identity.grants
            ADD CONSTRAINT grants_jwt_id_key UNIQUE (jwt_id);
    END IF;
END
$$;

