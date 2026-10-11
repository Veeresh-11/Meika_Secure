-- 006_extended_sessions.sql
-- Extend identity.sessions with grant tracking metadata

-- Ensure pgcrypto is available for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add grant type
ALTER TABLE identity.sessions
ADD COLUMN IF NOT EXISTS grant_type TEXT NOT NULL DEFAULT 'access';

-- Add JWT identifier
ALTER TABLE identity.sessions
ADD COLUMN IF NOT EXISTS jwt_id UUID;

-- Populate existing rows
UPDATE identity.sessions
SET jwt_id = gen_random_uuid()
WHERE jwt_id IS NULL;

-- Make jwt_id mandatory if it is not already
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'identity'
          AND table_name = 'sessions'
          AND column_name = 'jwt_id'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE identity.sessions
            ALTER COLUMN jwt_id SET NOT NULL;
    END IF;
END
$$;

-- Add uniqueness constraint if it doesn't already exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'sessions_jwt_id_key'
    ) THEN
        ALTER TABLE identity.sessions
            ADD CONSTRAINT sessions_jwt_id_key UNIQUE (jwt_id);
    END IF;
END
$$;

-- Add creator information
ALTER TABLE identity.sessions
ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT 'webauthn';