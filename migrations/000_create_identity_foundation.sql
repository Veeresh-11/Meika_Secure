-- ============================================================
-- Meika Secure ID
-- 000_create_identity_foundation.sql
--
-- Foundational identity schema.
--
-- This migration must execute before WebAuthn, grants, and
-- session-extension migrations because those objects depend
-- on the identity schema and its core tables.
-- ============================================================

-- ------------------------------------------------------------
-- PostgreSQL extensions
-- ------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------
-- Identity schema
-- ------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS identity;

-- ------------------------------------------------------------
-- Enumerated security states
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type t
        JOIN pg_namespace n
          ON n.oid = t.typnamespace
        WHERE n.nspname = 'identity'
          AND t.typname = 'risk_level'
    ) THEN
        CREATE TYPE identity.risk_level AS ENUM (
            'LOW',
            'MEDIUM',
            'HIGH',
            'CRITICAL'
        );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type t
        JOIN pg_namespace n
          ON n.oid = t.typnamespace
        WHERE n.nspname = 'identity'
          AND t.typname = 'guardian_state'
    ) THEN
        CREATE TYPE identity.guardian_state AS ENUM (
            'WATCHING',
            'OBSERVING',
            'ALERT',
            'CONTAINMENT',
            'TERMINATED'
        );
    END IF;
END
$$;

-- ------------------------------------------------------------
-- Users
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email TEXT NOT NULL UNIQUE,

    display_name TEXT,

    status TEXT NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT users_status_check
        CHECK (status IN ('active', 'disabled'))
);

-- ------------------------------------------------------------
-- Devices
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    device_identifier TEXT NOT NULL UNIQUE,

    device_name TEXT NOT NULL,

    device_type TEXT NOT NULL DEFAULT 'unknown',

    hardware_backed BOOLEAN NOT NULL DEFAULT FALSE,

    attestation_verified BOOLEAN NOT NULL DEFAULT FALSE,

    trust_level TEXT NOT NULL DEFAULT 'UNKNOWN',

    state TEXT NOT NULL DEFAULT 'ACTIVE',

    registered_at TIMESTAMP DEFAULT NOW(),

    last_seen TIMESTAMP DEFAULT NOW(),

    last_attested_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),

    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_devices_user_id
ON identity.devices(user_id);

CREATE INDEX IF NOT EXISTS ix_devices_identifier
ON identity.devices(device_identifier);

-- ------------------------------------------------------------
-- Credentials
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    type TEXT NOT NULL,

    secret_ref TEXT NOT NULL,

    status TEXT NOT NULL,

    created_at TIMESTAMP DEFAULT NOW(),

    last_used_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_credentials_user_id
ON identity.credentials(user_id);

-- ------------------------------------------------------------
-- Authentication sessions
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    device_id UUID
        REFERENCES identity.devices(id),

    issued_at TIMESTAMP DEFAULT NOW(),

    expires_at TIMESTAMP NOT NULL,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    last_seen TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_sessions_user_id
ON identity.sessions(user_id);

CREATE INDEX IF NOT EXISTS ix_sessions_device_id
ON identity.sessions(device_id);

-- ------------------------------------------------------------
-- Audit log
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    actor_type TEXT NOT NULL,

    actor_id UUID,

    action TEXT NOT NULL,

    resource TEXT NOT NULL,

    ip_address TEXT,

    user_agent TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_id
ON identity.audit_logs(actor_id);

CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at
ON identity.audit_logs(created_at);
