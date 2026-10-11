-- 015_add_session_tenant.sql
-- Add authoritative tenant identity to authentication sessions.

ALTER TABLE identity.sessions
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill existing sessions from their authoritative users.
UPDATE identity.sessions s
SET tenant_id = u.tenant_id
FROM identity.users u
WHERE s.user_id = u.id
  AND s.tenant_id IS NULL;

-- Existing sessions must now have a tenant.
ALTER TABLE identity.sessions
    ALTER COLUMN tenant_id SET NOT NULL;

-- Enforce tenant ownership at the database layer.
ALTER TABLE identity.sessions
    ADD CONSTRAINT fk_sessions_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

-- Support tenant-scoped session lookups.
CREATE INDEX IF NOT EXISTS ix_sessions_tenant_id
ON identity.sessions(tenant_id);