-- 017_add_audit_log_tenant.sql
-- Add authoritative tenant identity to operational audit records.

ALTER TABLE identity.audit_logs
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Existing audit rows, if any, must be attributable before
-- tenant ownership becomes mandatory.
UPDATE identity.audit_logs a
SET tenant_id = u.tenant_id
FROM identity.users u
WHERE a.actor_type = 'user'
  AND a.actor_id = u.id
  AND a.tenant_id IS NULL;

-- Tenant ownership is mandatory for all audit records.
ALTER TABLE identity.audit_logs
    ALTER COLUMN tenant_id SET NOT NULL;

-- Enforce tenant ownership at the database layer.
ALTER TABLE identity.audit_logs
    ADD CONSTRAINT fk_audit_logs_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

-- Support tenant-scoped audit queries.
CREATE INDEX IF NOT EXISTS ix_audit_logs_tenant_id
ON identity.audit_logs(tenant_id);
