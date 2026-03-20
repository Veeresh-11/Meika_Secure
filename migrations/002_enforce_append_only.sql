-- 002_enforce_append_only.sql
-- Sprint 2 — Enforce append-only immutability

-- Revoke dangerous privileges
REVOKE UPDATE, DELETE ON evidence_log FROM PUBLIC;

-- Application role: insert-only
-- (Assumes role exists in production)
-- GRANT INSERT ON evidence_log TO meika_app;

-- Auditor role: read-only
-- GRANT SELECT ON evidence_log TO meika_auditor;

-- Prevent accidental cascade delete
ALTER TABLE evidence_log
    DROP CONSTRAINT IF EXISTS evidence_log_id_fkey;
