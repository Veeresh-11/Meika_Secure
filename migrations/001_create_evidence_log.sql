-- 001_create_evidence_log.sql
-- Sprint 2 — Evidence Durability Hardening

CREATE TABLE IF NOT EXISTS evidence_log (
    id BIGSERIAL PRIMARY KEY,
    sequence BIGINT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Enforce monotonic sequence uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_sequence
ON evidence_log(sequence);

-- No foreign keys that cascade delete
-- No ON DELETE CASCADE allowed
