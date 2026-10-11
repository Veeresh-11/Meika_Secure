-- ============================================================
-- Meika Secure ID
-- 011_enforce_evidence_genesis_invariant.sql
--
-- Enforce the canonical representation of the evidence chain:
-- - sequence 0 is the genesis record and has no previous hash.
-- - every non-genesis record must reference a previous record.
--
-- Migration 010 established the canonical ledger but only
-- documented this invariant. This migration makes it a
-- database-enforced invariant.
-- ============================================================

ALTER TABLE identity.evidence_ledger
ADD CONSTRAINT evidence_ledger_genesis_invariant
CHECK (
    (sequence_number = 0 AND previous_hash IS NULL)
    OR
    (sequence_number > 0 AND previous_hash IS NOT NULL)
);
