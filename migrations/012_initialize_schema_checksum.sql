-- ============================================================
-- Meika Secure ID
-- 012_initialize_schema_checksum.sql
--
-- Initialize the immutable schema metadata checksum.
--
-- Migration 010 established schema_metadata with an empty
-- checksum and then protected the row from UPDATE/DELETE.
--
-- This migration performs the one-time checksum initialization
-- and restores the immutable trigger before completion.
--
-- Safety invariants:
-- - Exactly one metadata row with id=1 must exist.
-- - Schema version must be 1.0.0.
-- - Existing non-empty checksums must never be overwritten.
-- - The immutable trigger must be restored before commit.
-- ============================================================


-- ------------------------------------------------------------
-- Temporarily remove the metadata immutability trigger
-- ------------------------------------------------------------

DROP TRIGGER IF EXISTS no_schema_update
ON identity.schema_metadata;


-- ------------------------------------------------------------
-- Initialize the canonical schema checksum
-- ------------------------------------------------------------

DO
$$
DECLARE
    metadata_count INTEGER;
BEGIN

    SELECT COUNT(*)
    INTO metadata_count
    FROM identity.schema_metadata
    WHERE id = 1;

    IF metadata_count <> 1 THEN
        RAISE EXCEPTION
            'Expected exactly one schema metadata row with id=1, found %',
            metadata_count;
    END IF;


    IF EXISTS (
        SELECT 1
        FROM identity.schema_metadata
        WHERE id = 1
          AND schema_version <> '1.0.0'
    ) THEN
        RAISE EXCEPTION
            'Unexpected schema version for checksum initialization';
    END IF;


    IF EXISTS (
        SELECT 1
        FROM identity.schema_metadata
        WHERE id = 1
          AND schema_checksum <> ''
    ) THEN
        RAISE EXCEPTION
            'Schema checksum is already initialized; refusing to overwrite it';
    END IF;


    UPDATE identity.schema_metadata
    SET schema_checksum =
        'a47da5cdd9dd24df3e73f2feddf0a68d902d3f5db072d07db5839c2447e6ba3c'
    WHERE id = 1;

END;
$$;


-- ------------------------------------------------------------
-- Restore immutable schema metadata protection
-- ------------------------------------------------------------

CREATE TRIGGER no_schema_update
BEFORE UPDATE OR DELETE
ON identity.schema_metadata
FOR EACH ROW
EXECUTE FUNCTION identity.forbid_schema_version_change();