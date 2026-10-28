"""
Meika Secure ID
Database Schema Contract Validator

Validates:
- Required schemas
- Required PostgreSQL extensions
- Required tables
- Required columns
- Column data types
- Column nullability
- Required PostgreSQL enum types and values
- Required primary/unique/foreign-key constraints
- Required migration history
"""

from __future__ import annotations

import logging
from typing import Any

from db_utils import get_connection

logger = logging.getLogger(__name__)


# Canonical SHA-256 of app/security/persistence/evidence_schema.sql.
# This is the existing checksum initialized by migration 012.
EXPECTED_SCHEMA_VERSION = "1.0.0"
EXPECTED_SCHEMA_CHECKSUM = (
    "a47da5cdd9dd24df3e73f2feddf0a68d902d3f5db072d07db5839c2447e6ba3c"
)


# ============================================================
# Required database structure
# ============================================================

REQUIRED_SCHEMAS = (
    "public",
    "identity",
)

PUBLIC_TABLES = (
    "evidence_log",
    "schema_migrations",
)

IDENTITY_TABLES = (
    "organizations",
    "users",
    "credentials",
    "devices",
    "sessions",
    "audit_logs",
    "webauthn_challenges",
    "webauthn_credentials",
    "grants",
    "evidence_ledger",
    "schema_metadata",
)

REQUIRED_EXTENSIONS = (
    "pgcrypto",
)


# ============================================================
# Required enum types
# ============================================================

REQUIRED_ENUMS = {
    "identity.risk_level": (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ),
    "identity.guardian_state": (
        "WATCHING",
        "OBSERVING",
        "ALERT",
        "CONTAINMENT",
        "TERMINATED",
    ),
}


# ============================================================
# Required columns
#
# Format:
#   schema.table: {
#       column: (data_type, nullable)
#   }
#
# nullable:
#   True  -> column may be NULL
#   False -> column must be NOT NULL
#
# We intentionally validate the application contract rather than
# every incidental database default.
# ============================================================

REQUIRED_COLUMNS: dict[str, dict[str, tuple[str, bool]]] = {
    "public.schema_migrations": {
        "version": ("text", False),
        "applied_at": ("timestamp with time zone", False),
    },

    "identity.evidence_ledger": {
        "sequence_number": ("bigint", False),
        "previous_hash": ("text", True),
        "payload_hash": ("text", False),
        "record_hash": ("text", False),
        "created_at": ("timestamp without time zone", False),
    },

    "identity.schema_metadata": {
        "id": ("integer", False),
        "schema_version": ("text", False),
        "schema_checksum": ("text", False),
        "created_at": ("timestamp without time zone", False),
    },

    "identity.organizations": {
        "id": ("uuid", False),
        "name": ("text", False),
        "status": ("text", False),
        "created_at": ("timestamp without time zone", False),
        "updated_at": ("timestamp without time zone", False),
    },

    "identity.users": {
        "id": ("uuid", False),
        "email": ("text", False),
        "display_name": ("text", True),
        "status": ("text", False),
        "created_at": ("timestamp without time zone", False),
        "tenant_id": ("uuid", False),
    },

    "identity.credentials": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "type": ("text", False),
        "secret_ref": ("text", False),
        "status": ("text", False),
        "created_at": ("timestamp without time zone", True),
        "last_used_at": ("timestamp without time zone", True),
    },

    "identity.devices": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "tenant_id": ("uuid", False),
        "device_identifier": ("text", False),
        "device_name": ("text", False),
        "device_type": ("text", False),
        "hardware_backed": ("boolean", False),
        "attestation_verified": ("boolean", False),
        "trust_level": ("text", False),
        "state": ("text", False),
        "registered_at": ("timestamp without time zone", True),
        "last_seen": ("timestamp without time zone", True),
        "last_attested_at": ("timestamp without time zone", True),
        "created_at": ("timestamp without time zone", True),
        "updated_at": ("timestamp without time zone", True),
    },

    "identity.sessions": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "tenant_id": ("uuid", False),
        "device_id": ("uuid", True),
        "issued_at": ("timestamp without time zone", True),
        "expires_at": ("timestamp without time zone", False),
        "revoked": ("boolean", False),
        "last_seen": ("timestamp without time zone", True),

        # Retained because migrations 006 introduced these columns
        # and the live database currently contains them.
        "grant_type": ("text", False),
        "jwt_id": ("uuid", False),
        "created_by": ("text", False),
    },

    "identity.audit_logs": {
        "id": ("uuid", False),
        "actor_type": ("text", False),
        "actor_id": ("uuid", True),
        "tenant_id": ("uuid", False),
        "action": ("text", False),
        "resource": ("text", False),
        "ip_address": ("text", True),
        "user_agent": ("text", True),
        "created_at": ("timestamp without time zone", True),
    },

    "identity.webauthn_challenges": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "tenant_id": ("uuid", False),
        "challenge": ("text", False),
        "purpose": ("text", False),
        "used": ("boolean", False),
        "created_at": ("timestamp without time zone", False),
        "expires_at": ("timestamp without time zone", False),
    },

    "identity.webauthn_credentials": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "tenant_id": ("uuid", False),
        "credential_id": ("text", False),
        "device_id": ("uuid", False),
        "public_key": ("text", False),
        "sign_count": ("integer", False),
        "hardware_backed": ("boolean", False),
        "attestation_verified": ("boolean", False),
        "attestation_type": ("text", False),
        "revoked": ("boolean", True),
        "created_at": ("timestamp without time zone", True),
        "last_used_at": ("timestamp without time zone", True),
    },

    "identity.grants": {
        "id": ("uuid", False),
        "user_id": ("uuid", False),
        "tenant_id": ("uuid", False),
        "session_id": ("uuid", False),
        "credential_id": ("uuid", False),
        "grant_type": ("text", False),
        "risk_level": ("USER-DEFINED", False),
        "guardian_state": ("USER-DEFINED", False),
        "jwt_id": ("uuid", False),
        "device_id": ("uuid", False),
        "ip_address": ("text", True),
        "issued_at": ("timestamp without time zone", False),
        "expires_at": ("timestamp without time zone", False),
        "revoked": ("boolean", False),
        "revoked_at": ("timestamp without time zone", True),
        "created_at": ("timestamp without time zone", False),
        "grant_version": ("integer", False),
        "created_by": ("text", False),
        "last_used_at": ("timestamp without time zone", True),
        "last_used_ip": ("text", True),
        "revocation_reason": ("text", True),
    },
}


# ============================================================
# Required constraints
#
# Each tuple:
#   (constraint_name, table, expected_type, expected_definition)
# ============================================================

REQUIRED_FOREIGN_KEYS = (
    (
        "fk_users_tenant",
        "identity.users",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "credentials_user_id_fkey",
        "identity.credentials",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "devices_user_id_fkey",
        "identity.devices",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "fk_devices_tenant",
        "identity.devices",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "sessions_user_id_fkey",
        "identity.sessions",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "fk_sessions_tenant",
        "identity.sessions",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "sessions_device_id_fkey",
        "identity.sessions",
        "FOREIGN KEY (device_id) REFERENCES identity.devices(id)",
    ),
    (
        "webauthn_challenges_user_id_fkey",
        "identity.webauthn_challenges",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "fk_webauthn_challenges_tenant",
        "identity.webauthn_challenges",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "webauthn_credentials_user_id_fkey",
        "identity.webauthn_credentials",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "fk_webauthn_credentials_tenant",
        "identity.webauthn_credentials",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "webauthn_credentials_device_id_fkey",
        "identity.webauthn_credentials",
        "FOREIGN KEY (device_id) REFERENCES identity.devices(id)",
    ),
    (
        "grants_user_id_fkey",
        "identity.grants",
        "FOREIGN KEY (user_id) REFERENCES identity.users(id)",
    ),
    (
        "fk_audit_logs_tenant",
        "identity.audit_logs",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "fk_grants_tenant",
        "identity.grants",
        "FOREIGN KEY (tenant_id) REFERENCES identity.organizations(id)",
    ),
    (
        "grants_session_id_fkey",
        "identity.grants",
        "FOREIGN KEY (session_id) REFERENCES identity.sessions(id)",
    ),
    (
        "grants_credential_id_fkey",
        "identity.grants",
        "FOREIGN KEY (credential_id) REFERENCES identity.webauthn_credentials(id)",
    ),
    (
        "grants_device_id_fkey",
        "identity.grants",
        "FOREIGN KEY (device_id) REFERENCES identity.devices(id)",
    ),
)

REQUIRED_INDEXES = (
    (
        "ix_users_tenant_id",
        "identity.users",
    ),
    (
        "ix_devices_tenant_id",
        "identity.devices",
    ),
    (
        "ix_webauthn_credentials_tenant_id",
        "identity.webauthn_credentials",
    ),
    (
        "ix_audit_logs_tenant_id",
        "identity.audit_logs",
    ),
    (
        "ix_webauthn_challenges_tenant_id",
        "identity.webauthn_challenges",
    ),
    (
        "uq_webauthn_enrollment_purpose",
        "identity.webauthn_challenges",
    ),
    (
        "ix_sessions_tenant_id",
        "identity.sessions",
    ),
    (
        "ix_grants_tenant_id",
        "identity.grants",
    ),
)

REQUIRED_UNIQUE_CONSTRAINTS = (
    ("evidence_ledger_record_hash_key", "identity.evidence_ledger"),
    ("users_tenant_email_key", "identity.users"),
    ("devices_device_identifier_key", "identity.devices"),
    ("webauthn_challenges_challenge_key", "identity.webauthn_challenges"),
    ("webauthn_credentials_credential_id_key", "identity.webauthn_credentials"),
    ("grants_jwt_id_key", "identity.grants"),
    ("sessions_jwt_id_key", "identity.sessions"),
)


REQUIRED_CHECK_CONSTRAINTS = (
    (
        "organizations_status_check",
        "identity.organizations",
        "CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'DISABLED'::text])))",
    ),
    (
        "evidence_ledger_genesis_invariant",
        "identity.evidence_ledger",
        "CHECK ((((sequence_number = 0) AND (previous_hash IS NULL)) "
        "OR ((sequence_number > 0) AND (previous_hash IS NOT NULL))))",
    ),
)


REQUIRED_PRIMARY_KEYS = (
    ("evidence_ledger_pkey", "identity.evidence_ledger"),
    ("schema_metadata_pkey", "identity.schema_metadata"),
    ("organizations_pkey", "identity.organizations"),
    ("users_pkey", "identity.users"),
    ("credentials_pkey", "identity.credentials"),
    ("devices_pkey", "identity.devices"),
    ("sessions_pkey", "identity.sessions"),
    ("audit_logs_pkey", "identity.audit_logs"),
    ("webauthn_challenges_pkey", "identity.webauthn_challenges"),
    ("webauthn_credentials_pkey", "identity.webauthn_credentials"),
    ("grants_pkey", "identity.grants"),
)


# ============================================================
# Migration contract
# ============================================================

REQUIRED_MIGRATIONS = (
    "000_create_identity_foundation.sql",
    "001_create_evidence_log.sql",
    "002_create_evidence_ledger.sql",
    "003_enforce_append_only.sql",
    "004_create_webauthn.sql",
    "005_create_grants.sql",
    "006_extended_sessions.sql",
    "007_reconcile_grant_schema.sql",
    "008_reconcile_device_relationships.sql",
    "009_reconcile_webauthn_trust_defaults.sql",
    "010_reconcile_evidence_ledger_schema.sql",
    "011_enforce_evidence_genesis_invariant.sql",
    "012_initialize_schema_checksum.sql",
    "013_create_tenant_foundation.sql",
    "014_add_webauthn_challenge_tenant.sql",
    "015_add_session_tenant.sql",
    "016_add_grant_tenant.sql",
    "017_add_audit_log_tenant.sql",
    "018_enforce_single_use_webauthn_enrollment.sql",
)


# ============================================================
# Helpers
# ============================================================

def exists(cursor, query: str, params: tuple[Any, ...]) -> bool:
    cursor.execute(query, params)
    result = cursor.fetchone()
    return bool(result and result[0])


def schema_exists(cursor, schema: str) -> bool:
    return exists(
        cursor,
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.schemata
            WHERE schema_name = %s
        )
        """,
        (schema,),
    )


def table_exists(cursor, schema: str, table: str) -> bool:
    return exists(
        cursor,
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = %s
              AND table_name = %s
        )
        """,
        (schema, table),
    )


def extension_exists(cursor, extension: str) -> bool:
    return exists(
        cursor,
        """
        SELECT EXISTS (
            SELECT 1
            FROM pg_extension
            WHERE extname = %s
        )
        """,
        (extension,),
    )


def validate_columns(cursor) -> None:
    logger.info("Checking required columns...")

    cursor.execute(
        """
        SELECT
            table_schema,
            table_name,
            column_name,
            data_type,
            udt_schema,
            udt_name,
            is_nullable
        FROM information_schema.columns
        WHERE table_schema IN ('public', 'identity')
        """
    )

    actual = {
        (
            row[0],
            row[1],
            row[2],
        ): {
            "data_type": row[3],
            "udt_schema": row[4],
            "udt_name": row[5],
            "is_nullable": row[6] == "YES",
        }
        for row in cursor.fetchall()
    }

    for qualified_table, columns in REQUIRED_COLUMNS.items():
        schema, table = qualified_table.split(".", 1)

        for column, (expected_type, expected_nullable) in columns.items():
            key = (schema, table, column)

            if key not in actual:
                raise RuntimeError(
                    f"Missing column: {qualified_table}.{column}"
                )

            observed = actual[key]

            if expected_type == "USER-DEFINED":
                if observed["data_type"] != "USER-DEFINED":
                    raise RuntimeError(
                        f"Wrong type for {qualified_table}.{column}: "
                        f"expected USER-DEFINED, got {observed['data_type']}"
                    )
            elif observed["data_type"] != expected_type:
                raise RuntimeError(
                    f"Wrong type for {qualified_table}.{column}: "
                    f"expected {expected_type}, got {observed['data_type']}"
                )

            if observed["is_nullable"] != expected_nullable:
                expected = "NULL" if expected_nullable else "NOT NULL"
                actual_value = "NULL" if observed["is_nullable"] else "NOT NULL"

                raise RuntimeError(
                    f"Wrong nullability for {qualified_table}.{column}: "
                    f"expected {expected}, got {actual_value}"
                )


def validate_enums(cursor) -> None:
    logger.info("Checking PostgreSQL enum types...")

    for qualified_type, expected_values in REQUIRED_ENUMS.items():
        schema, type_name = qualified_type.split(".", 1)

        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_type t
                JOIN pg_namespace n
                  ON n.oid = t.typnamespace
                WHERE n.nspname = %s
                  AND t.typname = %s
                  AND t.typtype = 'e'
            )
            """,
            (schema, type_name),
        )

        if not cursor.fetchone()[0]:
            raise RuntimeError(f"Missing enum type: {qualified_type}")

        cursor.execute(
            """
            SELECT e.enumlabel
            FROM pg_enum e
            JOIN pg_type t
              ON t.oid = e.enumtypid
            JOIN pg_namespace n
              ON n.oid = t.typnamespace
            WHERE n.nspname = %s
              AND t.typname = %s
            ORDER BY e.enumsortorder
            """,
            (schema, type_name),
        )

        actual_values = tuple(row[0] for row in cursor.fetchall())

        if actual_values != tuple(expected_values):
            raise RuntimeError(
                f"Wrong enum values for {qualified_type}: "
                f"expected {tuple(expected_values)}, "
                f"got {actual_values}"
            )


def get_constraint(cursor, constraint_name: str):
    cursor.execute(
        """
        SELECT
            c.conrelid::regclass::text,
            c.contype,
            pg_get_constraintdef(c.oid)
        FROM pg_constraint c
        WHERE c.connamespace = 'identity'::regnamespace
          AND c.conname = %s
        """,
        (constraint_name,),
    )

    return cursor.fetchone()


def validate_primary_keys(cursor) -> None:
    logger.info("Checking primary keys...")

    for constraint_name, table in REQUIRED_PRIMARY_KEYS:
        result = get_constraint(cursor, constraint_name)

        if not result:
            raise RuntimeError(
                f"Missing primary key constraint: {table}.{constraint_name}"
            )

        actual_table, constraint_type, _ = result

        if actual_table != table or constraint_type != "p":
            raise RuntimeError(
                f"Invalid primary key constraint: {constraint_name}"
            )


def validate_unique_constraints(cursor) -> None:
    logger.info("Checking unique constraints...")

    for constraint_name, table in REQUIRED_UNIQUE_CONSTRAINTS:
        result = get_constraint(cursor, constraint_name)

        if not result:
            raise RuntimeError(
                f"Missing unique constraint: {table}.{constraint_name}"
            )

        actual_table, constraint_type, _ = result

        if actual_table != table or constraint_type != "u":
            raise RuntimeError(
                f"Invalid unique constraint: {constraint_name}"
            )


def normalize_constraint_definition(definition: str) -> str:
    return " ".join(definition.lower().split())


def validate_check_constraints(cursor) -> None:
    logger.info("Checking check constraints...")

    for constraint_name, table, expected_definition in REQUIRED_CHECK_CONSTRAINTS:
        result = get_constraint(cursor, constraint_name)

        if not result:
            raise RuntimeError(
                f"Missing check constraint: {table}.{constraint_name}"
            )

        actual_table, constraint_type, actual_definition = result

        if actual_table != table or constraint_type != "c":
            raise RuntimeError(
                f"Invalid check constraint: {constraint_name}"
            )

        if normalize_constraint_definition(actual_definition) != (
            normalize_constraint_definition(expected_definition)
        ):
            raise RuntimeError(
                f"Wrong definition for check constraint {constraint_name}: "
                f"expected '{expected_definition}', "
                f"got '{actual_definition}'"
            )
def validate_indexes(cursor) -> None:
    logger.info("Checking indexes...")

    for index_name, table in REQUIRED_INDEXES:
        schema, table_name = table.split(".", 1)

        cursor.execute(
            """
            SELECT 1
            FROM pg_indexes
            WHERE schemaname = %s
              AND tablename = %s
              AND indexname = %s
            """,
            (schema, table_name, index_name),
        )

        if cursor.fetchone() is None:
            raise RuntimeError(
                f"Missing index: {table}.{index_name}"
            )

def validate_foreign_keys(cursor) -> None:
    logger.info("Checking foreign keys...")

    for constraint_name, table, expected_definition in REQUIRED_FOREIGN_KEYS:
        result = get_constraint(cursor, constraint_name)

        if not result:
            raise RuntimeError(
                f"Missing foreign key constraint: {table}.{constraint_name}"
            )

        actual_table, constraint_type, actual_definition = result

        if actual_table != table or constraint_type != "f":
            raise RuntimeError(
                f"Invalid foreign key constraint: {constraint_name}"
            )

        if normalize_constraint_definition(actual_definition) != (
            normalize_constraint_definition(expected_definition)
        ):
            raise RuntimeError(
                f"Wrong definition for foreign key {constraint_name}: "
                f"expected '{expected_definition}', "
                f"got '{actual_definition}'"
            )




def validate_schema_metadata(cursor) -> None:
    """Validate the canonical schema metadata row."""
    logger.info("Checking schema metadata...")

    cursor.execute(
        """
        SELECT id, schema_version, schema_checksum
        FROM identity.schema_metadata
        ORDER BY id
        """
    )
    rows = cursor.fetchall()

    if len(rows) != 1 or rows[0][0] != 1:
        raise RuntimeError(
            "Schema metadata must contain exactly one row with id=1"
        )

    _, version, checksum = rows[0]

    if version != EXPECTED_SCHEMA_VERSION:
        raise RuntimeError(
            "Schema metadata version mismatch: "
            f"expected {EXPECTED_SCHEMA_VERSION}, got {version}"
        )

    if checksum != EXPECTED_SCHEMA_CHECKSUM:
        raise RuntimeError(
            "Schema metadata checksum mismatch: "
            "possible unauthorized modification"
        )


def validate_schema_metadata_trigger(cursor) -> None:
    """Require the enabled metadata immutability trigger."""
    logger.info("Checking schema metadata immutability trigger...")

    cursor.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM pg_trigger AS t
            JOIN pg_class AS c
              ON c.oid = t.tgrelid
            JOIN pg_namespace AS n
              ON n.oid = c.relnamespace
            JOIN pg_proc AS p
              ON p.oid = t.tgfoid
            JOIN pg_namespace AS pn
              ON pn.oid = p.pronamespace
            WHERE n.nspname = 'identity'
              AND c.relname = 'schema_metadata'
              AND t.tgname = 'no_schema_update'
              AND NOT t.tgisinternal
              AND t.tgenabled IN ('O', 'A')
              AND pn.nspname = 'identity'
              AND p.proname = 'forbid_schema_version_change'
              AND (t.tgtype & 2) = 2
              AND (t.tgtype & 8) = 8
              AND (t.tgtype & 16) = 16
        )
        """
    )

    result = cursor.fetchone()
    if not result or not result[0]:
        raise RuntimeError(
            "Missing, disabled, or invalid schema metadata "
            "immutability trigger: identity.no_schema_update"
        )


def validate_migrations(cursor) -> None:
    logger.info("Checking migration history...")

    if not table_exists(cursor, "public", "schema_migrations"):
        raise RuntimeError("Missing table: public.schema_migrations")

    cursor.execute(
        """
        SELECT version
        FROM public.schema_migrations
        ORDER BY version
        """
    )

    actual = tuple(row[0] for row in cursor.fetchall())
    expected = tuple(REQUIRED_MIGRATIONS)

    if actual != expected:
        raise RuntimeError(
            "Migration history mismatch: "
            f"expected {expected}, got {actual}"
        )


# ============================================================
# Main validation
# ============================================================

def validate() -> None:
    conn = get_connection()

    try:
        with conn.cursor() as cur:

            logger.info("Checking schemas...")

            for schema in REQUIRED_SCHEMAS:
                if not schema_exists(cur, schema):
                    raise RuntimeError(f"Missing schema: {schema}")

            logger.info("Checking public tables...")

            for table in PUBLIC_TABLES:
                if not table_exists(cur, "public", table):
                    raise RuntimeError(f"Missing table: public.{table}")

            logger.info("Checking identity tables...")

            for table in IDENTITY_TABLES:
                if not table_exists(cur, "identity", table):
                    raise RuntimeError(f"Missing table: identity.{table}")

            logger.info("Checking PostgreSQL extensions...")

            for extension in REQUIRED_EXTENSIONS:
                if not extension_exists(cur, extension):
                    raise RuntimeError(
                        f"Missing PostgreSQL extension: {extension}"
                    )

            validate_columns(cur)
            validate_enums(cur)
            validate_primary_keys(cur)
            validate_unique_constraints(cur)
            validate_check_constraints(cur)
            validate_foreign_keys(cur)
            validate_indexes(cur)
            validate_migrations(cur)
            validate_schema_metadata(cur)
            validate_schema_metadata_trigger(cur)

            logger.info("Schema validation completed successfully.")

    finally:
        conn.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    validate()
