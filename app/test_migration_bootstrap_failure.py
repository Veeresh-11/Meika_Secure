import importlib
import os
import sys
from pathlib import Path
from uuid import uuid4

import psycopg2
import pytest


@pytest.fixture
def migration_runner(monkeypatch):
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    monkeypatch.syspath_prepend(str(scripts_dir))

    sys.modules.pop("apply_migrations", None)
    sys.modules.pop("db_utils", None)

    return importlib.import_module("apply_migrations")


@pytest.mark.postgres
def test_failed_migration_does_not_record_or_partially_apply(
    migration_runner,
    tmp_path,
    monkeypatch,
):
    dsn = os.getenv("POSTGRES_TEST_DSN") or os.getenv("DATABASE_URL")

    if not dsn:
        pytest.skip("PostgreSQL test DSN not configured")

    psycopg2_dsn = dsn.replace(
        "postgresql+psycopg://",
        "postgresql://",
        1,
    )

    schema = f"migration_test_{uuid4().hex}"

    # ------------------------------------------------------------
    # Create isolated temporary schema.
    # ------------------------------------------------------------
    setup_conn = psycopg2.connect(psycopg2_dsn)
    setup_conn.autocommit = True

    try:
        with setup_conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    finally:
        setup_conn.close()

    # ------------------------------------------------------------
    # Create synthetic migrations.
    # ------------------------------------------------------------
    first = tmp_path / "001_success.sql"
    second = tmp_path / "002_failure.sql"

    first.write_text(
        f"""
        CREATE TABLE "{schema}".committed_marker (
            id INTEGER PRIMARY KEY
        );
        """,
        encoding="utf-8",
    )

    second.write_text(
        f"""
        CREATE TABLE "{schema}".rolled_back_marker (
            id INTEGER PRIMARY KEY
        );

        SELECT 1 / 0;
        """,
        encoding="utf-8",
    )

    # ------------------------------------------------------------
    # Force migration runner to use the isolated schema.
    #
    # IMPORTANT:
    # Keep autocommit=True here.
    #
    # Production apply() is responsible for switching the
    # connection to autocommit=False.
    # ------------------------------------------------------------
    def get_test_connection():
        conn = psycopg2.connect(psycopg2_dsn)

        # Keep this connection outside a transaction while
        # configuring the search_path.
        conn.autocommit = True

        with conn.cursor() as cur:
            cur.execute(
                f'SET search_path TO "{schema}", public'
            )

            cur.execute("SHOW search_path")
            search_path = cur.fetchone()[0]

            if not search_path.startswith(schema):
                conn.close()

                raise AssertionError(
                    f"Unexpected PostgreSQL search_path: "
                    f"{search_path!r}"
                )

            # Diagnostic information.
            cur.execute(
                """
                SELECT
                    current_database(),
                    current_user,
                    current_schema(),
                    current_schemas(false)
                """
            )

            print(
                "MIGRATION CONNECTION:",
                cur.fetchone(),
            )

            cur.execute("SHOW search_path")

            print(
                "MIGRATION SEARCH_PATH:",
                cur.fetchone()[0],
            )

        # IMPORTANT:
        # Do NOT set autocommit=False here.
        #
        # apply_migrations.apply() does that itself.
        return conn

    monkeypatch.setattr(
        migration_runner,
        "get_connection",
        get_test_connection,
    )

    # ------------------------------------------------------------
    # Replace real migration list with synthetic migrations.
    # ------------------------------------------------------------
    monkeypatch.setattr(
        migration_runner,
        "ordered_migrations",
        lambda: [first, second],
    )

    # ------------------------------------------------------------
    # Apply migrations.
    #
    # Migration 001 must commit.
    # Migration 002 must fail and roll back.
    # ------------------------------------------------------------
    with pytest.raises(Exception) as exc_info:
        migration_runner.apply()

    print(
        "MIGRATION APPLY EXCEPTION:",
        repr(exc_info.value),
    )

    # ------------------------------------------------------------
    # Verify final database state using a separate connection.
    # ------------------------------------------------------------
    verify_conn = psycopg2.connect(psycopg2_dsn)

    try:
        with verify_conn.cursor() as cur:
            # ----------------------------------------------------
            # Migration 001 MUST have survived.
            # ----------------------------------------------------
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_schema = %s
                      AND table_name = %s
                )
                """,
                (schema, "committed_marker"),
            )

            committed_exists = cur.fetchone()[0]

            print(
                "COMMITTED MARKER EXISTS:",
                committed_exists,
            )

            assert committed_exists is True

            # ----------------------------------------------------
            # Migration 002 MUST have been rolled back.
            # ----------------------------------------------------
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_schema = %s
                      AND table_name = %s
                )
                """,
                (schema, "rolled_back_marker"),
            )

            rolled_back_exists = cur.fetchone()[0]

            print(
                "ROLLED BACK MARKER EXISTS:",
                rolled_back_exists,
            )

            assert rolled_back_exists is False

            # ----------------------------------------------------
            # Only migration 001 MUST be recorded.
            # ----------------------------------------------------
            cur.execute(
                psycopg2.sql.SQL(
                    """
                    SELECT version
                    FROM {}.schema_migrations
                    ORDER BY version
                    """
                ).format(psycopg2.sql.Identifier(schema))
            )

            applied_versions = [
                row[0]
                for row in cur.fetchall()
            ]

            print(
                "RECORDED MIGRATIONS:",
                applied_versions,
            )

            assert applied_versions == [
                "001_success.sql"
            ]

    finally:
        verify_conn.close()

        # --------------------------------------------------------
        # Cleanup isolated schema.
        # --------------------------------------------------------
        cleanup_conn = psycopg2.connect(psycopg2_dsn)
        cleanup_conn.autocommit = True

        try:
            with cleanup_conn.cursor() as cur:
                cur.execute(
                    f'DROP SCHEMA "{schema}" CASCADE'
                )
        finally:
            cleanup_conn.close()


def test_bootstrap_stops_before_schema_validation(monkeypatch):
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    monkeypatch.syspath_prepend(str(scripts_dir))

    sys.modules.pop("bootstrap_db", None)
    sys.modules.pop("apply_migrations", None)
    sys.modules.pop("db_utils", None)
    sys.modules.pop("validate_schema", None)

    bootstrap_db = importlib.import_module("bootstrap_db")

    called = {"validate": False}

    def fail_apply():
        raise RuntimeError("migration failure")

    def validate():
        called["validate"] = True

    monkeypatch.setattr(
        bootstrap_db,
        "wait_for_database",
        lambda: None,
    )

    monkeypatch.setattr(
        bootstrap_db,
        "apply",
        fail_apply,
    )

    monkeypatch.setattr(
        bootstrap_db,
        "validate",
        validate,
    )

    with pytest.raises(
        RuntimeError,
        match="migration failure",
    ):
        bootstrap_db.bootstrap()

    assert called["validate"] is False