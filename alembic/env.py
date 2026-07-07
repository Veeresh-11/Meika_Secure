import os
from logging.config import fileConfig

from alembic import context

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from app.db.models import Base

# Import ALL models so they are registered with Base.metadata
import app.db.models
import app.db.device_models
import app.db.grant_models
import app.db.webauthn_models


config = context.config

database_url = os.environ.get("POSTGRES_DSN")

if not database_url:
    raise RuntimeError(
        "POSTGRES_DSN environment variable not configured."
    )

config.set_main_option(
    "sqlalchemy.url",
    database_url,
)

if config.config_file_name:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():

    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_schemas=True,
        literal_binds=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():

    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_schemas=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()