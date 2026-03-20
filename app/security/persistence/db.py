# app/security/persistence/db.py

import psycopg2
from psycopg2.extras import RealDictCursor
from app.config.settings import settings


def get_connection():
    return psycopg2.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
        dbname=settings.DB_NAME,
        cursor_factory=RealDictCursor,
    )
