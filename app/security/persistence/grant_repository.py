# app/security/persistence/grant_repository.py

import json
from datetime import datetime
from typing import List

from app.security.grants.models import Grant
from app.security.persistence.db import get_connection


class PersistentGrantRepository:
    """
    Persistent store for issued grants.
    Persistence remembers grants — it never authorizes.
    """

    def save(self, grant: Grant) -> None:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO grants (
                grant_id,
                principal_id,
                scopes,
                issued_at,
                expires_at,
                issued_by_policy,
                justification
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (grant_id) DO NOTHING
        """, (
            grant.grant_id,
            grant.principal_id,
            grant.issued_at,
            grant.expires_at,
            grant.issued_by_policy,
            grant.intent,
            grant.justification,
        ))

        conn.commit()
        cur.close()
        conn.close()

    def load_active(self) -> List[Grant]:
        """
        Load only non-expired grants.
        Expired grants are ignored (never revived).
        """
        now = datetime.utcnow()

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT *
            FROM grants
            WHERE expires_at > %s
        """, (now,))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        grants: List[Grant] = []

        for r in rows:
            grants.append(
                Grant(
                    grant_id=r["grant_id"],
                    principal_id=r["principal_id"],
                    issued_at=r["issued_at"],
                    expires_at=r["expires_at"],
                    issued_by_policy=r["issued_by_policy"],
                    intent=r["intent"],
                    justification=r["justification"],
                )
            )

        return grants
