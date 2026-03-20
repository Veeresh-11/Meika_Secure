# app/security/grants/store.py

from typing import Dict, List
from datetime import datetime
from app.security.grants.models import Grant


class GrantNotFoundError(Exception):
    pass


class GrantStore:
    def __init__(self):
        self._grants: Dict[str, Grant] = {}

    def add(self, grant: Grant) -> None:
        self._grants[grant.grant_id] = grant

    def revoke(self, grant_id: str) -> None:
        self._grants.pop(grant_id, None)

    def revoke_all_for_principal(self, principal_id: str) -> None:
        for gid in list(self._grants.keys()):
            if self._grants[gid].principal_id == principal_id:
                del self._grants[gid]

    def get(self, grant_id: str) -> Grant:
        if grant_id not in self._grants:
            raise GrantNotFoundError(grant_id)
        return self._grants[grant_id]

    def list_active(self) -> List[Grant]:
        now = datetime.utcnow()
        for gid in list(self._grants.keys()):
            if self._grants[gid].is_expired(now):
                del self._grants[gid]
        return list(self._grants.values())

