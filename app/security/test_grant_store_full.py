# app/security/test_grant_store_full.py

from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from app.security.grants.store import (
    GrantStore,
    GrantNotFoundError,
)


def make_grant(
    gid,
    principal="user1",
    expired=False,
):
    grant = Mock()

    grant.grant_id = gid
    grant.principal_id = principal

    grant.is_expired.return_value = expired

    return grant


def test_add_and_get():
    store = GrantStore()

    grant = make_grant("g1")

    store.add(grant)

    assert store.get("g1") is grant


def test_get_missing():
    store = GrantStore()

    with pytest.raises(GrantNotFoundError):
        store.get("missing")


def test_revoke():
    store = GrantStore()

    grant = make_grant("g1")

    store.add(grant)

    store.revoke("g1")

    with pytest.raises(GrantNotFoundError):
        store.get("g1")


def test_revoke_all_for_principal():
    store = GrantStore()

    g1 = make_grant("g1", "user1")
    g2 = make_grant("g2", "user2")

    store.add(g1)
    store.add(g2)

    store.revoke_all_for_principal("user1")

    with pytest.raises(GrantNotFoundError):
        store.get("g1")

    assert store.get("g2") is g2


def test_list_active_removes_expired():
    store = GrantStore()

    active = make_grant("active", expired=False)
    expired = make_grant("expired", expired=True)

    store.add(active)
    store.add(expired)

    result = store.list_active()

    assert active in result

    with pytest.raises(GrantNotFoundError):
        store.get("expired")