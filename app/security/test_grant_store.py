from app.security.grants.models import create_grant
from app.security.grants.store import (
    GrantStore,
    GrantNotFoundError,
)


def make_grant(principal="user"):
    return create_grant(
        principal_id=principal,
        intent="authentication.attempt",
        lifetime_seconds=300,
        issued_by_policy="v1",
        justification="test",
    )


def test_add_and_get_grant():
    store = GrantStore()

    grant = make_grant()

    store.add(grant)

    loaded = store.get(grant.grant_id)

    assert loaded.grant_id == grant.grant_id


def test_missing_grant():
    store = GrantStore()

    try:
        store.get("missing")
        assert False
    except GrantNotFoundError:
        pass


def test_revoke_grant():
    store = GrantStore()

    grant = make_grant()

    store.add(grant)

    store.revoke(grant.grant_id)

    try:
        store.get(grant.grant_id)
        assert False
    except GrantNotFoundError:
        pass


def test_revoke_all_for_principal():
    store = GrantStore()

    g1 = make_grant("alice")
    g2 = make_grant("alice")
    g3 = make_grant("bob")

    store.add(g1)
    store.add(g2)
    store.add(g3)

    store.revoke_all_for_principal("alice")

    assert store.get(g3.grant_id)


def test_list_active():
    store = GrantStore()

    grant = make_grant()

    store.add(grant)

    active = store.list_active()

    assert len(active) == 1