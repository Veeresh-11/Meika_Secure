import time

from app.security.federation.revocation_store import (
    InMemoryRevocationStore,
)


def test_revoke_token():
    store = InMemoryRevocationStore()

    store.revoke(
        "jti-1",
        int(time.time()) + 60,
    )

    assert store.is_revoked("jti-1") is True


def test_non_revoked_token():
    store = InMemoryRevocationStore()

    assert store.is_revoked("missing") is False


def test_expired_token_cleanup():
    store = InMemoryRevocationStore()

    store.revoke(
        "expired",
        int(time.time()) - 10,
    )

    assert store.is_revoked("expired") is False
    assert "expired" not in store._revoked
    
def test_revoke_expired_token_does_not_store(mocker):
    from app.security.federation.revocation_store_redis import RedisRevocationStore

    fake_client = mocker.Mock()

    mocker.patch(
        "app.security.federation.revocation_store_redis.redis.Redis.from_url",
        return_value=fake_client,
    )

    mocker.patch(
        "app.security.federation.revocation_store_redis.time.time",
        return_value=100,
    )

    store = RedisRevocationStore()

    store.revoke("abc", 100)

    fake_client.set.assert_not_called()