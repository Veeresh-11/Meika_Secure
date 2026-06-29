import pytest
import time

from app.security.federation.replay_store import (
    InMemoryReplayStore,
    ReplayAttackDetected,
)


def test_store_new_jti():
    store = InMemoryReplayStore()

    store.check_and_store(
        "jti-1",
        int(time.time()) + 60,
    )


def test_replay_detected():
    store = InMemoryReplayStore()

    exp = int(time.time()) + 60

    store.check_and_store("jti-1", exp)

    with pytest.raises(ReplayAttackDetected):
        store.check_and_store("jti-1", exp)


def test_expired_entry_removed():
    store = InMemoryReplayStore()

    store.check_and_store(
        "old-jti",
        int(time.time()) - 10,
    )

    store.check_and_store(
        "new-jti",
        int(time.time()) + 60,
    )

    assert "old-jti" not in store._store
    assert "new-jti" in store._store