# app/security/test_replay_store_redis_full.py

import pytest

from app.security.federation.replay_store_redis import (
    RedisReplayStore,
    ReplayAttackDetected,
)


def test_expired_token(monkeypatch):

    monkeypatch.setattr(
        "app.security.federation.replay_store_redis.time.time",
        lambda: 1000,
    )

    store = RedisReplayStore.__new__(RedisReplayStore)

    with pytest.raises(ReplayAttackDetected):
        store.check_and_store(
            jti="abc",
            exp=999,
        )
        
from unittest.mock import Mock, patch
import time
import pytest

from app.security.federation.replay_store_redis import (
    RedisReplayStore,
    ReplayAttackDetected,
)


@patch("app.security.federation.replay_store_redis.redis.Redis.from_url")
def test_constructor(mock_from_url):
    RedisReplayStore()
    mock_from_url.assert_called_once()


def test_store_success():
    store = RedisReplayStore.__new__(RedisReplayStore)

    client = Mock()
    client.set.return_value = True

    store.client = client

    store.check_and_store(
        "jti1",
        int(time.time()) + 100,
    )


def test_replay_detected():
    store = RedisReplayStore.__new__(RedisReplayStore)

    client = Mock()
    client.set.return_value = False

    store.client = client

    with pytest.raises(ReplayAttackDetected):
        store.check_and_store(
            "jti1",
            int(time.time()) + 100,
        )