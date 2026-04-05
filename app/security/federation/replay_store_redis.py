import redis
import time


class ReplayAttackDetected(Exception):
    pass


class RedisReplayStore:

    def __init__(self, url="redis://localhost:6379/0"):
        self.client = redis.Redis.from_url(url, decode_responses=True)

    def check_and_store(self, jti: str, exp: int):
        ttl = exp - int(time.time())

        if ttl <= 0:
            raise ReplayAttackDetected("Token expired")

        # SETNX → only set if not exists
        success = self.client.set(name=jti, value="1", nx=True, ex=ttl)

        if not success:
            raise ReplayAttackDetected("Replay detected")