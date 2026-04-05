import redis
import time


class RedisRevocationStore:

    def __init__(self, url="redis://localhost:6379/0"):
        self.client = redis.Redis.from_url(url, decode_responses=True)

    def revoke(self, jti: str, exp: int):
        ttl = exp - int(time.time())

        if ttl > 0:
            self.client.set(name=f"revoked:{jti}", value="1", ex=ttl)

    def is_revoked(self, jti: str) -> bool:
        return self.client.exists(f"revoked:{jti}") == 1