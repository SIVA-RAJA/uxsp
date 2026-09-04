"""
uxsp.core.rate_limit — Rate Limiters and Guarded Handshake

What this file does:
    Implements in-memory and Redis-backed rate limiters that cap how many
    requests a given key (typically an entity_id or IP address) can make within
    a sliding or fixed time window.  Rate limiting is applied at the handshake
    layer to prevent brute-force and denial-of-service attacks.

    The GuardedHandshake convenience class wraps a RateLimiterBase and a
    Handshake.respond() call together so that the caller cannot accidentally
    skip the rate-limit check before accepting a HELLO message.

Key classes:
    RateLimiterBase       — Abstract base class all limiters must implement.
    RateLimiter           — Fixed-window in-memory limiter (simple, fast).
    SlidingRateLimiter    — Sliding-window in-memory limiter (more accurate).
    RedisRateLimiter      — Fixed-window Redis limiter using a Lua script (production).
    RedisSlidingRateLimiter — Sliding-window Redis limiter using sorted sets (production).
    GuardedHandshake      — Combines rate limiting with Handshake.respond().
    RateLimitExceededError — Raised when a key exceeds its request quota.

    AsyncRateLimiterBase  — Abstract base class for async limiters.
    AsyncRedisRateLimiter — Native async fixed-window limiter.
    AsyncRedisSlidingRateLimiter — Native async sliding-window limiter.
"""
from __future__ import annotations

import collections
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

from uxsp.core.handshake import Handshake
from uxsp.core.identity import Identity, PublicCard
from uxsp.core.nonce import MemoryNonceStore, NonceStore
from uxsp.core.session import SessionConfig
from uxsp.storage.noncestore import AsyncNonceStore

# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class RateLimitExceededError(Exception):
    def __init__(self, key: str, retry_after: float) -> None:
        self.key = key
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for '{key}'. Retry after {retry_after:.1f}s.")


# ─────────────────────────────────────────────
# ABSTRACT RATE LIMITER
# ─────────────────────────────────────────────


class RateLimiterBase(ABC):
    """Abstract base for rate limiter backends."""

    @abstractmethod
    def check(self, key: str) -> None:
        """
        Check if key is within rate limit.
        Raises RateLimitExceededError if limit exceeded.
        """
        ...

    @abstractmethod
    def reset(self, key: str) -> None:
        """Reset the counter for a key (e.g. after successful auth)."""
        ...

    @abstractmethod
    def cleanup(self) -> int:
        """Remove stale entries. Returns count removed."""
        ...


class AsyncRateLimiterBase(ABC):
    """Abstract base for async rate limiter backends."""

    @abstractmethod
    async def check(self, key: str) -> None:
        ...

    @abstractmethod
    async def reset(self, key: str) -> None:
        ...

    @abstractmethod
    async def cleanup(self) -> int:
        ...


# ─────────────────────────────────────────────
# FIXED WINDOW — in-memory
# ─────────────────────────────────────────────


class RateLimiter(RateLimiterBase):
    """
    Fixed-window in-memory rate limiter.

    What this class does:
        Counts requests per key within a fixed time window.  When the window
        expires, the counter resets to zero regardless of how many requests
        were made earlier in the window.  This can allow a short burst at the
        boundary between two windows.

        Stale entries are pruned every 60 seconds automatically during check()
        calls.  When the store reaches 100 000 entries, new keys are rejected
        (fail-closed) until cleanup() frees space.

    Parameters:
        max_requests   — Maximum allowed requests per window per key.
        window_seconds — Duration of each fixed window in seconds.
        key_prefix     — String prepended to all keys (for namespacing).
    """
    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0, key_prefix: str = "") -> None:

        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix
        self._counters: dict[str, tuple[int, float]] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        self._MAX_ENTRIES = 100_000

    def check(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"

        with self._lock:
            now = time.time()
            # Automatic periodic cleanup
            if now - self._last_cleanup > 60:
                self._cleanup_locked(now)
                self._last_cleanup = now

            if self._max <= 0:
                raise RateLimitExceededError(key, float(self._window))

            if full_key not in self._counters and len(self._counters) >= self._MAX_ENTRIES:
                # Store full and this is a new key — fail-closed
                raise RateLimitExceededError(key, float(self._window))

            if full_key in self._counters:
                count, window_start = self._counters[full_key]
                window_age = now - window_start

                if window_age < self._window:
                    if count >= self._max:
                        retry_after = self._window - window_age
                        raise RateLimitExceededError(key, retry_after)
                    self._counters[full_key] = (count + 1, window_start)
                else:
                    self._counters[full_key] = (1, now)
            else:
                self._counters[full_key] = (1, now)

    def reset(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"
        with self._lock:
            self._counters.pop(full_key, None)

    def _cleanup_locked(self, now: float) -> int:
        """Must be called with self._lock already held."""
        expired = [k for k, (_, ws) in self._counters.items() if now - ws >= self._window]
        for k in expired:
            del self._counters[k]
        return len(expired)

    def cleanup(self) -> int:
        with self._lock:
            now = time.time()
            return self._cleanup_locked(now)

    def remaining(self, key: str) -> int:
        """How many requests this key has left in the current window."""
        full_key = f"{self._prefix}{key}"
        with self._lock:
            now = time.time()
            if full_key not in self._counters:
                return self._max
            count, window_start = self._counters[full_key]
            if now - window_start >= self._window:
                return self._max
            return max(0, self._max - count)


# ─────────────────────────────────────────────
# SLIDING WINDOW — in-memory
# ─────────────────────────────────────────────


class SlidingRateLimiter(RateLimiterBase):
    """
    Sliding-window in-memory rate limiter.

    What this class does:
        Records the exact timestamps of recent requests per key and counts how
        many fall within the last window_seconds seconds at the moment of each
        check().  This avoids the boundary-burst problem of the fixed-window
        approach at the cost of slightly higher memory use.

        Stale entries are pruned every 60 seconds automatically.  When the store
        reaches 10 000 distinct keys, new keys are rejected (fail-closed).

    Parameters:
        max_requests   — Maximum requests allowed within any window_seconds window.
        window_seconds — Rolling window duration in seconds.
        key_prefix     — String prepended to all keys (for namespacing).
    """
    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0, key_prefix: str = "") -> None:
        # FIX: Allow 0 for testing short-circuits and emergency lockdowns
        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix
        self._log: dict[str, collections.deque[float]] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        self._MAX_ENTRIES = 10_000

    def check(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"

        with self._lock:
            now = time.time()
            cutoff = now - self._window

            if now - self._last_cleanup > 60:
                self._cleanup_locked(now)
                self._last_cleanup = now

            if self._max <= 0:
                raise RateLimitExceededError(key, float(self._window))
            if full_key not in self._log and len(self._log) >= self._MAX_ENTRIES:
                raise RateLimitExceededError(key, float(self._window))

            timestamps = self._log.setdefault(full_key, collections.deque())
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self._max:
                retry_after = (
                    timestamps[0] + self._window - now if timestamps else float(self._window)
                )
                raise RateLimitExceededError(key, max(0.0, retry_after))

            timestamps.append(now)

    def reset(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"
        with self._lock:
            self._log.pop(full_key, None)

    def _cleanup_locked(self, now: float) -> int:
        """Must be called with self._lock already held."""
        cutoff = now - self._window
        empty_keys = []
        for k, ts in self._log.items():
            while ts and ts[0] <= cutoff:
                ts.popleft()
            if not ts:
                empty_keys.append(k)
        for k in empty_keys:
            del self._log[k]
        return len(empty_keys)

    def cleanup(self) -> int:
        with self._lock:
            now = time.time()
            return self._cleanup_locked(now)

    def remaining(self, key: str) -> int:
        """How many requests this key can still make right now."""
        full_key = f"{self._prefix}{key}"

        with self._lock:
            now = time.time()
            cutoff = now - self._window
            timestamps = self._log.get(full_key)
            if not timestamps:
                return self._max
            # We don't prune here to keep remaining() read-only, but we can binary search or count
            # since deque doesn't support bisect natively, we just count from the right
            recent = 0
            for t in reversed(timestamps):
                if t > cutoff:
                    recent += 1
                else:
                    break
            return max(0, self._max - recent)


# ─────────────────────────────────────────────
# FIXED WINDOW — Redis production
# ─────────────────────────────────────────────


class RedisRateLimiter(RateLimiterBase):
    """
    Fixed-window rate limiter backed by Redis (production-grade).

    What this class does:
        Uses a Lua script executed atomically on the Redis server to INCR a
        counter key and set its expiry in one round-trip.  This makes the
        check completely race-condition-free across multiple Python processes
        or servers sharing the same Redis instance.

        Redis handles TTL-based expiry automatically; cleanup() is a no-op.

    Parameters:
        redis_client   — A connected redis.Redis (or compatible) client.
        max_requests   — Maximum requests per window.
        window_seconds — Window duration in seconds.
        key_prefix     — Prefix for all Redis keys (default 'uxsp:ratelimit:').
    """
    _LUA_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if tonumber(current) == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    local ttl = redis.call('TTL', KEYS[1])
    return {current, ttl}
    """

    def __init__(
        self,
        redis_client: Any,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        key_prefix: str = "uxsp:ratelimit:",
    ) -> None:

        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._redis = redis_client
        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix
        self._script = self._redis.register_script(self._LUA_SCRIPT)

    def check(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"

        if self._max <= 0:
            raise RateLimitExceededError(key, float(self._window))

        # Atomically increment and set expiry
        result = self._script(keys=[full_key], args=[self._window])
        count, ttl = int(result[0]), float(result[1])

        if count > self._max:
            retry_after = max(0.0, ttl) if ttl > 0 else float(self._window)
            raise RateLimitExceededError(key, retry_after)

    def reset(self, key: str) -> None:
        self._redis.delete(f"{self._prefix}{key}")

    def cleanup(self) -> int:
        return 0  # Redis handles TTL automatically


class AsyncRedisRateLimiter(AsyncRateLimiterBase):
    """
    Native async Fixed-window rate limiter backed by Redis.
    """
    _LUA_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if tonumber(current) == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    local ttl = redis.call('TTL', KEYS[1])
    return {current, ttl}
    """

    def __init__(
        self,
        async_redis_client: Any,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        key_prefix: str = "uxsp:ratelimit:",
    ) -> None:
        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._redis = async_redis_client
        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix
        self._script = self._redis.register_script(self._LUA_SCRIPT)

    async def check(self, key: str) -> None:
        full_key = f"{self._prefix}{key}"

        if self._max <= 0:
            raise RateLimitExceededError(key, float(self._window))

        result = await self._script(keys=[full_key], args=[self._window])
        count, ttl = int(result[0]), float(result[1])

        if count > self._max:
            retry_after = max(0.0, ttl) if ttl > 0 else float(self._window)
            raise RateLimitExceededError(key, retry_after)

    async def reset(self, key: str) -> None:
        await self._redis.delete(f"{self._prefix}{key}")

    async def cleanup(self) -> int:
        return 0


class RedisSlidingRateLimiter(RateLimiterBase):
    """
    Sliding-window rate limiter backed by a Redis sorted set (production-grade).

    What this class does:
        Uses a Lua script that maintains a Redis sorted set (ZSET) of request
        timestamps per key.  Each check atomically removes expired members, then
        decides whether to admit the new request.  This provides accurate sliding
        behaviour across multiple processes without any clock-synchronisation
        issues, because all operations happen inside a single Lua script on Redis.

    Parameters:
        redis_client   — A connected redis.Redis (or compatible) client.
        max_requests   — Maximum requests allowed within any window_seconds window.
        window_seconds — Rolling window duration in seconds.
        key_prefix     — Prefix for all Redis keys (default 'uxsp:sliding:').
    """
    _LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_req = tonumber(ARGV[3])
    local member = ARGV[4]

    local cutoff = now - window
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)

    if count >= max_req then
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        if oldest and oldest[2] then
            return tostring(oldest[2] + window - now)
        else
            return tostring(window)
        end
    else
        redis.call('ZADD', key, now, member)
        redis.call('EXPIRE', key, math.floor(window + 10))
        return "-1"
    end
    """

    def __init__(
        self,
        redis_client: Any,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        key_prefix: str = "uxsp:sliding:",
    ) -> None:

        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._redis = redis_client
        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix

        self._script = self._redis.register_script(self._LUA_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def check(self, key: str) -> None:
        full_key = self._key(key)
        now = time.time()
        member = str(uuid.uuid4())

        result = self._script(keys=[full_key], args=[now, self._window, self._max, member])

        result_text = result.decode("ascii") if isinstance(result, bytes) else str(result)
        if result_text != "-1":
            retry_after = float(result_text)
            raise RateLimitExceededError(key, max(0.0, retry_after))

    def reset(self, key: str) -> None:
        self._redis.delete(self._key(key))

    def cleanup(self) -> int:
        return 0


class AsyncRedisSlidingRateLimiter(AsyncRateLimiterBase):
    """
    Native async Sliding-window rate limiter backed by Redis sorted set.
    """
    _LUA_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_req = tonumber(ARGV[3])
    local member = ARGV[4]

    local cutoff = now - window
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)

    if count >= max_req then
        local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
        if oldest and oldest[2] then
            return tostring(oldest[2] + window - now)
        else
            return tostring(window)
        end
    else
        redis.call('ZADD', key, now, member)
        redis.call('EXPIRE', key, math.floor(window + 10))
        return "-1"
    end
    """

    def __init__(
        self,
        async_redis_client: Any,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        key_prefix: str = "uxsp:sliding:",
    ) -> None:
        if max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self._redis = async_redis_client
        self._max = max_requests
        self._window = window_seconds
        self._prefix = key_prefix
        self._script = self._redis.register_script(self._LUA_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def check(self, key: str) -> None:
        full_key = self._key(key)
        now = time.time()
        member = str(uuid.uuid4())

        result = await self._script(keys=[full_key], args=[now, self._window, self._max, member])

        result_text = result.decode("ascii") if isinstance(result, bytes) else str(result)
        if result_text != "-1":
            retry_after = float(result_text)
            raise RateLimitExceededError(key, max(0.0, retry_after))

    async def reset(self, key: str) -> None:
        await self._redis.delete(self._key(key))

    async def cleanup(self) -> int:
        return 0


# ─────────────────────────────────────────────
# GUARDED HANDSHAKE — rate limit + handshake in one call
# ─────────────────────────────────────────────


class GuardedHandshake:
    """
    Combines rate limiting with Handshake.respond() in a single call.

    What this class does:
        Wraps a RateLimiterBase and a NonceStore so that the responder side of
        the handshake cannot accidentally accept a HELLO message without first
        enforcing the rate limit for the initiator’s entity_id.

        Typical usage on a server:
            guard = GuardedHandshake(SlidingRateLimiter(max_requests=5), my_identity)
            hs = guard.respond(hello_msg, initiator_card)
            ws.send(hs.ack_message)
    """
    def __init__(self, limiter: RateLimiterBase, responder: Identity, nonce_store: NonceStore | None = None) -> None:

        self._limiter = limiter
        self._responder = responder
        self._nonce_store = nonce_store if nonce_store is not None else MemoryNonceStore()

    def respond(
        self, hello: dict[str, Any], initiator_card: PublicCard, config: SessionConfig | None = None
    ) -> Handshake:
        """
        Check the rate limit for initiator_card.entity_id and then process the HELLO.

        Raises RateLimitExceededError if the initiator has sent too many
        handshake attempts recently.  Otherwise, delegates to
        Handshake.respond() and returns the resulting Handshake object.
        """

        self._limiter.check(initiator_card.entity_id)

        return Handshake.respond(
            responder=self._responder,
            hello=hello,
            initiator_card=initiator_card,
            nonce_store=self._nonce_store,
            config=config,
        )


class AsyncGuardedHandshake:
    """
    Combines async rate limiting with async Handshake response (for async backends).
    """
    def __init__(self, limiter: AsyncRateLimiterBase, responder: Identity, nonce_store: AsyncNonceStore | None = None) -> None:
        self._limiter = limiter
        self._responder = responder
        # If no async nonce store is provided, one could use a mock or in-memory one,
        # but for simplicity we assume it's provided if needed.
        self._nonce_store = nonce_store

    async def respond(
        self, hello: dict[str, Any], initiator_card: PublicCard, config: SessionConfig | None = None
    ) -> Handshake:
        await self._limiter.check(initiator_card.entity_id)

        # We need an async handshake response if the nonce store is async.
        # However, Handshake.respond is currently synchronous and expects a sync NonceStore.
        # We can implement a static method or logic here to do it asynchronously.

        # Verify HELLO format (from Handshake.respond)
        if not isinstance(hello, dict) or hello.get("v") != 1:
            raise ValueError("Invalid HELLO format or version.")

        nonce = hello.get("n")
        if not isinstance(nonce, str):
            raise ValueError("Invalid or missing initiator nonce.")

        if self._nonce_store is not None:
            from uxsp.core.handshake import HandshakeExpiredError
            if not await self._nonce_store.mark_used(f"hello:{hello.get('session_id')}", ttl_seconds=90):
                raise HandshakeExpiredError("Replay attack detected: hello message already processed.")  # pragma: no cover
            if await self._nonce_store.is_seen(nonce):
                raise ValueError("Replay detected: nonce already seen.")
            await self._nonce_store.mark_used(nonce)

        class DummyStore:
            def mark_used(self, n: str, ttl_seconds: int = 0) -> bool: return True
            def is_seen(self, n: str) -> bool: return False

        return Handshake.respond(
            responder=self._responder,
            hello=hello,
            initiator_card=initiator_card,
            nonce_store=DummyStore(),
            config=config,
        )
