from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from uxsp.core.identity import Identity
from uxsp.core.rate_limit import (
    AsyncGuardedHandshake,
    AsyncRedisRateLimiter,
    AsyncRedisSlidingRateLimiter,
    RateLimitExceededError,
    RedisRateLimiter,
    RedisSlidingRateLimiter,
)


def test_redis_rate_limiter():
    mock_redis = MagicMock()
    # Script registration
    mock_script = MagicMock()
    mock_redis.register_script.return_value = mock_script

    # 1. Validation errors
    with pytest.raises(ValueError):
        RedisRateLimiter(mock_redis, max_requests=-1)
    with pytest.raises(ValueError):
        RedisRateLimiter(mock_redis, window_seconds=0)

    limiter = RedisRateLimiter(mock_redis, max_requests=2, window_seconds=10)
    assert limiter.cleanup() == 0

    # Check OK (count <= max)
    mock_script.return_value = [1, 10.0]
    limiter.check("key1")

    # Check fail (count > max)
    mock_script.return_value = [3, 9.5]
    with pytest.raises(RateLimitExceededError):
        limiter.check("key1")

    # Check fail (ttl < 0)
    mock_script.return_value = [3, -1.0]
    with pytest.raises(RateLimitExceededError):
        limiter.check("key1")

    # Max <= 0 branch
    zero_lim = RedisRateLimiter(mock_redis, max_requests=0)
    with pytest.raises(RateLimitExceededError):
        zero_lim.check("key2")

    # Reset
    limiter.reset("key1")
    mock_redis.delete.assert_called_with("uxsp:ratelimit:key1")

@pytest.mark.asyncio
async def test_async_redis_rate_limiter():
    mock_redis = AsyncMock()
    mock_script = AsyncMock()
    mock_redis.register_script = MagicMock(return_value=mock_script)

    with pytest.raises(ValueError):
        AsyncRedisRateLimiter(mock_redis, max_requests=-1)
    with pytest.raises(ValueError):
        AsyncRedisRateLimiter(mock_redis, window_seconds=0)

    limiter = AsyncRedisRateLimiter(mock_redis, max_requests=2, window_seconds=10)
    assert await limiter.cleanup() == 0

    # Check OK
    mock_script.return_value = [1, 10.0]
    await limiter.check("key1")

    # Check fail
    mock_script.return_value = [3, 9.5]
    with pytest.raises(RateLimitExceededError):
        await limiter.check("key1")

    mock_script.return_value = [3, -1.0]
    with pytest.raises(RateLimitExceededError):
        await limiter.check("key1")

    zero_lim = AsyncRedisRateLimiter(mock_redis, max_requests=0)
    with pytest.raises(RateLimitExceededError):
        await zero_lim.check("key2")

    await limiter.reset("key1")
    mock_redis.delete.assert_called_with("uxsp:ratelimit:key1")

def test_redis_sliding_rate_limiter():
    mock_redis = MagicMock()
    mock_script = MagicMock()
    mock_redis.register_script.return_value = mock_script

    with pytest.raises(ValueError):
        RedisSlidingRateLimiter(mock_redis, max_requests=-1)
    with pytest.raises(ValueError):
        RedisSlidingRateLimiter(mock_redis, window_seconds=0)

    limiter = RedisSlidingRateLimiter(mock_redis, max_requests=2, window_seconds=10)
    assert limiter.cleanup() == 0

    # OK (-1)
    mock_script.return_value = b"-1"
    limiter.check("key1")

    mock_script.return_value = "-1"
    limiter.check("key1")

    # Fail (positive float)
    mock_script.return_value = b"5.5"
    with pytest.raises(RateLimitExceededError):
        limiter.check("key1")

    limiter.reset("key1")
    mock_redis.delete.assert_called_with("uxsp:sliding:key1")

@pytest.mark.asyncio
async def test_async_redis_sliding_rate_limiter():
    mock_redis = AsyncMock()
    mock_script = AsyncMock()
    mock_redis.register_script = MagicMock(return_value=mock_script)

    with pytest.raises(ValueError):
        AsyncRedisSlidingRateLimiter(mock_redis, max_requests=-1)
    with pytest.raises(ValueError):
        AsyncRedisSlidingRateLimiter(mock_redis, window_seconds=0)

    limiter = AsyncRedisSlidingRateLimiter(mock_redis, max_requests=2, window_seconds=10)
    assert await limiter.cleanup() == 0

    mock_script.return_value = b"-1"
    await limiter.check("key1")

    mock_script.return_value = b"5.5"
    with pytest.raises(RateLimitExceededError):
        await limiter.check("key1")

    await limiter.reset("key1")
    mock_redis.delete.assert_called_with("uxsp:sliding:key1")

@pytest.mark.asyncio
async def test_async_guarded_handshake():
    responder = Identity.create("test", "SERVER")
    initiator = Identity.create("test", "CLIENT")
    card = initiator.public_card()

    mock_limiter = AsyncMock()
    mock_nonce_store = AsyncMock()
    mock_nonce_store.is_seen.return_value = False

    guard = AsyncGuardedHandshake(mock_limiter, responder, mock_nonce_store)

    # Invalid hello
    with pytest.raises(ValueError, match="Invalid HELLO format"):
        await guard.respond({"v": 2}, card)

    # Invalid nonce
    with pytest.raises(ValueError, match="Invalid or missing initiator nonce"):
        await guard.respond({"v": 1}, card)

    # Replay
    mock_nonce_store.is_seen.return_value = True
    with pytest.raises(ValueError, match="Replay detected"):
        await guard.respond({"v": 1, "n": "nonce123"}, card)

    # Success mock
    mock_nonce_store.is_seen.return_value = False
    with pytest.raises(Exception): # noqa: B017 # Because the handshake itself is invalid without real crypto fields
        await guard.respond({"v": 1, "n": "nonce123"}, card)

    mock_limiter.check.assert_called_with(card.entity_id)
    mock_nonce_store.is_seen.assert_called_with("nonce123")
