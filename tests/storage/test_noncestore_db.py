from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from uxsp.storage.noncestore import (
    AsyncRedisNonceStore,
    UXSPStoreError,
)


@pytest.mark.asyncio
async def test_async_redis_noncestore():
    mock_redis = AsyncMock()
    store = AsyncRedisNonceStore(mock_redis)

    # mark_used (success)
    mock_redis.set.return_value = True
    assert await store.mark_used("nonce1") is True

    # mark_used (already exists)
    mock_redis.set.return_value = False
    assert await store.mark_used("nonce1") is False

    # mark_used (exception)
    mock_redis.set.side_effect = ConnectionError("redis down")
    with pytest.raises(UXSPStoreError, match="Replay protection cannot be guaranteed"):
        await store.mark_used("nonce2")
    mock_redis.set.side_effect = None

    # is_seen (true)
    mock_redis.exists.return_value = 1
    assert await store.is_seen("nonce1") is True

    # is_seen (false)
    mock_redis.exists.return_value = 0
    assert await store.is_seen("nonce3") is False

    # is_seen (exception)
    mock_redis.exists.side_effect = ConnectionError("redis down")
    with pytest.raises(UXSPStoreError, match="Async Nonce store unavailable"):
        await store.is_seen("nonce4")
    mock_redis.exists.side_effect = None

    # cleanup
    assert await store.cleanup() == 0
