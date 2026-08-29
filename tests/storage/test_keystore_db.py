from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from uxsp.core.identity import Identity
from uxsp.storage.keystore import (
    AsyncKeyStore,
    AsyncRedisKeyStore,
    CardNotFoundError,
    DuplicateCardError,
    KeyStoreBackendError,
)


class DummyAsyncKeyStore(AsyncKeyStore):
    def __init__(self):
        self._store = {}

    async def put(self, card, overwrite=True):
        from uxsp.storage.keystore import _entity_id
        self._store[_entity_id(card)] = card

    async def get(self, entity_id):
        return self._store.get(entity_id)

    async def delete(self, entity_id):
        if entity_id in self._store:
            del self._store[entity_id]
            return True
        return False

    async def list_ids(self):
        return list(self._store.keys())

@pytest.mark.asyncio
async def test_async_keystore_base_methods():
    ks = DummyAsyncKeyStore()

    # put_many
    id1 = Identity.create("test", "USER")
    id2 = Identity.create("test", "USER")
    await ks.put_many([id1.public_card(), id2.public_card()])

    assert await ks.has(id1.entity_id) is True
    assert await ks.has("nonexistent") is False

    # require
    card = await ks.require(id1.entity_id)
    assert card.entity_id == id1.entity_id

    with pytest.raises(CardNotFoundError):
        await ks.require("nonexistent")

    # public_card (PublicCard branch)
    pc = await ks.public_card(id1.entity_id)
    assert pc.entity_id == id1.entity_id

    # public_card (SignedCard branch)
    import time
    import uuid

    from uxsp.core.signing import SignedCard
    signed = SignedCard(
        card=id1.public_card(),
        cert_id=str(uuid.uuid4()),
        issuer_id="test",
        issuer_name="test",
        not_before=int(time.time()),
        not_after=int(time.time()) + 3600,
        classical_sig=b"123",
        pqc_sig=b"456"
    )
    await ks.put(signed)
    pc2 = await ks.public_card(signed.card.entity_id)
    assert pc2.entity_id == signed.card.entity_id

@pytest.mark.asyncio
async def test_async_redis_keystore():
    mock_redis = AsyncMock()
    ks = AsyncRedisKeyStore(mock_redis, ttl=100)

    id1 = Identity.create("test", "USER")
    card = id1.public_card()

    # Put (success)
    mock_redis.set.return_value = True
    await ks.put(card, overwrite=False)
    assert mock_redis.set.called

    # Put (overwrite=False duplicate)
    mock_redis.set.return_value = False
    with pytest.raises(DuplicateCardError):
        await ks.put(card, overwrite=False)

    # Put (overwrite=True, ttl > 0)
    await ks.put(card, overwrite=True)

    # Put (overwrite=True, ttl <= 0)
    ks_no_ttl = AsyncRedisKeyStore(mock_redis, ttl=0)
    await ks_no_ttl.put(card, overwrite=True)

    # Put (exception)
    mock_redis.set.side_effect = ConnectionError("redis down")
    with pytest.raises(KeyStoreBackendError):
        await ks.put(card)
    mock_redis.set.side_effect = None

    # Get (success)
    from uxsp.storage.keystore import _serialise_card
    mock_redis.get.return_value = json.dumps(_serialise_card(card)).encode()
    res = await ks.get(card.entity_id)
    assert res.entity_id == card.entity_id

    # Get (None)
    mock_redis.get.return_value = None
    assert await ks.get("not_there") is None

    # Get (exception generic)
    mock_redis.get.side_effect = ConnectionError("redis down")
    with pytest.raises(KeyStoreBackendError):
        await ks.get(card.entity_id)

    # Get (KeyStoreError passthrough)
    from uxsp.storage.keystore import KeyStoreError
    mock_redis.get.side_effect = KeyStoreError("already a keystore error")
    with pytest.raises(KeyStoreError, match="already a keystore error"):
        await ks.get(card.entity_id)
    mock_redis.get.side_effect = None

    # Delete
    mock_redis.delete.return_value = 1
    assert await ks.delete(card.entity_id) is True
    mock_redis.delete.side_effect = ConnectionError("redis down")
    with pytest.raises(KeyStoreBackendError):
        await ks.delete(card.entity_id)
    mock_redis.delete.side_effect = KeyStoreError("ks error")
    with pytest.raises(KeyStoreError):
        await ks.delete(card.entity_id)
    mock_redis.delete.side_effect = None

    # List IDs
    mock_redis.scan.side_effect = [
        (1, [b"uxsp:cards:id1", b"uxsp:cards:id2"]),
        (0, [b"uxsp:cards:id3"])
    ]
    ids = await ks.list_ids()
    assert ids == ["id1", "id2", "id3"]

    mock_redis.scan.side_effect = ConnectionError("redis down")
    with pytest.raises(KeyStoreBackendError):
        await ks.list_ids()
    mock_redis.scan.side_effect = KeyStoreError("ks error")
    with pytest.raises(KeyStoreError):
        await ks.list_ids()

    # Serialize SignedCard and Unknown Card Type
    import time
    import uuid

    from uxsp.core.signing import SignedCard
    from uxsp.storage.keystore import _deserialise_card, _serialise_card
    signed = SignedCard(
        card=card,
        cert_id=str(uuid.uuid4()),
        issuer_id="test",
        issuer_name="test",
        not_before=int(time.time()),
        not_after=int(time.time()) + 3600,
        classical_sig=b"123",
        pqc_sig=b"456"
    )

    # Test SignedCard
    s_raw = _serialise_card(signed)
    assert s_raw["type"] == "signed"
    mock_redis.get.return_value = json.dumps(s_raw).encode()
    s_restored = await ks.get(signed.card.entity_id)
    assert s_restored.card.entity_id == signed.card.entity_id

    # Test unknown card type
    with pytest.raises(KeyStoreError, match="Unknown card type"):
        _deserialise_card({"type": "magic"})
