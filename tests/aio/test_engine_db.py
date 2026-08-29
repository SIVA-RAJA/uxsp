from __future__ import annotations

import pytest

from uxsp.aio._engine import (
    _resolve_package_input,
    async_secure_receive_payload,
    async_secure_send_payload,
)
from uxsp.core.identity import Identity
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.secure._errors import SecureReceiveError, TypeMismatchError
from uxsp.storage.keystore import AsyncKeyStore
from uxsp.storage.noncestore import AsyncNonceStore


@pytest.fixture(autouse=True)
def reset_context_after_test():
    yield
    _GLOBAL_CONTEXT.reset()

class MockAsyncKeyStore(AsyncKeyStore):
    def __init__(self, card):
        self.card = card
    async def put(self, card, overwrite=True): pass
    async def get(self, entity_id): return self.card
    async def delete(self, entity_id): return True
    async def list_ids(self): return []

class MockAsyncNonceStore(AsyncNonceStore):
    def __init__(self):
        self.seen = set()
    async def mark_used(self, nonce, ttl_seconds=300):
        self.seen.add(nonce)
        return True
    async def is_seen(self, nonce):
        return nonce in self.seen
    async def cleanup(self): return 0

@pytest.mark.asyncio
async def test_engine_missing_receiver():
    with pytest.raises(ValueError, match="Receiver identity or receiver_id must be provided"):
        await async_secure_send_payload(payload_bytes=b"test")

@pytest.mark.asyncio
async def test_engine_missing_sender():
    with pytest.raises(ValueError, match="Sender identity/card or sender_id must be provided"):
        await async_secure_receive_payload(package_input={})

@pytest.mark.asyncio
async def test_engine_identity_and_async_keystore(tmp_path):
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")

    # Test identity target
    await async_secure_send_payload(receiver=receiver, payload_bytes=b"small", sender=sender)

    # Keystore async
    _GLOBAL_CONTEXT._keystore = MockAsyncKeyStore(receiver.public_card())
    await async_secure_send_payload(receiver_id=receiver.entity_id, payload_bytes=b"small", sender=sender)

    # Output file
    out = tmp_path / "pkg.uxsp"
    await async_secure_send_payload(receiver=receiver.public_card(), payload_bytes=b"test", sender=sender, output_file=out)
    assert out.exists()

@pytest.mark.asyncio
async def test_engine_chunked_send_and_receive():
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")

    # Chunked send (> 30KB)
    large_payload = b"A" * (40 * 1024)
    pkg = await async_secure_send_payload(receiver=receiver, payload_bytes=large_payload, sender=sender)

    assert pkg.is_chunked is True
    assert len(pkg.chunks) > 1

    # Receive chunked
    _GLOBAL_CONTEXT.set_identity(receiver)
    dec = await async_secure_receive_payload(
        sender_card=sender.public_card(),
        package_input=pkg,
    )
    assert dec == large_payload

@pytest.mark.asyncio
async def test_engine_async_noncestore():
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")
    pkg = await async_secure_send_payload(receiver=receiver, payload_bytes=b"test", sender=sender)

    from uxsp.core.replay import ReplayGuard
    store = MockAsyncNonceStore()
    _GLOBAL_CONTEXT._replay_guard = ReplayGuard(store)
    _GLOBAL_CONTEXT.set_identity(receiver)

    # Non-chunked
    dec = await async_secure_receive_payload(sender_card=sender.public_card(), package_input=pkg)
    assert dec == b"test"

    # Replay
    from uxsp.core.envelope import EnvelopeExpiredError
    with pytest.raises(EnvelopeExpiredError, match="Replay detected"):
        await async_secure_receive_payload(sender_card=sender.public_card(), package_input=pkg)

    # Chunked
    store2 = MockAsyncNonceStore()
    _GLOBAL_CONTEXT._replay_guard = ReplayGuard(store2)
    large_payload = b"B" * (40 * 1024)
    pkg_large = await async_secure_send_payload(receiver=receiver, payload_bytes=large_payload, sender=sender)

    dec_large = await async_secure_receive_payload(sender_card=sender.public_card(), package_input=pkg_large)
    assert dec_large == large_payload

    with pytest.raises(EnvelopeExpiredError, match="Replay detected"):
        await async_secure_receive_payload(sender_card=sender.public_card(), package_input=pkg_large)

@pytest.mark.asyncio
async def test_engine_resolve_input(tmp_path):
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")
    pkg = await async_secure_send_payload(receiver=receiver, payload_bytes=b"test", sender=sender)

    # bytes
    pkg_bytes = pkg.to_json().encode()
    assert _resolve_package_input(pkg_bytes).sender_id == sender.entity_id

    # string dict
    assert _resolve_package_input(pkg.to_json()).sender_id == sender.entity_id

    # file
    out = tmp_path / "pkg.uxsp"
    pkg.save(out)
    assert _resolve_package_input(out).sender_id == sender.entity_id

    # dict
    assert _resolve_package_input(pkg.to_dict()).sender_id == sender.entity_id

    # errors
    with pytest.raises(SecureReceiveError, match="Package file not found"):
        _resolve_package_input("not_a_file.uxsp")

    with pytest.raises(SecureReceiveError, match="Cannot resolve package from input of type int"):
        _resolve_package_input(123)

@pytest.mark.asyncio
async def test_engine_receive_errors():
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")
    pkg = await async_secure_send_payload(receiver=receiver, payload_bytes=b"test", sender=sender, data_type="photo")

    _GLOBAL_CONTEXT.set_identity(receiver)
    _GLOBAL_CONTEXT._keystore = MockAsyncKeyStore(sender.public_card())

    # async keystore get sender
    dec = await async_secure_receive_payload(sender_id=sender.entity_id, package_input=pkg)
    assert dec == b"test"

    # sender mismatch
    with pytest.raises(SecureReceiveError, match="Sender ID mismatch"):
        await async_secure_receive_payload(sender_id="other", package_input=pkg)

    # receiver mismatch
    fake_receiver = Identity.create("test", "USER")
    with pytest.raises(SecureReceiveError, match="Receiver ID mismatch"):
        await async_secure_receive_payload(sender=sender, package_input=pkg, receiver=fake_receiver)

    # type mismatch
    with pytest.raises(TypeMismatchError):
        await async_secure_receive_payload(sender=sender, package_input=pkg, expected_type="video")

    # Missing envelope
    pkg.envelope = None
    with pytest.raises(SecureReceiveError, match="missing envelope"):
        await async_secure_receive_payload(sender=sender, package_input=pkg)

    # Chunked missing chunks
    pkg2 = await async_secure_send_payload(receiver=receiver, payload_bytes=b"A" * 40000, sender=sender)
    pkg2.chunks = []
    with pytest.raises(SecureReceiveError, match="contains no chunks"):
        await async_secure_receive_payload(sender=sender, package_input=pkg2)

    # Chunked missing envelope
    pkg3 = await async_secure_send_payload(receiver=receiver, payload_bytes=b"A" * 40000, sender=sender)
    pkg3.envelope = None
    with pytest.raises(SecureReceiveError, match="missing session key envelope"):
        await async_secure_receive_payload(sender=sender, package_input=pkg3)

@pytest.mark.asyncio
async def test_engine_sync_keystore_string_ids():
    sender = Identity.create("test_sync_sender", "USER")
    receiver = Identity.create("test_sync_receiver", "USER")

    # Use sync keystore
    _GLOBAL_CONTEXT.set_identity(sender)
    _GLOBAL_CONTEXT._keystore.put(receiver.public_card())

    # Send using string id for receiver
    pkg = await async_secure_send_payload(receiver=receiver.entity_id, payload_bytes=b"sync_test", sender=sender)

    # Receive using string id for sender
    _GLOBAL_CONTEXT.set_identity(receiver)
    _GLOBAL_CONTEXT._keystore.put(sender.public_card())
    dec = await async_secure_receive_payload(sender_id=sender.entity_id, package_input=pkg)
    assert dec == b"sync_test"
