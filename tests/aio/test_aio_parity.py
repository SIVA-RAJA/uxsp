"""
Tests verifying feature parity between uxsp.secure and uxsp.aio
"""

from __future__ import annotations

from pathlib import Path

import pytest

import uxsp.aio as aio
from uxsp.core.identity import CardRevokedError, Identity
from uxsp.core.nonce import MemoryNonceStore
from uxsp.core.replay import ReplayGuard
from uxsp.secure import (
    CardExpiredError as SyncCardExpiredError,
)
from uxsp.secure import (
    CardRevokedError as SyncCardRevokedError,
)
from uxsp.secure import (
    PeerNotFoundError as SyncPeerNotFoundError,
)
from uxsp.secure import (
    SecureContext as SyncSecureContext,
)
from uxsp.secure import (
    SecureError as SyncSecureError,
)
from uxsp.secure import (
    SecurePackage as SyncSecurePackage,
)
from uxsp.secure import (
    SecureReceiveError as SyncSecureReceiveError,
)
from uxsp.secure import (
    SecureSendError as SyncSecureSendError,
)
from uxsp.secure import (
    TypeMismatchError as SyncTypeMismatchError,
)
from uxsp.storage.keystore import AsyncKeyStore, MemoryKeyStore


def test_reexported_classes_and_errors():
    # Classes
    assert aio.SecurePackage is SyncSecurePackage
    assert issubclass(aio.AsyncSecureContext, aio.SecureContext)
    assert aio.SecureContext is SyncSecureContext

    # Errors
    assert aio.SecureError is SyncSecureError
    assert aio.SecureSendError is SyncSecureSendError
    assert aio.SecureReceiveError is SyncSecureReceiveError
    assert aio.PeerNotFoundError is SyncPeerNotFoundError
    assert aio.TypeMismatchError is SyncTypeMismatchError
    assert aio.CardExpiredError is SyncCardExpiredError
    assert aio.CardRevokedError is SyncCardRevokedError

    # Inheritance sanity
    assert issubclass(aio.SecureSendError, aio.SecureError)
    assert issubclass(aio.SecureReceiveError, aio.SecureError)
    assert issubclass(aio.PeerNotFoundError, aio.SecureError)
    assert issubclass(aio.TypeMismatchError, aio.SecureReceiveError)


@pytest.mark.asyncio
async def test_async_create_identity():
    ident = await aio.create_identity("AsyncAlice", role="CLIENT")
    assert isinstance(ident, Identity)
    assert ident.name == "AsyncAlice"
    assert ident.role == "CLIENT"
    assert ident.public_card() is not None


@pytest.mark.asyncio
async def test_async_password_hashing():
    pw = "super_secret_password_123!"
    pw_hash = await aio.hash_password(pw)
    assert isinstance(pw_hash, str)
    assert "argon2id" in pw_hash

    valid = await aio.verify_password(pw_hash, pw)
    assert valid is True

    invalid = await aio.verify_password(pw_hash, "wrong_password")
    assert invalid is False


@pytest.mark.asyncio
async def test_async_identity_encryption_export_import():
    ident = await aio.create_identity("VaultUser", role="SERVER")
    passphrase = "backup-passphrase-456"

    enc_json = await aio.export_identity_encrypted(ident, passphrase)
    assert isinstance(enc_json, str)
    assert "encrypted_private" in enc_json

    imported = await aio.import_identity_encrypted(enc_json, passphrase)
    assert isinstance(imported, Identity)
    assert imported.entity_id == ident.entity_id
    assert imported.name == "VaultUser"

    with pytest.raises(ValueError):
        await aio.import_identity_encrypted(enc_json, "wrong-passphrase")


@pytest.mark.asyncio
async def test_async_configure_and_get_context(tmp_path):
    await aio.reset_context()

    alice = await aio.create_identity("Alice", role="CLIENT")
    hook_called = []

    def dummy_hook(pkg):
        hook_called.append(pkg)
        return pkg

    mem_keystore = MemoryKeyStore()
    mem_noncestore = MemoryNonceStore()
    replay_guard = ReplayGuard(mem_noncestore)

    await aio.configure(
        identity=alice,
        keystore=mem_keystore,
        noncestore=mem_noncestore,
        replay_guard=replay_guard,
        default_output_dir=tmp_path,
        transport_hook=dummy_hook,
    )

    ctx = await aio.get_context()
    assert isinstance(ctx, aio.AsyncSecureContext)
    assert isinstance(ctx, aio.SecureContext)

    cur_ident = await ctx.get_identity()
    assert cur_ident.entity_id == alice.entity_id
    assert ctx.keystore is mem_keystore
    assert ctx.noncestore is mem_noncestore
    assert ctx.replay_guard is replay_guard
    assert ctx.default_output_dir == tmp_path

    # Test dispatch_package with hook
    fake_pkg = aio.SecurePackage(
        sender_id=alice.entity_id,
        receiver_id="test",
        data_type="text",
        is_chunked=False,
    )
    res_pkg = ctx.dispatch_package(fake_pkg)
    assert res_pkg is fake_pkg
    assert len(hook_called) == 1

    await aio.reset_context()


@pytest.mark.asyncio
async def test_async_secure_context_standalone_and_async_keystore():
    class DummyAsyncKeyStore(AsyncKeyStore):
        def __init__(self):
            self.cards = {}
        async def put(self, card, overwrite=True):
            eid = card.entity_id
            if not overwrite and eid in self.cards:
                raise Exception("duplicate")
            self.cards[eid] = card
        async def get(self, entity_id):
            return self.cards.get(entity_id)
        async def delete(self, entity_id):
            return self.cards.pop(entity_id, None) is not None
        async def list_ids(self):
            return list(self.cards.keys())

    async_ks = DummyAsyncKeyStore()
    ctx = aio.AsyncSecureContext()

    bob = await aio.create_identity("Bob", role="SERVER")
    charlie = await aio.create_identity("Charlie", role="CLIENT")

    await ctx.configure(identity=bob, keystore=async_ks)
    assert ctx.identity.entity_id == bob.entity_id

    # Verify bob's card was placed in async_ks
    bob_card = await async_ks.get(bob.entity_id)
    assert bob_card is not None
    assert bob_card.entity_id == bob.entity_id

    # Register charlie
    await ctx.register_peer(charlie)
    charlie_card = await ctx.get_peer(charlie.entity_id)
    assert charlie_card.entity_id == charlie.entity_id

    # Peer not found
    with pytest.raises(aio.PeerNotFoundError):
        await ctx.get_peer("non_existent_entity_id")

    # Revoke peer
    revoked = await ctx.revoke_peer(charlie.entity_id, reason="compromised")
    assert revoked.is_revoked is True
    stored_charlie = await async_ks.get(charlie.entity_id)
    assert stored_charlie.is_revoked is True

    # set_identity on async context
    david = await aio.create_identity("David", role="CLIENT")
    await ctx.set_identity(david)
    assert (await ctx.get_identity()).entity_id == david.entity_id
    assert await async_ks.get(david.entity_id) is not None

    # Reset
    await ctx.reset()
    assert ctx.identity is None


@pytest.mark.asyncio
async def test_async_verify_peer_validity():
    await aio.reset_context()

    alice = await aio.create_identity("Alice", role="CLIENT")
    await aio.register_peer(alice.public_card())

    # Valid check via entity_id
    await aio.verify_peer_validity(alice.entity_id)
    # Valid check via card object
    await aio.verify_peer_validity(alice.public_card())
    # Valid check via identity object
    await aio.verify_peer_validity(alice)

    # Unknown card object verification
    stranger = await aio.create_identity("Stranger", role="CLIENT")
    await aio.verify_peer_validity(stranger.public_card())
    await aio.verify_peer_validity(stranger)

    # Unknown entity_id raises PeerNotFoundError
    with pytest.raises(aio.PeerNotFoundError):
        await aio.verify_peer_validity("non_existent_id")

    # Revoke and ensure verification raises CardRevokedError
    await aio.revoke_peer(alice.entity_id, reason="compromised")
    with pytest.raises(CardRevokedError):
        await aio.verify_peer_validity(alice.entity_id)

    # Test rotate_keys without arguments (rotates active context identity)
    rotated = await aio.rotate_keys()
    assert rotated is not None
    cur = await aio.get_identity()
    assert cur.entity_id == rotated.entity_id

    await aio.reset_context()


@pytest.mark.asyncio
async def test_async_context_signed_card_and_edge_cases():
    from unittest.mock import MagicMock

    from uxsp.core.signing import SignedCard

    class SignedDummyAsyncKeyStore(AsyncKeyStore):
        def __init__(self):
            self.cards = {}
        async def put(self, card, overwrite=True):
            self.cards[card.entity_id] = card
        async def get(self, entity_id):
            return self.cards.get(entity_id)
        async def delete(self, entity_id):
            return True
        async def list_ids(self):
            return list(self.cards.keys())

    ks = SignedDummyAsyncKeyStore()
    ctx = aio.AsyncSecureContext()
    await ctx.configure(keystore=ks)

    ident = await aio.create_identity("SignedPeer", role="SERVER")
    card = ident.public_card()
    # Wrap in SignedCard mock
    signed_card = MagicMock(spec=SignedCard)
    signed_card.card = card
    signed_card.entity_id = ident.entity_id
    await ks.put(signed_card)

    retrieved = await ctx.get_peer(ident.entity_id)
    assert retrieved is card

    # Test get_replay_guard and get_default_output_dir and transport_hook
    assert ctx.get_replay_guard() is not None
    assert isinstance(ctx.get_default_output_dir(), Path)
    assert ctx.transport_hook is None

    # Test _safe_put_card outside running loop
    from uxsp.secure._context import _safe_put_card
    mock_ks = MagicMock()
    async def dummy_coro():
        pass
    mock_ks.put.return_value = dummy_coro()
    # Calling in a thread where no event loop is set
    import threading
    def thread_target():
        _safe_put_card(mock_ks, card)
    t = threading.Thread(target=thread_target)
    t.start()
    t.join()

