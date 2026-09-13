from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import uxsp
import uxsp.aio as aio
from uxsp import (
    DuplicateMessageError,
    Identity,
    ReceiveText,
    SecurePackage,
    SecureReceiveError,
    SendFile,
    SendText,
)
from uxsp.client import UXSPClient
from uxsp.core.replay import DuplicateNonceError, ReplayGuard
from uxsp.storage.keystore import MemoryKeyStore
from uxsp.storage.noncestore import MemoryNonceStore


def test_send_file_return_type_consistency(tmp_path: Path):
    sender = Identity.create("Alice", role="CLIENT")
    receiver = Identity.create("Bob", role="SERVER")

    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello world payload")

    # Default stream=False returns SecurePackage
    pkg = SendFile(
        receiver=receiver.public_card(),
        file_path_or_bytes=test_file,
        sender=sender,
    )
    assert isinstance(pkg, SecurePackage)
    assert not hasattr(pkg, "__next__")

    # Explicit stream=True returns a generator / stream
    stream_gen = SendFile(
        receiver=receiver.public_card(),
        file_path_or_bytes=test_file,
        sender=sender,
        stream=True,
    )
    assert hasattr(stream_gen, "__iter__") or hasattr(stream_gen, "__next__")
    chunks = list(stream_gen)
    assert len(chunks) >= 1
    assert isinstance(chunks[0], SecurePackage)


def test_send_file_large_returns_secure_package_when_not_streaming(tmp_path: Path):
    sender = Identity.create("Alice", role="CLIENT")
    receiver = Identity.create("Bob", role="SERVER")

    test_file = tmp_path / "large_mock.bin"
    test_file.write_bytes(b"A" * 1024)

    # Mock st_size > 64MB using real os.stat_result
    import os
    orig_stat = Path.stat

    def mock_stat(self, *args, **kwargs):
        st = orig_stat(self, *args, **kwargs)
        if self == test_file:
            vals = list(st)
            vals[6] = 70 * 1024 * 1024  # 70 MB
            return os.stat_result(vals)
        return st

    with patch.object(Path, "stat", mock_stat):
        # When stream=False, should NOT convert to generator, must return SecurePackage!
        pkg = SendFile(
            receiver=receiver.public_card(),
            file_path_or_bytes=test_file,
            sender=sender,
            stream=False,
        )
        assert isinstance(pkg, SecurePackage)

        # When stream=True, returns generator
        stream_res = SendFile(
            receiver=receiver.public_card(),
            file_path_or_bytes=test_file,
            sender=sender,
            stream=True,
        )
        assert hasattr(stream_res, "__iter__")


@pytest.mark.asyncio
async def test_async_send_file_return_type_consistency(tmp_path: Path):
    sender = await aio.create_identity("Alice", role="CLIENT")
    receiver = await aio.create_identity("Bob", role="SERVER")

    test_file = tmp_path / "async_test.bin"
    test_file.write_bytes(b"async content")

    pkg = await aio.SendFile(
        receiver=receiver.public_card(),
        file_path_or_bytes=test_file,
        sender=sender,
    )
    assert isinstance(pkg, SecurePackage)

    out_file = await aio.ReceiveFile(
        sender=sender.public_card(),
        package=pkg,
        receiver=receiver,
        download_path=tmp_path / "downloaded.bin",
    )
    assert out_file.read_bytes() == b"async content"


def test_aio_configure_synchronous():
    """Verify uxsp.aio.configure(...) works synchronously without requiring await."""
    alice = Identity.create("SyncAlice", role="CLIENT")
    keystore = MemoryKeyStore()
    noncestore = MemoryNonceStore()
    guard = ReplayGuard(noncestore)

    # Calling synchronously without await
    res = aio.configure(
        identity=alice,
        keystore=keystore,
        noncestore=noncestore,
        replay_guard=guard,
    )
    assert res is not None

    ctx = aio.get_context()
    # Context should immediately reflect sync config
    assert ctx._sync_context._identity.entity_id == alice.entity_id
    assert ctx._sync_context._keystore is keystore
    assert ctx._sync_context._noncestore is noncestore


@pytest.mark.asyncio
async def test_aio_configure_awaitable():
    """Verify await uxsp.aio.configure(...) works cleanly with await."""
    bob = await aio.create_identity("AsyncBob", role="SERVER")
    keystore = MemoryKeyStore()

    await aio.configure(
        identity=bob,
        keystore=keystore,
    )

    ctx = await aio.get_context()
    ident = await ctx.get_identity()
    assert ident.entity_id == bob.entity_id


def test_developer_friendly_error_messages():
    sender = Identity.create("Alice", role="CLIENT")
    receiver = Identity.create("Bob", role="SERVER")

    guard = ReplayGuard(MemoryNonceStore(), window_seconds=60)
    uxsp.configure(identity=receiver, replay_guard=guard)

    pkg = SendText(receiver=receiver.public_card(), text="Test replay", sender=sender)

    # First receive succeeds
    msg = ReceiveText(sender=sender.public_card(), package=pkg, receiver=receiver)
    assert msg == "Test replay"

    # Second receive raises developer-friendly DuplicateMessageError
    with pytest.raises(DuplicateMessageError) as exc_info:
        ReceiveText(sender=sender.public_card(), package=pkg, receiver=receiver)

    err_str = str(exc_info.value)
    assert "Message already processed (duplicate)" in err_str
    # Must also be catchable as SecureReceiveError and DuplicateNonceError
    assert isinstance(exc_info.value, SecureReceiveError)
    assert isinstance(exc_info.value, DuplicateNonceError)


def test_client_fetch_with_json_parameter():
    client = UXSPClient(allow_fallback=True)

    with patch.object(client, "_raw_send", return_value=(200, {"content-type": "application/json"}, b'{"status": "ok"}')) as mock_send:
        # User passes json={"key": "value"}
        resp = client.fetch("https://api.example.com/data", method="POST", json={"key": "value"})
        assert resp.status_code == 200
        mock_send.assert_called_once()
        args, kwargs = mock_send.call_args
        # Content sent should be utf-8 json
        assert b'{"key": "value"}' in args[3]
