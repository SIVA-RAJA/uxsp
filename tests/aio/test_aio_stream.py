"""
Tests for UXSP Native Async Streaming (`uxsp.aio.stream`)
"""

import pytest

import uxsp
import uxsp.aio


@pytest.fixture
def alice_identity():
    return uxsp.create_identity("Alice", role="CLIENT")


@pytest.fixture
def bob_identity():
    return uxsp.create_identity("Bob", role="SERVER")


@pytest.mark.asyncio
async def test_async_stream_send_and_receive_bytes(alice_identity, bob_identity):
    payload = b"A" * 100000  # 100 KB payload to force multiple chunks

    # 1. Collect stream packages asynchronously
    packages = []
    async for pkg in uxsp.aio.stream_send_chunks(
        payload,
        chunk_size=16384,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    ):
        assert pkg is not None
        packages.append(pkg)

    assert len(packages) > 1

    # 2. Receive and reassemble stream packages asynchronously (AsyncIterable)
    async def package_generator():
        for p in packages:
            yield p

    reassembled = await uxsp.aio.stream_receive_chunks(
        package_generator(),
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert reassembled == payload


@pytest.mark.asyncio
async def test_async_stream_send_and_receive_file(tmp_path, alice_identity, bob_identity):
    f = tmp_path / "large_asset.bin"
    large_data = b"STREAMING_BINARY_DATA_" * 5000
    f.write_bytes(large_data)

    # 1. Stream chunks from file path
    packages = []
    async for pkg in uxsp.aio.stream_send_chunks(
        f,
        chunk_size=32768,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    ):
        packages.append(pkg)

    assert len(packages) > 1

    # 2. Receive and reassemble from list (Iterable)
    reassembled = await uxsp.aio.stream_receive_chunks(
        packages,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert reassembled == large_data


@pytest.mark.asyncio
async def test_async_stream_invalid_input(alice_identity, bob_identity):
    with pytest.raises(TypeError, match="data_or_path must be a file path"):
        async for _ in uxsp.aio.stream_send_chunks(
            12345,  # Invalid type
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        ):
            pass
