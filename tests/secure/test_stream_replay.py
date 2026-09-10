"""
Tests for multi-chunk streaming with ReplayGuard active.
Verifies that each stream chunk gets a distinct envelope nonce and does not cause false replay rejections.
"""

import io

import pytest

from uxsp import Identity, ReceiveStream, SendStream
from uxsp.core.nonce import MemoryNonceStore
from uxsp.core.replay import DuplicateNonceError, ReplayGuard
from uxsp.secure._context import _GLOBAL_CONTEXT


@pytest.fixture(autouse=True)
def reset_context():
    yield
    _GLOBAL_CONTEXT.reset()


def test_multichunk_streaming_with_active_replay_guard():
    sender = Identity.create("Alice", role="USER")
    receiver = Identity.create("Bob", role="USER")

    # Configure an active ReplayGuard in global context
    store = MemoryNonceStore()
    guard = ReplayGuard(store, window_seconds=60)
    _GLOBAL_CONTEXT._replay_guard = guard

    data = b"CHUNK_DATA_1234567890_" * 1000  # ~23 KB
    chunk_size = 4096

    # Generate stream chunks
    packages = list(
        SendStream(
            stream_or_path=io.BytesIO(data),
            sender=sender,
            receiver=receiver.public_card(),
            chunk_size=chunk_size,
        )
    )

    assert len(packages) > 1

    # Verify each chunk has a distinct envelope nonce
    nonces = [pkg.envelope["envelope_nonce"] for pkg in packages]
    assert len(nonces) == len(set(nonces)), "Each chunk envelope must have a unique nonce"

    # Consume stream through ReceiveStream with active replay guard
    out = io.BytesIO()
    written = ReceiveStream(
        packages_or_stream=packages,
        output_file=out,
        sender=sender.public_card(),
        receiver=receiver,
    )

    assert written == len(data)
    assert out.getvalue() == data

    # Attempting to replay any package must trigger DuplicateNonceError
    with pytest.raises(DuplicateNonceError):
        ReceiveStream(
            packages_or_stream=[packages[0]],
            output_file=io.BytesIO(),
            sender=sender.public_card(),
            receiver=receiver,
        )
