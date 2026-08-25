"""
UXSP Async Streaming Module (`uxsp.aio.stream`)

Provides non-blocking chunked streaming helpers for high-throughput ASGI and WebSocket
applications. Enables streaming large files and datasets concurrently across thousands
of non-blocking async connections.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable, AsyncIterator, Iterable
from pathlib import Path
from typing import Any

from uxsp.core.chunking import create_chunked_transfer, reassemble_chunked_transfer
from uxsp.core.identity import Identity, PublicCard
from uxsp.secure import SecurePackage


async def stream_send_chunks(
    data_or_path: bytes | bytearray | str | Path,
    *,
    chunk_size: int = 32768,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    filename: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AsyncIterator[SecurePackage]:
    """
    Async generator that splits large binary data or file assets into individual chunks,
    encrypts and signs each chunk in a threadpool, and yields `SecurePackage` objects.

    Yields:
        SecurePackage: Encrypted package representing an individual chunk.
    """
    if isinstance(data_or_path, (str, Path)):
        p = Path(data_or_path)
        fname = filename or p.name
        raw_bytes = await asyncio.to_thread(p.read_bytes)
    elif isinstance(data_or_path, (bytes, bytearray)):
        fname = filename or "stream.bin"
        raw_bytes = bytes(data_or_path)
    else:
        raise TypeError("data_or_path must be a file path, bytes, or bytearray.")

    # Create chunked transfer metadata & raw chunk items (list of bytes)
    chunks = await asyncio.to_thread(create_chunked_transfer, raw_bytes, chunk_size=chunk_size, filename=fname)

    total_chunks = len(chunks)
    for idx, chunk_bytes in enumerate(chunks):
        chunk_metadata = {
            "stream_chunk_index": idx,
            "stream_total_chunks": total_chunks,
            "stream_filename": fname,
            **(metadata or {}),
        }

        # Send chunk as binary payload asynchronously
        import uxsp.secure as sync_secure

        pkg = await asyncio.to_thread(
            sync_secure.SendBinary,
            data=chunk_bytes,
            receiver=receiver,
            sender=sender,
            metadata=chunk_metadata,
        )
        yield pkg


async def stream_receive_chunks(
    chunk_packages: AsyncIterable[Any] | Iterable[Any],
    *,
    sender: str | int | PublicCard | Identity | None = None,
    receiver: Identity | None = None,
) -> bytes:
    """
    Asynchronously iterates over encrypted stream `SecurePackage` chunks, decrypts
    each chunk in a threadpool, and reassembles the complete binary data payload.

    Returns:
        bytes: Reassembled binary payload.
    """
    import uxsp.secure as sync_secure

    raw_chunks: list[bytes] = []

    if isinstance(chunk_packages, AsyncIterable):
        async for item in chunk_packages:
            chunk_bytes = await asyncio.to_thread(
                sync_secure.ReceiveBinary,
                package=item,
                sender=sender,
                receiver=receiver,
            )
            raw_chunks.append(chunk_bytes)
    else:
        for item in chunk_packages:
            chunk_bytes = await asyncio.to_thread(
                sync_secure.ReceiveBinary,
                package=item,
                sender=sender,
                receiver=receiver,
            )
            raw_chunks.append(chunk_bytes)

    _, reassembled = await asyncio.to_thread(reassemble_chunked_transfer, raw_chunks)
    return reassembled
