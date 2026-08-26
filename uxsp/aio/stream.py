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
from typing import Any, cast

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


# ── MULTI-GIGABYTE ASYNC FILE STREAMING ────────────────────────


async def _async_iter_chunks_from_source(
    source: str | Path | Any,
    chunk_size: int = 64 * 1024,
) -> AsyncIterator[bytes]:
    """Asynchronously yield byte chunks from a file path, file descriptor, or generator."""
    if isinstance(source, (str, Path)):
        p = Path(source)
        if not await asyncio.to_thread(p.is_file):
            raise TypeError(f"File not found: {source}")

        f = await asyncio.to_thread(open, p, "rb")
        try:
            while True:
                chunk = await asyncio.to_thread(f.read, chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            await asyncio.to_thread(f.close)

    elif hasattr(source, "read") and callable(source.read):
        while True:
            chunk = await asyncio.to_thread(source.read, chunk_size)
            if not chunk:
                break
            yield chunk

    elif isinstance(source, AsyncIterable):
        async for chunk_item in source:
            if chunk_item:
                yield bytes(cast(Any, chunk_item))

    elif isinstance(source, Iterable):
        for chunk_item in source:
            if chunk_item:
                yield bytes(cast(Any, chunk_item))

    else:
        raise TypeError("Source must be a file path, file descriptor, or byte generator.")


async def SendStream(
    stream_or_path: str | Path | Any,
    *,
    receiver_id: str | int | PublicCard | Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    chunk_size: int = 64 * 1024,
    filename: str | None = None,
    output_destination: str | Path | Any = None,
    metadata: dict[str, Any] | None = None,
) -> AsyncIterator[SecurePackage] | Path | Any:
    """
    Asynchronously encrypt and stream multi-gigabyte files or binary generators chunk-by-chunk.

    Memory footprint is strictly O(chunk_size), preventing event-loop blocking or high RAM usage.

    If output_destination is provided, asynchronously writes line-delimited JSON packages
    directly to disk/stream and returns output_destination.
    Otherwise, returns an AsyncIterator yielding SecurePackage objects chunk-by-chunk.
    """
    import uxsp.secure as sync_secure

    fname = filename
    if isinstance(stream_or_path, (str, Path)):
        fname = fname or Path(stream_or_path).name

    async def _async_package_generator() -> AsyncIterator[SecurePackage]:
        chunk_idx = 0
        has_yielded = False
        async for chunk_bytes in _async_iter_chunks_from_source(stream_or_path, chunk_size=chunk_size):
            has_yielded = True
            chunk_meta = {
                "stream_chunk_index": chunk_idx,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = await asyncio.to_thread(
                sync_secure.SendBinary,
                receiver_id=receiver_id,
                data=chunk_bytes,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                filename=fname,
                metadata=chunk_meta,
            )
            chunk_idx += 1
            yield pkg

        if not has_yielded:
            chunk_meta = {
                "stream_chunk_index": 0,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = await asyncio.to_thread(
                sync_secure.SendBinary,
                receiver_id=receiver_id,
                data=b"",
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                filename=fname,
                metadata=chunk_meta,
            )
            yield pkg

    if output_destination is None:
        return _async_package_generator()

    if isinstance(output_destination, (str, Path)):
        out_p = Path(output_destination)
        await asyncio.to_thread(out_p.parent.mkdir, parents=True, exist_ok=True)
        f = await asyncio.to_thread(open, out_p, "w", encoding="utf-8")
        try:
            async for pkg in _async_package_generator():
                line = pkg.to_json() + "\n"
                await asyncio.to_thread(f.write, line)
        finally:
            await asyncio.to_thread(f.close)
        return out_p

    elif hasattr(output_destination, "write"):
        async for pkg in _async_package_generator():
            line_data = pkg.to_json() + "\n"
            def _do_write(data: str = line_data) -> None:
                try:
                    output_destination.write(data)
                except TypeError:
                    output_destination.write(data.encode("utf-8"))
            await asyncio.to_thread(_do_write)
        return output_destination
    else:
        raise TypeError("output_destination must be a file path or writable file descriptor.")


async def ReceiveStream(
    packages_or_stream: AsyncIterable[Any] | Iterable[Any] | str | Path | Any,
    output_file: str | Path | Any,
    *,
    sender_id: str | int | PublicCard | Identity | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path | int:
    """
    Asynchronously stream-decrypt incoming SecurePackage chunks and write decrypted bytes
    directly to disk or a file descriptor.

    Memory footprint is O(chunk_size), preventing event-loop blocking or high RAM usage.

    Returns Path to output_file (if path was given) or total bytes written (if descriptor was given).
    """
    import uxsp.secure as sync_secure

    out_fp = None
    close_out = False
    out_path = None

    if isinstance(output_file, (str, Path)):
        out_path = Path(output_file)
        await asyncio.to_thread(out_path.parent.mkdir, parents=True, exist_ok=True)
        out_fp = await asyncio.to_thread(open, out_path, "wb")
        close_out = True
    elif hasattr(output_file, "write"):
        out_fp = output_file
    else:
        raise TypeError("output_file must be a file path or writable file descriptor.")

    total_bytes_written = 0

    try:
        async def _async_iter_packages() -> AsyncIterator[SecurePackage]:
            if isinstance(packages_or_stream, (str, Path)):
                p = Path(packages_or_stream)
                f = await asyncio.to_thread(open, p, "r", encoding="utf-8")
                try:
                    while True:
                        line = await asyncio.to_thread(f.readline)
                        if not line:
                            break
                        line_str = line.strip()
                        if line_str:
                            yield SecurePackage.from_json(line_str)
                finally:
                    await asyncio.to_thread(f.close)

            elif hasattr(packages_or_stream, "read"):
                stream_obj: Any = packages_or_stream
                while True:
                    line = await asyncio.to_thread(stream_obj.readline)
                    if not line:
                        break
                    if isinstance(line, bytes):
                        line_str = line.decode("utf-8").strip()
                    else:
                        line_str = line.strip()
                    if line_str:
                        yield SecurePackage.from_json(line_str)

            elif isinstance(packages_or_stream, AsyncIterable):
                async for item in packages_or_stream:
                    if isinstance(item, SecurePackage):
                        yield item
                    elif isinstance(item, (str, bytes)):
                        s = item.decode("utf-8") if isinstance(item, bytes) else item
                        s = s.strip()
                        if s:
                            yield SecurePackage.from_json(s)

            elif isinstance(packages_or_stream, Iterable):
                for item in packages_or_stream:
                    if isinstance(item, SecurePackage):
                        yield item
                    elif isinstance(item, (str, bytes)):
                        s = item.decode("utf-8") if isinstance(item, bytes) else item
                        s = s.strip()
                        if s:
                            yield SecurePackage.from_json(s)
            else:
                raise TypeError("packages_or_stream must be an async iterable, iterable, file path, or file descriptor.")

        async for pkg in _async_iter_packages():
            decrypted_chunk = await asyncio.to_thread(
                sync_secure.ReceiveBinary,
                sender_id=sender_id,
                package=pkg,
                sender=sender,
                sender_card=sender_card,
                receiver=receiver,
                receiver_identity=receiver_identity,
            )
            await asyncio.to_thread(out_fp.write, decrypted_chunk)
            total_bytes_written += len(decrypted_chunk)

    finally:
        if close_out and out_fp is not None:
            await asyncio.to_thread(out_fp.close)

    if out_path is not None:
        return out_path
    return total_bytes_written

