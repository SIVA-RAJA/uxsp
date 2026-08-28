from __future__ import annotations

from collections.abc import Generator, Iterable
from pathlib import Path
from typing import Any, BinaryIO

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._errors import SecureSendError
from uxsp.secure._package import SecurePackage
from uxsp.secure.types.binary import SendBinary, ReceiveBinary

def _iter_chunks_from_source(
    source: str | Path | BinaryIO | Iterable[bytes],
    chunk_size: int = 64 * 1024,
) -> Generator[bytes, None, None]:
    """Stream raw byte chunks from a file path, file descriptor, or byte generator."""
    if isinstance(source, (str, Path)):
        p = Path(source)
        if not p.is_file():
            raise SecureSendError(f"File not found: {source}")
        with open(p, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    elif hasattr(source, "read") and callable(source.read):
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            yield chunk
    elif isinstance(source, Iterable):
        for item in source:
            if item:
                yield bytes(item)
    else:
        raise SecureSendError("Source must be a file path, file descriptor (BinaryIO), or byte iterable.")


def SendStream(
    stream_or_path: str | Path | BinaryIO | Iterable[bytes],
    *,
    receiver_id: str | int | PublicCard | Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    chunk_size: int = 64 * 1024,
    filename: str | None = None,
    output_destination: str | Path | BinaryIO | None = None,
    metadata: dict[str, Any] | None = None,
    data_type: str = "binary",
) -> Generator[SecurePackage, None, None] | Path | BinaryIO:
    """
    Encrypt and stream multi-gigabyte files or binary data generators chunk-by-chunk.

    Memory footprint is strictly O(chunk_size) to process 10GB+ files without high RAM usage.

    If output_destination is provided (file path or writable file descriptor), serializes line-delimited
    JSON packages directly to the output file/stream and returns output_destination.
    Otherwise, returns a Generator yielding SecurePackage objects chunk-by-chunk.
    """
    fname = filename
    if isinstance(stream_or_path, (str, Path)):
        fname = fname or Path(stream_or_path).name

    chunk_gen = _iter_chunks_from_source(stream_or_path, chunk_size=chunk_size)

    def _package_generator() -> Generator[SecurePackage, None, None]:
        has_yielded = False
        for chunk_idx, chunk_bytes in enumerate(chunk_gen):
            has_yielded = True
            chunk_meta = {
                "stream_chunk_index": chunk_idx,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = SendBinary(
                receiver_id=receiver_id,
                data=chunk_bytes,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                filename=fname,
                metadata=chunk_meta,
            )
            pkg.data_type = data_type
            yield pkg

        if not has_yielded:
            chunk_meta = {
                "stream_chunk_index": 0,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = SendBinary(
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
        return _package_generator()

    if isinstance(output_destination, (str, Path)):
        out_p = Path(output_destination)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            for pkg in _package_generator():
                f.write(pkg.to_json() + "\n")
        return out_p
    elif hasattr(output_destination, "write"):
        dest: Any = output_destination
        for pkg in _package_generator():
            line = pkg.to_json() + "\n"
            try:
                dest.write(line)
            except TypeError:
                dest.write(line.encode("utf-8"))
        return output_destination
    else:
        raise SecureSendError("output_destination must be a file path or writable file descriptor.")


def ReceiveStream(
    packages_or_stream: Iterable[SecurePackage | str | bytes] | str | Path | BinaryIO,
    output_file: str | Path | BinaryIO,
    *,
    sender_id: str | int | PublicCard | Identity | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path | int:
    """
    Stream-decrypt incoming SecurePackage chunks and write decrypted bytes directly to disk or a file descriptor.

    Memory footprint is O(chunk_size), making it safe to process multi-gigabyte (10GB+) files.

    Returns Path to output_file (if path was given) or total bytes written (if file descriptor was given).
    """
    out_fp: Any = None
    close_out = False
    out_path = None

    if isinstance(output_file, (str, Path)):
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_fp = open(out_path, "wb")  # noqa: SIM115
        close_out = True
    elif hasattr(output_file, "write"):
        out_fp = output_file
    else:
        raise ValueError("output_file must be a file path or writable file descriptor.")

    total_bytes_written = 0

    try:
        def _iter_packages() -> Generator[SecurePackage, None, None]:
            if isinstance(packages_or_stream, (str, Path)):
                p = Path(packages_or_stream)
                with open(p, encoding="utf-8") as f:
                    for line_item in f:
                        line_str = line_item.strip()
                        if line_str:
                            yield SecurePackage.from_json(line_str)
            elif hasattr(packages_or_stream, "read"):
                stream_obj: Any = packages_or_stream
                for raw_line in stream_obj:
                    if isinstance(raw_line, bytes):
                        line_str = raw_line.decode("utf-8").strip()
                    else:
                        line_str = str(raw_line).strip()
                    if line_str:
                        yield SecurePackage.from_json(line_str)
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
                raise ValueError("packages_or_stream must be an iterable, file path, or file descriptor.")

        for pkg in _iter_packages():
            decrypted_chunk = ReceiveBinary(
                sender_id=sender_id,
                package=pkg,
                sender=sender,
                sender_card=sender_card,
                receiver=receiver,
                receiver_identity=receiver_identity,
            )
            if out_fp is not None:
                out_fp.write(decrypted_chunk)
            total_bytes_written += len(decrypted_chunk)

    finally:
        if close_out and out_fp is not None:
            out_fp.close()

    if out_path is not None:
        return out_path
    return total_bytes_written
