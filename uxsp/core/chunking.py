"""
uxsp.core.chunking — Large-payload Chunked Transfer

What this file does:
    Splits a large binary/text/file payload into smaller, individually signed
    and integrity-checked chunks that can each be encrypted separately and sent
    over any transport.  When all chunks arrive, the receiver reassembles them,
    verifies every per-chunk SHA-256 hash and the whole-file SHA-256 hash, and
    rejects the transfer if anything does not match.

    This is the right layer to use when a single payload exceeds the Envelope
    size limit (default 64 KiB).  Each chunk is produced as raw bytes via
    UXSPChunk.to_bytes() and is ready to be passed directly to
    session.encrypt() or Identity.seal_for().

Public surface:
    UXSPChunk              — Frozen dataclass representing one chunk.
    create_chunked_transfer — Split bytes into a list of serialised chunks.
    reassemble_chunked_transfer — Verify and join chunks back into original bytes.
    create_chunked_text    — Convenience wrapper for text (str → chunks).
    decode_chunked_text    — Convenience wrapper for text (chunks → str).
    ChunkingError / ChunkFormatError / ChunkValidationError — Exception hierarchy.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self, cast, get_args

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

ChunkKind = Literal["file", "binary", "text"]
_VALID_KINDS: frozenset[str] = frozenset(get_args(ChunkKind))

_MAGIC = b"UXSP-CHUNK-1"
_HEADER_LEN_BYTES = 4
_MAX_HEADER_LEN = 64 * 1024  # 64 KiB


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ChunkingError(Exception):
    """Base class for chunked-transfer errors."""


class ChunkFormatError(ChunkingError):
    """Packed chunk bytes are malformed."""


class ChunkValidationError(ChunkingError):
    """Packed chunk metadata or hashes are invalid."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: bytes | bytearray) -> str:
    """Return the SHA-256 digest of data as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def _validate_sha256_hex(value: object, field_name: str) -> str:
    """
    Validate that value is a 64-character lowercase hex string (SHA-256 digest).

    Centralises hex-string validation so it is not duplicated in __post_init__
    and from_bytes.  Returns the lower-cased hex string on success.
    Raises ChunkValidationError for any invalid value.
    """
    if not isinstance(value, str):
        raise ChunkValidationError(f"{field_name} must be a string.")
    if len(value) != 64:
        raise ChunkValidationError(f"{field_name} must be a 64-char hex string.")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise ChunkValidationError(f"{field_name} must be a valid hex string.") from None
    return value.lower()


def _require_non_negative_int(value: object, field_name: str) -> int:
    """Validate that value is a non-negative integer (booleans are rejected). Returns the int."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ChunkValidationError(f"{field_name} must be an int.")
    if value < 0:
        raise ChunkValidationError(f"{field_name} must be non-negative.")
    return value


# ---------------------------------------------------------------------------
# Core dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UXSPChunk:
    """
    Represents one chunk of a larger UXSP payload.

    What this class does:
        Holds all metadata and the raw body bytes for a single fragment of a
        chunked transfer.  The dataclass is frozen (immutable after creation) so
        that hashes stored in the fields cannot be accidentally mutated after
        validation.

        __post_init__ normalises and re-validates the SHA-256 hex strings as
        soon as an instance is constructed.

    Encryption:
        Each chunk is typically passed to session.encrypt() or
        Identity.seal_for() after calling to_bytes().  The receiver calls
        from_bytes() after decryption, which re-validates the chunk_hash_sha256
        against the actual body before returning an instance.

    Integrity hashes:
        - chunk_hash_sha256  — SHA-256 of this chunk's body alone.
        - file_hash_sha256   — SHA-256 of the complete reassembled file;
                               carried in every chunk so the receiver can verify
                               the whole transfer once all chunks arrive.
    """

    transfer_id: str
    chunk_index: int
    total_chunks: int
    file_hash_sha256: str
    chunk_hash_sha256: str
    kind: ChunkKind
    body: bytes
    filename: str | None = None
    content_type: str = "application/octet-stream"
    encoding: str | None = None

    def __post_init__(self) -> None:

        for field_name in ("file_hash_sha256", "chunk_hash_sha256"):
            normed = _validate_sha256_hex(getattr(self, field_name), field_name)
            object.__setattr__(self, field_name, normed)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Serialise this chunk into a binary wire format.

        Format: MAGIC (12 bytes) | header_len (4 bytes big-endian) | header JSON | body bytes.
        Raises ChunkValidationError if the header exceeds 64 KiB.
        """
        header: dict[str, Any] = {
            "transfer_id": self.transfer_id,
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
            "file_hash_sha256": self.file_hash_sha256,
            "chunk_hash_sha256": self.chunk_hash_sha256,
            "kind": self.kind,
            "filename": self.filename,
            "content_type": self.content_type,
            "encoding": self.encoding,
            "body_len": len(self.body),
        }
        header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        header_len = len(header_raw)
        if header_len > _MAX_HEADER_LEN:
            raise ChunkValidationError(
                f"Chunk header exceeds maximum allowed size ({_MAX_HEADER_LEN} bytes)."
            )
        return (
            _MAGIC
            + header_len.to_bytes(_HEADER_LEN_BYTES, byteorder="big")
            + header_raw
            + self.body
        )

    # ------------------------------------------------------------------
    # Deserialisation
    # ------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> Self:
        """
        Deserialise and fully validate a chunk from raw bytes.

        Steps performed:
          1. Check the MAGIC header prefix.
          2. Parse the JSON header and validate all required fields.
          3. Verify that the body length matches the declared body_len.
          4. Recompute the SHA-256 of the body and compare against chunk_hash_sha256.
          5. Construct and return a validated UXSPChunk instance.

        Raises ChunkFormatError if the binary structure is malformed.
        Raises ChunkValidationError if any field or hash is invalid.
        """

        if not isinstance(raw, (bytes, bytearray)):
            raise ChunkFormatError("Packed chunk must be bytes or bytearray.")
        buf = bytes(raw)

        min_len = len(_MAGIC) + _HEADER_LEN_BYTES
        if len(buf) < min_len:
            raise ChunkFormatError("Packed chunk is too short.")
        if not buf.startswith(_MAGIC):
            raise ChunkFormatError("Invalid chunk magic header.")

        idx = len(_MAGIC)
        header_len = int.from_bytes(buf[idx : idx + _HEADER_LEN_BYTES], byteorder="big")
        if header_len > _MAX_HEADER_LEN:
            raise ChunkFormatError(
                f"Chunk header exceeds maximum allowed size ({_MAX_HEADER_LEN} bytes)."
            )
        idx += _HEADER_LEN_BYTES
        header_end = idx + header_len
        if header_end > len(buf):
            raise ChunkFormatError("Chunk header length exceeds packed size.")

        try:
            header = json.loads(buf[idx:header_end].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChunkFormatError("Invalid chunk header encoding.") from exc
        if not isinstance(header, dict):
            raise ChunkFormatError("Chunk header must be a JSON object.")

        body = buf[header_end:]

        expected_len = _require_non_negative_int(header.get("body_len"), "body_len")
        if expected_len != len(body):
            raise ChunkValidationError("Chunk body length mismatch.")

        kind = header.get("kind")
        if kind not in _VALID_KINDS:
            raise ChunkValidationError("Invalid chunk kind.")
        kind = cast(ChunkKind, kind)

        filename = header.get("filename")
        if filename is not None and not isinstance(filename, str):
            raise ChunkValidationError("filename must be string or null.")

        content_type = header.get("content_type")
        if not isinstance(content_type, str) or not content_type:
            raise ChunkValidationError("content_type must be a non-empty string.")

        encoding = header.get("encoding")
        if encoding is not None and not isinstance(encoding, str):
            raise ChunkValidationError("encoding must be string or null.")

        if encoding is not None and not encoding:
            raise ChunkValidationError("encoding must be non-empty when present.")

        transfer_id = header.get("transfer_id")
        if not isinstance(transfer_id, str) or not transfer_id:
            raise ChunkValidationError("transfer_id must be a non-empty string.")

        chunk_index = _require_non_negative_int(header.get("chunk_index"), "chunk_index")
        total_chunks = _require_non_negative_int(header.get("total_chunks"), "total_chunks")
        if total_chunks == 0:
            raise ChunkValidationError("total_chunks must be a positive int.")

        if chunk_index >= total_chunks:
            raise ChunkValidationError(
                f"chunk_index ({chunk_index}) cannot be >= total_chunks ({total_chunks})."
            )

        file_hash = _validate_sha256_hex(header.get("file_hash_sha256"), "file_hash_sha256")
        chunk_hash = _validate_sha256_hex(header.get("chunk_hash_sha256"), "chunk_hash_sha256")

        if _sha256_hex(body) != chunk_hash:
            raise ChunkValidationError("Chunk body hash mismatch (possible corruption).")

        return cls(
            transfer_id=transfer_id,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            file_hash_sha256=file_hash,
            chunk_hash_sha256=chunk_hash,
            kind=kind,
            body=body,
            filename=filename,
            content_type=content_type,
            encoding=encoding,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_chunked_transfer(
    data: bytes | bytearray,
    *,
    chunk_size: int = 32 * 1024,
    kind: ChunkKind = "binary",
    filename: str | None = None,
    content_type: str = "application/octet-stream",
    encoding: str | None = None,
) -> list[bytes]:
    """
    Split *data* into serialised chunk payloads ready for encryption.

    Each element of the returned list is the output of ``UXSPChunk.to_bytes()``.

    .. note::
        An empty *data* buffer produces exactly **one** chunk whose body is
        also empty.  This is intentional: the receiver always gets a valid,
        verifiable transfer even when the original payload is zero bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ChunkValidationError("data must be bytes or bytearray.")
    if chunk_size <= 0:
        raise ChunkValidationError("chunk_size must be positive.")

    raw = bytes(data)
    file_hash = _sha256_hex(raw)
    transfer_id = uuid.uuid4().hex

    raw_chunks: list[bytes]
    if not raw:
        raw_chunks = [b""]
    else:
        raw_chunks = [raw[i : i + chunk_size] for i in range(0, len(raw), chunk_size)]

    total = len(raw_chunks)
    packed: list[bytes] = []
    for i, chunk_body in enumerate(raw_chunks):
        chunk_hash = _sha256_hex(chunk_body)
        uxsp_chunk = UXSPChunk(
            transfer_id=transfer_id,
            chunk_index=i,
            total_chunks=total,
            file_hash_sha256=file_hash,
            chunk_hash_sha256=chunk_hash,
            kind=kind,
            body=chunk_body,
            filename=filename,
            content_type=content_type,
            encoding=encoding,
        )
        packed.append(uxsp_chunk.to_bytes())

    return packed


def create_chunked_stream_transfer(
    file_path: str | Path,
    *,
    chunk_size: int = 32 * 1024,
    kind: ChunkKind = "binary",
    filename: str | None = None,
    content_type: str = "application/octet-stream",
    encoding: str | None = None,
) -> Generator[bytes, None, None]:
    """
    Stream a file from disk, yielding serialised chunk payloads ready for encryption.
    Reads the file twice: once to compute the total SHA-256 hash and chunk count,
    and a second time to yield the chunks progressively to save memory.
    """
    from pathlib import Path

    if chunk_size <= 0:
        raise ChunkValidationError("chunk_size must be positive.")

    p = Path(file_path)
    if not p.is_file():
        raise ChunkValidationError(f"File not found: {file_path}")

    file_size = p.stat().st_size
    total = 1 if file_size == 0 else (file_size + chunk_size - 1) // chunk_size

    # Pass 1: Compute full file hash
    h = hashlib.sha256()
    with p.open("rb") as f:
        while chunk_bytes := f.read(chunk_size):
            h.update(chunk_bytes)
    file_hash = h.hexdigest()

    transfer_id = uuid.uuid4().hex

    # Pass 2: Yield chunks
    if file_size == 0:
        chunk_hash = _sha256_hex(b"")
        uxsp_chunk = UXSPChunk(
            transfer_id=transfer_id,
            chunk_index=0,
            total_chunks=total,
            file_hash_sha256=file_hash,
            chunk_hash_sha256=chunk_hash,
            kind=kind,
            body=b"",
            filename=filename,
            content_type=content_type,
            encoding=encoding,
        )
        yield uxsp_chunk.to_bytes()
        return

    with p.open("rb") as f:
        for i in range(total):
            chunk_body = f.read(chunk_size)
            if not chunk_body:
                break
            chunk_hash = _sha256_hex(chunk_body)
            uxsp_chunk = UXSPChunk(
                transfer_id=transfer_id,
                chunk_index=i,
                total_chunks=total,
                file_hash_sha256=file_hash,
                chunk_hash_sha256=chunk_hash,
                kind=kind,
                body=chunk_body,
                filename=filename,
                content_type=content_type,
                encoding=encoding,
            )
            yield uxsp_chunk.to_bytes()


def reassemble_chunked_transfer(
    packed_chunks: Sequence[bytes | bytearray],
) -> tuple[dict[str, Any], bytes]:
    """
    Verify and reassemble a chunked transfer.

    Returns ``(metadata_dict, original_bytes)``.
    Raises ``ChunkValidationError`` on any integrity failure.
    """
    if not packed_chunks:
        raise ChunkValidationError("No chunks provided.")

    decoded = [UXSPChunk.from_bytes(c) for c in packed_chunks]

    # Anchor all metadata to the first chunk.
    first = decoded[0]
    transfer_id = first.transfer_id
    total_chunks = first.total_chunks
    file_hash = first.file_hash_sha256
    kind = first.kind
    content_type = first.content_type
    filename = first.filename
    encoding = first.encoding

    for c in decoded[1:]:
        if c.transfer_id != transfer_id:
            raise ChunkValidationError("transfer_id mismatch across chunks.")
        if c.total_chunks != total_chunks:
            raise ChunkValidationError("total_chunks mismatch across chunks.")
        if c.file_hash_sha256 != file_hash:
            raise ChunkValidationError("file_hash_sha256 mismatch across chunks.")
        if (
            c.kind != kind
            or c.content_type != content_type
            or c.filename != filename
            or c.encoding != encoding
        ):
            raise ChunkValidationError("Chunk metadata mismatch across chunks.")

    index_set = {c.chunk_index for c in decoded}
    if len(index_set) != len(decoded):
        raise ChunkValidationError("Duplicate chunk_index detected.")
    if len(decoded) != total_chunks:
        raise ChunkValidationError(
            f"Chunk count mismatch: expected {total_chunks}, got {len(decoded)}."
        )

    decoded_sorted = sorted(decoded, key=lambda c: c.chunk_index)
    assembled = b"".join(c.body for c in decoded_sorted)

    if _sha256_hex(assembled) != file_hash:
        raise ChunkValidationError("Reassembled file hash mismatch (corruption).")

    meta: dict[str, Any] = {
        "transfer_id": transfer_id,
        "total_chunks": total_chunks,
        "kind": kind,
        "filename": filename,
        "content_type": content_type,
        "encoding": encoding,
        "file_hash_sha256": file_hash,
    }
    return meta, assembled


# ---------------------------------------------------------------------------
# Text convenience wrappers
# ---------------------------------------------------------------------------


def create_chunked_text(
    text: str,
    *,
    chunk_size: int = 32 * 1024,
    encoding: str = "utf-8",
) -> list[bytes]:
    """Encode *text* and chunk it as a ``"text"`` transfer."""
    if not isinstance(text, str):
        raise ChunkValidationError("text must be a str.")
    if not encoding:
        raise ChunkValidationError("encoding must be a non-empty string.")
    try:
        raw = text.encode(encoding)
    except LookupError as exc:
        raise ChunkValidationError(f"Invalid encoding: {encoding!r}") from exc
    return create_chunked_transfer(
        raw,
        chunk_size=chunk_size,
        kind="text",
        filename=None,
        content_type="text/plain",
        encoding=encoding,
    )


def decode_chunked_text(packed_chunks: Sequence[bytes | bytearray]) -> str:
    """Reassemble and decode a ``"text"`` chunked transfer."""
    meta, assembled = reassemble_chunked_transfer(packed_chunks)
    if meta["kind"] != "text":
        raise ChunkValidationError("Not a text chunked transfer.")
    enc: str = meta.get("encoding") or "utf-8"
    try:
        return assembled.decode(enc)
    except (LookupError, UnicodeDecodeError) as exc:
        raise ChunkValidationError(f"Failed to decode text with encoding {enc!r}") from exc
