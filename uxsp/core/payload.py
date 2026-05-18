"""
uxsp.core.payload — Payload Packing and Unpacking

What this file does:
    Provides a simple envelope-within-the-envelope mechanism for structured
    application messages.  Before encrypting with seal() or session.encrypt(),
    callers pack their content (text, binary, or a file) using the helpers in
    this module.  The receiver unpacks after decryption to determine how to
    interpret the bytes.

    Payload types:
        TEXT   — UTF-8 encoded string.
        BINARY — Raw bytes (base64-encoded in JSON representation).
        FILE   — Binary content plus an original filename.

    Wire format:
        A JSON dict with keys: type (one of TEXT/BINARY/FILE), and either
        A binary format with a custom magic header, length-prefixed JSON
        metadata, and the raw payload body.

Public functions:
    pack_text(text, encoding)    — str → bytes (payload).
    pack_binary(data, filename, content_type) — bytes → bytes (payload).
    pack_file(path, content_type) — Path → bytes (payload).
    unpack_to_file(payload_bytes, output_dir) — bytes → Path.
    unpack_text(payload_bytes)   — bytes → str (asserts TEXT type).
    unpack_binary(payload_bytes) — bytes → bytes (asserts BINARY/FILE type).
"""
from __future__ import annotations

import json
import mimetypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

PayloadKind = Literal["text", "file", "binary"]

_MAGIC = b"UXSP-PAYLOAD-1"
_HEADER_LEN_BYTES = 4
MAX_PACK_FILE_BYTES = 64 * 1024 * 1024


class PayloadError(Exception):
    """Base class for UXSP payload packaging errors."""


class PayloadFormatError(PayloadError):
    """Raised when packed payload bytes are malformed."""


class PayloadValidationError(PayloadError):
    """Raised when payload metadata fields are invalid."""


@dataclass(frozen=True)
class UXSPPayload:
    """
    Structured payload container for all message types.

    `body` is always raw bytes so this format can carry any file type.
    """

    kind: PayloadKind
    body: bytes
    filename: str | None = None
    content_type: str = "application/octet-stream"
    encoding: str | None = None

    def to_bytes(self) -> bytes:
        header: dict[str, Any] = {
            "kind": self.kind,
            "filename": self.filename,
            "content_type": self.content_type,
            "encoding": self.encoding,
            "body_len": len(self.body),
        }
        header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        header_len = len(header_raw)
        if header_len > 0xFFFFFFFF:
            raise PayloadValidationError("Payload header too large.")
        return (
            _MAGIC
            + header_len.to_bytes(_HEADER_LEN_BYTES, byteorder="big")
            + header_raw
            + self.body
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> UXSPPayload:
        if not isinstance(raw, (bytes, bytearray)):
            raise PayloadFormatError("Packed payload must be bytes.")
        buf = bytes(raw)
        min_len = len(_MAGIC) + _HEADER_LEN_BYTES
        if len(buf) < min_len:
            raise PayloadFormatError("Packed payload is too short.")
        if not buf.startswith(_MAGIC):
            raise PayloadFormatError("Invalid payload magic header.")

        idx = len(_MAGIC)
        header_len = int.from_bytes(buf[idx : idx + _HEADER_LEN_BYTES], byteorder="big")
        idx += _HEADER_LEN_BYTES
        header_end = idx + header_len
        if header_end > len(buf):
            raise PayloadFormatError("Header length exceeds payload size.")

        try:
            header = json.loads(buf[idx:header_end].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PayloadFormatError("Invalid payload header encoding.") from exc
        if not isinstance(header, dict):
            raise PayloadFormatError("Payload header must be a JSON object.")

        body = buf[header_end:]
        expected_len = header.get("body_len")
        if not isinstance(expected_len, int) or isinstance(expected_len, bool) or expected_len < 0:
            raise PayloadValidationError("Invalid body_len in payload header.")
        if expected_len != len(body):
            raise PayloadValidationError("Payload body length mismatch.")

        kind = header.get("kind")
        if kind not in {"text", "file", "binary"}:
            raise PayloadValidationError("Invalid payload kind.")
        kind = cast(PayloadKind, kind)

        filename = header.get("filename")
        if filename is not None and not isinstance(filename, str):
            raise PayloadValidationError("filename must be a string or null.")

        content_type = header.get("content_type")
        if not isinstance(content_type, str) or not content_type:
            raise PayloadValidationError("content_type must be a non-empty string.")

        encoding = header.get("encoding")
        if encoding is not None and (not isinstance(encoding, str) or not encoding):
            raise PayloadValidationError("encoding must be a non-empty string or null.")

        return cls(
            kind=kind,
            body=body,
            filename=filename,
            content_type=content_type,
            encoding=encoding,
        )


def pack_text(text: str, *, encoding: str = "utf-8") -> bytes:
    """
    Pack a plain-text string into a payload bytes object.

    The returned bytes are ready for encryption. Use unpack_text() on the
    receiver side. Raises PayloadValidationError if text is not a str.
    """
    if not isinstance(text, str):
        raise PayloadValidationError("text must be a string.")

    if not encoding:
        raise PayloadValidationError("encoding must be a non-empty string.")

    try:
        body = text.encode(encoding)
    except LookupError as exc:
        raise PayloadValidationError(f"Unknown encoding: {encoding!r}") from exc
    payload = UXSPPayload(kind="text", body=body, content_type="text/plain", encoding=encoding)
    return payload.to_bytes()


def unpack_text(raw: bytes) -> str:
    """
    Deserialise a TEXT payload and return the plain string.

    Raises PayloadValidationError if the payload is not of type TEXT, or if
    the underlying bytes are not valid in the specified encoding.
    """
    payload = UXSPPayload.from_bytes(raw)
    if payload.kind != "text":
        raise PayloadValidationError(f"Expected text payload, got {payload.kind}.")
    if payload.encoding is None:
        raise PayloadValidationError("Text payload is missing encoding field.")
    encoding = payload.encoding
    try:
        return payload.body.decode(encoding)
    except UnicodeDecodeError as exc:
        raise PayloadValidationError(f"Text payload is not valid {encoding}.") from exc


def pack_file(
    path: str | Path, *, content_type: str | None = None, max_bytes: int = MAX_PACK_FILE_BYTES
) -> bytes:
    """
    Pack a local file into a payload bytes object.

    Automatically detects MIME type if content_type is not provided.
    Raises PayloadValidationError if file exceeds max_bytes.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise PayloadValidationError(f"File does not exist: {path}")
    size = p.stat().st_size
    if size > max_bytes:
        raise PayloadValidationError(
            f"File '{p.name}' is {size} bytes, exceeds limit of {max_bytes} bytes."
        )
    body = p.read_bytes()
    guessed, _ = mimetypes.guess_type(str(p))

    if content_type is not None and not content_type:
        raise PayloadValidationError("content_type must be a non-empty string.")
    final_type = content_type or guessed or "application/octet-stream"

    payload = UXSPPayload(
        kind="file",
        body=body,
        filename=p.name,
        content_type=final_type,
        encoding=None,
    )
    return payload.to_bytes()


def unpack_to_file(raw: bytes, output_dir: str | Path) -> Path:
    """
    Deserialise a FILE or BINARY payload and save it to the specified directory.

    Returns the path to the written file.
    """
    payload = UXSPPayload.from_bytes(raw)
    if payload.kind not in {"file", "binary"}:
        raise PayloadValidationError(f"Expected file/binary payload, got {payload.kind}.")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = payload.filename or "uxsp_payload.bin"
    safe_name = Path(filename).name

    if not safe_name or safe_name in {".", ".."}:
        safe_name = "uxsp_payload.bin"

    out = out_dir / safe_name
    out.write_bytes(payload.body)

    return out


def pack_binary(
    data: bytes | bytearray,
    *,
    filename: str | None = None,
    content_type: str = "application/octet-stream",
) -> bytes:
    """
    Pack raw binary data into a payload bytes object.

    Use unpack_to_file() or unpack_binary() on the receiver side.
    Raises PayloadValidationError if data is not bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise PayloadValidationError("binary data must be bytes.")
    if not content_type:
        raise PayloadValidationError("content_type must be a non-empty string.")
    if filename is not None and not filename:
        raise PayloadValidationError("filename must be a non-empty string or None.")

    payload = UXSPPayload(
        kind="binary",
        body=bytes(data),
        filename=filename,
        content_type=content_type,
        encoding=None,
    )
    return payload.to_bytes()
