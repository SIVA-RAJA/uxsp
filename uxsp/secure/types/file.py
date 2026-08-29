from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload, pack_file
from uxsp.secure._engine import _secure_send_payload
from uxsp.secure._errors import SecureSendError
from uxsp.secure._package import SecurePackage
from uxsp.secure._types import _receive_file_type
from uxsp.secure._utils import _safe_is_file


def SendFile(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path_or_bytes: str | Path | bytes | bytearray | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    content_type: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    if isinstance(file_path_or_bytes, (bytes, bytearray)):
        payload = UXSPPayload(
            kind="file",
            body=bytes(file_path_or_bytes),
            filename=filename or "file.bin",
            content_type=content_type or "application/octet-stream",
        )
        packed = payload.to_bytes()
    elif isinstance(file_path_or_bytes, (str, Path)):
        if not _safe_is_file(file_path_or_bytes):
            raise SecureSendError(f"File not found: {file_path_or_bytes}")
        p = Path(file_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            from uxsp.secure._stream import SendStream
            return SendStream(  # type: ignore[return-value]
                stream_or_path=p,
                receiver_id=receiver_id,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="file",
                metadata=metadata,
            )
        packed = pack_file(p, content_type=content_type)
    else:
        raise SecureSendError("file_path_or_bytes must be a path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="file",
        output_file=output_file,
        metadata=metadata,
    )

def ReceiveFile(*args, **kwargs):  # type: ignore[no-untyped-def]
    return _receive_file_type(*args, **kwargs, expected_type="file", default_filename="received_file.bin")
