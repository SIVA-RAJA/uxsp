from __future__ import annotations

import asyncio
import mimetypes
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

from uxsp.aio._engine import async_secure_receive_payload, async_secure_send_payload
from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload, pack_binary, pack_file
from uxsp.secure._engine import _resolve_download_target
from uxsp.secure._errors import SecureSendError
from uxsp.secure._package import SecurePackage
from uxsp.secure._utils import _safe_is_file


async def async_send_file_type(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path_or_bytes: str | Path | bytes | bytearray | None = None,
    *,
    data_type: str,
    default_filename: str,
    default_content_type: str = "application/octet-stream",
    stream: bool | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | AsyncIterator[SecurePackage]:
    if isinstance(file_path_or_bytes, (str, Path)):
        if not _safe_is_file(file_path_or_bytes):
            raise SecureSendError(f"File not found: {file_path_or_bytes}")
        p = Path(file_path_or_bytes)
        should_stream = stream if stream is not None else (p.stat().st_size > 64 * 1024 * 1024)
        if should_stream:
            from uxsp.aio.stream import SendStream
            res = await SendStream(
                stream_or_path=p,
                receiver_id=receiver_id,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type=data_type,
                metadata=metadata,
            )
            return cast(AsyncIterator[SecurePackage], res)
        fname = filename or p.name or default_filename
        ctype, _ = mimetypes.guess_type(str(p))
        packed = await asyncio.to_thread(
            pack_file, p, content_type=ctype or default_content_type, max_bytes=1024 * 1024 * 1024
        )
    elif isinstance(file_path_or_bytes, (bytes, bytearray)):
        fname = filename or default_filename
        packed = pack_binary(file_path_or_bytes, filename=fname, content_type=default_content_type)
    else:
        param_name = f"{data_type}_path_or_bytes"
        if data_type == "document":
            param_name = "doc_path_or_bytes"
        raise SecureSendError(f"{param_name} must be a file path or bytes.")

    return await async_secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type=data_type,
        output_file=output_file,
        metadata=metadata,
    )

async def async_receive_file_type(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    expected_type: str,
    default_filename: str,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    raw_payload = await async_secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type=expected_type,
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    fname = payload.filename or default_filename
    target_file = _resolve_download_target(download_path, fname)
    await asyncio.to_thread(target_file.write_bytes, payload.body)
    return target_file
