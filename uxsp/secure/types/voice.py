from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload, pack_file, pack_binary
from uxsp.secure._errors import SecureSendError
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload, _resolve_download_target, _safe_is_file
from uxsp.secure._package import SecurePackage
from uxsp.secure._stream import SendStream

def SendVoice(
    receiver_id: str | int | PublicCard | Identity | None = None,
    voice_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    duration_seconds: float | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a voice note/message to receiver."""
    meta = metadata or {}
    if duration_seconds is not None:
        meta["duration_seconds"] = duration_seconds

    if isinstance(voice_path_or_bytes, (str, Path)):
        if not _safe_is_file(voice_path_or_bytes):
            raise SecureSendError(f"File not found: {voice_path_or_bytes}")
        p = Path(voice_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                stream_or_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="voice",
                metadata=metadata,
            )
        packed = pack_file(p, content_type="audio/ogg")
    elif isinstance(voice_path_or_bytes, (bytes, bytearray)):
        packed = pack_binary(voice_path_or_bytes, filename="voice.ogg", content_type="audio/ogg")
    else:
        raise SecureSendError("voice_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="voice",
        output_file=output_file,
        metadata=meta,
    )


def ReceiveVoice(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a voice note from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="voice",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_voice.ogg"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file
