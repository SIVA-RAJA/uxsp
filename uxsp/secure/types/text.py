from __future__ import annotations

from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import pack_text, unpack_text
from uxsp.secure._engine import (
    _resolve_download_target,
    _secure_receive_payload,
    _secure_send_payload,
)
from uxsp.secure._errors import SecureSendError
from uxsp.secure._package import SecurePackage


def SendText(
    receiver_id: str | int | PublicCard | Identity | None = None,
    text: str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    encoding: str = "utf-8",
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send a text message to receiver."""
    if not isinstance(text, str):
        raise SecureSendError("text must be a string.")
    packed = pack_text(text, encoding=encoding)
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="text",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveText(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> str:
    """
    Receive, decrypt, and return a text message from sender.
    If download_path is provided, also writes the text to that file.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="text",
    )
    text_content = unpack_text(raw_payload)
    if download_path is not None:
        target_file = _resolve_download_target(download_path, "received_text.txt")
        target_file.write_text(text_content, encoding="utf-8")
    return text_content
