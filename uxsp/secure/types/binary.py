from __future__ import annotations

from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload, pack_binary
from uxsp.secure._errors import SecureSendError
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload, _resolve_download_target
from uxsp.secure._package import SecurePackage

def SendBinary(
    receiver_id: str | int | PublicCard | Identity | None = None,
    data: bytes | bytearray | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    content_type: str = "application/octet-stream",
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send raw binary data to receiver."""
    if not isinstance(data, (bytes, bytearray)):
        raise SecureSendError("data must be bytes or bytearray.")
    packed = pack_binary(data, filename=filename, content_type=content_type)
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="binary",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveBinary(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> bytes:
    """
    Receive, decrypt, and return raw binary bytes from sender.
    If download_path is provided, also saves bytes to that path.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="binary",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    if download_path is not None:
        default_name = payload.filename or "received.bin"
        target_file = _resolve_download_target(download_path, default_name)
        target_file.write_bytes(payload.body)
    return payload.body
