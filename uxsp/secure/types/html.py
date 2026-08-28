from __future__ import annotations

from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload
from uxsp.secure._errors import SecureSendError
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload, _resolve_download_target
from uxsp.secure._package import SecurePackage

def SendHTML(
    receiver_id: str | int | PublicCard | Identity | None = None,
    html_content: str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send HTML content to receiver."""
    if not isinstance(html_content, str):
        raise SecureSendError("html_content must be a string.")
    payload = UXSPPayload(
        kind="text",
        body=html_content.encode("utf-8"),
        content_type="text/html",
        encoding="utf-8",
    )
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=payload.to_bytes(),
        data_type="html",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveHTML(
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
    Receive, decrypt, and return HTML content from sender.
    If download_path is provided, also writes HTML to that file.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="html",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    html_text = payload.body.decode(payload.encoding or "utf-8")
    if download_path is not None:
        target_file = _resolve_download_target(download_path, "received.html")
        target_file.write_text(html_text, encoding="utf-8")
    return html_text
