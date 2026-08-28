from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload
from uxsp.secure._errors import SecureSendError
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload, _resolve_download_target
from uxsp.secure._package import SecurePackage

def SendJSON(
    receiver_id: str | int | PublicCard | Identity | None = None,
    data: Any = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send JSON-serializable data (dict, list, etc.) to receiver."""
    try:
        json_text = json.dumps(data, ensure_ascii=False)
    except Exception as exc:
        raise SecureSendError(f"Data is not JSON-serializable: {exc}") from exc
    payload = UXSPPayload(
        kind="text",
        body=json_text.encode("utf-8"),
        content_type="application/json",
        encoding="utf-8",
    )
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=payload.to_bytes(),
        data_type="json",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveJSON(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Any:
    """
    Receive, decrypt, and return parsed JSON data from sender.
    If download_path is provided, also writes the JSON text to that file.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="json",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    text = payload.body.decode(payload.encoding or "utf-8")
    if download_path is not None:
        target_file = _resolve_download_target(download_path, "received.json")
        target_file.write_text(text, encoding="utf-8")
    return json.loads(text)
