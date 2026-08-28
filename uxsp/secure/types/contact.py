from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload
from uxsp.secure._errors import SecureSendError
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload
from uxsp.secure._package import SecurePackage

def SendContact(
    receiver_id: str | int | PublicCard | Identity | None = None,
    contact_data: dict[str, Any] | str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send a contact card/info to receiver."""
    if isinstance(contact_data, dict):
        body_bytes = json.dumps(contact_data).encode("utf-8")
        ctype = "application/vnd.uxsp.contact+json"
    elif isinstance(contact_data, str):
        body_bytes = contact_data.encode("utf-8")
        ctype = "text/vcard" if "BEGIN:VCARD" in contact_data else "text/plain"
    else:
        raise SecureSendError("contact_data must be a dict or string.")

    payload = UXSPPayload(
        kind="text",
        body=body_bytes,
        content_type=ctype,
        encoding="utf-8",
    )
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=payload.to_bytes(),
        data_type="contact",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveContact(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> dict[str, Any] | str:
    """Receive, decrypt, and return contact information from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="contact",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    raw_text = payload.body.decode("utf-8")
    try:
        return cast(dict[str, Any], json.loads(raw_text))
    except json.JSONDecodeError:
        return raw_text
