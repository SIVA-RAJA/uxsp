from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload
from uxsp.secure._engine import _secure_receive_payload, _secure_send_payload
from uxsp.secure._errors import SecureSendError
from uxsp.secure._package import SecurePackage


def SendLocation(
    receiver_id: str | int | PublicCard | Identity | None = None,
    latitude: float = 0.0,
    longitude: float = 0.0,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    description: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send geographic coordinates to receiver."""
    if not (-90.0 <= latitude <= 90.0):
        raise SecureSendError(f"Invalid latitude {latitude}: must be between -90.0 and +90.0")
    if not (-180.0 <= longitude <= 180.0):
        raise SecureSendError(f"Invalid longitude {longitude}: must be between -180.0 and +180.0")

    loc_data = {
        "latitude": latitude,
        "longitude": longitude,
        "description": description or "",
    }
    payload = UXSPPayload(
        kind="text",
        body=json.dumps(loc_data).encode("utf-8"),
        content_type="application/vnd.uxsp.location+json",
        encoding="utf-8",
    )
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=payload.to_bytes(),
        data_type="location",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveLocation(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> dict[str, Any]:
    """Receive, decrypt, and return location data dictionary from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="location",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    return cast(dict[str, Any], json.loads(payload.body.decode("utf-8")))
