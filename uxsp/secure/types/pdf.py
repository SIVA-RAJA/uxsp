from __future__ import annotations
from typing import Any
from collections.abc import Generator
from pathlib import Path

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._package import SecurePackage
from uxsp.secure._types import _send_file_type, _receive_file_type

def SendPDF(
    receiver_id: str | int | PublicCard | Identity | None = None,
    pdf_path_or_bytes: str | Path | bytes | bytearray | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    return _send_file_type(
        receiver_id=receiver_id,
        file_path_or_bytes=pdf_path_or_bytes,
        data_type="pdf",
        default_filename="document.pdf",
        default_content_type="application/pdf",
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )

def ReceivePDF(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    return _receive_file_type(
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        expected_type="pdf",
        default_filename="received_document.pdf",
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )




