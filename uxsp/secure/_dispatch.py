from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.payload import UXSPPayload
from uxsp.secure._engine import (
    _resolve_download_target,
    _resolve_package_input,
    _secure_receive_payload,
)
from uxsp.secure._errors import SecureSendError
from uxsp.secure._live import (
    ReceiveLiveSession,
    ReceiveLiveVoiceCall,
    SendLiveSession,
    SendLiveVoiceCall,
)
from uxsp.secure._package import SecurePackage
from uxsp.secure._utils import _safe_is_file
from uxsp.secure.types import (
    ReceiveArchive,
    ReceiveAudio,
    ReceiveBinary,
    ReceiveContact,
    ReceiveDocument,
    ReceiveFile,
    ReceiveHTML,
    ReceiveJSON,
    ReceiveLocation,
    ReceivePDF,
    ReceivePhoto,
    ReceiveText,
    ReceiveVideo,
    ReceiveVoice,
    SendArchive,
    SendAudio,
    SendBinary,
    SendContact,
    SendDocument,
    SendFile,
    SendHTML,
    SendJSON,
    SendPDF,
    SendPhoto,
    SendText,
    SendVideo,
    SendVoice,
)


def Send(
    receiver_id: str | int | PublicCard | Identity | None = None,
    item: Any = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    data_type: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """
    Polymorphic sender: automatically inspects `item` and routes to the correct
    specialized Send* function.
    """
    rec = receiver if receiver is not None else receiver_id
    snd = sender if sender is not None else sender_identity

    if data_type is not None:
        dt = data_type.lower()
        if dt == "video":
            return SendVideo(receiver=rec, video_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt == "audio":
            return SendAudio(receiver=rec, audio_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt in {"photo", "image"}:
            return SendPhoto(receiver=rec, photo_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt == "text":
            return SendText(receiver=rec, text=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"document", "doc"}:
            return SendDocument(receiver=rec, doc_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt == "pdf":
            return SendPDF(receiver=rec, pdf_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt in {"archive", "zip"}:
            return SendArchive(receiver=rec, archive_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt == "voice":
            return SendVoice(receiver=rec, voice_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt == "json":
            return SendJSON(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "html":
            return SendHTML(receiver=rec, html_content=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "contact":
            return SendContact(receiver=rec, contact_data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "binary":
            return SendBinary(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "file":
            return SendFile(receiver=rec, file_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        if dt in {"live_voice_session", "live_voice_call", "live_voice", "voice_call"}:
            pkg, _ = SendLiveVoiceCall(receiver=rec, sender=snd, metadata=metadata)
            return pkg
        if dt == "live_session":
            pkg, _ = SendLiveSession(receiver=rec, sender=snd, metadata=metadata)
            return pkg

    if isinstance(item, (str, Path)):
        if _safe_is_file(item):
            p = Path(item)
            ext = p.suffix.lower()
            if ext in {".mp4", ".mkv", ".avi", ".mov", ".webm"}:
                return SendVideo(receiver=rec, video_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
            if ext in {".mp3", ".wav", ".aac", ".flac", ".m4a"}:
                return SendAudio(receiver=rec, audio_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
            if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}:
                return SendPhoto(receiver=rec, photo_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
            if ext == ".pdf":
                return SendPDF(receiver=rec, pdf_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
            if ext in {".zip", ".tar", ".gz", ".7z", ".bz2"}:
                return SendArchive(receiver=rec, archive_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
            if ext in {".html", ".htm"}:
                return SendHTML(receiver=rec, html_content=p.read_text(encoding="utf-8"), sender=snd, output_file=output_file, metadata=metadata)
            if ext == ".json":
                return SendJSON(receiver=rec, data=json.loads(p.read_text(encoding="utf-8")), sender=snd, output_file=output_file, metadata=metadata)
            return SendFile(receiver=rec, file_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)  # type: ignore[return-value]
        elif isinstance(item, str):
            return SendText(receiver=rec, text=item, sender=snd, output_file=output_file, metadata=metadata)

    if isinstance(item, (dict, list)):
        return SendJSON(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)

    if isinstance(item, (bytes, bytearray)):
        return SendBinary(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)

    raise SecureSendError(f"Cannot automatically infer data type for item of type {type(item).__name__}")


def Receive(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    download_path: str | Path | None = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Any:
    """
    Polymorphic receiver: automatically detects data_type from the secure package
    and dispatches to the matching Receive* handler.
    """
    snd = sender_card if sender_card is not None else (sender if sender is not None else sender_id)
    rec = receiver if receiver is not None else receiver_identity
    pkg = _resolve_package_input(package)
    dt = pkg.data_type.lower()

    if dt == "video":
        return ReceiveVideo(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "audio":
        return ReceiveAudio(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt in {"photo", "image"}:
        return ReceivePhoto(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "text":
        return ReceiveText(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt in {"document", "doc"}:
        return ReceiveDocument(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "pdf":
        return ReceivePDF(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "file":
        return ReceiveFile(sender=snd, download_path=download_path, package=pkg, receiver=rec)  # type: ignore[no-untyped-call]
    if dt == "binary":
        return ReceiveBinary(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt == "json":
        return ReceiveJSON(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt == "html":
        return ReceiveHTML(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt in {"archive", "zip"}:
        return ReceiveArchive(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "voice":
        return ReceiveVoice(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "location":
        return ReceiveLocation(sender=snd, package=pkg, receiver=rec)
    if dt == "contact":
        return ReceiveContact(sender=snd, package=pkg, receiver=rec)
    if dt == "live_session":
        return ReceiveLiveSession(sender=snd, package=pkg, receiver=rec)
    if dt in {"live_voice_session", "live_voice_call", "live_voice", "voice_call"}:
        return ReceiveLiveVoiceCall(sender=snd, package=pkg, receiver=rec)

    # Fallback to generic payload or raw binary unpack
    raw = _secure_receive_payload(sender=snd, package_input=pkg, receiver=rec)
    try:
        payload = UXSPPayload.from_bytes(raw)
        data_to_write = payload.body
        default_name = payload.filename or "received_payload.bin"
    except Exception:
        data_to_write = raw
        default_name = "received_payload.bin"

    if download_path is not None:
        target = _resolve_download_target(download_path, default_name)
        target.write_bytes(data_to_write)
        return target
    return data_to_write
