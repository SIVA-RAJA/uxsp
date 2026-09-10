"""
UXSP Native Async Support (`uxsp.aio`)

High-throughput, non-blocking asynchronous dispatchers and streaming APIs for
ASGI frameworks (FastAPI, Starlette, Quart) and WebSocket connections.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import uxsp.secure as sync_secure
from uxsp.aio._types import async_receive_file_type, async_send_file_type
from uxsp.core.identity import Identity, PublicCard

# ── 1. GLOBAL CONTEXT & IDENTITY (Async Wrappers) ───────────

async def set_identity(identity: Identity) -> None:
    return await asyncio.to_thread(sync_secure.set_identity, identity)

async def get_identity() -> Identity:
    return await asyncio.to_thread(sync_secure.get_identity)

async def register_peer(peer_card_or_identity: PublicCard | Identity) -> None:
    return await asyncio.to_thread(sync_secure.register_peer, peer_card_or_identity)

async def get_peer(entity_id: str | int | PublicCard | Identity) -> PublicCard:
    return await asyncio.to_thread(sync_secure.get_peer, entity_id)

async def reset_context() -> None:
    return await asyncio.to_thread(sync_secure.reset_context)

async def rotate_keys(identity: Identity | None = None) -> Identity:
    return await asyncio.to_thread(sync_secure.rotate_keys, identity)

async def revoke_peer(peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
    return await asyncio.to_thread(sync_secure.revoke_peer, peer, reason)

async def verify_peer_validity(peer: str | int | PublicCard | Identity) -> None:
    return await asyncio.to_thread(sync_secure.verify_peer_validity, peer)

# ── 2. DATA TYPE DISPATCHERS ───────────────────────────────

def _remap_kwargs(kwargs, old_key, new_key="file_path_or_bytes"):  # type: ignore[no-untyped-def]
    if old_key in kwargs:
        kwargs[new_key] = kwargs.pop(old_key)
    return kwargs

async def SendVideo(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="video", default_filename="video.mp4", default_content_type="video/mp4", **_remap_kwargs(kwargs, "video_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceiveVideo(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="video", default_filename="received_video.mp4", **kwargs)

async def SendAudio(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="audio", default_filename="audio.mp3", default_content_type="audio/mpeg", **_remap_kwargs(kwargs, "audio_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceiveAudio(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="audio", default_filename="received_audio.mp3", **kwargs)

async def SendPhoto(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="photo", default_filename="photo.jpg", default_content_type="image/jpeg", **_remap_kwargs(kwargs, "photo_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceivePhoto(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="photo", default_filename="received_photo.jpg", **kwargs)

SendImage = SendPhoto
ReceiveImage = ReceivePhoto

async def SendText(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendText, *args, **kwargs)
async def ReceiveText(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveText, *args, **kwargs)

async def SendDocument(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="document", default_filename="document.docx", default_content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", **_remap_kwargs(kwargs, "doc_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceiveDocument(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="document", default_filename="received_document.docx", **kwargs)

SendDoc = SendDocument
ReceiveDoc = ReceiveDocument

async def SendPDF(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="pdf", default_filename="document.pdf", default_content_type="application/pdf", **_remap_kwargs(kwargs, "pdf_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceivePDF(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="pdf", default_filename="received_document.pdf", **kwargs)

async def SendFile(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="file", default_filename="file.bin", default_content_type="application/octet-stream", **kwargs)
async def ReceiveFile(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="file", default_filename="received_file.bin", **kwargs)

async def SendBinary(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendBinary, *args, **kwargs)
async def ReceiveBinary(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveBinary, *args, **kwargs)

async def SendJSON(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendJSON, *args, **kwargs)
async def ReceiveJSON(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveJSON, *args, **kwargs)

async def SendHTML(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendHTML, *args, **kwargs)
async def ReceiveHTML(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveHTML, *args, **kwargs)

async def SendArchive(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="archive", default_filename="archive.zip", default_content_type="application/zip", **_remap_kwargs(kwargs, "archive_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceiveArchive(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="archive", default_filename="received_archive.zip", **kwargs)

SendZip = SendArchive
ReceiveZip = ReceiveArchive

async def SendVoice(*args: Any, **kwargs: Any) -> Any:
    return await async_send_file_type(*args, data_type="voice", default_filename="voice.m4a", default_content_type="audio/mp4", **_remap_kwargs(kwargs, "voice_path_or_bytes"))  # type: ignore[no-untyped-call]
async def ReceiveVoice(*args: Any, **kwargs: Any) -> Any:
    return await async_receive_file_type(*args, expected_type="voice", default_filename="received_voice.m4a", **kwargs)

async def SendLocation(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendLocation, *args, **kwargs)
async def ReceiveLocation(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveLocation, *args, **kwargs)

async def SendContact(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.SendContact, *args, **kwargs)
async def ReceiveContact(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.ReceiveContact, *args, **kwargs)

# ── 3. POLYMORPHIC DISPATCHERS ─────────────────────────────

async def Send(
    receiver_id: str | int | PublicCard | Identity | None = None,
    item: Any = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    data_type: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> Any:
    """
    Async polymorphic sender: automatically inspects `item` or `data_type`
    and routes directly to native async handlers (e.g. SendVideo, SendFile).
    """
    import json

    from uxsp.secure._errors import SecureSendError
    from uxsp.secure._utils import _safe_is_file

    rec = receiver if receiver is not None else receiver_id
    snd = sender if sender is not None else sender_identity

    if data_type is not None:
        dt = data_type.lower()
        if dt == "video":
            return await SendVideo(receiver=rec, video_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "audio":
            return await SendAudio(receiver=rec, audio_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"photo", "image"}:
            return await SendPhoto(receiver=rec, photo_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "text":
            return await SendText(receiver=rec, text=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"document", "doc"}:
            return await SendDocument(receiver=rec, doc_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "pdf":
            return await SendPDF(receiver=rec, pdf_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"archive", "zip"}:
            return await SendArchive(receiver=rec, archive_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "voice":
            return await SendVoice(receiver=rec, voice_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "json":
            return await SendJSON(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "html":
            return await SendHTML(receiver=rec, html_content=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "contact":
            return await SendContact(receiver=rec, contact_data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "location":
            if isinstance(item, dict):
                lat = float(item.get("latitude", item.get("lat", 0.0)))
                lon = float(item.get("longitude", item.get("lon", 0.0)))
                desc = item.get("description")
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                lat, lon = float(item[0]), float(item[1])
                desc = None
            else:
                lat, lon, desc = 0.0, 0.0, None
            return await SendLocation(receiver=rec, latitude=lat, longitude=lon, sender=snd, description=desc, output_file=output_file, metadata=metadata)
        if dt == "binary":
            return await SendBinary(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "file":
            return await SendFile(receiver=rec, file_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"live_voice_session", "live_voice_call", "live_voice", "voice_call"}:
            pkg, _ = await SendLiveVoiceCall(receiver=rec, sender=snd, metadata=metadata)
            return pkg
        if dt == "live_session":
            pkg, _ = await SendLiveSession(receiver=rec, sender=snd, metadata=metadata)
            return pkg

    if isinstance(item, (str, Path)):
        if _safe_is_file(item):
            p = Path(item)
            ext = p.suffix.lower()
            if ext in {".mp4", ".mkv", ".avi", ".mov", ".webm"}:
                return await SendVideo(receiver=rec, video_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".mp3", ".wav", ".aac", ".flac", ".m4a"}:
                return await SendAudio(receiver=rec, audio_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}:
                return await SendPhoto(receiver=rec, photo_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext == ".pdf":
                return await SendPDF(receiver=rec, pdf_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".zip", ".tar", ".gz", ".7z", ".bz2"}:
                return await SendArchive(receiver=rec, archive_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".html", ".htm"}:
                text_content = await asyncio.to_thread(p.read_text, encoding="utf-8")
                return await SendHTML(receiver=rec, html_content=text_content, sender=snd, output_file=output_file, metadata=metadata)
            if ext == ".json":
                json_data = await asyncio.to_thread(lambda: json.loads(p.read_text(encoding="utf-8")))
                return await SendJSON(receiver=rec, data=json_data, sender=snd, output_file=output_file, metadata=metadata)
            return await SendFile(receiver=rec, file_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
        elif isinstance(item, str):
            return await SendText(receiver=rec, text=item, sender=snd, output_file=output_file, metadata=metadata)

    if isinstance(item, (dict, list)):
        return await SendJSON(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)

    if isinstance(item, (bytes, bytearray)):
        return await SendBinary(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)

    raise SecureSendError(f"Cannot automatically infer data type for item of type {type(item).__name__}")


async def Receive(
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
    Async polymorphic receiver: automatically detects data_type from the secure package
    and dispatches to the matching async Receive* handler.
    """
    from uxsp.secure._engine import _resolve_package_input

    snd = sender_card if sender_card is not None else (sender if sender is not None else sender_id)
    rec = receiver if receiver is not None else receiver_identity
    pkg = _resolve_package_input(package)
    dt = pkg.data_type.lower()

    if dt == "video":
        return await ReceiveVideo(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "audio":
        return await ReceiveAudio(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt in {"photo", "image"}:
        return await ReceivePhoto(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "text":
        return await ReceiveText(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt in {"document", "doc"}:
        return await ReceiveDocument(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "pdf":
        return await ReceivePDF(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "file":
        return await ReceiveFile(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "binary":
        return await ReceiveBinary(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt == "json":
        return await ReceiveJSON(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt == "html":
        return await ReceiveHTML(sender=snd, package=pkg, download_path=download_path, receiver=rec)
    if dt in {"archive", "zip"}:
        return await ReceiveArchive(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "voice":
        return await ReceiveVoice(sender=snd, download_path=download_path, package=pkg, receiver=rec)
    if dt == "location":
        return await ReceiveLocation(sender=snd, package=pkg, receiver=rec)
    if dt == "contact":
        return await ReceiveContact(sender=snd, package=pkg, receiver=rec)
    if dt == "live_session":
        return await ReceiveLiveSession(sender=snd, package=pkg, receiver=rec)
    if dt in {"live_voice_session", "live_voice_call", "live_voice", "voice_call"}:
        return await ReceiveLiveVoiceCall(sender=snd, package=pkg, receiver=rec)

    from uxsp.aio._engine import async_secure_receive_payload
    return await async_secure_receive_payload(
        sender_id=snd,
        package_input=pkg,
        receiver=rec,
        expected_type=dt,
    )

# ── 4. LIVE SESSIONS ────────────────────────────────────────

async def SendLiveSession(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendLiveSession, *args, **kwargs)
async def ReceiveLiveSession(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveLiveSession, *args, **kwargs)

async def SendLiveVoiceCall(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendLiveVoiceCall, *args, **kwargs)
async def ReceiveLiveVoiceCall(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveLiveVoiceCall, *args, **kwargs)

SendLiveVoice = SendLiveVoiceCall
ReceiveLiveVoice = ReceiveLiveVoiceCall
SendVoiceCall = SendLiveVoiceCall
ReceiveVoiceCall = ReceiveLiveVoiceCall
