"""
UXSP Native Async Support (`uxsp.aio`)

High-throughput, non-blocking asynchronous dispatchers and streaming APIs for
ASGI frameworks (FastAPI, Starlette, Quart) and WebSocket connections.
"""

from __future__ import annotations

import asyncio
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

async def Send(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.Send, *args, **kwargs)

async def Receive(*args: Any, **kwargs: Any) -> Any:
    return await asyncio.to_thread(sync_secure.Receive, *args, **kwargs)

# ── 4. LIVE SESSIONS ────────────────────────────────────────

async def SendLiveSession(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendLiveSession, *args, **kwargs)
async def ReceiveLiveSession(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveLiveSession, *args, **kwargs)

async def SendLiveVoiceCall(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendLiveVoiceCall, *args, **kwargs)
async def ReceiveLiveVoiceCall(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveLiveVoiceCall, *args, **kwargs)

SendLiveVoice = SendLiveVoiceCall
ReceiveLiveVoice = ReceiveLiveVoiceCall
SendVoiceCall = SendLiveVoiceCall
ReceiveVoiceCall = ReceiveLiveVoiceCall
