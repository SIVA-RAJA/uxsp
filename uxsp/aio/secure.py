"""
UXSP Native Async Support (`uxsp.aio`)

High-throughput, non-blocking asynchronous dispatchers and streaming APIs for
ASGI frameworks (FastAPI, Starlette, Quart) and WebSocket connections.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._package import SecurePackage
import uxsp.secure as sync_secure

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

async def SendVideo(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendVideo, *args, **kwargs)
async def ReceiveVideo(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveVideo, *args, **kwargs)

async def SendAudio(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendAudio, *args, **kwargs)
async def ReceiveAudio(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveAudio, *args, **kwargs)

async def SendPhoto(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendPhoto, *args, **kwargs)
async def ReceivePhoto(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceivePhoto, *args, **kwargs)

SendImage = SendPhoto
ReceiveImage = ReceivePhoto

async def SendText(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendText, *args, **kwargs)
async def ReceiveText(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveText, *args, **kwargs)

async def SendDocument(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendDocument, *args, **kwargs)
async def ReceiveDocument(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveDocument, *args, **kwargs)

SendDoc = SendDocument
ReceiveDoc = ReceiveDocument

async def SendPDF(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendPDF, *args, **kwargs)
async def ReceivePDF(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceivePDF, *args, **kwargs)

async def SendFile(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendFile, *args, **kwargs)
async def ReceiveFile(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveFile, *args, **kwargs)

async def SendBinary(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendBinary, *args, **kwargs)
async def ReceiveBinary(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveBinary, *args, **kwargs)

async def SendJSON(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendJSON, *args, **kwargs)
async def ReceiveJSON(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveJSON, *args, **kwargs)

async def SendHTML(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendHTML, *args, **kwargs)
async def ReceiveHTML(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveHTML, *args, **kwargs)

async def SendArchive(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendArchive, *args, **kwargs)
async def ReceiveArchive(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveArchive, *args, **kwargs)

SendZip = SendArchive
ReceiveZip = ReceiveArchive

async def SendVoice(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendVoice, *args, **kwargs)
async def ReceiveVoice(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveVoice, *args, **kwargs)

async def SendLocation(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendLocation, *args, **kwargs)
async def ReceiveLocation(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveLocation, *args, **kwargs)

async def SendContact(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.SendContact, *args, **kwargs)
async def ReceiveContact(*args: Any, **kwargs: Any) -> Any: return await asyncio.to_thread(sync_secure.ReceiveContact, *args, **kwargs)

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
